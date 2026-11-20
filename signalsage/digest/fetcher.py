"""RSS/web content fetcher for the daily digest."""

import asyncio
import calendar
import datetime
import html
import ipaddress
import json
import logging
import re
import socket
import tempfile
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from cachetools import TTLCache

logger = logging.getLogger(__name__)

_FEED_EXTENSIONS = (".xml", ".rss", ".atom")
_XML_CONTENT_TYPES = (
    "application/rss+xml",
    "application/atom+xml",
    "text/xml",
    "application/xml",
)
_WHITESPACE_RE = re.compile(r"\s+")

_DEFAULT_UA = "SignalSage/1.0 (Threat Intelligence Bot)"
_BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"
# Hosts that reject or stall non-browser User-Agents (verified from the
# production host): Reddit 429s, DX World and bom.gov.au 403, and
# cyber.gov.au (ASD's ACSC) hangs until the request times out.
_BROWSER_UA_HOSTS = ("reddit.com", "dx-world.net", "cyber.gov.au", "bom.gov.au")


def _user_agent(url: str) -> str:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return _DEFAULT_UA
    if any(host == h or host.endswith("." + h) for h in _BROWSER_UA_HOSTS):
        return _BROWSER_UA
    return _DEFAULT_UA


# Max audio file size to attempt transcription (bytes). Gemini bills audio at
# ~32 tokens/second, and the free tier caps tokens per minute (~125k), so one
# request must stay under roughly an hour of audio: 64 MB is ~65 minutes at
# 128 kbps. Longer episodes fall back to their feed description.
_MAX_AUDIO_BYTES = 64 * 1024 * 1024  # 64 MB

# Gemini-accepted audio types by file extension, for servers that send a generic
# Content-Type such as application/octet-stream.
_AUDIO_MIME = {
    ".mp3": "audio/mpeg",
    ".m4a": "audio/aac",
    ".aac": "audio/aac",
    ".ogg": "audio/ogg",
    ".oga": "audio/ogg",
    ".opus": "audio/ogg",
    ".wav": "audio/wav",
    ".flac": "audio/flac",
}

Transcriber = Callable[[str, str], Awaitable[str | None]]

# Cap how many redirect hops the audio downloader will follow. A compromised feed
# can redirect from a benign-looking URL to internal infrastructure (services on the
# internal Docker network, cloud metadata services, etc.) — limit + revalidate.
_MAX_AUDIO_REDIRECTS = 3

# Transcripts keyed by audio URL. Podcast feeds list the same ~10 episodes on
# every fetch, and a multi-day lookback re-sees the same episode on every run —
# without this each run re-downloads and re-transcribes tens of MB per episode.
# Failures are remembered for a shorter window so a flaky host (or a quota limit)
# is retried later rather than hammered on every poll.
_TRANSCRIPT_CACHE: TTLCache = TTLCache(maxsize=256, ttl=14 * 86400)
_TRANSCRIPT_FAILURES: TTLCache = TTLCache(maxsize=256, ttl=6 * 3600)


async def _resolve_is_public_host(host: str) -> bool:
    """Return True only if every resolved address for *host* is publicly routable.

    Used as an SSRF guard before fetching attacker-influenced URLs (audio enclosures
    from RSS feeds). Rejects loopback/link-local/private/multicast/reserved/cloud-
    metadata addresses (169.254.169.254 falls under link-local).
    """
    if not host:
        return False
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return False
    for info in infos:
        addr_str = info[4][0]
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            return False
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            return False
    return True


def parse_lookback(lookback: str | None) -> int | None:
    """Convert a lookback string like '24h' or '7d' to seconds, or None for no limit."""
    if not lookback:
        return None
    s = lookback.strip().lower()
    try:
        if s.endswith("h"):
            return int(s[:-1]) * 3600
        if s.endswith("d"):
            return int(s[:-1]) * 86400
    except ValueError:
        logger.warning("Unrecognised lookback format %r — no time filter applied", lookback)
        return None
    logger.warning("Unrecognised lookback format %r — no time filter applied", lookback)
    return None


def _is_feed_url(url: str, content_type: str = "") -> bool:
    """Determine if URL points to a feed."""
    url_lower = url.lower().split("?")[0]
    if any(url_lower.endswith(ext) for ext in _FEED_EXTENSIONS):
        return True
    if any(ct in content_type for ct in _XML_CONTENT_TYPES):
        return True
    return False


_TAG_RE = re.compile(r"</?[a-zA-Z][^>]*>")


def clean_title(title: str) -> str:
    """One-line plain-text headline: no HTML tags, entities or line breaks.

    Some feeds put markup in titles (The Register wraps words in ``<span>``)
    or line breaks (BOM warnings); either breaks a Slack ``<url|title>`` link.
    """
    title = str(title or "")
    if _TAG_RE.search(title):
        title = BeautifulSoup(title, "lxml").get_text()
    else:
        title = html.unescape(title)
    return _WHITESPACE_RE.sub(" ", title).strip()


# A date written into a URL or headline: 20240415, 2024-04-15, 2023.03.27.
_TEXT_DATE_RE = re.compile(
    r"(?<!\d)(20\d\d)[-./_]?(0[1-9]|1[0-2])[-./_]?(0[1-9]|[12]\d|3[01])(?!\d)"
)


def _date_from_text(*values: str) -> float | None:
    """Midnight UTC of the first date found in *values*, else None."""
    for value in values:
        for match in _TEXT_DATE_RE.finditer(value or ""):
            try:
                day = datetime.date(int(match[1]), int(match[2]), int(match[3]))
            except ValueError:
                continue
            return float(calendar.timegm(day.timetuple()))
    return None


def _extract_page_links(html_text: str, base_url: str, pattern: str) -> list[dict]:
    """Turn an index page's links into feed items, for sites without RSS.

    Every link whose absolute URL matches *pattern* becomes one item, titled
    with its link text. A date in the URL or link text becomes its publish
    time, so the first-install lookback skips old entries; undated links are
    imported on the first run.
    """
    regex = re.compile(pattern)
    soup = BeautifulSoup(html_text, "lxml")
    items: list[dict] = []
    seen: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        url = urljoin(base_url, str(anchor["href"]).strip())
        title = clean_title(anchor.get_text(" ", strip=True))
        if not title or url in seen or not regex.search(url):
            continue
        seen.add(url)
        items.append(
            {
                "title": title,
                "link": url,
                "summary": title,
                "published_ts": _date_from_text(url, title),
            }
        )
    return items


def _strip_html(html: str) -> str:
    """Strip HTML tags and collapse whitespace."""
    soup = BeautifulSoup(html, "lxml")
    text = soup.get_text(separator=" ")
    return _WHITESPACE_RE.sub(" ", text).strip()


async def _transcribe_audio(audio_url: str, transcriber: Transcriber) -> str | None:
    """Download an audio file and transcribe it, with results (and failures) cached by URL.

    *transcriber* is called with (local_path, mime_type), e.g. GeminiLLM.transcribe.
    Returns the transcript text, or None on failure.
    """
    if audio_url in _TRANSCRIPT_CACHE:
        return _TRANSCRIPT_CACHE[audio_url]
    if audio_url in _TRANSCRIPT_FAILURES:
        logger.debug("Skipping audio that recently failed to transcribe: %s", audio_url)
        return None
    transcript = await _download_and_transcribe(audio_url, transcriber)
    if transcript:
        _TRANSCRIPT_CACHE[audio_url] = transcript
    else:
        _TRANSCRIPT_FAILURES[audio_url] = True
    return transcript


async def _download_and_transcribe(audio_url: str, transcriber: Transcriber) -> str | None:
    logger.info("Downloading audio for transcription: %s", audio_url)

    # SSRF guard: only allow http(s) URLs whose host resolves to a public address.
    # A malicious or compromised feed could otherwise redirect this fetch to
    # cloud-metadata endpoints or internal services.
    parsed = urlparse(audio_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        logger.warning("Refusing audio URL with disallowed scheme/host: %s", audio_url)
        return None
    if not await _resolve_is_public_host(parsed.hostname):
        logger.warning("Refusing audio URL — host resolves to non-public address: %s", audio_url)
        return None

    tmp_path: str | None = None
    total = 0
    mime = "audio/mpeg"
    try:
        # max_redirects keeps the redirect chain short; even after the upfront
        # host check, the server could 302 toward an internal address.
        async with httpx.AsyncClient(
            timeout=60,
            follow_redirects=True,
            max_redirects=_MAX_AUDIO_REDIRECTS,
            headers={"User-Agent": _DEFAULT_UA},
        ) as client:
            async with client.stream("GET", audio_url) as resp:
                resp.raise_for_status()
                content_length = int(resp.headers.get("content-length", 0))
                if content_length and content_length > _MAX_AUDIO_BYTES:
                    logger.warning(
                        "Audio file too large (%d MB), skipping: %s",
                        content_length // (1024 * 1024),
                        audio_url,
                    )
                    return None

                suffix = Path(audio_url.split("?")[0]).suffix.lower() or ".mp3"
                served = resp.headers.get("content-type", "").split(";")[0].strip().lower()
                mime = served if served.startswith("audio/") else _AUDIO_MIME.get(suffix, mime)
                # delete=False so the file can be re-opened for upload; the outer
                # finally block guarantees cleanup on every exit path.
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                    tmp_path = tmp.name
                    async for chunk in resp.aiter_bytes(chunk_size=65536):
                        total += len(chunk)
                        if total > _MAX_AUDIO_BYTES:
                            logger.warning(
                                "Audio stream exceeded size limit, skipping: %s", audio_url
                            )
                            return None
                        tmp.write(chunk)

        if not tmp_path:
            return None
        logger.info("Transcribing %.1f MB of %s audio...", total / (1024 * 1024), mime)
        transcript = (await transcriber(tmp_path, mime) or "").strip()
        logger.info("Transcription complete: %d characters", len(transcript))
        return transcript or None
    except Exception as exc:
        logger.warning("Audio download/transcription failed for %s: %s", audio_url, exc)
        return None
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass


def _get_audio_enclosure(entry: dict) -> str | None:
    """Return the URL of the first audio enclosure in a feed entry, or None."""
    for enc in entry.get("enclosures", []):
        mime = enc.get("type", "")
        url = enc.get("href", "") or enc.get("url", "")
        if mime.startswith("audio/") and url:
            return url
    return None


async def _extract_feed_items(
    feed_data: dict,
    max_chars: int,
    lookback_seconds: int | None = None,
) -> list[dict]:
    """Extract discrete items from a parsed feedparser feed, optionally filtered by age.

    Returns a list of {title, link, summary, published_ts} dicts, newest-feed-order
    preserved. All available entries are inspected before date filtering. Audio
    enclosures are recorded as ``audio_url``; episodes are transcribed later, only
    once shortlisted (see DigestPipeline.prepare).
    """
    cutoff = time.time() - lookback_seconds if lookback_seconds else None
    items: list[dict] = []

    entries = feed_data.get("entries", [])
    logger.info("Feed has %d entries (cutoff=%s)", len(entries), "set" if cutoff else "none")
    for entry in entries:
        published_ts: float | None = None
        published = entry.get("published_parsed") or entry.get("updated_parsed")
        if published:
            published_ts = calendar.timegm(published)

        # Filter by publish date when lookback is set
        if cutoff is not None and published_ts is not None and published_ts < cutoff:
            logger.info("Skipping entry (too old): %r", entry.get("title", ""))
            continue  # too old

        title = clean_title(entry.get("title", ""))
        full_content = entry.get("content") or []
        summary = (
            (full_content[0].get("value", "") if full_content else "")
            or entry.get("summary", "")
            or entry.get("description", "")
        )
        link = entry.get("link", "")

        if summary:
            # Full-content entries can be large HTML; parse off the event loop.
            summary = await asyncio.to_thread(_strip_html, summary)

        audio_url = _get_audio_enclosure(entry)

        if not link:
            logger.warning("Feed entry has no link: %r", title)

        items.append(
            {
                "title": title,
                "link": link,
                "summary": summary[:max_chars],
                "published_ts": published_ts,
                "guid": entry.get("id", ""),
                "audio_url": audio_url,
            }
        )

    return items


_SOFT_404_PATTERNS = (
    "404",
    "page not found",
    "not found",
    "no longer exists",
    "has been removed",
    "does not exist",
    "error 404",
)


def _is_soft_404(soup: BeautifulSoup) -> bool:
    """Return True if the page looks like a soft-404 (200 OK but error content)."""
    title_tag = soup.find("title")
    if title_tag:
        title = title_tag.get_text().lower()
        if any(pat in title for pat in _SOFT_404_PATTERNS):
            return True
    # Also check the first h1
    h1 = soup.find("h1")
    if h1:
        h1_text = h1.get_text().lower()
        if any(pat in h1_text for pat in _SOFT_404_PATTERNS):
            return True
    return False


def _extract_web_content(html: str, max_chars: int) -> tuple[str, str]:
    """Extract readable text from an HTML page. Returns (content, page_title)."""
    soup = BeautifulSoup(html, "lxml")

    if _is_soft_404(soup):
        return "", ""

    # Extract page title (strip site-name suffix after " | ")
    title_tag = soup.find("title")
    page_title = ""
    if title_tag:
        raw = _WHITESPACE_RE.sub(" ", title_tag.get_text()).strip()
        page_title = re.split(r"\s*\|\s*", raw)[0].strip()

    # Remove script/style elements
    for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
        tag.decompose()

    # Try to find main content area
    content_tag = (
        soup.find("article")
        or soup.find("main")
        or soup.find(id="content")
        or soup.find(class_="content")
        or soup.find("body")
    )

    if content_tag:
        # Extract paragraphs
        paragraphs = content_tag.find_all("p")
        if paragraphs:
            text = " ".join(p.get_text(separator=" ") for p in paragraphs)
        else:
            text = content_tag.get_text(separator=" ")
    else:
        text = soup.get_text(separator=" ")

    text = _WHITESPACE_RE.sub(" ", text).strip()
    return text[:max_chars], page_title


def _extract_json_feed_items(raw: str, lookback_seconds: int | None = None) -> list[dict]:
    """
    Extract discrete items from JSON feeds.

    Handles the CISA KEV format ({"vulnerabilities": [...]}) and generic
    arrays-of-objects that have title/name + description/summary fields.
    Returns a list of {title, link, summary, published_ts} dicts.
    """
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return []

    cutoff = time.time() - lookback_seconds if lookback_seconds else None

    # Normalise to a list of objects
    if isinstance(data, dict):
        # CISA KEV: {"vulnerabilities": [...]}
        raw_items = data.get("vulnerabilities") or data.get("items") or data.get("entries") or []
    elif isinstance(data, list):
        raw_items = data
    else:
        return []

    if not isinstance(raw_items, list):
        return []

    items: list[dict] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue

        # Date filter — find the first present date field and decide once
        item_ts: float | None = None
        too_old = False
        for date_field in ("dateAdded", "date_published", "datePublished", "published", "date"):
            raw_date = item.get(date_field, "")
            if not raw_date:
                continue
            try:
                parsed = datetime.datetime.fromisoformat(str(raw_date).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=datetime.UTC)
                item_ts = parsed.timestamp()
                if cutoff and item_ts < cutoff:
                    too_old = True
            except (ValueError, TypeError):
                pass
            break
        if too_old:
            continue

        # Extract fields — prefer CISA KEV names, fall back to generic names
        title = clean_title(
            item.get("vulnerabilityName")
            or item.get("cveID")
            or item.get("title")
            or item.get("name")
            or ""
        )
        description = (
            item.get("shortDescription")
            or item.get("content_text")
            or item.get("content_html")
            or item.get("description")
            or item.get("summary")
            or ""
        )
        cve_id = item.get("cveID") or item.get("id") or ""
        url = (
            item.get("url")
            or item.get("link")
            or (f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else "")
        )
        action = item.get("requiredAction") or ""

        if not title:
            continue

        summary = _strip_html(description)
        if str(cve_id).startswith("CVE-"):
            summary = f"{cve_id}: {summary}"
        if action:
            summary = (
                f"{summary}\nRequired action: {action}" if summary else f"Required action: {action}"
            )

        items.append({"title": title, "link": url, "summary": summary, "published_ts": item_ts})

    return items


async def _fetch_raw(url: str, timeout: int) -> tuple[str, str, str] | None:
    """Fetch *url* and return (raw_content, content_type, final_url), or None on failure."""
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": _user_agent(url)},
        ) as client:
            async with client.stream("GET", url) as resp:
                resp.raise_for_status()
                chunks = bytearray()
                async for chunk in resp.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > 10 * 1024 * 1024:
                        raise ValueError("Source exceeds 10 MB download limit")
                return (
                    chunks.decode(resp.encoding or "utf-8", errors="replace"),
                    resp.headers.get("content-type", ""),
                    str(resp.url),
                )
    except httpx.TimeoutException:
        logger.warning("Timeout fetching %s", url)
    except httpx.HTTPStatusError as exc:
        logger.warning("HTTP error %d fetching %s", exc.response.status_code, url)
    except Exception as exc:
        logger.warning("Error fetching %s: %s", url, exc)
    return None
