"""RSS/web content fetcher for the daily digest."""

import asyncio
import calendar
import datetime
import ipaddress
import json
import logging
import re
import socket
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

import feedparser
import httpx
from bs4 import BeautifulSoup

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
# Reddit blocks non-browser User-Agents — use a generic browser UA for reddit.com
_REDDIT_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0"


def _user_agent(url: str) -> str:
    if "reddit.com" in url:
        return _REDDIT_UA
    return _DEFAULT_UA


# Max audio file size to attempt transcription (bytes). Downloads larger than this are skipped.
_MAX_AUDIO_BYTES = 200 * 1024 * 1024  # 200 MB

# Cap how many redirect hops the audio downloader will follow. A compromised feed
# can redirect from a benign-looking URL to internal infrastructure (Ollama on the
# internal Docker network, cloud metadata services, etc.) — limit + revalidate.
_MAX_AUDIO_REDIRECTS = 3


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


def _strip_html(html: str) -> str:
    """Strip HTML tags and collapse whitespace."""
    soup = BeautifulSoup(html, "lxml")
    text = soup.get_text(separator=" ")
    return _WHITESPACE_RE.sub(" ", text).strip()


async def _transcribe_audio(
    audio_url: str,
    whisper_base_url: str,
    timeout: int = 600,
) -> str | None:
    """
    Download an audio file and transcribe it via the Whisper API.

    Returns the transcript text, or None on failure.
    """
    logger.info("Downloading audio for transcription: %s", audio_url)

    # SSRF guard: only allow http(s) URLs whose host resolves to a public address.
    # A malicious or compromised feed could otherwise redirect this fetch to
    # cloud-metadata endpoints or internal services on the Docker network.
    parsed = urlparse(audio_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        logger.warning("Refusing audio URL with disallowed scheme/host: %s", audio_url)
        return None
    if not await _resolve_is_public_host(parsed.hostname):
        logger.warning("Refusing audio URL — host resolves to non-public address: %s", audio_url)
        return None

    tmp_path: str | None = None
    total = 0
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

                suffix = Path(audio_url.split("?")[0]).suffix or ".mp3"
                # delete=False so we can re-open the file for upload to Whisper;
                # the outer finally block guarantees cleanup on every exit path.
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

        logger.info("Transcribing %.1f MB audio via Whisper...", total / (1024 * 1024))
        whisper_url = f"{whisper_base_url.rstrip('/')}/v1/audio/transcriptions"
        async with httpx.AsyncClient(timeout=timeout) as client:
            with open(tmp_path, "rb") as audio_file:
                resp = await client.post(
                    whisper_url,
                    files={"file": (Path(tmp_path).name, audio_file, "audio/mpeg")},
                    data={"model": "Systran/faster-whisper-base.en"},
                )
            resp.raise_for_status()
            transcript = resp.json().get("text", "").strip()
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


async def _extract_feed_content(
    feed_data: dict,
    max_chars: int,
    lookback_seconds: int | None = None,
    whisper_base_url: str | None = None,
) -> str:
    """Extract text content from a parsed feedparser feed, optionally filtered by age."""
    cutoff = time.time() - lookback_seconds if lookback_seconds else None
    parts: list[str] = []

    entries = feed_data.get("entries", [])[:10]
    logger.info("Feed has %d entries (cutoff=%s)", len(entries), "set" if cutoff else "none")
    for entry in entries:
        # Filter by publish date when lookback is set
        if cutoff is not None:
            published = entry.get("published_parsed") or entry.get("updated_parsed")
            if published:
                entry_ts = calendar.timegm(published)
                if entry_ts < cutoff:
                    logger.info("Skipping entry (too old): %r", entry.get("title", ""))
                    continue  # too old

        title = entry.get("title", "")
        summary = entry.get("summary", "") or entry.get("description", "")
        link = entry.get("link", "")

        if summary:
            summary = _strip_html(summary)

        # Try podcast transcription if Whisper is configured and entry has audio
        audio_url = _get_audio_enclosure(entry)
        if audio_url:
            if whisper_base_url:
                transcript = await _transcribe_audio(audio_url, whisper_base_url)
                if transcript:
                    summary = f"[Transcript]\n{transcript[:max_chars]}"
            else:
                logger.info("Audio enclosure found but Whisper disabled — skipping: %s", audio_url)
        else:
            logger.debug("No audio enclosure in entry: %r", title)

        if not link:
            logger.warning("Feed entry has no link: %r", title)
        text = f"Title: {title}"
        if link:
            text += f"\nURL: {link}"
        if summary:
            text += f"\n{summary}"
        parts.append(text)

        if len(parts) >= 10:
            break

    if not parts:
        return ""

    linked = sum(1 for p in parts if "\nURL: " in p)
    logger.info("Feed: %d entries included, %d have URLs", len(parts), linked)
    combined = "\n\n---\n\n".join(parts)
    return combined[:max_chars]


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


def _extract_json_feed(raw: str, max_chars: int, lookback_seconds: int | None = None) -> str:
    """
    Extract digest content from JSON feeds.

    Handles the CISA KEV format ({"vulnerabilities": [...]}) and generic
    arrays-of-objects that have title/name + description/summary fields.
    """
    try:
        data = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return ""

    cutoff = time.time() - lookback_seconds if lookback_seconds else None

    # Normalise to a list of objects
    if isinstance(data, dict):
        # CISA KEV: {"vulnerabilities": [...]}
        items = data.get("vulnerabilities") or data.get("items") or data.get("entries") or []
    elif isinstance(data, list):
        items = data
    else:
        return ""

    if not isinstance(items, list):
        return ""

    parts: list[str] = []
    for item in items[:20]:
        if not isinstance(item, dict):
            continue

        # Date filter — find the first present date field and decide once
        if cutoff:
            too_old = False
            for date_field in ("dateAdded", "datePublished", "published", "date"):
                raw_date = item.get(date_field, "")
                if not raw_date:
                    continue
                try:
                    parsed = datetime.date.fromisoformat(str(raw_date)[:10])
                    item_ts = datetime.datetime(parsed.year, parsed.month, parsed.day).timestamp()
                    if item_ts < cutoff:
                        too_old = True
                except (ValueError, TypeError):
                    pass
                break
            if too_old:
                continue

        # Extract fields — prefer CISA KEV names, fall back to generic names
        title = (
            item.get("vulnerabilityName")
            or item.get("cveID")
            or item.get("title")
            or item.get("name")
            or ""
        )
        description = (
            item.get("shortDescription") or item.get("description") or item.get("summary") or ""
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

        text = f"Title: {title}"
        if url:
            text += f"\nURL: {url}"
        if description:
            text += f"\n{description}"
        if action:
            text += f"\nRequired action: {action}"
        parts.append(text)

        if len("".join(parts)) >= max_chars:
            break

    if not parts:
        return ""

    combined = "\n\n---\n\n".join(parts)
    logger.info("JSON feed: extracted %d item(s)", len(parts))
    return combined[:max_chars]


async def fetch_source(
    url: str,
    max_chars: int = 3000,
    timeout: int = 15,
    lookback_seconds: int | None = None,
    whisper_base_url: str | None = None,
) -> tuple[str, str]:
    """
    Fetch content from a URL.

    Returns:
        tuple: (text_content, canonical_url)
    """
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": _user_agent(url)},
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            raw_content = resp.text
            final_url = str(resp.url)
    except httpx.TimeoutException:
        logger.warning("Timeout fetching %s", url)
        return "", url
    except httpx.HTTPStatusError as exc:
        logger.warning("HTTP error %d fetching %s", exc.response.status_code, url)
        return "", url
    except Exception as exc:
        logger.warning("Error fetching %s: %s", url, exc)
        return "", url

    # Determine if it's a feed
    if _is_feed_url(url, content_type) or "xml" in content_type.lower():
        try:
            # Use feedparser (it works on strings too)
            feed_data = feedparser.parse(raw_content)
            if feed_data.get("entries"):
                content = await _extract_feed_content(
                    feed_data, max_chars, lookback_seconds, whisper_base_url
                )
                return content, final_url
        except Exception as exc:
            logger.warning("Feedparser failed for %s: %s", url, exc)

    # JSON feed — try CISA KEV format and generic array-of-objects
    if "json" in content_type.lower() or url.lower().split("?")[0].endswith(".json"):
        content = _extract_json_feed(raw_content, max_chars, lookback_seconds)
        if content:
            return content, final_url

    # Fall back to HTML extraction — prefix with Title:/URL: so the summarizer
    # can stamp an [A<N>] label and inject URLs for items from this page.
    content, page_title = _extract_web_content(raw_content, max_chars)
    if content:
        if page_title:
            content = f"Title: {page_title}\nURL: {final_url}\n{content}"
        else:
            content = f"{content}\nURL: {final_url}"
    return content, final_url


async def fetch_topic(
    sources: list[dict],
    max_chars: int = 3000,
    timeout: int = 15,
    lookback_seconds: int | None = None,
    whisper_base_url: str | None = None,
) -> list[dict]:
    """
    Fetch all sources for a topic concurrently.

    Args:
        sources: list of dicts with 'name' and 'url' keys
        max_chars: max characters per source
        timeout: HTTP timeout in seconds
        whisper_base_url: base URL of Whisper service for podcast transcription (optional)

    Returns:
        list of dicts: {name, url, content}
    """

    async def _fetch_one(source: dict) -> dict:
        name = source.get("name", "Unknown")
        url = source.get("url", "")
        image_url = source.get("image_url") or None
        if not url:
            return {"name": name, "url": url, "content": "", "image_url": image_url}
        content, canonical_url = await fetch_source(
            url, max_chars, timeout, lookback_seconds, whisper_base_url
        )
        return {
            "name": name,
            "url": canonical_url or url,
            "content": content,
            "image_url": image_url,
        }

    tasks = [_fetch_one(s) for s in sources]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    output: list[dict] = []
    for source, result in zip(sources, results):
        if isinstance(result, Exception):
            logger.warning("Failed to fetch %s: %s", source.get("url", ""), result)
            output.append(
                {
                    "name": source.get("name", ""),
                    "url": source.get("url", ""),
                    "content": "",
                    "image_url": source.get("image_url") or None,
                }
            )
        else:
            output.append(result)  # type: ignore[arg-type]

    return output
