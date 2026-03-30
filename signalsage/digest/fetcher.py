"""RSS/web content fetcher for the daily digest."""

import asyncio
import calendar
import logging
import re
import tempfile
import time
from pathlib import Path

import feedparser
import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

_FEED_EXTENSIONS = (".xml", ".rss", ".atom")
_XML_CONTENT_TYPES = ("application/rss+xml", "application/atom+xml", "text/xml", "application/xml")
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


def parse_lookback(lookback: str | None) -> int | None:
    """Convert a lookback string like '24h' or '7d' to seconds, or None for no limit."""
    if not lookback:
        return None
    lookback = lookback.strip().lower()
    if lookback.endswith("h"):
        return int(lookback[:-1]) * 3600
    if lookback.endswith("d"):
        return int(lookback[:-1]) * 86400
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
    try:
        async with httpx.AsyncClient(
            timeout=60,
            follow_redirects=True,
            headers={"User-Agent": "SignalSage/1.0 (Threat Intelligence Bot)"},
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

                # Stream into a temp file
                suffix = Path(audio_url.split("?")[0]).suffix or ".mp3"
                with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
                    tmp_path = tmp.name
                    total = 0
                    async for chunk in resp.aiter_bytes(chunk_size=65536):
                        total += len(chunk)
                        if total > _MAX_AUDIO_BYTES:
                            logger.warning(
                                "Audio stream exceeded size limit, skipping: %s", audio_url
                            )
                            return None
                        tmp.write(chunk)
    except Exception as exc:
        logger.warning("Failed to download audio %s: %s", audio_url, exc)
        return None

    logger.info("Transcribing %.1f MB audio via Whisper...", total / (1024 * 1024))
    try:
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
        logger.warning("Whisper transcription failed for %s: %s", audio_url, exc)
        return None
    finally:
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

    entries = feed_data.get("entries", [])[:20]
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
            logger.info("No audio enclosure in entry: %r", title)

        text = f"Title: {title}\n{summary}"
        if link:
            text += f"\nURL: {link}"
        parts.append(text)

        if len(parts) >= 10:
            break

    if not parts:
        return ""

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


def _extract_web_content(html: str, max_chars: int) -> str:
    """Extract readable text from an HTML page."""
    soup = BeautifulSoup(html, "lxml")

    if _is_soft_404(soup):
        return ""

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
    return text[:max_chars]


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

    # Fall back to HTML extraction
    content = _extract_web_content(raw_content, max_chars)
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
        if not url:
            return {"name": name, "url": url, "content": ""}
        content, canonical_url = await fetch_source(
            url, max_chars, timeout, lookback_seconds, whisper_base_url
        )
        return {"name": name, "url": canonical_url or url, "content": content}

    tasks = [_fetch_one(s) for s in sources]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    output: list[dict] = []
    for source, result in zip(sources, results):
        if isinstance(result, Exception):
            logger.warning("Failed to fetch %s: %s", source.get("url", ""), result)
            output.append(
                {"name": source.get("name", ""), "url": source.get("url", ""), "content": ""}
            )
        else:
            output.append(result)  # type: ignore[arg-type]

    return output
