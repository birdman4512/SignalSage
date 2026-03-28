"""RSS/web content fetcher for the daily digest."""

import asyncio
import logging
import re

import feedparser
import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

_FEED_EXTENSIONS = (".xml", ".rss", ".atom")
_XML_CONTENT_TYPES = ("application/rss+xml", "application/atom+xml", "text/xml", "application/xml")
_WHITESPACE_RE = re.compile(r"\s+")


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


def _extract_feed_content(feed_data: dict, max_chars: int) -> str:
    """Extract text content from a parsed feedparser feed."""
    parts: list[str] = []
    for entry in feed_data.get("entries", [])[:5]:
        title = entry.get("title", "")
        summary = entry.get("summary", "") or entry.get("description", "")
        link = entry.get("link", "")

        # Strip HTML from summary
        if summary:
            summary = _strip_html(summary)
        text = f"Title: {title}\n{summary}"
        if link:
            text += f"\nURL: {link}"
        parts.append(text)

    combined = "\n\n---\n\n".join(parts)
    return combined[:max_chars]


def _extract_web_content(html: str, max_chars: int) -> str:
    """Extract readable text from an HTML page."""
    soup = BeautifulSoup(html, "lxml")

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
            headers={"User-Agent": "SignalSage/1.0 (Threat Intelligence Bot)"},
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
                content = _extract_feed_content(feed_data, max_chars)
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
) -> list[dict]:
    """
    Fetch all sources for a topic concurrently.

    Args:
        sources: list of dicts with 'name' and 'url' keys
        max_chars: max characters per source
        timeout: HTTP timeout in seconds

    Returns:
        list of dicts: {name, url, content}
    """

    async def _fetch_one(source: dict) -> dict:
        name = source.get("name", "Unknown")
        url = source.get("url", "")
        if not url:
            return {"name": name, "url": url, "content": ""}
        content, canonical_url = await fetch_source(url, max_chars, timeout)
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
