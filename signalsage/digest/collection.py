"""Collect article records without model calls or podcast downloads."""

import asyncio
import json
import time
from urllib.parse import urljoin, urlparse

import feedparser
import httpx

from .fetcher import (
    _extract_feed_items,
    _extract_json_feed_items,
    _extract_web_content,
    _fetch_raw,
    _is_feed_url,
    _resolve_is_public_host,
    _user_agent,
)

# Most recent entries kept per source per collection. Some feeds publish their
# entire archive (MSRC ~5,000 items, OpenAI ~1,200); re-ingesting all of that
# every collection is pure waste, and 100 comfortably covers late or
# out-of-order publications.
_MAX_ITEMS_PER_SOURCE = 100

# Minimum seconds between requests to hosts with strict unauthenticated rate
# limits. Reddit allows ~10 requests/min per IP and 429s bursts even 3s apart.
_HOST_MIN_INTERVAL = {"reddit.com": 7.0}
_host_locks: dict[str, asyncio.Lock] = {}
_host_last: dict[str, float] = {}


async def _throttle(url: str) -> None:
    host = (urlparse(url).hostname or "").lower()
    for domain, interval in _HOST_MIN_INTERVAL.items():
        if host == domain or host.endswith("." + domain):
            lock = _host_locks.setdefault(domain, asyncio.Lock())
            async with lock:
                wait = _host_last.get(domain, 0.0) + interval - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(wait)
                _host_last[domain] = time.monotonic()
            return


def _most_recent(items: list[dict]) -> list[dict]:
    """Newest first (undated entries keep feed order, ahead of dated ones), capped."""
    if len(items) <= _MAX_ITEMS_PER_SOURCE:
        return items
    ordered = sorted(items, key=lambda i: -(i.get("published_ts") or float("inf")))
    return ordered[:_MAX_ITEMS_PER_SOURCE]


async def collect_source(source: dict) -> tuple[list[dict], str | None]:
    await _throttle(source["url"])
    items, error = await _collect_source(source)
    return _most_recent(items), error


async def _collect_source(source: dict) -> tuple[list[dict], str | None]:
    url = source["url"]
    response = await _fetch_raw(url, 20)
    if response is None:
        return [], "Source download failed"
    raw, content_type, final_url = response
    try:
        if "json" in content_type or url.split("?")[0].endswith(".json"):
            data = json.loads(raw)
            if not isinstance(data, (dict, list)):
                raise ValueError("Invalid JSON feed")
            # Large JSON feeds (CISA KEV has 1000+ entries, each HTML-stripped) are
            # CPU-bound; keep them off the event loop.
            return await asyncio.to_thread(_extract_json_feed_items, raw), None
        if (
            _is_feed_url(url, content_type)
            or "xml" in content_type
            or raw.lstrip().startswith(("<?xml", "<rss", "<feed"))
        ):
            feed = await asyncio.to_thread(feedparser.parse, raw)
            if not feed.get("entries") and feed.get("bozo"):
                raise ValueError("Malformed feed")
            items = await _extract_feed_items(feed, max_chars=12000)
            for item in items:
                item["link"] = urljoin(final_url, item.get("link", "")) if item.get("link") else ""
            return items, None
        content, title = await asyncio.to_thread(_extract_web_content, raw, 12000)
        if not content:
            return [], "No readable page content"
        return [
            {
                "title": title or source.get("name", url),
                "link": final_url,
                "summary": content,
                "published_ts": None,
                "whole_page": True,
            }
        ], None
    except (ValueError, TypeError, KeyError) as exc:
        return [], str(exc)


async def fetch_article_text(url: str, max_chars: int = 6000) -> str | None:
    """Fetch only shortlisted public articles; validate every redirect and bound download size."""
    async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
        for _ in range(4):
            parsed = urlparse(url)
            if (
                parsed.scheme not in {"https", "http"}
                or parsed.username
                or not await _resolve_is_public_host(parsed.hostname or "")
            ):
                return None
            try:
                async with client.stream(
                    "GET", url, headers={"User-Agent": _user_agent(url)}
                ) as response:
                    if response.is_redirect:
                        url = urljoin(url, response.headers.get("location", ""))
                        continue
                    response.raise_for_status()
                    if "html" not in response.headers.get("content-type", "").lower():
                        return None
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 2 * 1024 * 1024:
                            return None
                    html = body.decode(response.encoding or "utf-8", errors="replace")
                text, _ = await asyncio.to_thread(_extract_web_content, html, max_chars)
                return text if len(text) >= 200 else None
            except (httpx.HTTPError, ValueError):
                return None
    return None
