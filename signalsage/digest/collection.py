"""Collect article records without model calls or podcast downloads."""

import asyncio
import json
import time
from urllib.parse import urljoin, urlparse

import feedparser
import httpx

from . import reddit
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

# Hosts with strict unauthenticated rate limits. Reddit's response headers on
# the production host show a budget of ONE request per ~60s window
# (x-ratelimit-used=1, remaining=0, reset<=60), so requests are spaced a
# minute apart, and each subreddit's result (success or 429) is reused for an
# hour — digests only publish twice a day, so hourly freshness costs nothing,
# and it keeps each 15-minute collection to a few Reddit fetches rather than
# ten minutes of waiting. Reddit OAuth credentials would lift this to ~100/min.
_HOST_MIN_INTERVAL = {"reddit.com": 61.0}
_HOST_REFRESH_SECONDS = {"reddit.com": 3600.0}
_host_locks: dict[str, asyncio.Lock] = {}
_host_last: dict[str, float] = {}
_result_cache: dict[str, tuple[float, list[dict], str | None]] = {}


def _host_setting(url: str, table: dict[str, float]) -> tuple[str, float] | None:
    host = (urlparse(url).hostname or "").lower()
    for domain, value in table.items():
        if host == domain or host.endswith("." + domain):
            return domain, value
    return None


async def _throttle(url: str) -> None:
    setting = _host_setting(url, _HOST_MIN_INTERVAL)
    if setting is None:
        return
    domain, interval = setting
    async with _host_locks.setdefault(domain, asyncio.Lock()):
        wait = _host_last.get(domain, 0.0) + interval - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        _host_last[domain] = time.monotonic()


def _most_recent(items: list[dict]) -> list[dict]:
    """Newest first (undated entries keep feed order, ahead of dated ones), capped."""
    if len(items) <= _MAX_ITEMS_PER_SOURCE:
        return items
    ordered = sorted(items, key=lambda i: -(i.get("published_ts") or float("inf")))
    return ordered[:_MAX_ITEMS_PER_SOURCE]


async def collect_source(source: dict) -> tuple[list[dict], str | None]:
    url = source["url"]
    if reddit.enabled() and reddit.listing_url(url):
        # Approved API client: ~100 requests/min, so no spacing or hourly reuse.
        # Other Reddit URLs (e.g. a private front-page feed, which is tied to a
        # user rather than the app) stay on the throttled RSS path below.
        items, error = await reddit.collect(url)
        return _most_recent(items), error
    refresh = _host_setting(url, _HOST_REFRESH_SECONDS)
    cached = _result_cache.get(url)
    if refresh and cached and time.monotonic() - cached[0] < refresh[1]:
        return list(cached[1]), cached[2]  # re-ingesting is idempotent
    await _throttle(url)
    items, error = await _collect_source(source)
    items = _most_recent(items)
    if refresh:
        _result_cache[url] = (time.monotonic(), items, error)
    return items, error


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
