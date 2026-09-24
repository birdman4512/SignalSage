"""Authenticated Reddit listings via the official Data API (application-only OAuth).

Unauthenticated RSS from the production host is limited to about one request a
minute; an approved API client gets ~100 a minute. This is only used once
credentials are configured (digest.reddit in config.yaml, from REDDIT_* in
.env) — until then collection keeps using the throttled RSS feeds.

Reddit requires explicit approval for API access (Responsible Builder Policy)
and an honest, descriptive User-Agent, which this sends instead of the
browser User-Agent the RSS fallback uses.
"""

import logging
import re
import time
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
_API_BASE = "https://oauth.reddit.com"
# Accepts the subreddit feed URLs used in config/digests: /r/<name>/.rss (hot)
# or /r/<name>/<sort>/.rss.
_LISTING_PATH = re.compile(r"^/r/([A-Za-z0-9_]{2,21})(?:/(hot|new|top|rising))?/?(?:\.rss)?/?$")

_credentials: dict[str, str] = {}
_token: tuple[str, float] | None = None  # (access token, expiry monotonic time)


def configure(settings: dict | None) -> None:
    """Enable the API when both client_id and client_secret are set."""
    global _token
    settings = settings or {}
    client_id = str(settings.get("client_id") or "").strip()
    secret = str(settings.get("client_secret") or "").strip()
    _credentials.clear()
    _token = None
    if client_id and secret:
        username = str(settings.get("username") or "").strip() or "unknown"
        _credentials.update(
            client_id=client_id,
            client_secret=secret,
            user_agent=f"linux:signalsage:1.0 (by /u/{username})",
        )
        logger.info("Reddit API enabled for subreddit sources")


def enabled() -> bool:
    return bool(_credentials)


def is_reddit(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == "reddit.com" or host.endswith(".reddit.com")


def listing_url(feed_url: str) -> str | None:
    """Map a subreddit RSS URL to its API listing, e.g. /r/netsec/.rss -> /r/netsec/hot."""
    match = _LISTING_PATH.match(urlparse(feed_url).path)
    if not match:
        return None
    name, sort = match.group(1), match.group(2) or "hot"
    return f"{_API_BASE}/r/{name}/{sort}?limit=50&raw_json=1"


async def _access_token(client: httpx.AsyncClient) -> str:
    global _token
    if _token and time.monotonic() < _token[1]:
        return _token[0]
    response = await client.post(
        _TOKEN_URL,
        auth=(_credentials["client_id"], _credentials["client_secret"]),
        data={"grant_type": "client_credentials"},
        headers={"User-Agent": _credentials["user_agent"]},
    )
    response.raise_for_status()
    data = response.json()
    if "access_token" not in data:  # e.g. {"error": "invalid_grant"} with HTTP 200
        raise ValueError(f"Reddit token request refused: {data.get('error', 'unknown')}")
    _token = (
        data["access_token"],
        time.monotonic() + max(60, int(data.get("expires_in", 3600))) - 60,
    )
    return _token[0]


def _to_item(post: dict) -> dict | None:
    title = str(post.get("title") or "").strip()
    permalink = str(post.get("permalink") or "")
    if not title or not permalink.startswith("/r/"):
        return None
    # Same comment-page link the RSS feed used, so stored articles keep their identity.
    link = "https://www.reddit.com" + permalink
    body = str(post.get("selftext") or "").strip()
    external = str(post.get("url") or "")
    if not body and external and not is_reddit(external):
        body = f"{title}\nLinked article: {external}"
    return {
        "title": title,
        "link": link,
        "summary": body[:12000],
        "published_ts": float(post["created_utc"]) if post.get("created_utc") else None,
        "guid": str(post.get("name") or ""),
    }


async def collect(feed_url: str) -> tuple[list[dict], str | None]:
    """Fetch a subreddit through the API. Returns (items, error) like collect_source."""
    global _token
    api_url = listing_url(feed_url)
    if api_url is None:
        return [], f"Not a recognised subreddit feed URL: {feed_url}"
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            for attempt in range(2):
                token = await _access_token(client)
                response = await client.get(
                    api_url,
                    headers={
                        "Authorization": f"bearer {token}",
                        "User-Agent": _credentials["user_agent"],
                    },
                )
                if response.status_code == 401 and attempt == 0:
                    _token = None  # expired or revoked: fetch a fresh token once
                    continue
                response.raise_for_status()
                children = response.json().get("data", {}).get("children", [])
                items = [_to_item(c.get("data") or {}) for c in children if isinstance(c, dict)]
                return [i for i in items if i], None
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        # Never include credentials: httpx errors carry only method, URL and status.
        return [], f"Reddit API request failed: {exc}"
    return [], "Reddit API rejected the access token"
