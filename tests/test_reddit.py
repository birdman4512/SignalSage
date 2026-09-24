from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from signalsage.digest import collection, reddit

CREDS = {"client_id": "id123", "client_secret": "s3cret", "username": "dean"}
LISTING = {
    "data": {
        "children": [
            {
                "data": {
                    "title": "New RCE in widget",
                    "permalink": "/r/netsec/comments/abc/new_rce/",
                    "url": "https://blog.example.com/rce",
                    "selftext": "",
                    "created_utc": 1_790_000_000,
                    "name": "t3_abc",
                }
            },
            {"data": {"title": "", "permalink": "/r/netsec/comments/x/"}},  # no title: dropped
        ]
    }
}


@pytest.fixture(autouse=True)
def reset():
    reddit.configure(None)
    yield
    reddit.configure(None)


def test_listing_url_mapping():
    assert (
        reddit.listing_url("https://www.reddit.com/r/netsec/.rss")
        == "https://oauth.reddit.com/r/netsec/hot?limit=50&raw_json=1"
    )
    assert reddit.listing_url("https://www.reddit.com/r/amateurradio/new/.rss").startswith(
        "https://oauth.reddit.com/r/amateurradio/new?"
    )
    assert reddit.listing_url("https://www.reddit.com/user/someone/.rss") is None


def test_disabled_without_both_credentials():
    reddit.configure({"client_id": "id123", "client_secret": ""})
    assert not reddit.enabled()
    reddit.configure(CREDS)
    assert reddit.enabled()


@respx.mock
async def test_api_listing_becomes_items_with_rss_style_links():
    reddit.configure(CREDS)
    token = respx.post("https://www.reddit.com/api/v1/access_token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok", "expires_in": 86400})
    )
    listing = respx.get("https://oauth.reddit.com/r/netsec/hot").mock(
        return_value=httpx.Response(200, json=LISTING)
    )
    items, error = await reddit.collect("https://www.reddit.com/r/netsec/.rss")
    assert error is None
    assert items == [
        {
            "title": "New RCE in widget",
            "link": "https://www.reddit.com/r/netsec/comments/abc/new_rce/",
            "summary": "New RCE in widget\nLinked article: https://blog.example.com/rce",
            "published_ts": 1_790_000_000.0,
            "guid": "t3_abc",
        }
    ]
    request = listing.calls.last.request
    assert request.headers["Authorization"] == "bearer tok"
    assert request.headers["User-Agent"] == "linux:signalsage:1.0 (by /u/dean)"
    # The token is reused rather than requested per subreddit.
    await reddit.collect("https://www.reddit.com/r/netsec/.rss")
    assert token.call_count == 1


@respx.mock
async def test_expired_token_is_refreshed_once():
    reddit.configure(CREDS)
    respx.post("https://www.reddit.com/api/v1/access_token").mock(
        side_effect=[
            httpx.Response(200, json={"access_token": "old", "expires_in": 86400}),
            httpx.Response(200, json={"access_token": "new", "expires_in": 86400}),
        ]
    )
    respx.get("https://oauth.reddit.com/r/netsec/hot").mock(
        side_effect=[httpx.Response(401), httpx.Response(200, json=LISTING)]
    )
    items, error = await reddit.collect("https://www.reddit.com/r/netsec/.rss")
    assert error is None and len(items) == 1


@respx.mock
async def test_refused_credentials_report_an_error_without_the_secret():
    reddit.configure(CREDS)
    respx.post("https://www.reddit.com/api/v1/access_token").mock(return_value=httpx.Response(401))
    items, error = await reddit.collect("https://www.reddit.com/r/netsec/.rss")
    assert items == [] and error and "s3cret" not in error


async def test_collect_source_uses_api_only_when_enabled(monkeypatch):
    api = AsyncMock(return_value=([{"title": "via api"}], None))
    rss = AsyncMock(return_value=([{"title": "via rss"}], None))
    monkeypatch.setattr(reddit, "collect", api)
    monkeypatch.setattr(collection, "_collect_source", rss)
    monkeypatch.setattr(collection, "_throttle", AsyncMock())
    monkeypatch.setattr(collection, "_result_cache", {})
    source = {"url": "https://www.reddit.com/r/netsec/.rss"}

    assert (await collection.collect_source(source))[0] == [{"title": "via rss"}]
    reddit.configure(CREDS)
    assert (await collection.collect_source(source))[0] == [{"title": "via api"}]
    rss.assert_awaited_once()


async def test_private_front_page_feed_stays_on_rss_even_with_api(monkeypatch):
    api = AsyncMock(return_value=([{"title": "via api"}], None))
    rss = AsyncMock(return_value=([{"title": "home"}], None))
    monkeypatch.setattr(reddit, "collect", api)
    monkeypatch.setattr(collection, "_collect_source", rss)
    monkeypatch.setattr(collection, "_throttle", AsyncMock())
    monkeypatch.setattr(collection, "_result_cache", {})
    reddit.configure(CREDS)
    home = {"url": "https://www.reddit.com/.rss?feed=abc123&user=dean"}
    assert (await collection.collect_source(home))[0] == [{"title": "home"}]
    api.assert_not_awaited()
