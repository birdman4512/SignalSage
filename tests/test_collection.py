import json
import time
from unittest.mock import AsyncMock

import httpx
import respx

from signalsage.digest.collection import collect_source, fetch_article_text
from signalsage.digest.fetcher import _extract_json_feed_items
from signalsage.digest.ranking import article_identity, canonical_url, contains, score_article


def test_keywords_respect_word_boundaries():
    assert not contains("adaptation", "apt")
    assert contains("APT group", "apt")
    assert contains("CVE-2026-1234", "cve")
    assert contains("Open weight model", "open weight")


def test_keywords_accept_common_inflections():
    assert contains("New open LLMs released", "llm")
    assert contains("Flaw actively exploited in the wild", "exploit")
    assert contains("Two data breaches disclosed", "breach")
    assert not contains("aptitude test", "apt")
    assert not contains("claudette", "claude")


def test_exclusion_and_trust_cannot_promote_irrelevant_article():
    profile = {
        "topics": {"ransomware": 3},
        "sources": {"example.com": 100},
        "exclude": ["sponsored"],
    }
    assert (
        score_article({"title": "Weather", "link": "https://example.com/"}, profile, [], [])[0] == 0
    )
    assert score_article({"title": "Sponsored ransomware story"}, profile, [], [])[2]


def test_identity_normalizes_tracking_but_preserves_meaningful_query():
    assert (
        canonical_url("https://example.com/a?id=3&utm_source=x#frag")
        == "https://example.com/a?id=3"
    )
    assert article_identity(
        {"title": "A", "summary": "body", "link": "https://example.com/a"}
    ) == article_identity(
        {"title": "A", "summary": "body", "link": "https://example.com/a?utm_source=x"}
    )


def test_json_feed_processes_new_entries_after_first_twenty():
    entries = [{"title": f"Item {i}", "date": "2000-01-01"} for i in range(25)]
    entries.append({"title": "Fresh", "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    result = _extract_json_feed_items(json.dumps(entries), 3600)
    assert [item["title"] for item in result] == ["Fresh"]


async def test_collection_never_transcribes_audio(monkeypatch):
    raw = '<rss version="2.0"><channel><title>Feed</title><item><title>Podcast</title><link>https://example.com/a</link><enclosure url="https://example.com/a.mp3" type="audio/mpeg" length="1"/></item></channel></rss>'
    monkeypatch.setattr(
        "signalsage.digest.collection._fetch_raw",
        AsyncMock(return_value=(raw, "application/rss+xml", "https://example.com/rss")),
    )
    transcribe = AsyncMock()
    monkeypatch.setattr("signalsage.digest.fetcher._transcribe_audio", transcribe)
    items, error = await collect_source({"url": "https://example.com/rss"})
    assert error is None
    assert items[0]["audio_url"] == "https://example.com/a.mp3"
    transcribe.assert_not_awaited()


async def test_empty_json_feed_does_not_fall_through_to_html(monkeypatch):
    monkeypatch.setattr(
        "signalsage.digest.collection._fetch_raw",
        AsyncMock(return_value=('{"items": []}', "application/json", "https://example.com/feed")),
    )
    assert await collect_source({"url": "https://example.com/feed"}) == ([], None)


@respx.mock
async def test_article_redirect_to_private_host_is_blocked(monkeypatch):
    monkeypatch.setattr(
        "signalsage.digest.collection._resolve_is_public_host", AsyncMock(side_effect=[True, False])
    )
    route = respx.get("https://example.com/article").mock(
        return_value=httpx.Response(302, headers={"location": "http://127.0.0.1/private"})
    )
    assert await fetch_article_text("https://example.com/article") is None
    assert route.call_count == 1


@respx.mock
async def test_article_download_size_is_bounded(monkeypatch):
    monkeypatch.setattr(
        "signalsage.digest.collection._resolve_is_public_host", AsyncMock(return_value=True)
    )
    respx.get("https://example.com/a").mock(
        return_value=httpx.Response(
            200, headers={"content-type": "text/html"}, content=b"x" * (2 * 1024 * 1024 + 1)
        )
    )
    assert await fetch_article_text("https://example.com/a") is None


def test_browser_user_agent_only_for_hosts_that_block_bots():
    from signalsage.digest.fetcher import _BROWSER_UA, _DEFAULT_UA, _user_agent

    assert _user_agent("https://www.cyber.gov.au/rss/alerts") == _BROWSER_UA
    assert _user_agent("https://www.reddit.com/r/netsec/.rss") == _BROWSER_UA
    assert _user_agent("https://dx-world.net/feed/") == _BROWSER_UA
    assert _user_agent("https://krebsonsecurity.com/feed/") == _DEFAULT_UA
    # Host match, not substring: a lookalike domain or path mention doesn't qualify.
    assert _user_agent("https://notreddit.com/feed") == _DEFAULT_UA
    assert _user_agent("https://example.com/?u=reddit.com") == _DEFAULT_UA


def test_large_feeds_keep_only_the_most_recent_entries():
    from signalsage.digest.collection import _MAX_ITEMS_PER_SOURCE, _most_recent

    # Oldest-first order, like the CISA KEV JSON feed appends new entries.
    items = [{"title": str(i), "published_ts": 1_000_000 + i} for i in range(500)]
    kept = _most_recent(items)
    assert len(kept) == _MAX_ITEMS_PER_SOURCE
    assert kept[0]["title"] == "499"
    assert {i["title"] for i in kept} == {str(i) for i in range(400, 500)}


async def test_reddit_requests_are_spaced_out(monkeypatch):
    from signalsage.digest import collection

    sleeps: list[float] = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(collection.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(collection, "_host_last", {})
    await collection._throttle("https://www.reddit.com/r/a/.rss")
    await collection._throttle("https://www.reddit.com/r/b/.rss")
    await collection._throttle("https://krebsonsecurity.com/feed/")
    assert len(sleeps) == 1 and 6 < sleeps[0] <= 7
