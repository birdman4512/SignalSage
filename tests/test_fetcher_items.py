"""Tests for per-item extraction used by watch-mode polling."""

import json
import time

from signalsage.digest.fetcher import (
    _extract_feed_content,
    _extract_feed_items,
    _extract_json_feed,
    _extract_json_feed_items,
)

# ---------------------------------------------------------------------------
# _extract_feed_items
# ---------------------------------------------------------------------------


async def test_extract_feed_items_basic_fields():
    feed_data = {
        "entries": [
            {"title": "Story One", "link": "https://a.com/1", "summary": "<p>Body one</p>"},
            {"title": "Story Two", "link": "https://a.com/2", "summary": "Body two"},
        ]
    }
    items = await _extract_feed_items(feed_data, max_chars=3000)
    assert len(items) == 2
    assert items[0]["title"] == "Story One"
    assert items[0]["link"] == "https://a.com/1"
    assert items[0]["summary"] == "Body one"  # HTML stripped


async def test_extract_feed_items_caps_at_10():
    feed_data = {
        "entries": [{"title": f"Story {i}", "link": f"https://a.com/{i}"} for i in range(15)]
    }
    items = await _extract_feed_items(feed_data, max_chars=3000)
    assert len(items) == 10


async def test_extract_feed_items_filters_old_entries():
    now = time.time()
    old_ts = time.gmtime(now - 100000)  # older than 24h lookback
    new_ts = time.gmtime(now - 100)
    feed_data = {
        "entries": [
            {"title": "Old", "link": "https://a.com/old", "published_parsed": old_ts},
            {"title": "New", "link": "https://a.com/new", "published_parsed": new_ts},
        ]
    }
    items = await _extract_feed_items(feed_data, max_chars=3000, lookback_seconds=3600)
    titles = [i["title"] for i in items]
    assert titles == ["New"]


async def test_extract_feed_content_matches_items_joined():
    """The text-blob wrapper should stay consistent with the item-level extraction."""
    feed_data = {
        "entries": [{"title": "Story One", "link": "https://a.com/1", "summary": "Body one"}]
    }
    items = await _extract_feed_items(feed_data, max_chars=3000)
    text = await _extract_feed_content(feed_data, max_chars=3000)
    assert items[0]["title"] in text
    assert items[0]["link"] in text
    assert items[0]["summary"] in text


# ---------------------------------------------------------------------------
# _extract_json_feed_items
# ---------------------------------------------------------------------------


def test_extract_json_feed_items_cisa_kev_format():
    raw = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vulnerabilityName": "Example Vuln",
                    "shortDescription": "A bad bug.",
                }
            ]
        }
    )
    items = _extract_json_feed_items(raw)
    assert len(items) == 1
    assert items[0]["title"] == "Example Vuln"
    assert "CVE-2024-0001" in items[0]["link"]
    assert "A bad bug." in items[0]["summary"]


def test_extract_json_feed_items_generic_array():
    raw = json.dumps([{"title": "Generic Item", "description": "desc", "url": "https://x.com"}])
    items = _extract_json_feed_items(raw)
    assert items == [
        {"title": "Generic Item", "link": "https://x.com", "summary": "desc", "published_ts": None}
    ]


def test_extract_json_feed_items_invalid_json_returns_empty():
    assert _extract_json_feed_items("not json") == []


def test_extract_json_feed_matches_items_joined():
    raw = json.dumps([{"title": "Item A", "description": "desc A", "url": "https://x.com/a"}])
    items = _extract_json_feed_items(raw)
    text = _extract_json_feed(raw, max_chars=3000)
    assert items[0]["title"] in text
    assert items[0]["link"] in text


# ---------------------------------------------------------------------------
# Audio transcription: caching + skipping already-seen entries
# ---------------------------------------------------------------------------


def _audio_feed(n: int = 2) -> dict:
    return {
        "entries": [
            {
                "title": f"Episode {i}",
                "link": f"https://pod.example/{i}",
                "enclosures": [{"type": "audio/mpeg", "href": f"https://pod.example/{i}.mp3"}],
            }
            for i in range(n)
        ]
    }


async def test_skip_audio_predicate_skips_transcription(monkeypatch):
    from signalsage.digest import fetcher

    calls: list[str] = []

    async def fake_transcribe(url, base, timeout=600):
        calls.append(url)
        return "transcript"

    monkeypatch.setattr(fetcher, "_transcribe_audio", fake_transcribe)
    items = await _extract_feed_items(
        _audio_feed(),
        max_chars=3000,
        whisper_base_url="http://whisper",
        skip_audio=lambda i: i["link"] == "https://pod.example/0",
    )
    assert calls == ["https://pod.example/1.mp3"]
    assert len(items) == 2  # skipped entries are still returned for seen-filtering


async def test_transcripts_and_failures_are_cached(monkeypatch):
    from signalsage.digest import fetcher

    fetcher._TRANSCRIPT_CACHE.clear()
    fetcher._TRANSCRIPT_FAILURES.clear()
    calls: list[str] = []

    async def fake_download(url, base, timeout):
        calls.append(url)
        return None if "bad" in url else "hello"

    monkeypatch.setattr(fetcher, "_download_and_transcribe", fake_download)
    for _ in range(3):
        assert await fetcher._transcribe_audio("https://x/good.mp3", "http://w") == "hello"
        assert await fetcher._transcribe_audio("https://x/bad.mp3", "http://w") is None
    assert calls == ["https://x/good.mp3", "https://x/bad.mp3"]
