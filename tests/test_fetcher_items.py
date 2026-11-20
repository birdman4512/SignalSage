"""Tests for feed item extraction and podcast audio transcription."""

import json
import pathlib
import time
from unittest.mock import AsyncMock

import httpx
import respx

from signalsage.digest.fetcher import (
    _extract_feed_items,
    _extract_json_feed_items,
    clean_title,
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


def test_clean_title_strips_markup_and_line_breaks():
    # Real titles seen in the wild: The Register's <span>, BOM's multi-line warnings.
    assert (
        clean_title('Nvidia <span class="t42">picks OpenShell to </span>tame AI agents')
        == "Nvidia picks OpenShell to tame AI agents"
    )
    assert (
        clean_title("22/07:55 EST\n\t\tSevere Thunderstorm Warning\n\n\nfor\n\t\tMoreton Bay.")
        == "22/07:55 EST Severe Thunderstorm Warning for Moreton Bay."
    )
    assert clean_title("AT&amp;T &amp; Q&A") == "AT&T & Q&A"
    assert clean_title("1 < 2 and 3 > 2") == "1 < 2 and 3 > 2"
    assert clean_title(None) == ""


async def test_extract_feed_items_cleans_titles():
    feed_data = {"entries": [{"title": "A <b>bold</b>\nclaim", "link": "https://a.com/1"}]}
    items = await _extract_feed_items(feed_data, max_chars=3000)
    assert items[0]["title"] == "A bold claim"


async def test_extract_feed_items_preserves_all_15_entries():
    feed_data = {
        "entries": [{"title": f"Story {i}", "link": f"https://a.com/{i}"} for i in range(15)]
    }
    items = await _extract_feed_items(feed_data, max_chars=3000)
    assert len(items) == 15


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


async def test_transcripts_and_failures_are_cached(monkeypatch):
    from signalsage.digest import fetcher

    fetcher._TRANSCRIPT_CACHE.clear()
    fetcher._TRANSCRIPT_FAILURES.clear()
    calls: list[str] = []

    async def fake_download(url, transcriber):
        calls.append(url)
        return None if "bad" in url else "hello"

    monkeypatch.setattr(fetcher, "_download_and_transcribe", fake_download)
    transcriber = AsyncMock()
    for _ in range(3):
        assert await fetcher._transcribe_audio("https://x/good.mp3", transcriber) == "hello"
        assert await fetcher._transcribe_audio("https://x/bad.mp3", transcriber) is None
    assert calls == ["https://x/good.mp3", "https://x/bad.mp3"]


@respx.mock
async def test_download_hands_file_and_mime_to_transcriber(monkeypatch):
    from signalsage.digest import fetcher

    monkeypatch.setattr(fetcher, "_resolve_is_public_host", AsyncMock(return_value=True))
    respx.get("https://pod.example/ep1.m4a").mock(
        return_value=httpx.Response(
            200, content=b"AUDIO", headers={"content-type": "application/octet-stream"}
        )
    )
    seen = {}

    async def transcriber(path, mime):
        seen["mime"] = mime
        seen["bytes"] = pathlib.Path(path).read_bytes()
        return "  the transcript  "

    out = await fetcher._download_and_transcribe("https://pod.example/ep1.m4a", transcriber)
    assert out == "the transcript"
    assert seen == {"mime": "audio/aac", "bytes": b"AUDIO"}  # mapped from the extension


@respx.mock
async def test_oversized_audio_is_skipped(monkeypatch):
    from signalsage.digest import fetcher

    monkeypatch.setattr(fetcher, "_resolve_is_public_host", AsyncMock(return_value=True))
    respx.get("https://pod.example/long.mp3").mock(
        return_value=httpx.Response(
            200, content=b"x", headers={"content-length": str(fetcher._MAX_AUDIO_BYTES + 1)}
        )
    )
    transcriber = AsyncMock()
    assert (
        await fetcher._download_and_transcribe("https://pod.example/long.mp3", transcriber) is None
    )
    transcriber.assert_not_awaited()
