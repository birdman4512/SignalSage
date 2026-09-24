import time
from unittest.mock import AsyncMock

import pytest

from signalsage.digest import pipeline as pipeline_module
from signalsage.digest.pipeline import TranscriptPending
from signalsage.digest.transcripts import select_passages, transcript_url

from .test_pipeline import ARTICLE, SOURCE, TOPIC, make_pipeline

SN_SOURCE = {
    "name": "Security Now",
    "url": SOURCE["url"],
    "transcript_url": "https://www.grc.com/sn/sn-{episode}.txt",
    "episode_pattern": r"SN\s*(\d+)",
}
SN_TOPIC = {**TOPIC, "sources": [SN_SOURCE]}
EPISODE = {
    **ARTICLE,
    "title": "SN 1097: CVE-2026-1234 Patch Tuesday Fallout",
    "link": "https://twit.tv/shows/security-now/episodes/1097",
}


def test_transcript_url_only_substitutes_digits():
    assert transcript_url(SN_SOURCE, "SN 1097: Mega Patch") == "https://www.grc.com/sn/sn-1097.txt"
    assert transcript_url(SN_SOURCE, "Bonus: holiday special") is None
    assert transcript_url({"url": "x"}, "SN 1097") is None  # source hasn't opted in


def test_long_transcript_keeps_header_and_on_topic_passages():
    header = "SERIES: Security Now!\n\nDESCRIPTION: This week, Patch Tuesday fallout."
    chatter = [f"LEO: Welcome back, small talk number {i}." for i in range(60)]
    topic = "STEVE: The Patch Tuesday fallout came from a broken driver update."
    text = "\n\n".join([header, *chatter[:30], topic, *chatter[30:]])
    out = select_passages(text, "Patch Tuesday Fallout", [], budget=400)
    assert out.startswith("SERIES: Security Now!")
    assert "DESCRIPTION: This week" in out
    assert topic in out
    assert "small talk number 5." not in out
    assert len(out) <= 400


def test_whisper_blob_is_windowed_and_short_text_untouched():
    blob = " ".join(["Intro sentence here."] * 200 + ["The ransomware gang struck again."])
    out = select_passages(blob, "Ransomware roundup", [], budget=800)
    assert "ransomware gang struck" in out
    assert select_passages("short", "Title", [], budget=800) == "short"


async def test_episode_waits_for_its_published_transcript(tmp_path, monkeypatch):
    pipeline, dest = make_pipeline(tmp_path)
    pipeline.store.ingest(TOPIC["name"], SOURCE, [{**EPISODE, "published_ts": time.time()}])
    fetch = AsyncMock(return_value=None)  # not on grc.com yet
    monkeypatch.setattr(pipeline_module, "fetch_transcript", fetch)
    await pipeline.publish(SN_TOPIC, 5)
    assert dest.messages == []
    fetch.assert_awaited_once_with("https://www.grc.com/sn/sn-1097.txt")
    pipeline.summarizer.summarize_article.assert_not_awaited()

    fetch.return_value = "DESCRIPTION: A patch is available for CVE-2026-1234.\n\nMore."
    await pipeline.publish(SN_TOPIC, 5)
    assert len(dest.messages) == 1
    card = dest.messages[0][1]["items"][0]
    assert card["content_kind"] == "show transcript"


async def test_missing_transcript_falls_back_after_wait(tmp_path, monkeypatch):
    pipeline, dest = make_pipeline(tmp_path)
    old = time.time() - 5 * 86400  # past the 4-day wait
    pipeline.store.ingest(TOPIC["name"], SOURCE, [{**EPISODE, "published_ts": old}])
    monkeypatch.setattr(pipeline_module, "fetch_transcript", AsyncMock(return_value=None))
    await pipeline.publish(SN_TOPIC, 5)
    assert dest.messages[0][1]["items"][0]["content_kind"] == "feed excerpt"


async def test_pending_transcript_is_not_a_failure():
    assert issubclass(TranscriptPending, ValueError)  # never trips the model-down break
    with pytest.raises(ValueError):
        raise TranscriptPending("x")
