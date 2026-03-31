"""Tests for the digest scheduler."""

import json
from datetime import date, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from signalsage.scheduler import DigestScheduler


def _make_watchlist(*schedules: str) -> dict:
    topics = [
        {"name": f"Topic {chr(65 + i)}", "schedule": s, "sources": []}
        for i, s in enumerate(schedules)
    ]
    return {"topics": topics}


def _make_summarizer(summary: str = "summary text") -> MagicMock:
    summarizer = MagicMock()
    summarizer.max_chars = 3000
    summarizer.summarize_topic = AsyncMock(return_value=summary)
    return summarizer


def _make_scheduler(watchlist, notifiers=None, summarizer=None, tmp_path=None) -> DigestScheduler:
    return DigestScheduler(
        summarizer=summarizer or _make_summarizer(),
        watchlist=watchlist,
        notifiers=notifiers or [],
        data_dir=str(tmp_path) if tmp_path else str(tmp_path or "data"),
    )


# ---------------------------------------------------------------------------
# Job registration
# ---------------------------------------------------------------------------


def test_one_job_per_topic(tmp_path):
    scheduler = _make_scheduler(_make_watchlist("0 6 * * *", "0 8 * * 1"), tmp_path=tmp_path)
    assert len(scheduler._scheduler.get_jobs()) == 2


def test_job_ids_based_on_topic_name(tmp_path):
    scheduler = _make_scheduler(_make_watchlist("0 6 * * *", "0 7 * * *"), tmp_path=tmp_path)
    job_ids = {j.id for j in scheduler._scheduler.get_jobs()}
    assert "digest_topic_a" in job_ids
    assert "digest_topic_b" in job_ids


def test_empty_watchlist_no_jobs(tmp_path):
    scheduler = _make_scheduler({"topics": []}, tmp_path=tmp_path)
    assert scheduler._scheduler.get_jobs() == []


def test_topic_without_schedule_uses_default(tmp_path):
    watchlist = {"topics": [{"name": "No Schedule Topic", "sources": []}]}
    scheduler = DigestScheduler(
        summarizer=_make_summarizer(),
        watchlist=watchlist,
        notifiers=[],
        default_schedule="0 9 * * *",
        data_dir=str(tmp_path),
    )
    assert len(scheduler._scheduler.get_jobs()) == 1


def test_invalid_cron_skips_topic(tmp_path, caplog):
    import logging

    with caplog.at_level(logging.ERROR):
        scheduler = _make_scheduler(_make_watchlist("not a cron", "0 6 * * *"), tmp_path=tmp_path)
    assert len(scheduler._scheduler.get_jobs()) == 1


def test_get_topics_returns_name_tags_next_run(tmp_path):
    watchlist = {"topics": [{"name": "My Topic", "tags": ["foo", "bar"], "sources": []}]}
    scheduler = _make_scheduler(watchlist, tmp_path=tmp_path)
    topics = scheduler.get_topics()
    assert len(topics) == 1
    name, tags, next_run = topics[0]
    assert name == "My Topic"
    assert tags == ["foo", "bar"]


def test_get_topic_names(tmp_path):
    scheduler = _make_scheduler(_make_watchlist("0 6 * * *", "0 7 * * *"), tmp_path=tmp_path)
    names = scheduler.get_topic_names()
    assert "Topic A" in names
    assert "Topic B" in names


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------


async def test_run_topic_calls_notifiers(tmp_path):
    notifier = AsyncMock()
    watchlist = _make_watchlist("0 6 * * *")
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, notifiers=[notifier], tmp_path=tmp_path)
        await scheduler._run_topic(watchlist["topics"][0])
    notifier.assert_called_once()
    assert notifier.call_args[0][0] == "Topic A"


async def test_run_topic_passes_meta_to_notifier(tmp_path):
    notifier = AsyncMock()
    watchlist = _make_watchlist("0 6 * * *")
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, notifiers=[notifier], tmp_path=tmp_path)
        await scheduler._run_topic(watchlist["topics"][0])
    meta = notifier.call_args[1]["meta"]
    assert "sources_total" in meta
    assert "sources_ok" in meta
    assert "empty_sources" in meta


async def test_run_topic_notifier_failure_does_not_crash(tmp_path):
    bad_notifier = AsyncMock(side_effect=RuntimeError("slack down"))
    watchlist = _make_watchlist("0 6 * * *")
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, notifiers=[bad_notifier], tmp_path=tmp_path)
        await scheduler._run_topic(watchlist["topics"][0])  # must not raise


async def test_run_all_now_triggers_all_topics(tmp_path):
    notifier = AsyncMock()
    watchlist = _make_watchlist("0 6 * * *", "0 8 * * *")
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, notifiers=[notifier], tmp_path=tmp_path)
        await scheduler.run_all_now()
    assert notifier.call_count == 2


# ---------------------------------------------------------------------------
# run_topic_now — tag/name matching
# ---------------------------------------------------------------------------


async def test_run_topic_now_matches_by_tag(tmp_path):
    notifier = AsyncMock()
    watchlist = {"topics": [{"name": "Cyber News", "tags": ["cyber"], "sources": []}]}
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, notifiers=[notifier], tmp_path=tmp_path)
        found = await scheduler.run_topic_now("cyber")
    assert found is True
    notifier.assert_called_once()


async def test_run_topic_now_matches_by_name(tmp_path):
    notifier = AsyncMock()
    watchlist = {"topics": [{"name": "Vuln Alerts", "tags": [], "sources": []}]}
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, notifiers=[notifier], tmp_path=tmp_path)
        found = await scheduler.run_topic_now("vuln")
    assert found is True


async def test_run_topic_now_no_match_returns_false(tmp_path):
    watchlist = {"topics": [{"name": "Cyber News", "tags": ["cyber"], "sources": []}]}
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, tmp_path=tmp_path)
        found = await scheduler.run_topic_now("nonexistent")
    assert found is False


# ---------------------------------------------------------------------------
# Cross-topic deduplication
# ---------------------------------------------------------------------------


async def test_cross_topic_dedup_removes_duplicate(tmp_path):
    """An item seen in topic A should be removed from topic B's output."""
    shared_headline = "Critical CVE exploited in the wild"
    structured = json.dumps(
        {
            "tldr": [],
            "coverage_confidence": "high",
            "items": [
                {
                    "icon": "🔴",
                    "severity": "critical",
                    "headline": shared_headline,
                    "blurb": "Bad.",
                    "url": "https://example.com",
                }
            ],
        }
    )
    summarizer = _make_summarizer(summary=structured)

    topics = [
        {"name": "Topic A", "sources": [{"name": "S", "url": "https://a.com"}]},
        {"name": "Topic B", "sources": [{"name": "S", "url": "https://b.com"}]},
    ]
    watchlist = {"topics": topics}

    fetched_source = [{"name": "S", "url": "https://x.com", "content": "content"}]

    calls: list[dict] = []

    async def capture_notify(name, summary, **kwargs):
        calls.append({"name": name, "summary": summary, "meta": kwargs.get("meta", {})})

    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=fetched_source)):
        scheduler = DigestScheduler(
            summarizer=summarizer,
            watchlist=watchlist,
            notifiers=[capture_notify],
            data_dir=str(tmp_path),
        )
        await scheduler._run_topic(topics[0])
        await scheduler._run_topic(topics[1])

    # Topic A: 0 deduped, Topic B: 1 deduped
    assert calls[0]["meta"]["deduped_count"] == 0
    assert calls[1]["meta"]["deduped_count"] == 1


# ---------------------------------------------------------------------------
# Session reset on new day
# ---------------------------------------------------------------------------


def test_session_resets_on_new_day(tmp_path):
    scheduler = _make_scheduler(_make_watchlist("0 6 * * *"), tmp_path=tmp_path)
    scheduler._session_hashes.add("abc123")
    scheduler._session_date = (date.today() - timedelta(days=1)).isoformat()
    scheduler._reset_session_if_new_day()
    assert len(scheduler._session_hashes) == 0
    assert scheduler._session_date == date.today().isoformat()


def test_session_not_reset_same_day(tmp_path):
    scheduler = _make_scheduler(_make_watchlist("0 6 * * *"), tmp_path=tmp_path)
    scheduler._session_hashes.add("abc123")
    scheduler._reset_session_if_new_day()
    assert "abc123" in scheduler._session_hashes
