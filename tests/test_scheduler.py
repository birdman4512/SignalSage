"""Tests for the digest scheduler."""

from unittest.mock import AsyncMock, MagicMock, patch

from signalsage.scheduler import DigestScheduler


def _make_watchlist(*schedules: str) -> dict:
    topics = [
        {"name": f"Topic {chr(65 + i)}", "schedule": s, "sources": []}
        for i, s in enumerate(schedules)
    ]
    return {"topics": topics}


def _make_summarizer() -> MagicMock:
    summarizer = MagicMock()
    summarizer.max_chars = 3000
    summarizer.summarize_topic = AsyncMock(return_value="summary text")
    return summarizer


# ---------------------------------------------------------------------------
# Job registration
# ---------------------------------------------------------------------------


def test_one_job_per_topic():
    watchlist = _make_watchlist("0 6 * * *", "0 8 * * 1")
    scheduler = DigestScheduler(
        summarizer=_make_summarizer(),
        watchlist=watchlist,
        notifiers=[],
        default_schedule="0 6 * * *",
    )
    jobs = scheduler._scheduler.get_jobs()
    assert len(jobs) == 2


def test_job_ids_based_on_topic_name():
    watchlist = _make_watchlist("0 6 * * *", "0 7 * * *")
    scheduler = DigestScheduler(
        summarizer=_make_summarizer(),
        watchlist=watchlist,
        notifiers=[],
    )
    job_ids = {j.id for j in scheduler._scheduler.get_jobs()}
    assert "digest_topic_a" in job_ids
    assert "digest_topic_b" in job_ids


def test_empty_watchlist_no_jobs():
    scheduler = DigestScheduler(
        summarizer=_make_summarizer(),
        watchlist={"topics": []},
        notifiers=[],
    )
    assert scheduler._scheduler.get_jobs() == []


def test_topic_without_schedule_uses_default():
    watchlist = {"topics": [{"name": "No Schedule Topic", "sources": []}]}
    scheduler = DigestScheduler(
        summarizer=_make_summarizer(),
        watchlist=watchlist,
        notifiers=[],
        default_schedule="0 9 * * *",
    )
    jobs = scheduler._scheduler.get_jobs()
    assert len(jobs) == 1


def test_invalid_cron_skips_topic(caplog):
    watchlist = _make_watchlist("not a cron", "0 6 * * *")
    import logging

    with caplog.at_level(logging.ERROR):
        scheduler = DigestScheduler(
            summarizer=_make_summarizer(),
            watchlist=watchlist,
            notifiers=[],
        )
    # Only the valid topic should be scheduled
    assert len(scheduler._scheduler.get_jobs()) == 1


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------


async def test_run_topic_calls_notifiers():
    notifier = AsyncMock()
    watchlist = _make_watchlist("0 6 * * *")

    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = DigestScheduler(
            summarizer=_make_summarizer(),
            watchlist=watchlist,
            notifiers=[notifier],
        )
        await scheduler._run_topic(watchlist["topics"][0])

    notifier.assert_called_once()
    msg = notifier.call_args[0][0]
    assert "Topic A" in msg


async def test_run_topic_notifier_failure_does_not_crash():
    bad_notifier = AsyncMock(side_effect=RuntimeError("slack down"))
    watchlist = _make_watchlist("0 6 * * *")

    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = DigestScheduler(
            summarizer=_make_summarizer(),
            watchlist=watchlist,
            notifiers=[bad_notifier],
        )
        # Should not raise
        await scheduler._run_topic(watchlist["topics"][0])


async def test_run_all_now_triggers_all_topics():
    notifier = AsyncMock()
    watchlist = _make_watchlist("0 6 * * *", "0 8 * * *")

    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = DigestScheduler(
            summarizer=_make_summarizer(),
            watchlist=watchlist,
            notifiers=[notifier],
        )
        await scheduler.run_all_now()

    assert notifier.call_count == 2
