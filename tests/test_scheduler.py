"""Scheduler orchestration and cron coverage regressions."""

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from signalsage.scheduler import DigestScheduler, _within_active_hours


def make_scheduler(tmp_path, topics=None, **kwargs):
    return DigestScheduler(
        AsyncMock(),
        {"topics": topics or [{"name": "News", "tags": ["news"], "sources": []}]},
        [],
        data_dir=str(tmp_path),
        **kwargs,
    )


def test_registers_publication_collection_and_retries(tmp_path):
    scheduler = make_scheduler(tmp_path)
    assert {j.id for j in scheduler._scheduler.get_jobs()} == {
        "digest_news",
        "collect_articles",
        "retry_delivery",
    }
    assert scheduler.get_topic_names() == ["News"]
    assert len(scheduler.get_topics()) == 1


def test_empty_watchlist_has_no_jobs(tmp_path):
    scheduler = DigestScheduler(AsyncMock(), {"topics": []}, [], data_dir=str(tmp_path))
    assert scheduler._scheduler.get_jobs() == []


def test_invalid_schedule_is_skipped(tmp_path):
    scheduler = make_scheduler(tmp_path, [{"name": "Broken", "schedule": "invalid", "sources": []}])
    assert scheduler.get_topics() == []


def test_watch_mode_requires_separate_interval(tmp_path):
    scheduler = make_scheduler(
        tmp_path,
        [
            {
                "name": "Urgent",
                "watch_mode": True,
                "alert_keywords": ["actively exploited"],
                "sources": [],
            }
        ],
    )
    assert scheduler._scheduler.get_job("watch_urgent")
    assert scheduler._scheduler.get_job("collect_articles")


async def test_collection_continues_during_quiet_hours(tmp_path):
    scheduler = make_scheduler(tmp_path)
    scheduler.pipeline.collect = AsyncMock(return_value=1)
    with patch.object(scheduler, "_in_active_hours", return_value=False):
        await scheduler._collect_all()
    scheduler.pipeline.collect.assert_awaited_once()


async def test_scheduled_posts_and_retries_respect_quiet_hours(tmp_path):
    scheduler = make_scheduler(tmp_path)
    scheduler._run_topic = AsyncMock()
    scheduler.pipeline.flush = AsyncMock()
    with patch.object(scheduler, "_in_active_hours", return_value=False):
        await scheduler._run_topic_scheduled(scheduler._topics[0])
        await scheduler._retry_delivery()
    scheduler._run_topic.assert_not_awaited()
    scheduler.pipeline.flush.assert_not_awaited()


async def test_on_demand_bypasses_quiet_gate_and_reports_progress(tmp_path):
    scheduler = make_scheduler(tmp_path)
    scheduler.pipeline.collect = AsyncMock(return_value=1)
    scheduler.pipeline.publish = AsyncMock()
    progress = AsyncMock()
    with patch.object(scheduler, "_in_active_hours", return_value=False):
        assert await scheduler.run_topic_now("news", progress=progress, override_channel="C123")
    scheduler.pipeline.collect.assert_awaited_once()
    assert scheduler.pipeline.publish.call_args.args[2] == "C123"
    assert progress.await_count >= 2


async def test_exact_tag_beats_partial_name(tmp_path):
    scheduler = make_scheduler(
        tmp_path,
        [
            {"name": "AI News", "tags": ["ai"], "sources": []},
            {"name": "General", "tags": ["news"], "sources": []},
        ],
    )
    scheduler._run_topic = AsyncMock()
    assert await scheduler.run_topic_now("news")
    assert scheduler._run_topic.call_args.args[0]["name"] == "General"


async def test_unknown_topic_returns_false(tmp_path):
    assert not await make_scheduler(tmp_path).run_topic_now("nonexistent")


async def test_all_command_ignores_maintenance_jobs(tmp_path):
    scheduler = make_scheduler(tmp_path)
    scheduler._run_topic = AsyncMock()
    await scheduler.run_all_now()
    scheduler._run_topic.assert_awaited_once()


def test_keywords_available_on_scheduled_topics(tmp_path):
    scheduler = make_scheduler(tmp_path, [{"name": "News", "keywords": ["CVE"], "tags": ["news"]}])
    assert scheduler.find_watch_topic("news")["name"] == "News"
    assert scheduler.watch_keywords.get("News") == (["CVE"], [])


def test_topic_story_limit_clamped(tmp_path):
    scheduler = make_scheduler(tmp_path)
    assert scheduler._top_n({"top_stories_count": 900}) == 20
    scheduler.set_top_stories_count(3)
    assert scheduler._top_n({}) == 3
    assert scheduler._top_n({"top_stories_count": 5}) == 3


def test_active_hours_weekend_and_exclusive_end():
    assert _within_active_hours(datetime(2026, 9, 26, 9), "06:00", "18:00", "09:00", "17:00")
    assert not _within_active_hours(datetime(2026, 9, 26, 17), "06:00", "18:00", "09:00", "17:00")


def test_quiet_days_are_quiet_all_day():
    hours = ("06:00", "18:00", "09:00", "17:00")
    # 2026-09-27 is a Sunday, 2026-09-26 a Saturday.
    assert not _within_active_hours(datetime(2026, 9, 27, 12), *hours, ["sun"])
    assert not _within_active_hours(datetime(2026, 9, 27, 12), *hours, ["Sunday"])
    assert _within_active_hours(datetime(2026, 9, 26, 12), *hours, ["sun"])
    assert _within_active_hours(datetime(2026, 9, 27, 12), *hours)


# Fixed reference times so cron walks are deterministic. May 4 2026 is a Monday;
# the 09:00 UTC offset means each scheduled fire of interest has already passed
# earlier in the day (so the "previous fire" exists in every test schedule).
_MON_0900 = datetime(2026, 5, 4, 9, 0, tzinfo=UTC)
_TUE_0900 = datetime(2026, 5, 5, 9, 0, tzinfo=UTC)


_CATCHUP_ACTIVE_HOURS = {
    "weekday_start": "07:00",
    "weekday_end": "18:00",
    "weekend_start": "07:00",
    "weekend_end": "18:00",
}
_TUE_1105 = datetime(2026, 5, 5, 11, 5, tzinfo=UTC)


async def test_ignore_active_hours_watch_topic_posts_in_quiet_hours(tmp_path):
    weather = {
        "name": "Weather",
        "watch_mode": True,
        "ignore_active_hours": True,
        "alert_keywords": ["severe thunderstorm"],
        "sources": [],
    }
    scheduler = make_scheduler(tmp_path, [weather])
    assert scheduler.pipeline.always_deliver == {"Weather"}
    scheduler._run_watch_topic = AsyncMock()
    scheduler.pipeline.flush = AsyncMock()
    with patch.object(scheduler, "_in_active_hours", return_value=False):
        await scheduler._run_watch_topic_scheduled(weather)
        await scheduler._retry_delivery()
    scheduler._run_watch_topic.assert_awaited_once()
    scheduler.pipeline.flush.assert_awaited_once()


async def test_quiet_hours_flush_only_delivers_always_deliver_topics(tmp_path):
    scheduler = make_scheduler(tmp_path)
    pipeline = scheduler.pipeline
    pipeline.always_deliver = {"Weather"}
    rows = [
        {
            "id": "a",
            "destination": "test:C1",
            "topic": "News",
            "offset": 0,
            "body": json.dumps({"channel": "C1", "summary": "{}", "meta": {}}),
        },
        {
            "id": "b",
            "destination": "test:C1",
            "topic": "Weather",
            "offset": 0,
            "body": json.dumps({"channel": "C1", "summary": "{}", "meta": {}}),
        },
    ]
    sent = []

    class Owner:
        platform_name = "test"

        async def notify(self, topic, summary, channel=None, meta=None):
            sent.append(topic)

    pipeline.notifiers = [Owner().notify]
    calls = []

    async def acall(name, *args, **kwargs):
        calls.append(name)
        return rows if name == "pending" else None

    pipeline.store.acall = acall
    await pipeline.flush(allowed=lambda: False)
    assert sent == ["Weather"]
