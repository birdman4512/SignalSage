"""Scheduler orchestration and cron coverage regressions."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

from signalsage.scheduler import DigestScheduler, _compute_auto_lookback, _within_active_hours


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


# Fixed reference times so cron walks are deterministic. May 4 2026 is a Monday;
# the 09:00 UTC offset means each scheduled fire of interest has already passed
# earlier in the day (so the "previous fire" exists in every test schedule).
_MON_0900 = datetime(2026, 5, 4, 9, 0, tzinfo=UTC)
_TUE_0900 = datetime(2026, 5, 5, 9, 0, tzinfo=UTC)


def test_auto_lookback_every_6_hours():
    """Every-6h schedule: prev fire at 06:00, prev-prev at 00:00 → 6h gap + 2h = 8h."""
    assert _compute_auto_lookback("0 0,6,12,18 * * *", "UTC", 2.0, _now=_MON_0900) == "8h"


def test_auto_lookback_intraday_uses_previous_gap():
    """At 09:00 Mon: prev fire 05:00 Mon, prev-prev 23:00 Sun → 6h gap → 8h."""
    assert _compute_auto_lookback("0 5,11,17,23 * * *", "UTC", 2.0, _now=_MON_0900) == "8h"


def test_auto_lookback_daily_schedule():
    """Daily 06:00: prev = Mon 06:00, prev-prev = Sun 06:00 → 24h → 26h."""
    assert _compute_auto_lookback("0 6 * * *", "UTC", 2.0, _now=_MON_0900) == "26h"


def test_auto_lookback_weekday_only_monday_covers_weekend():
    """Monday 09:00 on `mon-fri` 06:00: prev = Mon 06:00, prev-prev = Fri 06:00 → 72h → 74h.

    This is the weekend-coverage case — Monday's run must look back through
    the weekend or it misses two days of content.
    """
    assert _compute_auto_lookback("0 6 * * mon-fri", "UTC", 2.0, _now=_MON_0900) == "74h"


def test_auto_lookback_weekday_only_tuesday_stays_tight():
    """Tuesday 09:00 on `mon-fri` 06:00: prev = Tue 06:00, prev-prev = Mon 06:00 → 24h → 26h.

    Tue–Fri runs should NOT widen to 74h — the wide window is only used after
    a long off-period.
    """
    assert _compute_auto_lookback("0 6 * * mon-fri", "UTC", 2.0, _now=_TUE_0900) == "26h"


def test_auto_lookback_weekly_schedule():
    """Weekly cron → 7 days = 168h, plus 2h buffer = 170h."""
    assert _compute_auto_lookback("0 6 * * wed", "UTC", 2.0, _now=_MON_0900) == "170h"


def test_auto_lookback_custom_buffer():
    """Buffer should be applied as configured."""
    # 6h gap + 0h buffer = 6h
    assert _compute_auto_lookback("0 0,6,12,18 * * *", "UTC", 0.0, _now=_MON_0900) == "6h"
    # 6h gap + 1h buffer = 7h
    assert _compute_auto_lookback("0 0,6,12,18 * * *", "UTC", 1.0, _now=_MON_0900) == "7h"


_CATCHUP_ACTIVE_HOURS = {
    "weekday_start": "07:00",
    "weekday_end": "18:00",
    "weekend_start": "07:00",
    "weekend_end": "18:00",
}
_TUE_1105 = datetime(2026, 5, 5, 11, 5, tzinfo=UTC)


def test_auto_lookback_skips_quiet_hours_fires():
    """Fires the quiet-hours gate would skip must not count as a 'last run'.

    Schedule fires at 05/11/17/23; only 11:00 and 17:00 fall inside the
    07:00-18:00 active window. Tuesday's 11:00 run must therefore catch up
    to Monday's last *actual* run (17:00, an 18h gap), not the nominal ~6h
    cron-field gap the un-filtered calculation would use.
    """
    assert (
        _compute_auto_lookback(
            "0 5,11,17,23 * * *", "UTC", 2.0, active_hours=_CATCHUP_ACTIVE_HOURS, _now=_TUE_1105
        )
        == "20h"
    )


def test_auto_lookback_unaffected_without_active_hours():
    """Sanity check: active_hours=None preserves the original un-filtered gap."""
    assert _compute_auto_lookback("0 5,11,17,23 * * *", "UTC", 2.0, _now=_MON_0900) == "8h"
