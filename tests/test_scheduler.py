"""Tests for the digest scheduler."""

import json
from datetime import UTC, date, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from signalsage.scheduler import DigestScheduler, _compute_auto_lookback


def _make_watchlist(*schedules: str) -> dict:
    topics = [
        {"name": f"Topic {chr(65 + i)}", "schedule": s, "sources": []}
        for i, s in enumerate(schedules)
    ]
    return {"topics": topics}


def _default_watch_json(relevant: bool = True) -> str:
    return json.dumps(
        {
            "overview": "",
            "coverage_confidence": "high",
            "items": [
                {
                    "art_id": "A1",
                    "relevant": relevant,
                    "icon": "🔴",
                    "severity": "high",
                    "headline": "Test headline",
                    "summary": "Test summary.",
                    "url": "https://example.com",
                }
            ],
        }
    )


def _make_summarizer(summary: str = "summary text", watch_items: str | None = None) -> MagicMock:
    summarizer = MagicMock()
    summarizer.max_chars = 3000
    summarizer.summarize_topic = AsyncMock(return_value=summary)
    summarizer.summarize_watch_items = AsyncMock(return_value=watch_items or _default_watch_json())
    return summarizer


def _make_scheduler(watchlist, notifiers=None, summarizer=None, tmp_path=None) -> DigestScheduler:
    return DigestScheduler(
        summarizer=summarizer or _make_summarizer(),
        watchlist=watchlist,
        notifiers=notifiers or [],
        data_dir=str(tmp_path) if tmp_path else "data",
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


async def test_run_topic_now_progress_callback(tmp_path):
    """progress callable is invoked with status messages during the run."""
    progress = AsyncMock()
    watchlist = {"topics": [{"name": "Cyber News", "tags": ["cyber"], "sources": []}]}
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, tmp_path=tmp_path)
        await scheduler.run_topic_now("cyber", progress=progress)
    assert progress.call_count >= 2
    messages = [c.args[0] for c in progress.call_args_list]
    assert any("Fetch" in m or "fetch" in m for m in messages)
    assert any("Summar" in m for m in messages)


async def test_run_topic_now_tag_priority_over_name(tmp_path):
    """Exact tag match must win over partial name match regardless of job order."""
    notifier = AsyncMock()
    # "AI & ML News" (alphabetically first) contains "news" in its name;
    # "General News" has "news" as an explicit tag — it should be triggered.
    watchlist = {
        "topics": [
            {"name": "AI & ML News", "tags": ["ai", "ml"], "sources": []},
            {"name": "General News", "tags": ["news", "aus"], "sources": []},
        ]
    }
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, notifiers=[notifier], tmp_path=tmp_path)
        found = await scheduler.run_topic_now("news")
    assert found is True
    # The notifier must have been called with "General News", not "AI & ML News"
    called_name = notifier.call_args[0][0]
    assert called_name == "General News"


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


# ---------------------------------------------------------------------------
# Auto-lookback derived from schedule
# ---------------------------------------------------------------------------


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


async def test_run_topic_auto_derives_lookback_when_omitted(tmp_path):
    """A topic without `lookback` should have one derived from its schedule."""
    notifier = AsyncMock()
    summarizer = _make_summarizer()
    # 6h gap → 8h with default buffer of 2h.
    watchlist = {
        "topics": [{"name": "Hourly Topic", "schedule": "0 0,6,12,18 * * *", "sources": []}]
    }
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(
            watchlist, notifiers=[notifier], summarizer=summarizer, tmp_path=tmp_path
        )
        await scheduler._run_topic(watchlist["topics"][0])

    # summarizer.summarize_topic must have been called with the derived lookback
    assert summarizer.summarize_topic.await_args.kwargs["lookback"] == "8h"
    # notifier should also receive it so the channel header shows the right window
    assert notifier.call_args.kwargs["lookback"] == "8h"


# ---------------------------------------------------------------------------
# Watch-mode topics
# ---------------------------------------------------------------------------


def test_watch_mode_topic_gets_interval_job_not_cron(tmp_path):
    watchlist = {"topics": [{"name": "Watched Topic", "watch_mode": True, "sources": []}]}
    scheduler = _make_scheduler(watchlist, tmp_path=tmp_path)
    jobs = scheduler._scheduler.get_jobs()
    assert len(jobs) == 1
    assert jobs[0].id == "watch_watched_topic"


def test_watch_mode_topic_seeds_keywords_from_yaml(tmp_path):
    watchlist = {
        "topics": [
            {
                "name": "Watched Topic",
                "watch_mode": True,
                "keywords": ["ransomware"],
                "exclude_keywords": ["sponsored"],
                "sources": [],
            }
        ]
    }
    scheduler = _make_scheduler(watchlist, tmp_path=tmp_path)
    include, exclude = scheduler.watch_keywords.get("Watched Topic")
    assert include == ["ransomware"]
    assert exclude == ["sponsored"]


def test_get_topics_includes_watch_mode_topics(tmp_path):
    watchlist = {
        "topics": [
            {"name": "Cron Topic", "schedule": "0 6 * * *", "sources": []},
            {"name": "Watched Topic", "watch_mode": True, "sources": []},
        ]
    }
    scheduler = _make_scheduler(watchlist, tmp_path=tmp_path)
    names = [name for name, _tags, _next in scheduler.get_topics()]
    assert "Cron Topic" in names
    assert "Watched Topic" in names


async def test_run_watch_topic_no_new_items_skips_notify(tmp_path):
    notifier = AsyncMock()
    watchlist = {"topics": [{"name": "Watched Topic", "watch_mode": True, "sources": []}]}
    with patch("signalsage.scheduler.fetch_topic_items", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, notifiers=[notifier], tmp_path=tmp_path)
        result = await scheduler._run_watch_topic(watchlist["topics"][0])
    assert result is False
    notifier.assert_not_called()


async def test_run_watch_topic_no_keyword_match_skips_notify(tmp_path):
    notifier = AsyncMock()
    topic = {
        "name": "Watched Topic",
        "watch_mode": True,
        "sources": [{"name": "S", "url": "https://a.com"}],
    }
    watchlist = {"topics": [topic]}
    items = [
        {
            "source_name": "S",
            "source_url": "https://a.com",
            "title": "Unrelated story",
            "link": "https://a.com/1",
            "summary": "nothing interesting",
            "published_ts": None,
        }
    ]
    with patch("signalsage.scheduler.fetch_topic_items", new=AsyncMock(return_value=items)):
        scheduler = _make_scheduler(watchlist, notifiers=[notifier], tmp_path=tmp_path)
        scheduler.watch_keywords.add("Watched Topic", "ransomware")
        result = await scheduler._run_watch_topic(topic)
    assert result is True  # new items were seen, just none matched
    notifier.assert_not_called()


async def test_run_watch_topic_matched_item_posts_immediately(tmp_path):
    notifier = AsyncMock()
    topic = {
        "name": "Watched Topic",
        "watch_mode": True,
        "sources": [{"name": "S", "url": "https://a.com"}],
    }
    watchlist = {"topics": [topic]}
    items = [
        {
            "source_name": "S",
            "source_url": "https://a.com",
            "title": "New ransomware strain found",
            "link": "https://a.com/1",
            "summary": "details here",
            "published_ts": None,
        }
    ]
    summarizer = _make_summarizer()
    with patch("signalsage.scheduler.fetch_topic_items", new=AsyncMock(return_value=items)):
        scheduler = _make_scheduler(
            watchlist, notifiers=[notifier], summarizer=summarizer, tmp_path=tmp_path
        )
        scheduler.watch_keywords.add("Watched Topic", "ransomware")
        result = await scheduler._run_watch_topic(topic)
    assert result is True
    notifier.assert_called_once()
    assert notifier.call_args[0][0] == "Watched Topic"
    assert notifier.call_args.kwargs["meta"]["top_stories_count"] == 1
    assert notifier.call_args.kwargs["meta"]["bare"] is True


async def test_run_watch_topic_llm_marks_item_irrelevant_skips_notify(tmp_path):
    """A substring match the LLM judges as a coincidental/irrelevant hit must not post."""
    notifier = AsyncMock()
    topic = {
        "name": "Watched Topic",
        "watch_mode": True,
        "sources": [{"name": "S", "url": "https://a.com"}],
    }
    watchlist = {"topics": [topic]}
    items = [
        {
            "source_name": "S",
            "source_url": "https://a.com",
            "title": "The apt tenant renewed their lease",
            "link": "https://a.com/1",
            "summary": "unrelated real-estate story",
            "published_ts": None,
        }
    ]
    summarizer = _make_summarizer(watch_items=_default_watch_json(relevant=False))
    with patch("signalsage.scheduler.fetch_topic_items", new=AsyncMock(return_value=items)):
        scheduler = _make_scheduler(
            watchlist, notifiers=[notifier], summarizer=summarizer, tmp_path=tmp_path
        )
        scheduler.watch_keywords.add("Watched Topic", "apt")
        result = await scheduler._run_watch_topic(topic)
    assert result is True  # new items were seen, just judged not relevant
    notifier.assert_not_called()


async def test_run_watch_topic_does_not_repost_same_item(tmp_path):
    """An item already seen on a prior poll must not be re-evaluated."""
    notifier = AsyncMock()
    topic = {
        "name": "Watched Topic",
        "watch_mode": True,
        "sources": [{"name": "S", "url": "https://a.com"}],
    }
    watchlist = {"topics": [topic]}
    items = [
        {
            "source_name": "S",
            "source_url": "https://a.com",
            "title": "Ransomware alert",
            "link": "https://a.com/1",
            "summary": "details",
            "published_ts": None,
        }
    ]
    with patch("signalsage.scheduler.fetch_topic_items", new=AsyncMock(return_value=items)):
        scheduler = _make_scheduler(watchlist, notifiers=[notifier], tmp_path=tmp_path)
        scheduler.watch_keywords.add("Watched Topic", "ransomware")
        await scheduler._run_watch_topic(topic)
        result = await scheduler._run_watch_topic(topic)
    assert result is False  # second poll sees nothing new
    notifier.assert_called_once()


async def test_run_topic_now_dispatches_to_watch_topic(tmp_path):
    notifier = AsyncMock()
    topic = {"name": "Watched Topic", "watch_mode": True, "tags": ["watched"], "sources": []}
    watchlist = {"topics": [topic]}
    with patch("signalsage.scheduler.fetch_topic_items", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, notifiers=[notifier], tmp_path=tmp_path)
        found = await scheduler.run_topic_now("watched")
    assert found is True


def test_find_watch_topic_by_tag(tmp_path):
    topic = {"name": "Watched Topic", "watch_mode": True, "tags": ["watched"], "sources": []}
    watchlist = {"topics": [topic]}
    scheduler = _make_scheduler(watchlist, tmp_path=tmp_path)
    assert scheduler.find_watch_topic("watched") == topic


def test_find_watch_topic_excludes_cron_topics(tmp_path):
    watchlist = {"topics": [{"name": "Cron Topic", "schedule": "0 6 * * *", "sources": []}]}
    scheduler = _make_scheduler(watchlist, tmp_path=tmp_path)
    assert scheduler.find_watch_topic("Cron Topic") is None


async def test_run_topic_explicit_lookback_not_overridden(tmp_path):
    """An explicit `lookback` on the topic must be preserved verbatim."""
    summarizer = _make_summarizer()
    watchlist = {
        "topics": [
            {
                "name": "Pinned Topic",
                "schedule": "0 0,6,12,18 * * *",
                "lookback": "24h",
                "sources": [],
            }
        ]
    }
    with patch("signalsage.scheduler.fetch_topic", new=AsyncMock(return_value=[])):
        scheduler = _make_scheduler(watchlist, summarizer=summarizer, tmp_path=tmp_path)
        await scheduler._run_topic(watchlist["topics"][0])

    assert summarizer.summarize_topic.await_args.kwargs["lookback"] == "24h"
