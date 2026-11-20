"""Global urgent route: any topic's alerts go to one channel, capped, not repeated."""

import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from signalsage.config import ConfigError, validate_config
from signalsage.digest.pipeline import DigestPipeline
from signalsage.digest.store import ArticleStore
from signalsage.digest.watch import WatchKeywords
from signalsage.scheduler import DigestScheduler

SOURCE = {"name": "Feed", "url": "https://source.test/feed"}
TOPIC = {"name": "Security", "keywords": ["CVE"], "digest_channel": "#news", "sources": [SOURCE]}
URGENT = {"channel": "#general", "max_per_day": 10, "alert_keywords": ["zero-day"]}


def story(n, title, published=None):
    return {
        "title": title,
        "summary": f"Details for story {n}: CVE-2026-{n:04d} affects many systems.",
        "link": f"https://source.test/{n}",
        "published_ts": published,
    }


def make(tmp_path, settings=None):
    store = ArticleStore(str(tmp_path))
    keywords = WatchKeywords(str(tmp_path))
    keywords.seed_defaults(TOPIC["name"], ["CVE"], [])
    sent: list[tuple[str, dict, dict]] = []

    async def send(topic, summary, channel=None, meta=None):
        sent.append((channel, json.loads(summary), meta))
        meta["_ack"](1)

    send.__self__ = SimpleNamespace(  # type: ignore[attr-defined]
        platform_name="slack",
        digest_destination=lambda channel=None: ("slack", channel),
    )

    async def summarize(articles, interests):
        return {a["id"]: {"summary": "Summary.", "evidence": "Details for story"} for a in articles}

    summarizer = SimpleNamespace(
        cache_key="k",
        batch_size=8,
        summarize_batch=AsyncMock(side_effect=summarize),
        judge_relevance_batch=AsyncMock(return_value={}),
    )
    pipeline = DigestPipeline(
        summarizer,
        [send],
        store,
        keywords,
        settings={"fetch_article_text": False, "urgent": URGENT, **(settings or {})},
    )
    return pipeline, store, sent


async def test_urgent_story_goes_to_urgent_channel_and_digest_skips_it(tmp_path):
    pipeline, store, sent = make(tmp_path)
    store.ingest(
        TOPIC["name"],
        SOURCE,
        [story(1, "Vendor fixes CVE-2026-0001 zero-day"), story(2, "CVE-2026-0002 patched")],
    )

    await pipeline.publish(TOPIC, 3, urgent=True, alert_terms=["zero-day"], channel="#general")
    assert [(c, [i["headline"] for i in s["items"]]) for c, s, _ in sent] == [
        ("#general", ["Vendor fixes CVE-2026-0001 zero-day"])
    ]
    assert sent[0][2]["urgent_route"] is True
    assert store.urgent_count("slack:#general", time.time() - 60) == 1

    await pipeline.publish(TOPIC, 3)
    channel, digest, _ = sent[1]
    assert channel == "#news"
    titles = [i["headline"] for i in digest["items"]] + [m["headline"] for m in digest["more"]]
    assert titles == ["CVE-2026-0002 patched"]


async def test_old_matches_wait_for_the_digest(tmp_path):
    pipeline, store, sent = make(tmp_path)
    two_days_ago = time.time() - 2 * 86400
    store.ingest(TOPIC["name"], SOURCE, [story(1, "CVE-2026-0001 zero-day", two_days_ago)])

    await pipeline.publish(TOPIC, 3, urgent=True, alert_terms=["zero-day"], channel="#general")
    assert sent == []


async def test_watch_topic_alerts_do_not_count_toward_the_cap(tmp_path):
    pipeline, store, sent = make(tmp_path)
    store.ingest(TOPIC["name"], SOURCE, [story(1, "CVE-2026-0001 zero-day")])
    watch = {**TOPIC, "digest_channel": "#general", "alert_keywords": ["zero-day"]}

    await pipeline.publish(watch, 3, urgent=True)
    assert len(sent) == 1
    assert store.urgent_count("slack:#general", time.time() - 60) == 0


def _scheduler(pipeline, store, topics, active=True):
    scheduler = DigestScheduler.__new__(DigestScheduler)
    scheduler.pipeline = pipeline
    scheduler.store = store
    scheduler._topics = topics
    scheduler._in_active_hours = lambda: active
    return scheduler


async def test_urgent_pass_checks_topics_respects_opt_out_and_topic_terms(tmp_path):
    pipeline, store, sent = make(tmp_path)
    solar = {**TOPIC, "name": "Solar", "alert_keywords": ["geomagnetic storm"]}
    quiet = {**TOPIC, "name": "VIP", "urgent": False}
    watch = {**TOPIC, "name": "Weather", "watch_mode": True}
    for topic in (solar, quiet, watch):
        pipeline.keywords.seed_defaults(topic["name"], ["CVE"], [])
    store.ingest("Solar", SOURCE, [story(1, "Severe geomagnetic storm hits CVE-2026-0001 radios")])
    store.ingest("VIP", SOURCE, [story(2, "CVE-2026-0002 zero-day")])
    store.ingest("Weather", SOURCE, [story(3, "CVE-2026-0003 zero-day")])

    await _scheduler(pipeline, store, [solar, quiet, watch])._urgent_pass()

    assert [(c, s["items"][0]["headline"]) for c, s, _ in sent] == [
        ("#general", "Severe geomagnetic storm hits CVE-2026-0001 radios")
    ]


async def test_urgent_pass_stops_at_daily_cap_and_in_quiet_hours(tmp_path):
    pipeline, store, sent = make(tmp_path, {"urgent": {**URGENT, "max_per_day": 2}})
    store.ingest(
        TOPIC["name"],
        SOURCE,
        [story(n, f"CVE-2026-{n:04d} zero-day number {n}") for n in (1, 2, 3)],
    )

    await _scheduler(pipeline, store, [TOPIC], active=False)._urgent_pass()
    assert sent == []

    scheduler = _scheduler(pipeline, store, [TOPIC])
    await scheduler._urgent_pass()
    await scheduler._urgent_pass()
    assert sum(len(s["items"]) for _, s, _ in sent) == 2


def test_urgent_config_validation():
    assert validate_config({"digest": {"urgent": URGENT}})
    with pytest.raises(ConfigError, match="channel"):
        validate_config({"digest": {"urgent": {"max_per_day": 3}}})
    with pytest.raises(ConfigError, match="max_per_day"):
        validate_config({"digest": {"urgent": {"channel": "#g", "max_per_day": 0}}})
