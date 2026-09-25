import asyncio
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from signalsage.digest.pipeline import DigestPipeline
from signalsage.digest.store import ArticleStore
from signalsage.digest.watch import WatchKeywords
from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOCType
from signalsage.ioc.processor import IOCProcessor

SOURCE = {"name": "Feed", "url": "https://source.test/feed"}
TOPIC = {"name": "Security", "keywords": ["CVE"], "sources": [SOURCE]}
ARTICLE = {
    "title": "CVE-2026-1234 receives a patch",
    "summary": "A patch is available for CVE-2026-1234. It fixes a buffer overflow.",
    "link": "https://source.test/story",
    "published_ts": None,
}


class Destination:
    platform_name = "slack"

    def __init__(self):
        self.messages = []
        self.error = None

    def digest_destination(self, channel=None):
        return "slack", channel or "C123"

    async def send(self, topic, summary, channel=None, meta=None):
        if self.error:
            raise self.error
        self.messages.append((topic, json.loads(summary), channel, meta))
        meta["_ack"](1)


def make_pipeline(tmp_path, destination=None, **kwargs):
    dest = destination or Destination()
    store = ArticleStore(str(tmp_path))
    keywords = WatchKeywords(str(tmp_path))
    keywords.seed_defaults(TOPIC["name"], ["CVE"], [])
    summarizer = SimpleNamespace(
        cache_key="test-model-v1",
        summarize_article=AsyncMock(
            return_value={"summary": "A patch is available.", "evidence": "A patch is available"}
        ),
        judge_relevance=AsyncMock(return_value=(True, "Relevant")),
    )
    pipeline = DigestPipeline(
        summarizer, [dest.send], store, keywords, settings={"fetch_article_text": False}, **kwargs
    )
    return pipeline, dest


def ingest(pipeline, item=None, topic=TOPIC):
    return pipeline.store.ingest(topic["name"], SOURCE, [item or ARTICLE])


async def test_model_failure_does_not_lose_article_after_restart(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    pipeline.summarizer.summarize_article.side_effect = RuntimeError("model unavailable")
    await pipeline.publish(TOPIC, 5)
    assert dest.messages == []
    assert len(pipeline.store.candidates(TOPIC["name"], "profile")) == 1
    restarted, _ = make_pipeline(tmp_path, dest)
    await restarted.publish(TOPIC, 5)
    assert len(dest.messages) == 1
    assert restarted.store.status()["pending_deliveries"] == 0


async def test_delivery_failure_retries_from_persisted_summary(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    dest.error = RuntimeError("Slack unavailable")
    await pipeline.publish(TOPIC, 5)
    assert pipeline.store.status()["pending_deliveries"] == 1
    restarted, _ = make_pipeline(tmp_path, dest)
    dest.error = None
    await restarted.flush(force=True)
    assert len(dest.messages) == 1
    restarted.summarizer.summarize_article.assert_not_awaited()
    await restarted.publish(TOPIC, 5)
    assert len(dest.messages) == 1


async def test_cross_topic_dedup_before_model_and_per_destination(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    other = {**TOPIC, "name": "Research"}
    ingest(pipeline, topic=other)
    await pipeline.publish(TOPIC, 5)
    await pipeline.publish(other, 5)
    assert len(dest.messages) == 1
    assert pipeline.summarizer.summarize_article.await_count == 1
    await pipeline.publish(other, 5, override_channel="C456")
    assert len(dest.messages) == 2
    assert pipeline.summarizer.summarize_article.await_count == 1  # cached summary


async def test_pending_delivery_reserves_article_across_topics(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    other = {**TOPIC, "name": "Research"}
    ingest(pipeline, topic=other)
    dest.error = RuntimeError("offline")
    await pipeline.publish(TOPIC, 5)
    await pipeline.publish(other, 5)
    assert pipeline.store.status()["pending_deliveries"] == 1
    assert pipeline.summarizer.summarize_article.await_count == 1


async def test_same_url_with_changed_facts_is_an_update(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    await pipeline.publish(TOPIC, 5)
    ingest(
        pipeline,
        {
            **ARTICLE,
            "summary": "CVE-2026-1234 is now actively exploited. A second patch was released.",
        },
    )
    await pipeline.publish(TOPIC, 5)
    assert len(dest.messages) == 2
    assert pipeline.summarizer.summarize_article.await_count == 2


async def test_canonical_tracking_urls_do_not_duplicate(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    ingest(pipeline, {**ARTICLE, "link": ARTICLE["link"] + "?utm_source=email#top"})
    await pipeline.publish(TOPIC, 5)
    assert len(dest.messages[0][1]["items"]) == 1


async def test_profile_change_reconsiders_rejected_articles(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(
        pipeline,
        {**ARTICLE, "title": "Radio release", "summary": "A new radio transceiver is available."},
    )
    await pipeline.publish(TOPIC, 5)
    assert not dest.messages
    pipeline.keywords.add(TOPIC["name"], "radio")
    await pipeline.publish(TOPIC, 5)
    assert len(dest.messages) == 1


async def test_collection_failure_does_not_advance_checkpoint(tmp_path, monkeypatch):
    pipeline, _ = make_pipeline(tmp_path)
    ingest(pipeline)
    before = pipeline.store.checkpoint(TOPIC["name"], SOURCE["url"])
    monkeypatch.setattr(
        "signalsage.digest.pipeline.collect_source", AsyncMock(return_value=([], "HTTP error"))
    )
    await pipeline.collect(TOPIC)
    assert pipeline.store.checkpoint(TOPIC["name"], SOURCE["url"]) == before
    assert pipeline.store.status()["source_errors"] == 1


async def test_successful_empty_feed_is_not_a_source_error(tmp_path, monkeypatch):
    pipeline, _ = make_pipeline(tmp_path)
    monkeypatch.setattr(
        "signalsage.digest.pipeline.collect_source", AsyncMock(return_value=([], None))
    )
    await pipeline.collect(TOPIC)
    assert pipeline.store.checkpoint(TOPIC["name"], SOURCE["url"])
    assert pipeline.store.status()["source_errors"] == 0


async def test_restart_collects_delayed_publication_without_short_lookback(tmp_path, monkeypatch):
    pipeline, _ = make_pipeline(tmp_path)
    ingest(pipeline)
    restarted, _ = make_pipeline(tmp_path)
    late = {**ARTICLE, "link": "https://source.test/late", "published_ts": time.time() - 10 * 86400}
    monkeypatch.setattr(
        "signalsage.digest.pipeline.collect_source", AsyncMock(return_value=([late], None))
    )
    await restarted.collect({**TOPIC, "lookback": "24h"})
    assert restarted.store.status()["articles"] == 2


async def test_summary_budget_does_not_discard_remaining_articles(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    for i in range(8):
        ingest(
            pipeline,
            {**ARTICLE, "title": f"CVE-2026-{1000 + i} patch", "link": f"https://source.test/{i}"},
        )
    await pipeline.publish(TOPIC, 3)
    assert len(dest.messages[0][1]["items"]) == 3
    await pipeline.publish(TOPIC, 3)
    assert len(dest.messages[1][1]["items"]) == 3
    assert pipeline.store.status()["articles"] == 8


async def test_shortlisted_cve_enrichment_reuses_existing_ioc_processor(tmp_path):
    provider = SimpleNamespace(
        enabled=True,
        supports=lambda kind: kind == IOCType.CVE,
        lookup=AsyncMock(
            return_value=IntelResult(
                provider="CVE",
                ioc_value="CVE-2026-1234",
                ioc_type=IOCType.CVE,
                summary="CVSS 9.8",
                details={"cvss": 9.8},
            )
        ),
    )
    processor = IOCProcessor([provider])
    pipeline, _ = make_pipeline(tmp_path, processor=processor)
    ingest(pipeline)
    await pipeline.publish(TOPIC, 5)
    sent_article = pipeline.summarizer.summarize_article.call_args.args[0]
    assert sent_article["enrichment"][0]["details"]["cvss"] == 9.8
    # Automatic message enrichment remains available and uses the same cache.
    result = await processor.process("Please check CVE-2026-1234")
    assert result[0][1][0].summary == "CVSS 9.8"
    provider.lookup.assert_awaited_once()


async def test_podcasts_only_transcribed_after_selection(tmp_path, monkeypatch):
    pipeline, _ = make_pipeline(tmp_path, whisper_base_url="http://whisper")
    transcript = AsyncMock(return_value="A podcast transcript discussing CVE patches.")
    monkeypatch.setattr("signalsage.digest.pipeline._transcribe_audio", transcript)
    ingest(pipeline, {**ARTICLE, "audio_url": "https://source.test/audio.mp3"})
    ingest(
        pipeline,
        {
            **ARTICLE,
            "title": "Cooking podcast",
            "summary": "An episode about food",
            "link": "https://source.test/food",
            "audio_url": "https://source.test/food.mp3",
        },
    )
    await pipeline.publish(TOPIC, 5)
    transcript.assert_awaited_once_with("https://source.test/audio.mp3", "http://whisper")


async def test_fallback_summary_is_labelled_excerpt(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    await pipeline.publish(TOPIC, 5)
    card = dest.messages[0][1]["items"][0]
    assert card["content_kind"] == "feed excerpt"
    assert card["url"] == ARTICLE["link"]
    assert "CVE" in card["relevance_reason"]


async def test_urgent_delivery_requires_explicit_rule(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    await pipeline.publish(TOPIC, 5, urgent=True)
    assert not dest.messages
    await pipeline.publish({**TOPIC, "alert_keywords": ["patch"]}, 5, urgent=True)
    assert len(dest.messages) == 1


async def test_parallel_publish_does_not_duplicate_model_or_delivery(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    await asyncio.gather(pipeline.publish(TOPIC, 5), pipeline.publish(TOPIC, 5))
    assert len(dest.messages) == 1
    pipeline.summarizer.summarize_article.assert_awaited_once()


async def test_summary_finishing_after_quiet_hours_stays_queued(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    await pipeline.publish(TOPIC, 5, delivery_allowed=lambda: False)
    assert not dest.messages
    assert pipeline.store.status()["pending_deliveries"] == 1
    await pipeline.flush(allowed=lambda: True)
    assert len(dest.messages) == 1


def test_feedback_upsert_is_idempotent_and_persistent(tmp_path):
    pipeline, _ = make_pipeline(tmp_path)
    ingest(pipeline)
    article = pipeline.store.candidates(TOPIC["name"], "x")[0]
    assert pipeline.store.record_feedback(article["id"][:12], "user", True)
    assert pipeline.store.record_feedback(article["id"][:12], "user", True)
    assert ArticleStore(str(tmp_path)).feedback_weights() == {"source.test": 0.25}
    assert pipeline.store.record_feedback(article["id"][:12], "user", False)
    assert pipeline.store.feedback_weights() == {"source.test": -0.25}


def test_reaction_feedback_follows_story_message(tmp_path):
    pipeline, _ = make_pipeline(tmp_path)
    ingest(pipeline)
    article = pipeline.store.candidates(TOPIC["name"], "x")[0]
    pipeline.store.record_message("slack", "C1:1.2", article["id"])
    assert not pipeline.store.react_feedback("slack", "C1:9.9", "user", True)
    assert pipeline.store.react_feedback("slack", "C1:1.2", "user", True)
    assert pipeline.store.feedback_weights() == {"source.test": 0.25}
    assert pipeline.store.react_feedback("slack", "C1:1.2", "user", False)
    assert pipeline.store.feedback_weights() == {"source.test": -0.25}
    # Removing the stale 👍 keeps the current 👎; removing the 👎 clears the vote.
    pipeline.store.react_feedback("slack", "C1:1.2", "user", True, removed=True)
    assert pipeline.store.feedback_weights() == {"source.test": -0.25}
    pipeline.store.react_feedback("slack", "C1:1.2", "user", False, removed=True)
    assert pipeline.store.feedback_weights() == {}


def test_pruning_preserves_pending_articles(tmp_path):
    pipeline, _ = make_pipeline(tmp_path)
    ingest(pipeline)
    with pipeline.store.connect() as db:
        db.execute("UPDATE articles SET collected=0")
    pipeline.store.prune(7)
    assert pipeline.store.status()["articles"] == 1


def test_acknowledgement_survives_restart(tmp_path):
    pipeline, _ = make_pipeline(tmp_path)
    ingest(pipeline)
    article = pipeline.store.candidates(TOPIC["name"], "x")[0]
    key = pipeline.store.enqueue(
        "slack:C123", TOPIC["name"], {"summary": "{}", "meta": {}, "channel": "C123"}, [article]
    )
    pipeline.store.acknowledge(key, 2)
    pipeline.store.failed(key, RuntimeError("offline"))
    row = ArticleStore(str(tmp_path)).pending(force=True)[0]
    assert row["offset"] == 2
    assert row["next_attempt"] > time.time()


async def test_bootstrap_exclusion_survives_later_polls_and_restart(tmp_path, monkeypatch):
    old = {**ARTICLE, "published_ts": time.time() - 60 * 86400}
    monkeypatch.setattr(
        "signalsage.digest.pipeline.collect_source", AsyncMock(return_value=([old], None))
    )
    pipeline, _ = make_pipeline(tmp_path)
    await pipeline.collect(TOPIC)
    assert pipeline.store.status()["articles"] == 0
    restarted, _ = make_pipeline(tmp_path)
    await restarted.collect(TOPIC)
    assert restarted.store.status()["articles"] == 0


def test_pruned_completed_article_is_not_reimported(tmp_path):
    pipeline, _ = make_pipeline(tmp_path)
    ingest(pipeline)
    article = pipeline.store.candidates(TOPIC["name"], "x")[0]
    pipeline.store.decision(TOPIC["name"], article["id"], "x", "rejected", 0, [])
    with pipeline.store.connect() as db:
        db.execute("UPDATE articles SET collected=0")
    pipeline.store.prune(7)
    assert pipeline.store.status()["articles"] == 0
    assert ingest(pipeline) == 0


async def test_rendered_payload_persists_and_is_used_for_retry(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    dest.digest_payloads = lambda topic, summary, meta: [{"text": "Original rendered payload"}]
    ingest(pipeline)
    dest.error = RuntimeError("offline")
    await pipeline.publish(TOPIC, 5)
    row = pipeline.store.pending(force=True)[0]
    assert json.loads(row["body"])["payloads"] == [{"text": "Original rendered payload"}]
    dest.digest_payloads = lambda *args: [{"text": "New formatter"}]
    dest.error = None
    restarted, _ = make_pipeline(tmp_path, dest)
    await restarted.flush(force=True)
    assert dest.messages[0][3]["_payloads"] == [{"text": "Original rendered payload"}]


async def test_collection_to_validated_summary_to_slack_then_restart(tmp_path, monkeypatch):
    from signalsage.bots.slack import SlackBot
    from signalsage.digest.summarizer import DigestSummarizer

    monkeypatch.setattr(
        "signalsage.digest.pipeline.collect_source", AsyncMock(return_value=([ARTICLE], None))
    )
    llm = SimpleNamespace(model="test-model")

    async def complete(**kwargs):
        article = json.loads(kwargs["user"])
        return json.dumps(
            {
                "art_id": article["art_id"],
                "summary": "A patch is available for CVE-2026-1234.",
                "evidence": "A patch is available for CVE-2026-1234.",
            }
        )

    llm.complete = AsyncMock(side_effect=complete)
    slack = SlackBot.__new__(SlackBot)
    slack.cfg = {"digest_channel": "C123"}
    slack.app = SimpleNamespace(
        client=SimpleNamespace(chat_postMessage=AsyncMock(return_value={"ts": "1"}))
    )
    store = ArticleStore(str(tmp_path))
    keywords = WatchKeywords(str(tmp_path))
    keywords.seed_defaults(TOPIC["name"], ["CVE"], [])
    pipeline = DigestPipeline(
        DigestSummarizer(llm),
        [slack.send_digest],
        store,
        keywords,
        settings={"fetch_article_text": False},
    )
    await pipeline.collect(TOPIC)
    await pipeline.publish(TOPIC, 5)
    posted = slack.app.client.chat_postMessage.call_args.kwargs
    assert posted["channel"] == "C123"
    assert ARTICLE["link"] in posted["blocks"][1]["text"]["text"]
    assert store.status()["pending_deliveries"] == 0
    restarted = DigestPipeline(
        DigestSummarizer(llm),
        [slack.send_digest],
        ArticleStore(str(tmp_path)),
        keywords,
        settings={"fetch_article_text": False},
    )
    await restarted.collect(TOPIC)
    await restarted.publish(TOPIC, 5)
    slack.app.client.chat_postMessage.assert_awaited_once()
    llm.complete.assert_awaited_once()


def test_atomic_enqueue_rolls_back_on_duplicate_reservation(tmp_path):
    pipeline, _ = make_pipeline(tmp_path)
    ingest(pipeline)
    article = pipeline.store.candidates(TOPIC["name"], "x")[0]
    pipeline.store.enqueue("slack:C123", TOPIC["name"], {}, [article])
    with pytest.raises(Exception):
        pipeline.store.enqueue("slack:C123", TOPIC["name"], {}, [article])
    assert pipeline.store.status()["pending_deliveries"] == 1


async def test_stale_backlog_is_never_posted(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    old = time.time() - 30 * 86400
    ingest(pipeline, {**ARTICLE, "published_ts": old})
    await pipeline.publish(TOPIC, 5)
    assert dest.messages == []
    pipeline.summarizer.summarize_article.assert_not_awaited()


def test_superseded_page_versions_are_pruned_early(tmp_path):
    store = ArticleStore(str(tmp_path))
    for n in range(3):
        store.ingest("Solar", SOURCE, [{**ARTICLE, "summary": f"Solar flux reading {n}"}])
    with store.connect() as db:
        db.execute("UPDATE articles SET collected=collected-3*86400")
        db.execute(
            "UPDATE articles SET collected=? WHERE rowid=(SELECT MAX(rowid) FROM articles)",
            (time.time(),),
        )
    store.prune(retention_days=90)
    remaining = store.candidates("Solar", "profile")
    assert len(remaining) == 1 and remaining[0]["summary"] == "Solar flux reading 2"
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM articles").fetchone()[0] == 1


async def test_digest_does_not_wait_for_running_background_collection(tmp_path):
    pipeline, _ = make_pipeline(tmp_path)
    pipeline.collect = AsyncMock(return_value=1)
    async with pipeline._collection_lock:
        assert await pipeline.collect_if_idle(TOPIC) == 0
        pipeline.collect.assert_not_awaited()
    assert await pipeline.collect_if_idle(TOPIC) == 1


async def test_failed_grounding_posts_a_quoted_excerpt_once(tmp_path):
    from signalsage.digest.summarizer import SummaryValidationError

    pipeline, dest = make_pipeline(tmp_path)
    ingest(pipeline)
    pipeline.summarizer.summarize_article.side_effect = SummaryValidationError("bad evidence")
    await pipeline.publish(TOPIC, 5)
    card = dest.messages[0][1]["items"][0]
    assert card["summary"].startswith("A patch is available for CVE-2026-1234.")
    assert card["content_kind"] == "quoted excerpt of feed excerpt"
    # The fallback is cached: later runs never pay for the same failing call.
    await pipeline.publish({**TOPIC, "digest_channel": "C999"}, 5)
    assert pipeline.summarizer.summarize_article.await_count == 1


def test_store_commits_without_fsync(tmp_path):
    store = ArticleStore(str(tmp_path))
    with store.connect() as db:
        assert db.execute("PRAGMA synchronous").fetchone()[0] == 1  # NORMAL


async def test_edited_reddit_post_is_not_reposted(tmp_path):
    pipeline, dest = make_pipeline(tmp_path)
    post = {**ARTICLE, "link": "https://www.reddit.com/r/netsec/comments/abc/cve_2026_1234/"}
    ingest(pipeline, post)
    await pipeline.publish(TOPIC, 5)
    ingest(pipeline, {**post, "summary": post["summary"] + " EDIT: typo fixed."})
    await pipeline.publish(TOPIC, 5)
    assert len(dest.messages) == 1  # an edit is not news; a news-site update still is
