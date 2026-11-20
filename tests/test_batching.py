"""Batch mode: several articles per model call (large-context backends like Gemini)."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

from signalsage.digest.pipeline import DigestPipeline
from signalsage.digest.store import ArticleStore
from signalsage.digest.summarizer import DigestSummarizer, SummaryValidationError
from signalsage.digest.watch import WatchKeywords
from signalsage.llm.base import LLMRateLimitError

ART_A = {"id": "a1", "title": "Patch for CVE", "body": "Vendor patched CVE-2026-1 on Monday."}
ART_B = {"id": "b2", "title": "New comet", "body": "Astronomers spotted an interstellar comet."}


def batch_reply(*items):
    return json.dumps({"summaries": list(items)})


def item(art_id, summary, evidence):
    return {"art_id": art_id, "summary": summary, "evidence": evidence}


# --------------------------------------------------------------------------- #
# Summarizer                                                                  #
# --------------------------------------------------------------------------- #
async def test_summarize_batch_uses_one_call_and_validates_each_item():
    llm = AsyncMock()
    llm.complete.return_value = batch_reply(
        item("a1", "The vendor patched a CVE.", "Vendor patched CVE-2026-1"),
        item("b2", "An interstellar comet was found.", "spotted an interstellar comet"),
    )
    out = await DigestSummarizer(llm, batch_size=8).summarize_batch([ART_A, ART_B], ["comet"])

    assert llm.complete.await_count == 1
    assert out["a1"]["summary"] == "The vendor patched a CVE."
    assert out["b2"]["evidence"] == "spotted an interstellar comet"
    payload = json.loads(llm.complete.call_args.kwargs["user"])
    assert [a["art_id"] for a in payload["articles"]] == ["a1", "b2"]
    assert payload["reader_interests"] == ["comet"]


async def test_batch_retries_only_failed_items_then_flags_them():
    llm = AsyncMock()
    llm.complete.side_effect = [
        batch_reply(
            item("a1", "The vendor patched a CVE.", "Vendor patched CVE-2026-1"),
            item("b2", "A comet.", "this text is not in the source"),
        ),
        batch_reply(item("b2", "A comet.", "still not in the source")),
    ]
    out = await DigestSummarizer(llm, batch_size=8).summarize_batch([ART_A, ART_B])

    assert llm.complete.await_count == 2
    retry_payload = json.loads(llm.complete.call_args.kwargs["user"])
    assert [a["art_id"] for a in retry_payload["articles"]] == ["b2"]
    assert "summary" in out["a1"]
    assert isinstance(out["b2"], SummaryValidationError)


async def test_batch_rate_limit_is_returned_for_every_article():
    llm = AsyncMock()
    llm.complete.side_effect = LLMRateLimitError("quota")
    out = await DigestSummarizer(llm, batch_size=8, batch_chars=10).summarize_batch([ART_A, ART_B])
    # Tiny batch_chars forces two groups; the second is never sent.
    assert llm.complete.await_count == 1
    assert all(isinstance(v, LLMRateLimitError) for v in out.values())


async def test_judge_batch_maps_verdicts_by_id_and_drops_unknown():
    llm = AsyncMock()
    llm.complete.return_value = json.dumps(
        {
            "verdicts": [
                {"art_id": "a1", "relevant": True, "reason": "cyber"},
                {"art_id": "zz", "relevant": True, "reason": "made up"},
            ]
        }
    )
    out = await DigestSummarizer(llm, batch_size=8).judge_relevance_batch([ART_A, ART_B], {})
    assert out == {"a1": (True, "cyber")}


def test_batch_mode_changes_cache_key():
    llm = SimpleNamespace(model="m")
    assert DigestSummarizer(llm).cache_key != DigestSummarizer(llm, batch_size=8).cache_key


# --------------------------------------------------------------------------- #
# Pipeline                                                                    #
# --------------------------------------------------------------------------- #
SOURCE = {"name": "Feed", "url": "https://source.test/feed"}
TOPIC = {"name": "Security", "keywords": ["CVE"], "sources": [SOURCE]}


def story(n):
    return {
        "title": f"CVE-2026-{n:04d} receives a patch {'xyz' * n}",
        "summary": f"A patch is available for CVE-2026-{n:04d}. Story number {n} detail.",
        "link": f"https://source.test/story{n}",
        "published_ts": None,
    }


def batch_pipeline(tmp_path, summarize_batch):
    store = ArticleStore(str(tmp_path))
    keywords = WatchKeywords(str(tmp_path))
    keywords.seed_defaults(TOPIC["name"], ["CVE"], [])
    dest = SimpleNamespace(messages=[])

    async def send(topic, summary, channel=None, meta=None):
        dest.messages.append(json.loads(summary))
        meta["_ack"](1)

    send.__self__ = SimpleNamespace(  # type: ignore[attr-defined]
        platform_name="slack", digest_destination=lambda channel=None: ("slack", "C1")
    )
    summarizer = SimpleNamespace(
        cache_key="batch-v1",
        batch_size=8,
        summarize_batch=AsyncMock(side_effect=summarize_batch),
        judge_relevance_batch=AsyncMock(return_value={}),
        summarize_article=AsyncMock(),
        judge_relevance=AsyncMock(),
    )
    pipeline = DigestPipeline(
        summarizer, [send], store, keywords, settings={"fetch_article_text": False}
    )
    pipeline.destinations = lambda topic, override=None: [("slack:C1", send, "C1")]
    for n in range(1, 4):
        store.ingest(TOPIC["name"], SOURCE, [story(n)])
    return pipeline, dest


async def test_pipeline_summarizes_all_selected_stories_in_one_batch(tmp_path):
    async def ok(articles, interests):
        return {
            a["id"]: {"summary": "Patched.", "evidence": "A patch is available"} for a in articles
        }

    pipeline, dest = batch_pipeline(tmp_path, ok)
    await pipeline.publish(TOPIC, 3)

    pipeline.summarizer.summarize_batch.assert_awaited_once()
    pipeline.summarizer.summarize_article.assert_not_awaited()
    assert len(dest.messages[0]["items"]) == 3


async def test_pipeline_quotes_excerpts_when_quota_is_exhausted(tmp_path):
    async def quota(articles, interests):
        return {a["id"]: LLMRateLimitError("daily quota") for a in articles}

    pipeline, dest = batch_pipeline(tmp_path, quota)
    await pipeline.publish(TOPIC, 3)

    items = dest.messages[0]["items"]
    assert len(items) == 3
    assert all(i["content_kind"].startswith("quoted excerpt") for i in items)
    assert items[0]["summary"].startswith("A patch is available")


async def test_prompt_credits_named_source_and_writes_in_english():
    llm = AsyncMock()
    article = {
        "id": "r1",
        "title": "Основные результаты деятельности НКЦКИ",
        "body": "НКЦКИ зафиксировал 120 атак на объекты КИИ.",
        "source_name": "NKCKI (Russia)",
    }
    llm.complete.return_value = batch_reply(
        item("r1", "NKCKI says it recorded 120 attacks.", "зафиксировал 120 атак")
    )
    out = await DigestSummarizer(llm, batch_size=8).summarize_batch([article])

    assert out["r1"]["evidence"] == "зафиксировал 120 атак"
    payload = json.loads(llm.complete.call_args.kwargs["user"])
    assert payload["articles"][0]["source"] == "NKCKI (Russia)"
    system = llm.complete.call_args.kwargs["system"]
    assert "in English" in system and "TASS says" in system
