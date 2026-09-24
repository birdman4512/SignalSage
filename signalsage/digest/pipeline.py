"""Article collection, selection, enrichment and durable delivery orchestration."""

import asyncio
import json
import logging
import re
import time

from signalsage.ioc.models import IOC, IOCType

from . import reddit
from .collection import collect_source, fetch_article_text
from .fetcher import _transcribe_audio, parse_lookback
from .ranking import contains, fingerprint, score_article, similar_story
from .store import ArticleStore
from .transcripts import fetch_transcript, select_passages, transcript_url

logger = logging.getLogger(__name__)


class TranscriptPending(ValueError):
    """The show's published transcript isn't out yet; retry on a later run."""


class DigestPipeline:
    def __init__(
        self,
        summarizer,
        notifiers,
        store: ArticleStore,
        keywords,
        profile=None,
        processor=None,
        whisper_base_url=None,
        settings=None,
    ):
        self.summarizer = summarizer
        self.notifiers = notifiers
        self.store = store
        self.keywords = keywords
        self.profile = profile or {}
        self.processor = processor
        self.whisper_base_url = whisper_base_url
        self.settings = settings or {}
        self._collection_lock = asyncio.Lock()
        self._publish_lock = asyncio.Lock()
        self._delivery_lock = asyncio.Lock()
        self._fetch_limit = asyncio.Semaphore(4)
        self._source_cache: dict = {}
        self._generation_retry: dict[str, float] = {}
        reddit.configure(self.settings.get("reddit"))

    async def collect(self, topic: dict) -> int:
        async with self._collection_lock:

            async def fetch(source):
                async with self._fetch_limit:
                    cached = self._source_cache.get(source["url"])
                    if cached and time.monotonic() - cached[0] < 60:
                        return source, cached[1], cached[2]
                    try:
                        items, error = await collect_source(source)
                    except Exception as exc:
                        items, error = [], str(exc)
                    self._source_cache[source["url"]] = (time.monotonic(), items, error)
                    return source, items, error

            results = await asyncio.gather(*(fetch(s) for s in topic.get("sources", [])))
            added = 0
            for source, items, error in results:
                cutoff = None
                # A lookback is only a first-install bootstrap bound. Thereafter examine
                # every available feed entry, including delayed/out-of-order publications.
                if self.store.checkpoint(topic["name"], source["url"]) is None:
                    seconds = (
                        parse_lookback(topic.get("lookback"))
                        or int(self.settings.get("bootstrap_days", 7)) * 86400
                    )
                    cutoff = time.time() - seconds
                added += self.store.ingest(
                    topic["name"], source, items, error, bootstrap_cutoff=cutoff
                )
                if error:
                    logger.warning("Source %s failed: %s", source.get("name"), error)
            return added

    async def collect_if_idle(self, topic: dict) -> int:
        """Collect *topic* now, unless a background collection is already running.

        Background collection runs every few minutes and can be slow (Reddit is
        fetched a minute apart), so a digest never waits on it: the articles it
        has already stored are recent enough to publish from.
        """
        if self._collection_lock.locked():
            logger.info("Collection in progress; %s publishes from stored articles", topic["name"])
            return 0
        return await self.collect(topic)

    def destinations(self, topic, override_channel=None):
        destinations = []
        channel = topic.get("digest_channel") or override_channel
        for index, notify in enumerate(self.notifiers):
            owner = getattr(notify, "__self__", None)
            if owner is not None and hasattr(owner, "digest_destination"):
                try:
                    platform, resolved = owner.digest_destination(channel)
                except ValueError as exc:
                    logger.error("Digest destination is invalid: %s", exc)
                    continue
            else:
                platform, resolved = f"notifier-{index}", channel
            destinations.append((f"{platform}:{resolved or 'default'}", notify, resolved))
        return destinations

    async def prepare(
        self, article: dict, source: dict | None = None, focus_terms: list[str] | None = None
    ) -> dict:
        if article.get("body"):
            return article
        budget = int(self.settings.get("article_chars", 6000))
        body, kind = article.get("summary", ""), "feed excerpt"
        published_url = transcript_url(source or {}, article.get("title", ""))
        published = await fetch_transcript(published_url) if published_url else None
        if published_url and not published:
            # Human transcripts (e.g. GRC's for Security Now) land a few days
            # after the episode. Hold the episode for them rather than posting
            # from show notes; fall back only if one never appears.
            age = time.time() - (article.get("published_ts") or article.get("collected") or 0)
            if age < float(self.settings.get("transcript_wait_days", 4)) * 86400:
                raise TranscriptPending(f"Transcript not yet published: {published_url}")
            logger.info("No transcript at %s; using the feed description", published_url)
        if published:
            body, kind = published, "show transcript"
        elif article.get("whole_page"):
            kind = "source page"
        elif article.get("audio_url") and self.whisper_base_url and not published_url:
            transcript = await _transcribe_audio(article["audio_url"], self.whisper_base_url)
            if transcript:
                body, kind = transcript, "podcast transcript"
        elif article.get("link") and self.settings.get("fetch_article_text", True):
            text = await fetch_article_text(
                article["link"], int(self.settings.get("article_chars", 6000))
            )
            if text:
                body, kind = text, "article text"
        if kind in ("show transcript", "podcast transcript"):
            # A transcript runs to ~40-130k chars but the model reads `budget`;
            # send its most on-topic passages instead of the opening chatter.
            body = select_passages(body, article.get("title", ""), focus_terms or [], budget)
        enrichment = []
        if self.processor and self.settings.get("enrich_cves", True):
            cves = list(
                dict.fromkeys(
                    re.findall(r"\bCVE-\d{4}-\d{4,}\b", article["title"] + " " + body, re.I)
                )
            )[:3]
            for cve in cves:
                try:
                    results = await self.processor.lookup_ioc(
                        IOC(value=cve.upper(), type=IOCType.CVE, raw=cve)
                    )
                    for result in results:
                        if not result.error:
                            enrichment.append(
                                {
                                    "indicator": cve.upper(),
                                    "provider": result.provider,
                                    "summary": result.summary,
                                    "details": result.details,
                                    "report_url": result.report_url,
                                }
                            )
                except Exception:
                    logger.exception("Article CVE enrichment failed for %s", cve)
        body = body[: int(self.settings.get("article_chars", 6000))]
        self.store.cache_content(article["id"], body, kind, enrichment)
        article.update(body=body, body_kind=kind, enrichment=enrichment)
        return article

    async def publish(
        self,
        topic: dict,
        top_n: int,
        override_channel=None,
        progress=None,
        urgent=False,
        delivery_allowed=None,
    ):
        async with self._publish_lock:
            started = time.time()
            metrics: dict = {
                "candidates": 0,
                "rejected": 0,
                "deduplicated": 0,
                "summaries": 0,
                "cached": 0,
                "failed": 0,
                "queued": 0,
            }
            destinations = self.destinations(topic, override_channel)
            if not destinations:
                return
            include, exclude = self.keywords.get(topic["name"])
            sources_by_url = {s["url"]: s for s in topic.get("sources", []) if s.get("url")}
            profile = {**self.profile, **topic.get("profile", {})}
            threshold = float(profile.get("minimum_score", 2.5))
            feedback = self.store.feedback_weights()
            profile_key = fingerprint([profile, include, exclude, feedback])
            candidates = self.store.candidates(
                topic["name"],
                profile_key,
                max_age_days=float(self.settings.get("max_article_age_days", 8)),
            )
            metrics["candidates"] = len(candidates)
            # Safe to snapshot: _publish_lock serialises every enqueue.
            reservations = {dest: self.store.reservations(dest) for dest, _, _ in destinations}
            ranked = []
            for article in candidates:
                if all(self.store.reserved(reservations[dest], article) for dest in reservations):
                    metrics["deduplicated"] += 1
                    continue
                score, reasons, veto = score_article(article, profile, include, exclude, feedback)
                if veto or score <= 0:
                    self.store.decision(
                        topic["name"], article["id"], profile_key, "rejected", score, reasons
                    )
                    metrics["rejected"] += 1
                    continue
                if urgent:
                    alert_terms = topic.get("alert_keywords") or []
                    text = article["title"] + " " + article.get("summary", "")
                    if not alert_terms or not any(contains(text, term) for term in alert_terms):
                        continue
                article.update(relevance_score=score, reasons=reasons)
                ranked.append(article)
            ranked.sort(
                key=lambda a: (a["relevance_score"], a.get("published_ts") or 0), reverse=True
            )
            selected: list[dict] = []
            # Bound model work even when a feed or first-install backlog is large.
            attempted = 0
            for article in ranked:
                if len(selected) >= top_n or attempted >= top_n * 2:
                    break
                if any(similar_story(article, other) for other in selected):
                    metrics["deduplicated"] += 1
                    continue
                if time.monotonic() < self._generation_retry.get(article["id"], 0):
                    continue
                attempted += 1
                try:
                    if article["relevance_score"] < threshold:
                        relevant, reason = await self.summarizer.judge_relevance(
                            article, {**profile, "keywords": include}
                        )
                        if not relevant:
                            self.store.decision(
                                topic["name"],
                                article["id"],
                                profile_key,
                                "rejected",
                                article["relevance_score"],
                                [reason],
                            )
                            metrics["rejected"] += 1
                            continue
                        article["reasons"].append(reason)
                    self.store.decision(
                        topic["name"],
                        article["id"],
                        profile_key,
                        "selected",
                        article["relevance_score"],
                        article["reasons"],
                    )
                    article = await self.prepare(
                        article, sources_by_url.get(article.get("source_url", "")), include
                    )
                    cache_key = self.summarizer.cache_key
                    if article.get("cached_summary") and article.get("summary_key") == cache_key:
                        summary = json.loads(article["cached_summary"])
                        metrics["cached"] += 1
                    else:
                        if progress:
                            await progress(f"Summarizing: {article['title'][:100]}")
                        summary = await self.summarizer.summarize_article(article)
                        self.store.cache_summary(article["id"], cache_key, json.dumps(summary))
                        metrics["summaries"] += 1
                    # Source identity and relevance are never taken from model output.
                    article["card"] = {
                        "art_id": article["id"],
                        "headline": article["title"][:160],
                        "url": article["link"],
                        "icon": "📰",
                        "severity": "low",
                        "summary": summary["summary"],
                        "evidence": summary["evidence"],
                        "relevance_reason": "; ".join(article["reasons"][:3]),
                        "content_kind": article["body_kind"],
                        "relevance_score": article["relevance_score"],
                    }
                    selected.append(article)
                except TranscriptPending as exc:
                    metrics["deferred"] = metrics.get("deferred", 0) + 1
                    logger.info("Article %s deferred: %s", article["id"][:12], exc)
                except Exception as exc:
                    metrics["failed"] += 1
                    self._generation_retry[article["id"]] = time.monotonic() + 300
                    logger.warning("Article %s remains pending: %s", article["id"][:12], exc)
                    if not isinstance(exc, ValueError):
                        break  # unavailable model: don't pay another timeout per article
            for destination, notify, channel in destinations:
                articles = [
                    a for a in selected if not self.store.reserved(reservations[destination], a)
                ]
                if not articles:
                    continue
                cards = [a["card"] for a in articles]
                body = {
                    "channel": channel,
                    "summary": json.dumps(
                        {
                            "overview": f"{len(cards)} stories selected for your interests.",
                            "items": cards,
                        }
                    ),
                    "meta": {
                        "top_stories_count": len(cards),
                        "compact": True,
                        "bare": urgent,
                        "preserve_order": True,
                        "images": list(
                            dict.fromkeys(
                                a["source_image_url"] for a in articles if a.get("source_image_url")
                            )
                        ),
                    },
                }
                owner = getattr(notify, "__self__", None)
                if owner is not None and hasattr(owner, "digest_payloads"):
                    body["payloads"] = owner.digest_payloads(
                        topic["name"], body["summary"], body["meta"]
                    )
                self.store.enqueue(destination, topic["name"], body, articles)
                metrics["queued"] += len(articles)
            metrics["seconds"] = round(time.time() - started, 3)
            self.store.record_run(topic["name"], started, metrics)
            logger.info("Digest run %s: %s", topic["name"], metrics)
        await self.flush(allowed=delivery_allowed)

    async def flush(self, force=False, allowed=None):
        async with self._delivery_lock:
            failed_destinations: set[str] = set()
            for row in self.store.pending(force=force):
                if allowed is not None and not allowed():
                    break
                if row["destination"] in failed_destinations:
                    continue
                platform = row["destination"].split(":", 1)[0]
                notify = None
                for index, candidate in enumerate(self.notifiers):
                    owner = getattr(candidate, "__self__", None)
                    name = getattr(owner, "platform_name", f"notifier-{index}")
                    if name == platform:
                        notify = candidate
                        break
                if notify is None:
                    continue  # retain pending rows when a platform is temporarily disabled
                body = json.loads(row["body"])
                meta = body["meta"] | {
                    "_delivery_id": row["id"],
                    "_offset": row["offset"],
                    "_ack": lambda offset, key=row["id"]: self.store.acknowledge(key, offset),
                }
                if "payloads" in body:
                    meta["_payloads"] = body["payloads"]
                try:
                    await notify(row["topic"], body["summary"], channel=body["channel"], meta=meta)
                    self.store.delivered(row["id"])
                except Exception as exc:
                    self.store.failed(row["id"], exc)
                    failed_destinations.add(row["destination"])
                    logger.warning("Delivery %s remains queued: %s", row["id"], exc)
