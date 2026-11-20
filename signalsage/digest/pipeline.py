"""Article collection, selection, enrichment and durable delivery orchestration."""

import asyncio
import json
import logging
import re
import time

from signalsage.ioc.models import IOC, IOCType
from signalsage.llm.base import LLMRateLimitError

from . import reddit
from .collection import collect_source, fetch_article_text
from .fetcher import _transcribe_audio, clean_title, parse_lookback
from .ranking import contains, fingerprint, score_article, similar_story
from .store import ArticleStore
from .summarizer import SummaryValidationError, excerpt_summary
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
        transcriber=None,
        settings=None,
    ):
        self.summarizer = summarizer
        self.notifiers = notifiers
        self.store = store
        self.keywords = keywords
        self.profile = profile or {}
        self.processor = processor
        # async (path, mime) -> transcript, e.g. GeminiLLM.transcribe; None = off.
        self.transcriber = transcriber
        self.settings = settings or {}
        # Topics whose queued posts are delivered even outside active hours.
        self.always_deliver: set[str] = set()
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
                if await self.store.acall("checkpoint", topic["name"], source["url"]) is None:
                    seconds = (
                        parse_lookback(topic.get("lookback"))
                        or int(self.settings.get("bootstrap_days", 7)) * 86400
                    )
                    cutoff = time.time() - seconds
                added += await self.store.acall(
                    "ingest", topic["name"], source, items, error, bootstrap_cutoff=cutoff
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
        elif article.get("audio_url") and self.transcriber and not published_url:
            transcript = await _transcribe_audio(article["audio_url"], self.transcriber)
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
        await self.store.acall("cache_content", article["id"], body, kind, enrichment)
        article.update(body=body, body_kind=kind, enrichment=enrichment)
        return article

    @staticmethod
    def _card(article: dict, summary: dict) -> dict:
        # Source identity and relevance are never taken from model output.
        return {
            "art_id": article["id"],
            # Cleaned again here: articles stored before titles
            # were cleaned at fetch time can still hold markup.
            "headline": clean_title(article["title"])[:160],
            "url": article["link"],
            "icon": "📰",
            "severity": "low",
            "summary": summary["summary"],
            "evidence": summary["evidence"],
            "relevance_reason": "; ".join(article["reasons"][:3]),
            "content_kind": (
                f"quoted excerpt of {article['body_kind']}"
                if summary.get("fallback")
                else article["body_kind"]
            ),
            "relevance_score": article["relevance_score"],
        }

    @property
    def _batch_size(self) -> int:
        try:
            return max(1, int(getattr(self.summarizer, "batch_size", 1) or 1))
        except (TypeError, ValueError):
            return 1

    async def _judge_all(self, articles: list[dict], profile: dict) -> dict:
        """{art_id: (relevant, reason) | Exception} for borderline articles.

        Batched backends judge up to batch_size articles per call; otherwise one
        call each. A non-ValueError (model down, quota gone) is recorded for every
        remaining article instead of paying another failed call per article.
        """
        out: dict = {}
        size = self._batch_size
        if size > 1:
            for start in range(0, len(articles), size):
                chunk = articles[start : start + size]
                try:
                    out.update(await self.summarizer.judge_relevance_batch(chunk, profile))
                except Exception as exc:
                    rest = chunk if isinstance(exc, ValueError) else articles[start:]
                    out.update({a["id"]: exc for a in rest})
                    if not isinstance(exc, ValueError):
                        break
            return out
        for index, article in enumerate(articles):
            try:
                out[article["id"]] = await self.summarizer.judge_relevance(article, profile)
            except Exception as exc:
                if isinstance(exc, ValueError):
                    out[article["id"]] = exc
                    continue
                out.update({a["id"]: exc for a in articles[index:]})
                break
        return out

    async def _summarize_all(self, articles: list[dict], profile: dict, include) -> dict:
        """{art_id: summary dict | Exception}, batched when the backend allows it."""
        size = self._batch_size
        if size > 1:
            interests = list(dict.fromkeys([*(profile.get("topics") or {}), *(include or [])]))
            out: dict = {}
            for start in range(0, len(articles), size):
                chunk = articles[start : start + size]
                out.update(await self.summarizer.summarize_batch(chunk, interests))
                fatal = [
                    r
                    for r in out.values()
                    if isinstance(r, Exception) and not isinstance(r, ValueError)
                ]
                if fatal:
                    out.update({a["id"]: fatal[0] for a in articles[start + size :]})
                    break
            return out
        out = {}
        for index, article in enumerate(articles):
            try:
                out[article["id"]] = await self.summarizer.summarize_article(article)
            except Exception as exc:
                if isinstance(exc, ValueError):
                    out[article["id"]] = exc
                    continue
                # Unavailable model: don't pay another timeout per article.
                out.update({a["id"]: exc for a in articles[index:]})
                break
        return out

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
            feedback = await self.store.acall("feedback_weights")
            profile_key = fingerprint([profile, include, exclude, feedback])
            candidates = await self.store.acall(
                "candidates",
                topic["name"],
                profile_key,
                max_age_days=float(self.settings.get("max_article_age_days", 8)),
            )
            metrics["candidates"] = len(candidates)
            # Safe to snapshot: _publish_lock serialises every enqueue.
            reservations = {
                dest: await self.store.acall("reservations", dest) for dest, _, _ in destinations
            }
            ranked = []
            for article in candidates:
                if all(self.store.reserved(reservations[dest], article) for dest in reservations):
                    metrics["deduplicated"] += 1
                    continue
                score, reasons, veto = score_article(
                    article, profile, include, exclude, feedback, open_topic=not include
                )
                if veto or score <= 0:
                    await self.store.acall(
                        "decision",
                        topic["name"],
                        article["id"],
                        profile_key,
                        "rejected",
                        score,
                        reasons,
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
            tried: set[str] = set()
            # Bound model work even when a feed or first-install backlog is large:
            # at most top_n * 2 distinct stories are considered per run.
            window: list[dict] = []
            for article in ranked:
                if len(window) >= top_n * 2:
                    break
                if any(similar_story(article, other) for other in window):
                    metrics["deduplicated"] += 1
                    continue
                if time.monotonic() < self._generation_retry.get(article["id"], 0):
                    continue
                window.append(article)
            borderline = [a for a in window if a["relevance_score"] < threshold]
            verdicts = (
                await self._judge_all(borderline, {**profile, "keywords": include})
                if borderline
                else {}
            )
            awaiting: list[dict] = []  # selected, still needing a model summary
            cache_key = self.summarizer.cache_key
            for article in window:
                if len(selected) >= top_n:
                    break
                tried.add(article["id"])
                try:
                    if article["relevance_score"] < threshold:
                        verdict = verdicts.get(article["id"]) or ValueError("No relevance verdict")
                        if isinstance(verdict, Exception):
                            raise verdict
                        relevant, reason = verdict
                        if not relevant:
                            await self.store.acall(
                                "decision",
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
                    await self.store.acall(
                        "decision",
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
                    if article.get("cached_summary") and article.get("summary_key") == cache_key:
                        article["card"] = self._card(article, json.loads(article["cached_summary"]))
                        metrics["cached"] += 1
                    else:
                        awaiting.append(article)
                    selected.append(article)
                except TranscriptPending as exc:
                    metrics["deferred"] = metrics.get("deferred", 0) + 1
                    logger.info("Article %s deferred: %s", article["id"][:12], exc)
                except Exception as exc:
                    metrics["failed"] += 1
                    self._generation_retry[article["id"]] = time.monotonic() + 300
                    logger.warning("Article %s remains pending: %s", article["id"][:12], exc)
            if awaiting:
                if progress:
                    titles = "; ".join(a["title"][:60] for a in awaiting[:3])
                    await progress(f"Summarizing {len(awaiting)}: {titles}")
                results = await self._summarize_all(awaiting, profile, include)
                for article in awaiting:
                    result = results.get(article["id"]) or RuntimeError("No summary produced")
                    try:
                        if isinstance(result, SummaryValidationError):
                            # At temperature 0 a retry fails identically, so post a
                            # verbatim excerpt instead. It's cached under this
                            # model/prompt key; a model change gets a fresh attempt.
                            logger.info("Article %s: %s; quoting it", article["id"][:12], result)
                            summary = excerpt_summary(article)
                            metrics["quoted"] = metrics.get("quoted", 0) + 1
                        elif isinstance(result, LLMRateLimitError):
                            # Out of model quota: post the story as a quoted excerpt
                            # now rather than holding it. Not cached, so a later
                            # selection under a fresh quota can still summarise it.
                            logger.warning("Article %s: %s; quoting it", article["id"][:12], result)
                            article["card"] = self._card(article, excerpt_summary(article))
                            metrics["quoted"] = metrics.get("quoted", 0) + 1
                            continue
                        elif isinstance(result, Exception):
                            raise result
                        else:
                            summary = result
                            metrics["summaries"] += 1
                        await self.store.acall(
                            "cache_summary", article["id"], cache_key, json.dumps(summary)
                        )
                        article["card"] = self._card(article, summary)
                    except Exception as exc:
                        metrics["failed"] += 1
                        self._generation_retry[article["id"]] = time.monotonic() + 300
                        selected.remove(article)
                        logger.warning("Article %s remains pending: %s", article["id"][:12], exc)
            # The next-best confident matches ride along as headline-only links:
            # no model work, and once shown they count as delivered.
            headline_count = (
                0
                if urgent
                else int(topic.get("headline_count", self.settings.get("headline_count", 5)))
            )
            headlines: list[dict] = []
            for article in ranked:
                if len(headlines) >= headline_count:
                    break
                if (
                    article["id"] in tried
                    or article["relevance_score"] < threshold
                    or any(similar_story(article, other) for other in selected + headlines)
                ):
                    continue
                headlines.append(article)
            for destination, notify, channel in destinations:
                articles = [
                    a for a in selected if not self.store.reserved(reservations[destination], a)
                ]
                if not articles:
                    continue
                extras = [
                    a for a in headlines if not self.store.reserved(reservations[destination], a)
                ]
                cards = [a["card"] for a in articles]
                body = {
                    "channel": channel,
                    "summary": json.dumps(
                        {
                            "overview": f"{len(cards)} stories selected for your interests.",
                            "items": cards,
                            "more": [
                                {"headline": clean_title(a["title"])[:160], "url": a["link"]}
                                for a in extras
                            ],
                        }
                    ),
                    "meta": {
                        "top_stories_count": len(cards),
                        "compact": True,
                        # Every story in ONE message, numbered in this order.
                        "combined": True,
                        "bare": urgent,
                        "preserve_order": True,
                        "articles": [a["id"] for a in articles],
                        "seed_votes": bool(self.settings.get("seed_vote_reactions", True)),
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
                await self.store.acall(
                    "enqueue", destination, topic["name"], body, articles + extras
                )
                metrics["queued"] += len(articles)
                metrics["headlines"] = len(extras)
            metrics["seconds"] = round(time.time() - started, 3)
            await self.store.acall("record_run", topic["name"], started, metrics)
            logger.info("Digest run %s: %s", topic["name"], metrics)
        await self.flush(allowed=delivery_allowed)

    def _record_message(self, platform: str, message: str, meta: dict, index: int) -> None:
        articles = meta.get("articles") or []
        try:
            if meta.get("combined"):
                if index == 0:
                    for position, article in enumerate(articles, 1):
                        self.store.record_story(platform, message, position, article)
            elif index < len(articles):
                self.store.record_message(platform, message, articles[index])
        except Exception as exc:  # never fail (and so re-post) a delivered message
            logger.warning("Could not record story message %s: %s", message, exc)

    async def flush(self, force=False, allowed=None):
        async with self._delivery_lock:
            failed_destinations: set[str] = set()
            for row in await self.store.acall("pending", force=force):
                if (
                    allowed is not None
                    and row["topic"] not in self.always_deliver
                    and not allowed()
                ):
                    continue
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
                    "_sent": lambda index, message, platform=platform, meta=body["meta"]: (
                        self._record_message(platform, message, meta, index)
                    ),
                }
                if "payloads" in body:
                    meta["_payloads"] = body["payloads"]
                try:
                    await notify(row["topic"], body["summary"], channel=body["channel"], meta=meta)
                    await self.store.acall("delivered", row["id"])
                except Exception as exc:
                    await self.store.acall("failed", row["id"], exc)
                    failed_destinations.add(row["destination"])
                    logger.warning(
                        "Delivery %s remains queued: %s: %s", row["id"], type(exc).__name__, exc
                    )
