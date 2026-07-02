"""LLM-powered digest summarizer."""

import asyncio
import json
import logging
import re
import time
from datetime import date
from urllib.parse import urlparse

from cachetools import TTLCache

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC
from signalsage.llm.base import BaseLLM, LLMRateLimitError

_LLM_RETRIES = 2
_LLM_RETRY_DELAY = 5  # seconds between retries
_URL_MATCH_THRESHOLD = 0.20  # minimum Jaccard similarity to inject a URL

logger = logging.getLogger(__name__)

_PUNCT_RE = re.compile(r"[^\w\s]")
# Stamps each "Title: ..." line in fetched source content with an [A<N>] article ID.
# Compiled once at module load instead of per topic-run.
_TITLE_LINE_RE = re.compile(
    r"^Title:\s*(.+)\n(URL:\s*https?://[^\s<>|\"'`{}\\^]+)?",
    re.MULTILINE,
)
_INLINE_URL_RE = re.compile(r"URL:\s*(https?://[^\s<>|\"'`{}\\^]+)")

# A URL coming from an attacker-influenced source (a feed entry, an LLM hallucination)
# can contain characters like "|" or "<" that break Slack's <url|label> link syntax
# or Discord embed boundaries — letting a crafted feed point a "Read More" button at
# one URL while displaying another. These chars are illegal in well-formed URLs anyway.
_UNSAFE_URL_CHARS = set("|<>\"'`{}\\^")


def _safe_url(url: str | None) -> str | None:
    """Return *url* if it is an http(s) URL with a host and no message-formatting
    metacharacters; otherwise None. Used to validate URLs from third-party content."""
    if not url:
        return None
    url = url.strip().rstrip(".,;)")
    if any(c in url for c in _UNSAFE_URL_CHARS):
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return None
    return url


def _jaccard(a: str, b: str) -> float:
    wa = set(_PUNCT_RE.sub("", a.lower()).split())
    wb = set(_PUNCT_RE.sub("", b.lower()).split())
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


def _decode_url_encoded_json(text: str) -> str:
    """Decode structural characters that some LLMs URL-encode after URL values."""
    for enc, char in [("%7B", "{"), ("%7D", "}"), ("%5B", "["), ("%5D", "]")]:
        text = re.sub(enc, char, text, flags=re.IGNORECASE)
    return text


def _inject_urls(
    raw_json: str,
    url_map: dict[str, str],
    title_url_pairs: list[tuple[str, str]],
) -> str:
    """
    Post-process LLM JSON: resolve URLs from article IDs and/or title matching.

    Priority:
    1. LLM already returned a valid http URL — keep it.
    2. LLM returned an art_id (e.g. "A3") — look up in url_map.
    3. Fallback: Jaccard title match against title_url_pairs.
    """
    text = _decode_url_encoded_json(raw_json)

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Full parse failed (truncated JSON) — inject URLs into individual item objects in-place.
        if not url_map and not title_url_pairs:
            return raw_json

        def _fix_item(m: re.Match) -> str:
            try:
                obj = json.loads(m.group(0))
            except (json.JSONDecodeError, ValueError):
                return m.group(0)
            existing = _safe_url(str(obj.get("url") or ""))
            if existing:
                obj["url"] = existing
                return json.dumps(obj)
            obj["url"] = ""  # drop tainted/invalid URL before fallback lookup
            art_id = re.split(
                r"[,\s]+", re.sub(r"[\[\]]", "", str(obj.get("art_id") or "")).strip().upper()
            )[0]
            if art_id and art_id in url_map:
                obj["url"] = url_map[art_id]
                return json.dumps(obj)
            headline = str(obj.get("headline") or "")
            best_url, best_score = "", 0.0
            for title, url in title_url_pairs:
                score = _jaccard(headline, title)
                if score > best_score:
                    best_score, best_url = score, url
            if best_score >= _URL_MATCH_THRESHOLD and best_url:
                obj["url"] = best_url
            return json.dumps(obj)

        return re.sub(r'\{[^{}]*"art_id"[^{}]*\}', _fix_item, text, flags=re.DOTALL)

    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return raw_json

    injected = 0
    no_url = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        existing = _safe_url(str(item.get("url") or ""))
        if existing:
            item["url"] = existing  # normalise (strip trailing punctuation)
            continue
        # Drop any URL the LLM emitted that didn't pass _safe_url so we don't
        # propagate a tainted URL into the rendered card.
        if item.get("url"):
            item["url"] = ""

        # Try art_id lookup — normalise brackets/case and take first id if LLM emits "A1, A3"
        art_id_raw = re.sub(r"[\[\]]", "", str(item.get("art_id") or "")).strip().upper()
        art_id = re.split(r"[,\s]+", art_id_raw)[0].strip() if art_id_raw else ""
        if art_id and art_id in url_map:
            item["url"] = url_map[art_id]
            injected += 1
            continue

        # Jaccard title fallback
        headline = str(item.get("headline") or "")
        best_url, best_score = "", 0.0
        for title, url in title_url_pairs:
            if not url:
                continue
            score = _jaccard(headline, title)
            if score > best_score:
                best_score, best_url = score, url
        if best_score >= _URL_MATCH_THRESHOLD and best_url:
            item["url"] = best_url
            injected += 1
        else:
            no_url += 1
            logger.info(
                "No URL resolved for item art_id=%r headline=%r (best_jaccard=%.2f, url_map=%d keys)",
                art_id,
                headline[:60],
                best_score,
                len(url_map),
            )

    if injected:
        logger.info("URL injection: filled %d missing URL(s)", injected)
    if no_url:
        logger.warning("URL injection: %d item(s) have no URL after all fallbacks", no_url)
    return json.dumps(data)


def _build_system_prompt(interest_topics: list[str]) -> str:
    """Build the LLM system prompt, optionally injecting interest topic hints."""
    interest_section = ""
    if interest_topics:
        topics_str = ", ".join(f'"{t}"' for t in interest_topics)
        interest_section = (
            f"\nTopics of high interest to prioritise: {topics_str}. "
            "Rank items most relevant to these topics higher in the items array.\n"
        )
    return f"""\
You are a broadcast news anchor delivering a spoken news bulletin to your audience. \
Write everything the way it would be READ ALOUD on air — natural, conversational, in the \
active voice, with smooth transitions between ideas. Never write a dry list, a bullet blob, \
or telegraphic notes. Produce a single JSON object with EXACTLY these keys.

STEP 1 — Write "overview" first: your on-air opening. A flowing 3-5 sentence paragraph that \
welcomes the audience and walks them through the major themes and biggest developments across \
ALL sources, the way an anchor opens a bulletin ("In today's top stories...", "We begin with..."). \
Never reference a time of day ("tonight", "this morning", "this evening") — the bulletin may be \
read at any hour; say "today" or nothing at all. \
Synthesise across stories and connect them — do not just read headlines back. This field is \
REQUIRED and must never be null, empty, or a single sentence.

STEP 2 — Set "coverage_confidence": "high" (many rich sources), "medium" (some sources, patchy), \
or "low" (few or sparse sources).

STEP 3 — Build "items": an array of up to 20 story objects, most important first. \
Each object MUST have all of these fields:
  "art_id": the [A<N>] label for this article (e.g. "A3"). REQUIRED.
  "icon": exactly ONE emoji. Choose the closest: \
🔴=critical  🛡️=patch  🦠=malware  🔗=phishing  📢=announcement  🔍=research  \
⚠️=advisory  📡=threat-intel  🏛️=policy  📻=radio  ☀️=space  🤖=AI  📰=general
  "severity": "critical", "high", "medium", or "low"
  "headline": max 80 characters
  "summary": REQUIRED — read this story aloud the way a news anchor would: 3-5 full sentences, \
conversational and in the active voice, telling the audience what happened, the key details, \
and why it matters to them. Lead with the news, not background. A single sentence, a bare list \
of facts, or copy-pasted feed text is NOT acceptable.
  "url": copy verbatim from the article's URL line; if no per-article URL exists, use the "Source URL:" from the same source block header.
{interest_section}
STRICT RULES — you will be penalised for breaking these:
- Output ONLY the raw JSON object. No markdown fences, no code blocks, no explanation.
- Write in a spoken broadcast-anchor voice throughout — conversational, active voice, flowing prose.
- Never mention a time of day ("tonight", "this morning", "this evening") anywhere in the output.
- "overview" MUST be a non-empty paragraph. Never return null or "".
- Every item "summary" MUST be 3-5 sentences. Never return one sentence.
- Use ONLY content from the sources provided. Do not invent facts or URLs.
- "art_id" must match an [A<N>] label in the source content.
- "url" must be copied verbatim — do not paraphrase or shorten.
"""


# JSON schema enforced via Ollama structured outputs. Plain "json" mode only
# guarantees syntactic validity — a small model can legally emit
# {"overview": "..."} and stop, which is exactly the overview-only failure seen
# with phi3:mini. Required keys force the "items" array to be generated.
_DIGEST_JSON_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "overview": {"type": "string"},
        "coverage_confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "items": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "properties": {
                    "art_id": {"type": "string"},
                    "icon": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "headline": {"type": "string"},
                    "summary": {"type": "string"},
                    "url": {"type": "string"},
                },
                "required": ["art_id", "icon", "severity", "headline", "summary", "url"],
            },
        },
    },
    "required": ["overview", "coverage_confidence", "items"],
}


def _lacks_story_items(raw: str) -> bool:
    """True when an LLM response contains no story items at all.

    An overview-only object (missing "items") or JSON truncated before the first
    complete item is worth retrying. An explicit "items": [] or a truncated
    response that still holds salvageable item objects is not.
    """
    text = raw.strip()
    text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
    text = re.sub(r"\s*```$", "", text).strip()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        # Unparseable (likely truncated) — the formatter can salvage complete
        # item objects, so only retry when none survived.
        return not re.search(r'\{[^{}]*"art_id"[^{}]*\}', text, re.DOTALL)
    if isinstance(data, list):
        return not any(isinstance(i, dict) for i in data)
    if isinstance(data, dict):
        return not isinstance(data.get("items"), list)
    return True


_IOC_SYSTEM_PROMPT = (
    "You are a senior threat intelligence analyst. "
    "Given threat intelligence results for an indicator, write a concise 2-3 sentence assessment. "
    "State the overall verdict, what the indicator is associated with, and any recommended action. "
    "Be direct and factual. Do not repeat the raw numbers - interpret them."
)


class DigestSummarizer:
    """Fetches topic sources and summarizes them using a configured LLM."""

    def __init__(
        self,
        llm: BaseLLM,
        max_chars: int = 3000,
        max_total_chars: int = 20000,
        interest_topics: list[str] | None = None,
        ioc_assessment_cache_ttl: int = 3600,
        ioc_assessment_capacity: int = 30,
        ioc_assessment_refill_per_sec: float = 0.5,
    ) -> None:
        self.llm = llm
        self.max_chars = max_chars
        self.max_total_chars = max_total_chars
        self.interest_topics: list[str] = interest_topics or []
        # IOC assessments are cached identically to intel results so a re-posted IOC
        # doesn't re-spend LLM tokens. The token-bucket caps the burst rate of LLM
        # calls so a user dumping fresh IOCs cannot run up an unbounded API bill.
        self._ioc_cache: TTLCache = TTLCache(maxsize=500, ttl=ioc_assessment_cache_ttl)
        self._ioc_bucket_capacity = float(ioc_assessment_capacity)
        self._ioc_bucket_refill = float(ioc_assessment_refill_per_sec)
        self._ioc_bucket = self._ioc_bucket_capacity
        self._ioc_bucket_last = time.monotonic()

    async def summarize_topic(
        self, topic_name: str, sources: list[dict], lookback: str | None = None
    ) -> str:
        today = date.today().strftime("%B %d, %Y")

        source_blocks: list[str] = []
        url_map: dict[str, str] = {}  # art_id → url  (e.g. "A3" → "https://...")
        title_url_pairs: list[tuple[str, str]] = []  # Jaccard fallback
        art_counter = 0
        total_chars = 0
        skipped = 0
        for src in sources:
            content = src.get("content", "").strip()
            if not content:
                continue

            # Stamp each "Title: ..." line with a unique article ID and record its URL.
            # Regex captures just the headline text (group 1) without the "Title: " prefix
            # so that title_url_pairs stores clean titles for Jaccard matching.
            def _stamp_article(m: re.Match) -> str:
                nonlocal art_counter
                art_counter += 1
                art_id = f"A{art_counter}"
                headline = m.group(1).strip()
                url_line = m.group(2) or ""
                # Restrict to URL-safe chars so a crafted feed cannot smuggle "|" or "<"
                # into the captured URL (would later break Slack <url|label> boundaries).
                url_match = _INLINE_URL_RE.search(url_line)
                if url_match:
                    safe = _safe_url(url_match.group(1))
                    if safe:
                        url_map[art_id] = safe
                        title_url_pairs.append((headline, safe))
                return f"[{art_id}] Title: {headline}\n{url_line}"

            labelled = _TITLE_LINE_RE.sub(_stamp_article, content)

            block = f"### {src['name']}\nSource URL: {src['url']}\n{labelled}\n"
            if total_chars + len(block) > self.max_total_chars:
                skipped += 1
                continue
            source_blocks.append(block)
            total_chars += len(block)
        if skipped:
            logger.info(
                "Topic '%s': skipped %d source(s) - total content would exceed %d chars",
                topic_name,
                skipped,
                self.max_total_chars,
            )

        logger.info(
            "Topic '%s': %d articles labelled, %d have URLs (url_map)",
            topic_name,
            art_counter,
            len(url_map),
        )

        if not source_blocks:
            window = f"the last {lookback}" if lookback else today
            return f"No content found for {topic_name} covering {window}."

        window_phrase = f"from the last {lookback}" if lookback else f"for {today}"
        user_prompt = (
            f"The following content has been pre-fetched for you from {topic_name} sources "
            f"{window_phrase}. Summarize it.\n"
            + (
                f"Focus only on items published in the last {lookback}. Skip older content.\n"
                if lookback
                else ""
            )
            + "\n--- BEGIN CONTENT ---\n"
            + "\n".join(source_blocks)
            + "\n--- END CONTENT ---"
        )

        last_exc: Exception | None = None
        for attempt in range(1 + _LLM_RETRIES):
            try:
                raw = await self.llm.complete(
                    system=_build_system_prompt(self.interest_topics),
                    user=user_prompt,
                    max_tokens=4096,
                    json_mode=True,
                    json_schema=_DIGEST_JSON_SCHEMA,
                )
                logger.debug("LLM raw output for topic %r: %s", topic_name, raw[:500])
                if _lacks_story_items(raw):
                    # Small local models sometimes stop after the overview even in
                    # JSON mode. Retry immediately (no sleep — the LLM call itself
                    # provides pacing); on the last attempt return what we have so
                    # the formatter can render the overview instead of raw JSON.
                    if attempt < _LLM_RETRIES:
                        logger.warning(
                            "LLM returned no story items for topic %s (attempt %d/%d) - retrying",
                            topic_name,
                            attempt + 1,
                            1 + _LLM_RETRIES,
                        )
                        continue
                    logger.warning(
                        "LLM returned no story items for topic %s after %d attempts - "
                        "rendering overview only",
                        topic_name,
                        1 + _LLM_RETRIES,
                    )
                return _inject_urls(raw, url_map, title_url_pairs)
            except LLMRateLimitError as exc:
                # A quota reset is minutes/hours away — retrying now just burns
                # attempts and log noise. Stop and surface the message to the user.
                last_exc = exc
                logger.error("LLM usage limit hit for topic %s; not retrying: %s", topic_name, exc)
                break
            except Exception as exc:
                last_exc = exc
                if attempt < _LLM_RETRIES:
                    logger.warning(
                        "LLM error for topic %s (attempt %d/%d): %s - retrying in %ds",
                        topic_name,
                        attempt + 1,
                        1 + _LLM_RETRIES,
                        exc,
                        _LLM_RETRY_DELAY,
                    )
                    await asyncio.sleep(_LLM_RETRY_DELAY)
                else:
                    logger.error(
                        "LLM error for topic %s after %d attempt(s): %s",
                        topic_name,
                        1 + _LLM_RETRIES,
                        exc,
                        exc_info=True,
                    )

        # All retries exhausted - produce a minimal fallback from raw headlines
        return self._fallback_summary(source_blocks, last_exc, 1 + _LLM_RETRIES)

    def _fallback_summary(
        self,
        source_blocks: list[str],
        error: Exception | None = None,
        attempts: int = 1,
    ) -> str:
        """
        Return a minimal plain-text summary built from raw source headlines
        when the LLM is unavailable.
        """
        if isinstance(error, LLMRateLimitError):
            # Clear, actionable header (includes any "try again at …" reset time)
            # instead of the generic retry-exhausted wording.
            header = f"⚠️ LLM usage limit reached: {error} — showing headlines only:\n"
        else:
            attempt_str = f" after {attempts} attempt{'s' if attempts != 1 else ''}"
            error_detail = f": {error}" if error else ""
            header = f"⚠️ LLM unavailable{attempt_str}{error_detail} — headlines only:\n"
        lines = [header]
        for block in source_blocks:
            source_name = None
            headlines: list[str] = []
            for line in block.splitlines():
                line = line.strip()
                if line.startswith("### "):
                    source_name = line[4:]
                elif re.match(r"^\[A\d+\] Title:", line):
                    headlines.append(re.sub(r"^\[A\d+\] Title:\s*", "", line))
            if source_name:
                lines.append(f"\n*{source_name}*")
            for h in headlines:
                lines.append(f"  • {h}")
        return "\n".join(lines)

    def _take_ioc_token(self) -> bool:
        """Consume one token from the IOC-assessment bucket. Returns False if empty."""
        now = time.monotonic()
        elapsed = now - self._ioc_bucket_last
        self._ioc_bucket_last = now
        self._ioc_bucket = min(
            self._ioc_bucket_capacity, self._ioc_bucket + elapsed * self._ioc_bucket_refill
        )
        if self._ioc_bucket >= 1.0:
            self._ioc_bucket -= 1.0
            return True
        return False

    @staticmethod
    def _ioc_cache_key(ioc: IOC, results: list[IntelResult]) -> tuple:
        """Build a cache key from the IOC plus a fingerprint of every provider's verdict."""
        sig = tuple(sorted((r.provider, r.malicious, r.score, bool(r.error)) for r in results))
        return (ioc.value, ioc.type.value, sig)

    async def summarize_ioc(self, ioc: IOC, results: list[IntelResult]) -> str:
        """Generate a plain-English assessment of an IOC from its enrichment results."""
        cache_key = self._ioc_cache_key(ioc, results)
        cached = self._ioc_cache.get(cache_key)
        if cached is not None:
            return cached

        if not self._take_ioc_token():
            logger.warning(
                "IOC assessment rate-limited (token bucket empty); skipping LLM call for %s",
                ioc.value,
            )
            return "⚠️ Assessment rate-limited — try again in a moment."

        lines: list[str] = []
        for r in results:
            if r.error:
                lines.append(f"- {r.provider}: error - {r.error}")
            else:
                verdict = (
                    "MALICIOUS"
                    if r.malicious is True
                    else "CLEAN"
                    if r.malicious is False
                    else "UNKNOWN"
                )
                lines.append(f"- {r.provider}: {verdict} - {r.summary or 'no details'}")

        label = ioc.type.value.upper()
        user_prompt = (
            f"Indicator: {ioc.value} ({label})\n\nThreat intelligence results:\n" + "\n".join(lines)
        )
        try:
            text = await self.llm.complete(system=_IOC_SYSTEM_PROMPT, user=user_prompt)
        except Exception as exc:
            logger.error("LLM error summarizing IOC %s: %s", ioc.value, exc)
            return f"⚠️ Assessment unavailable - {exc}"

        self._ioc_cache[cache_key] = text
        return text
