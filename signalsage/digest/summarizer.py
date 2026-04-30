"""LLM-powered digest summarizer."""

import asyncio
import json
import logging
import re
from datetime import date

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC
from signalsage.llm.base import BaseLLM

_LLM_RETRIES = 2
_LLM_RETRY_DELAY = 5  # seconds between retries
_URL_MATCH_THRESHOLD = 0.20  # minimum Jaccard similarity to inject a URL

logger = logging.getLogger(__name__)

_PUNCT_RE = re.compile(r"[^\w\s]")


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
        return raw_json

    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return raw_json

    injected = 0
    no_url = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        existing = str(item.get("url") or "").strip()
        if existing.startswith("http"):
            continue  # already have a good URL

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
You are a news digest analyst. Produce a single JSON object with EXACTLY these keys.

STEP 1 — Write "overview" first: a flowing 3-5 sentence paragraph that summarises the major \
themes and most important developments across ALL sources. This field is REQUIRED and must never \
be null, empty, or a single sentence. Write it as a news editor would: synthesise across stories, \
do not just list headlines.

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
  "summary": REQUIRED — write 3-5 full sentences covering what happened, the key details, \
and why it matters. A single sentence is NOT acceptable.
  "url": copy verbatim from the article's URL line, or null if none.
{interest_section}
STRICT RULES — you will be penalised for breaking these:
- Output ONLY the raw JSON object. No markdown fences, no code blocks, no explanation.
- "overview" MUST be a non-empty paragraph. Never return null or "".
- Every item "summary" MUST be 3-5 sentences. Never return one sentence.
- Use ONLY content from the sources provided. Do not invent facts or URLs.
- "art_id" must match an [A<N>] label in the source content.
- "url" must be copied verbatim — do not paraphrase or shorten.
"""


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
    ) -> None:
        self.llm = llm
        self.max_chars = max_chars
        self.max_total_chars = max_total_chars
        self.interest_topics: list[str] = interest_topics or []

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
                url = re.search(r"URL:\s*(https?://\S+)", url_line)
                if url:
                    url_map[art_id] = url.group(1)
                    title_url_pairs.append((headline, url.group(1)))
                return f"[{art_id}] Title: {headline}\n{url_line}"

            labelled = re.sub(
                r"^Title:\s*(.+)\n(URL:\s*https?://\S+)?",
                _stamp_article,
                content,
                flags=re.MULTILINE,
            )

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
                )
                logger.debug("LLM raw output for topic %r: %s", topic_name, raw[:500])
                return _inject_urls(raw, url_map, title_url_pairs)
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
        attempt_str = f" after {attempts} attempt{'s' if attempts != 1 else ''}"
        error_detail = f": {error}" if error else ""
        lines = [f"⚠️ LLM unavailable{attempt_str}{error_detail} — headlines only:\n"]
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

    async def summarize_ioc(self, ioc: IOC, results: list[IntelResult]) -> str:
        """Generate a plain-English assessment of an IOC from its enrichment results."""
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
            return await self.llm.complete(system=_IOC_SYSTEM_PROMPT, user=user_prompt)
        except Exception as exc:
            logger.error("LLM error summarizing IOC %s: %s", ioc.value, exc)
            return f"⚠️ Assessment unavailable - {exc}"
