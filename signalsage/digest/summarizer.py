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
_URL_MATCH_THRESHOLD = 0.35  # minimum Jaccard similarity to inject a URL

logger = logging.getLogger(__name__)

_PUNCT_RE = re.compile(r"[^\w\s]")


def _jaccard(a: str, b: str) -> float:
    wa = set(_PUNCT_RE.sub("", a.lower()).split())
    wb = set(_PUNCT_RE.sub("", b.lower()).split())
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


def _inject_urls(raw_json: str, title_url_pairs: list[tuple[str, str]]) -> str:
    """
    Post-process LLM JSON: for any item with a null/missing URL, find the best
    matching source article by Jaccard title similarity and inject its URL.
    """
    if not title_url_pairs:
        return raw_json

    # Decode URL-encoded structural characters some LLMs emit after URL values
    text = raw_json
    for enc, char in [("%7B", "{"), ("%7D", "}"), ("%5B", "["), ("%5D", "]")]:
        text = re.sub(enc, char, text, flags=re.IGNORECASE)

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return raw_json

    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return raw_json

    injected = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        existing = str(item.get("url") or "").strip()
        if existing.startswith("http"):
            continue  # already has a URL
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

    if injected:
        logger.info("URL injection: filled %d missing URL(s) by title match", injected)
    return json.dumps(data)


_SYSTEM_PROMPT = """\
You are an analyst producing a structured news digest from pre-fetched source content.
The source content is provided below - you do not need to access the internet.

Return a single JSON object with these keys:

"tldr": array of 3-5 one-sentence strings summarising the most important signals across ALL sources. Highlight cross-cutting themes. Do not repeat individual story headlines verbatim.

"coverage_confidence": "high" (many sources, rich overlapping content), "medium" (some sources, patchy), or "low" (few sources, sparse/off-topic).

"items": array of 5-10 individual story objects, one per notable article. Each object has:
  "icon": ONE emoji character - output the emoji only, no words. Choose the closest match:
    🔴=critical-incident  🛡️=patch-or-fix  🦠=malware  🔗=phishing  📢=announcement
    🔍=research  ⚠️=advisory  📡=threat-intel  🏛️=policy-or-legal  📻=radio
    ☀️=space-weather  🤖=AI-or-ML  📰=general
  "severity": "critical", "high", "medium", or "low"
  "headline": title from or based on the article, max 80 characters
  "blurb": 1-2 sentences - what happened and why it matters
  "url": prefer the article URL copied from the "URL:" line that appears directly after the matching article's "Title:" line. If that article has no "URL:" line, fall back to the "Source URL:" line for that source block. If neither exists, use null. Never fabricate a URL.

Rules:
- Output ONLY the JSON object. No markdown fences, no explanation, no extra text.
- Use ONLY content from the sources provided. Do not invent facts.
- "icon" must be a single emoji character - never include any words after it.
- Every "url" must be copied verbatim from the source content or be null.
"""

_IOC_SYSTEM_PROMPT = (
    "You are a senior threat intelligence analyst. "
    "Given threat intelligence results for an indicator, write a concise 2-3 sentence assessment. "
    "State the overall verdict, what the indicator is associated with, and any recommended action. "
    "Be direct and factual. Do not repeat the raw numbers - interpret them."
)


class DigestSummarizer:
    """Fetches topic sources and summarizes them using a configured LLM."""

    def __init__(self, llm: BaseLLM, max_chars: int = 3000, max_total_chars: int = 20000) -> None:
        self.llm = llm
        self.max_chars = max_chars
        self.max_total_chars = max_total_chars

    async def summarize_topic(
        self, topic_name: str, sources: list[dict], lookback: str | None = None
    ) -> str:
        today = date.today().strftime("%B %d, %Y")

        source_blocks: list[str] = []
        title_url_pairs: list[tuple[str, str]] = []  # (title, url) for URL injection fallback
        total_chars = 0
        skipped = 0
        for src in sources:
            content = src.get("content", "").strip()
            if not content:
                continue
            block = f"### {src['name']}\nSource URL: {src['url']}\n{content}\n"
            if total_chars + len(block) > self.max_total_chars:
                skipped += 1
                continue
            source_blocks.append(block)
            total_chars += len(block)
            # Extract (title, url) pairs from feed content for fallback URL matching
            for m in re.finditer(r"^Title:\s*(.+)\nURL:\s*(https?://\S+)", content, re.MULTILINE):
                title_url_pairs.append((m.group(1).strip(), m.group(2).strip()))
        if skipped:
            logger.info(
                "Topic '%s': skipped %d source(s) - total content would exceed %d chars",
                topic_name,
                skipped,
                self.max_total_chars,
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

        for attempt in range(1 + _LLM_RETRIES):
            try:
                raw = await self.llm.complete(
                    system=_SYSTEM_PROMPT, user=user_prompt, max_tokens=2048
                )
                logger.debug("LLM raw output for topic %r: %s", topic_name, raw[:500])
                return _inject_urls(raw, title_url_pairs)
            except Exception as exc:
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
                    )

        # All retries exhausted - produce a minimal fallback from raw headlines
        return self._fallback_summary(source_blocks)

    def _fallback_summary(self, source_blocks: list[str]) -> str:
        """
        Return a minimal plain-text summary built from raw source headlines
        when the LLM is unavailable. Extracts the first line of each source
        block (the ### Source Name heading) so users still see what was fetched.
        """
        lines = ["⚠️ LLM summary unavailable - showing raw source headlines:\n"]
        for block in source_blocks:
            for line in block.splitlines():
                line = line.strip()
                if line.startswith("### "):
                    lines.append(f"• {line[4:]}")
                    break
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
