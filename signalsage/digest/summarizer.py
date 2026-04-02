"""LLM-powered digest summarizer."""

import asyncio
import logging
from datetime import date

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC
from signalsage.llm.base import BaseLLM

_LLM_RETRIES = 2
_LLM_RETRY_DELAY = 5  # seconds between retries

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are an analyst producing a structured news digest from pre-fetched source content.
The source content is provided below — you do not need to access the internet.

Return a single JSON object with these keys:

"tldr": array of 3-5 one-sentence strings summarising the most important signals across ALL sources. Highlight cross-cutting themes. Do not repeat individual story headlines verbatim.

"coverage_confidence": "high" (many sources, rich overlapping content), "medium" (some sources, patchy), or "low" (few sources, sparse/off-topic).

"items": array of 5-10 individual story objects, one per notable article. Each object has:
  "icon": ONE emoji chosen from this list — pick the closest match, NEVER leave empty:
    🔴 critical incident  🛡️ patch/fix  🦠 malware  🔗 phishing  📢 announcement
    🔍 research  ⚠️ advisory  📡 threat-intel  🏛️ policy/legal  📻 radio
    ☀️ space-weather  🤖 AI/ML/LLM  📰 general (use this if nothing else fits)
  "severity": "critical", "high", "medium", or "low"
  "headline": title from or based on the article, max 80 characters
  "blurb": 1-2 sentences — what happened and why it matters
  "url": copy the URL exactly from the "URL:" line in that article's source block. \
If that article has no "URL:" line, use null. Never fabricate a URL.

Rules:
- Output ONLY the JSON object. No markdown fences, no explanation, no extra text.
- Use ONLY content from the sources provided. Do not invent facts.
- Every "icon" field must contain one of the emoji above — empty string is not allowed.
- Every "url" must be copied verbatim from the source content or be null.
"""

_IOC_SYSTEM_PROMPT = (
    "You are a senior threat intelligence analyst. "
    "Given threat intelligence results for an indicator, write a concise 2-3 sentence assessment. "
    "State the overall verdict, what the indicator is associated with, and any recommended action. "
    "Be direct and factual. Do not repeat the raw numbers — interpret them."
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
        total_chars = 0
        skipped = 0
        for src in sources:
            content = src.get("content", "").strip()
            if not content:
                continue
            block = f"### {src['name']}\n{content}\nSource: {src['url']}\n"
            if total_chars + len(block) > self.max_total_chars:
                skipped += 1
                continue
            source_blocks.append(block)
            total_chars += len(block)
        if skipped:
            logger.info(
                "Topic '%s': skipped %d source(s) — total content would exceed %d chars",
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
                return await self.llm.complete(
                    system=_SYSTEM_PROMPT, user=user_prompt, max_tokens=2048
                )
            except Exception as exc:
                if attempt < _LLM_RETRIES:
                    logger.warning(
                        "LLM error for topic %s (attempt %d/%d): %s — retrying in %ds",
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

        # All retries exhausted — produce a minimal fallback from raw headlines
        return self._fallback_summary(source_blocks)

    def _fallback_summary(self, source_blocks: list[str]) -> str:
        """
        Return a minimal plain-text summary built from raw source headlines
        when the LLM is unavailable.  Extracts the first line of each source
        block (the ### Source Name heading) so users still see what was fetched.
        """
        lines = ["⚠️ LLM summary unavailable — showing raw source headlines:\n"]
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
                lines.append(f"- {r.provider}: error — {r.error}")
            else:
                verdict = (
                    "MALICIOUS"
                    if r.malicious is True
                    else "CLEAN"
                    if r.malicious is False
                    else "UNKNOWN"
                )
                lines.append(f"- {r.provider}: {verdict} — {r.summary or 'no details'}")

        label = ioc.type.value.upper()
        user_prompt = (
            f"Indicator: {ioc.value} ({label})\n\nThreat intelligence results:\n" + "\n".join(lines)
        )
        try:
            return await self.llm.complete(system=_IOC_SYSTEM_PROMPT, user=user_prompt)
        except Exception as exc:
            logger.error("LLM error summarizing IOC %s: %s", ioc.value, exc)
            return f"⚠️ Assessment unavailable — {exc}"
