"""LLM-powered digest summarizer."""

import logging
from datetime import date

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC
from signalsage.llm.base import BaseLLM

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an analyst producing a structured news digest. "
    "The content below has already been fetched from the sources and is provided to you directly — "
    "you do not need to access the internet or any external URLs. "
    "Return a single JSON object with exactly these keys:\n"
    '  "tldr": an array of 3-5 short plain-text strings (one sentence each) synthesising the most '
    "important signals across ALL sources. Highlight cross-cutting themes or the single most critical "
    "items. Do not repeat individual story headlines verbatim.\n"
    '  "coverage_confidence": your assessment of how well the sources covered the topic — '
    'one of "high" (many sources responded with relevant, overlapping content), '
    '"medium" (some sources responded but coverage is patchy or thin), '
    '"low" (few sources responded, content is sparse or off-topic).\n'
    '  "items": an array of individual story objects. Each must have exactly these fields:\n'
    '    "icon": a single emoji representing the story type (MUST NOT be empty). '
    "Choose from: 🔴 critical/severe, 🛡️ patch/fix/defence, 🦠 malware/ransomware, "
    "🔗 phishing/scam, 📢 news/announcement, 🔍 research/report, ⚠️ warning/advisory, "
    "📡 threat intel, 🏛️ policy/legal/government, 📻 radio/propagation, ☀️ solar/space weather, "
    "🤖 AI/ML/LLM. Use 📰 as a fallback if none of the above fit.\n"
    '    "severity": your assessment of urgency/impact — one of "critical", "high", "medium", "low"\n'
    '    "headline": a short, clear title (max 80 characters)\n'
    '    "blurb": 1-2 sentences explaining what happened and why it matters\n'
    "    \"url\": the direct article URL taken from the 'URL:' line in the source content. "
    "Never use a feed URL (e.g. ending in /feed/, /rss.xml, /atom, .rss) — set to null if no "
    "direct article URL is available.\n"
    "Return ONLY the JSON object with no other text, no markdown fences, no explanation.\n"
    'Example: {"tldr": ["Ransomware activity is up 30% this week."], "coverage_confidence": "high", '
    '"items": [{"icon": "🔴", "severity": "critical", "headline": "Example title", '
    '"blurb": "What happened.", "url": "https://example.com/article"}]}'
)

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

        try:
            return await self.llm.complete(system=_SYSTEM_PROMPT, user=user_prompt, max_tokens=2048)
        except Exception as exc:
            logger.error("LLM error for topic %s: %s", topic_name, exc)
            return f"Summary unavailable: {exc}"

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
