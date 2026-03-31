"""LLM-powered digest summarizer."""

import logging
from datetime import date

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC
from signalsage.llm.base import BaseLLM

from .fetcher import fetch_topic

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an analyst producing a structured news digest. "
    "The content below has already been fetched from the sources and is provided to you directly — "
    "you do not need to access the internet or any external URLs. "
    "Extract the most noteworthy items and return them as a JSON array. "
    "Each element must have exactly these four fields:\n"
    '  "icon": a single emoji that best represents the story type. '
    "Choose from: 🔴 critical/severe, 🛡️ patch/fix/defence, 🦠 malware/ransomware, "
    "🔗 phishing/scam, 📢 news/announcement, 🔍 research/report, ⚠️ warning/advisory, "
    "📡 threat intel, 🏛️ policy/legal/government, 📻 radio/propagation, ☀️ solar/space weather\n"
    '  "headline": a short, clear title (max 80 characters)\n'
    '  "blurb": 1-2 sentences explaining what happened and why it matters\n'
    '  "url": the direct URL to the original article or item (null if not available)\n'
    "Return ONLY the JSON array with no other text, no markdown fences, no explanation.\n"
    'Example: [{"icon": "🔴", "headline": "Example title", "blurb": "What happened and why it matters.", "url": "https://example.com/article"}]'
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

    async def summarize_all(self, watchlist: dict, timeout: int = 15) -> list[tuple[str, str]]:
        topics = watchlist.get("topics", [])
        results: list[tuple[str, str]] = []

        for topic in topics:
            name = topic.get("name", "Unknown")
            logger.info("Fetching sources for topic: %s", name)
            try:
                fetched = await fetch_topic(topic.get("sources", []), self.max_chars, timeout)
            except Exception as exc:
                logger.error("Failed to fetch topic %s: %s", name, exc)
                fetched = []

            logger.info("Summarizing topic: %s", name)
            summary = await self.summarize_topic(name, fetched)
            results.append((name, summary))

        return results
