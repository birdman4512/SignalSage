"""LLM-powered digest summarizer."""

import logging
from datetime import date

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC
from signalsage.llm.base import BaseLLM

from .fetcher import fetch_topic

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an analyst producing a digest summary. "
    "The content below has already been fetched from the sources and is provided to you directly — "
    "you do not need to access the internet or any external URLs. "
    "Summarize the provided content concisely using bullet points. "
    "Include source names and key details. "
    "If no useful content is provided, say so briefly."
)

_IOC_SYSTEM_PROMPT = (
    "You are a senior threat intelligence analyst. "
    "Given threat intelligence results for an indicator, write a concise 2-3 sentence assessment. "
    "State the overall verdict, what the indicator is associated with, and any recommended action. "
    "Be direct and factual. Do not repeat the raw numbers — interpret them."
)


class DigestSummarizer:
    """Fetches topic sources and summarizes them using a configured LLM."""

    def __init__(self, llm: BaseLLM, max_chars: int = 3000) -> None:
        self.llm = llm
        self.max_chars = max_chars

    async def summarize_topic(
        self, topic_name: str, sources: list[dict], lookback: str | None = None
    ) -> str:
        today = date.today().strftime("%B %d, %Y")

        source_blocks: list[str] = []
        for src in sources:
            content = src.get("content", "").strip()
            if not content:
                continue
            source_blocks.append(f"### {src['name']}\n{content}\nSource: {src['url']}\n")

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
            return await self.llm.complete(system=_SYSTEM_PROMPT, user=user_prompt)
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
            return ""

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
