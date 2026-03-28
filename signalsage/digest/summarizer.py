"""LLM-powered digest summarizer."""

import logging
from datetime import date

from signalsage.llm.base import BaseLLM

from .fetcher import fetch_topic

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Summarize security news concisely. "
    "Use bullet points. Include source names and key details. "
    "Focus on actionable intelligence, new threats, and important vulnerabilities."
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
            f"Summarize these {topic_name} sources {window_phrase}.\n"
            + (f"Focus only on items published in the last {lookback}. Skip older content.\n" if lookback else "")
            + f"\n" + "\n".join(source_blocks)
        )

        try:
            return await self.llm.complete(system=_SYSTEM_PROMPT, user=user_prompt)
        except Exception as exc:
            logger.error("LLM error for topic %s: %s", topic_name, exc)
            return f"Summary unavailable: {exc}"

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
