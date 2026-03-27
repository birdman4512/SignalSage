"""LLM-powered digest summarizer using Claude via Anthropic SDK."""

import logging
from datetime import date
from typing import Dict, List, Optional, Tuple

import anthropic

from .fetcher import fetch_topic

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Summarize security news concisely. "
    "Use bullet points. Include source names and key details. "
    "Focus on actionable intelligence, new threats, and important vulnerabilities."
)


class DigestSummarizer:
    """Fetches topic sources and summarizes them using Claude."""

    def __init__(
        self,
        llm_model: str = "claude-haiku-4-5-20251001",
        llm_api_key: str = "",
        max_chars: int = 3000,
    ) -> None:
        self.llm_model = llm_model
        self.max_chars = max_chars
        self._client = anthropic.AsyncAnthropic(api_key=llm_api_key)

    async def summarize_topic(
        self,
        topic_name: str,
        sources: List[Dict],
    ) -> str:
        """Summarize content from a list of fetched sources for a topic."""
        today = date.today().strftime("%B %d, %Y")

        # Build source content blocks
        source_blocks: List[str] = []
        for src in sources:
            content = src.get("content", "").strip()
            if not content:
                continue
            block = f"### {src['name']}\n{content}\nSource: {src['url']}\n"
            source_blocks.append(block)

        if not source_blocks:
            return f"No content available for {topic_name} on {today}."

        user_prompt = (
            f"Summarize these {topic_name} sources for {today}:\n\n"
            + "\n".join(source_blocks)
        )

        try:
            response = await self._client.messages.create(
                model=self.llm_model,
                max_tokens=1024,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return response.content[0].text
        except anthropic.APIStatusError as exc:
            logger.error("Anthropic API error for topic %s: %s", topic_name, exc)
            return f"Summary unavailable due to API error: {exc.status_code}"
        except Exception as exc:
            logger.exception("Failed to summarize topic %s", topic_name)
            return f"Summary generation failed: {exc}"

    async def summarize_all(
        self,
        watchlist: Dict,
        timeout: int = 15,
    ) -> List[Tuple[str, str]]:
        """
        Fetch and summarize all topics in the watchlist.

        Returns:
            list of (topic_name, summary) tuples
        """
        topics = watchlist.get("topics", [])
        results: List[Tuple[str, str]] = []

        for topic in topics:
            topic_name = topic.get("name", "Unknown")
            sources_cfg = topic.get("sources", [])

            logger.info("Fetching sources for topic: %s", topic_name)
            try:
                fetched = await fetch_topic(sources_cfg, self.max_chars, timeout)
            except Exception as exc:
                logger.error("Failed to fetch topic %s: %s", topic_name, exc)
                fetched = []

            logger.info("Summarizing topic: %s", topic_name)
            summary = await self.summarize_topic(topic_name, fetched)
            results.append((topic_name, summary))

        return results
