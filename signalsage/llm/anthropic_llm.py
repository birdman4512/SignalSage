"""Anthropic Claude backend (paid API)."""

import logging

import anthropic

from .base import BaseLLM

logger = logging.getLogger(__name__)


class AnthropicLLM(BaseLLM):
    """
    Calls Anthropic's Claude API.

    Get an API key: https://console.anthropic.com/
    Recommended model: claude-haiku-4-5-20251001 (cheapest, fast)
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-haiku-4-5-20251001",
    ) -> None:
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self.model = model
        logger.info("Anthropic LLM: model=%s", model)

    async def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        try:
            response = await self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return response.content[0].text
        except anthropic.AuthenticationError:
            raise RuntimeError("Invalid Anthropic API key — check ANTHROPIC_API_KEY in .env")
        except anthropic.APIStatusError as exc:
            raise RuntimeError(f"Anthropic API error {exc.status_code}: {exc.message}")
