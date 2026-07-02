"""Base class for LLM backends."""

from abc import ABC, abstractmethod


class LLMRateLimitError(RuntimeError):
    """Raised when a backend reports a usage/rate limit.

    Distinct from a generic failure so callers can skip futile retries (a quota
    reset is minutes/hours away, not seconds) and surface a clear, actionable
    message — including any reset time — to the user.
    """


class BaseLLM(ABC):
    """Minimal interface for LLM completion."""

    @abstractmethod
    async def complete(
        self,
        system: str,
        user: str,
        max_tokens: int = 1024,
        json_mode: bool = False,
        json_schema: dict | None = None,
    ) -> str:
        """Return the model's text response.

        If json_mode is True, the backend should constrain output to valid JSON
        where it supports doing so (e.g. Ollama's structured-output format).
        json_schema optionally carries a full JSON schema for backends that can
        enforce one (Ollama structured outputs); others may ignore it and rely
        on the prompt.
        """
