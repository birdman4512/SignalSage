"""Base class for LLM backends."""

from abc import ABC, abstractmethod


class BaseLLM(ABC):
    """Minimal interface for LLM completion."""

    @abstractmethod
    async def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """Return the model's text response."""
