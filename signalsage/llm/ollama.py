"""Ollama local LLM backend (free, runs on your own hardware)."""

import logging

import httpx

from .base import BaseLLM

logger = logging.getLogger(__name__)


class OllamaLLM(BaseLLM):
    """
    Calls a locally-running Ollama instance via its native /api/chat endpoint.

    Install Ollama:  https://ollama.com/download
    Pull a model:    ollama pull llama3.2        (lean, ~2 GB)
                     ollama pull phi3:mini        (very lean, ~2.2 GB)
                     ollama pull llama3.1:8b      (higher quality, ~4.7 GB)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "llama3.2",
        timeout: int = 600,
        num_ctx: int = 8192,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        logger.info("Ollama LLM: model=%s base_url=%s num_ctx=%d", model, self.base_url, num_ctx)

    async def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"num_predict": max_tokens, "num_ctx": self.num_ctx},
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                return resp.json()["message"]["content"]
            except httpx.ConnectError:
                raise RuntimeError(
                    f"Cannot connect to Ollama at {self.base_url}. "
                    "Ensure Ollama is running: https://ollama.com/download"
                )
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(
                    f"Ollama API error {exc.response.status_code}: {exc.response.text}"
                )
            except KeyError:
                raise RuntimeError("Unexpected Ollama response format")
