"""Ollama local LLM backend (free, runs on your own hardware)."""

import asyncio
import logging
import time

import httpx

from .base import BaseLLM

logger = logging.getLogger(__name__)

# Rough chars-per-token for sizing the context window. English prose averages ~4;
# 3 is deliberately pessimistic so the estimate errs toward a larger window.
_CHARS_PER_TOKEN = 3


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
        num_ctx: int = 4096,
        temperature: float = 0,
        think: bool | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.temperature = temperature
        self.think = think
        self.last_metrics: dict = {}
        # One generation at a time. On CPU-only hosts Ollama processes requests
        # serially anyway; queueing here instead of inside Ollama means
        # `timeout` measures actual generation time rather than time spent
        # waiting behind other topics' polls (which is what was tripping the
        # 1800s timeout when several watch topics fired at once).
        self._lock = asyncio.Lock()
        logger.info("Ollama LLM: model=%s base_url=%s num_ctx=%d", model, self.base_url, num_ctx)

    def _ctx_for(self, system: str, user: str, max_tokens: int) -> int:
        """Reject oversized prompts rather than silently increasing memory use."""
        needed = (len(system) + len(user)) // _CHARS_PER_TOKEN + max_tokens
        if needed <= self.num_ctx:
            return self.num_ctx
        raise ValueError(
            f"Prompt needs approximately {needed} tokens; fixed context budget is {self.num_ctx}. Shorten the article input."
        )

    async def complete(
        self,
        system: str,
        user: str,
        max_tokens: int = 1024,
        json_mode: bool = False,
        json_schema: dict | None = None,
    ) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "num_ctx": self._ctx_for(system, user, max_tokens),
                "temperature": self.temperature,
            },
        }
        if self.think is not None:
            payload["think"] = self.think
        if json_mode:
            # Constrains decoding to syntactically valid JSON so small local models
            # can't wrap the digest JSON in prose ("Here's your summary:\n\n{...}").
            # A full schema is stronger still: bare "json" mode lets a small model
            # legally stop after {"overview": "..."} — the schema's required keys
            # force the "items" array to be emitted too.
            payload["format"] = json_schema or "json"

        queued = time.monotonic()
        async with self._lock, httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                started = time.monotonic()
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()
                self.last_metrics = {
                    key: data.get(key)
                    for key in (
                        "prompt_eval_count",
                        "eval_count",
                        "load_duration",
                        "eval_duration",
                        "total_duration",
                    )
                }
                self.last_metrics.update(
                    queue_seconds=started - queued, request_seconds=time.monotonic() - started
                )
                logger.info("Ollama generation metrics: %s", self.last_metrics)
                if data.get("done_reason") == "length":
                    raise ValueError(
                        "Ollama output reached its token limit; response is incomplete"
                    )
                try:
                    return data["message"]["content"]
                except (KeyError, TypeError):
                    raise RuntimeError(f"Unexpected Ollama response format: {data}")
            except httpx.TimeoutException:
                raise RuntimeError(
                    f"Ollama request timed out after {self.timeout}s — "
                    "prompt may be too large for this model/hardware"
                )
            except httpx.ConnectError:
                raise RuntimeError(
                    f"Cannot connect to Ollama at {self.base_url}. "
                    "Ensure Ollama is running: https://ollama.com/download"
                )
            except httpx.HTTPStatusError as exc:
                raise RuntimeError(
                    f"Ollama API error {exc.response.status_code}: {exc.response.text}"
                )
