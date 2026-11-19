"""Google Gemini backend (free tier available via Google AI Studio)."""

import asyncio
import logging
import re
import time

import httpx

from .base import BaseLLM, LLMRateLimitError

logger = logging.getLogger(__name__)

API_BASE = "https://generativelanguage.googleapis.com/v1beta"

# JSON Schema keywords Gemini's responseJsonSchema is known to accept. Anything
# else (e.g. minLength/maxLength) is dropped rather than risking a 400; the
# summarizer validates the parsed output itself, so nothing is lost.
_SCHEMA_KEYS = {
    "type",
    "properties",
    "required",
    "items",
    "enum",
    "description",
    "title",
    "additionalProperties",
    "anyOf",
    "minItems",
    "maxItems",
    "minimum",
    "maximum",
    "format",
}

# A per-minute 429 is worth waiting out; a per-day one (retryDelay of hours, or
# none at all) is surfaced immediately as LLMRateLimitError.
_MAX_RETRY_WAIT = 65.0
_MAX_RETRIES = 2


def _clean_schema(schema):
    if isinstance(schema, dict):
        out = {}
        for key, value in schema.items():
            if key not in _SCHEMA_KEYS:
                continue
            if key == "properties" and isinstance(value, dict):
                out[key] = {name: _clean_schema(sub) for name, sub in value.items()}
            else:
                out[key] = _clean_schema(value)
        return out
    if isinstance(schema, list):
        return [_clean_schema(item) for item in schema]
    return schema


def _retry_delay(body: dict) -> float | None:
    """Seconds from a google.rpc.RetryInfo detail (e.g. "37s"), if present."""
    for detail in (body.get("error") or {}).get("details") or []:
        delay = detail.get("retryDelay") if isinstance(detail, dict) else None
        if delay:
            match = re.fullmatch(r"([\d.]+)s", str(delay))
            if match:
                return float(match.group(1))
    return None


class GeminiLLM(BaseLLM):
    """
    Calls Google's Gemini API (generateContent) directly over HTTPS.

    Get a free API key: https://aistudio.google.com/apikey
    Free-tier quotas are per model and change often — check
    https://ai.google.dev/gemini-api/docs/rate-limits. Note that Google may use
    free-tier prompts and responses to improve its products.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-flash-lite-latest",
        timeout: int = 120,
        temperature: float = 0,
        min_interval: float = 6.0,
        thinking_budget: int | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key
        self.model = model.removeprefix("models/")
        self.timeout = timeout
        self.temperature = temperature
        self.min_interval = float(min_interval)
        self.thinking_budget = thinking_budget
        self._client = http_client
        # Serialise calls and space them out so a burst of digest topics stays
        # under the free tier's requests-per-minute cap instead of tripping 429s.
        self._lock = asyncio.Lock()
        self._last_call = 0.0
        logger.info("Gemini LLM: model=%s min_interval=%.1fs", self.model, self.min_interval)

    def _payload(self, system: str, user: str, max_tokens: int, json_mode: bool, json_schema):
        config: dict = {"maxOutputTokens": max_tokens, "temperature": self.temperature}
        if self.thinking_budget is not None:
            # Only sent when configured: gemini-2.5 models accept a budget (0 =
            # off), but gemini-3.x rejects thinkingBudget with a 400. Flash-Lite
            # models don't think by default, so omitting it is the safe default.
            config["thinkingConfig"] = {"thinkingBudget": int(self.thinking_budget)}
        if json_mode:
            config["responseMimeType"] = "application/json"
            if json_schema:
                config["responseJsonSchema"] = _clean_schema(json_schema)
        return {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": config,
        }

    async def _wait_turn(self) -> None:
        wait = self._last_call + self.min_interval - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        self._last_call = time.monotonic()

    async def _post(self, client: httpx.AsyncClient, payload: dict) -> dict:
        url = f"{API_BASE}/models/{self.model}:generateContent"
        headers = {"x-goog-api-key": self.api_key}
        for attempt in range(_MAX_RETRIES + 1):
            await self._wait_turn()
            resp = await client.post(url, json=payload, headers=headers, timeout=self.timeout)
            if resp.status_code != 429:
                break
            try:
                body = resp.json()
            except ValueError:
                body = {}
            delay = _retry_delay(body)
            message = (body.get("error") or {}).get("message") or resp.text
            if delay is None or delay > _MAX_RETRY_WAIT or attempt == _MAX_RETRIES:
                hint = f" (retry in ~{int(delay)}s)" if delay else ""
                raise LLMRateLimitError(f"Gemini free-tier quota exhausted{hint}: {message}")
            logger.warning("Gemini 429; retrying in %.0fs", delay)
            await asyncio.sleep(delay)
        if resp.status_code in (400, 403) and "API key" in resp.text:
            raise RuntimeError("Invalid Gemini API key — check GEMINI_API_KEY in .env")
        if resp.status_code >= 400:
            raise RuntimeError(f"Gemini API error {resp.status_code}: {resp.text[:500]}")
        return resp.json()

    async def complete(
        self,
        system: str,
        user: str,
        max_tokens: int = 1024,
        json_mode: bool = False,
        json_schema: dict | None = None,
    ) -> str:
        payload = self._payload(system, user, max_tokens, json_mode, json_schema)
        async with self._lock:
            try:
                if self._client is not None:
                    data = await self._post(self._client, payload)
                else:
                    async with httpx.AsyncClient() as client:
                        data = await self._post(client, payload)
            except httpx.TimeoutException:
                raise RuntimeError(f"Gemini request timed out after {self.timeout}s")
            except httpx.TransportError as exc:
                raise RuntimeError(f"Cannot reach the Gemini API: {exc}")

        blocked = (data.get("promptFeedback") or {}).get("blockReason")
        if blocked:
            raise RuntimeError(f"Gemini blocked the prompt: {blocked}")
        candidates = data.get("candidates") or []
        if not candidates:
            raise RuntimeError(f"Unexpected Gemini response format: {data}")
        candidate = candidates[0]
        reason = candidate.get("finishReason")
        if reason == "MAX_TOKENS":
            raise ValueError("Gemini output reached its token limit; response is incomplete")
        parts = (candidate.get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        if not text and reason not in (None, "STOP"):
            raise RuntimeError(f"Gemini returned no text (finishReason={reason})")
        return text
