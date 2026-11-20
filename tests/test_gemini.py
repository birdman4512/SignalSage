"""Tests for the Gemini LLM backend."""

import json
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from signalsage.bootstrap import build_llm
from signalsage.config import validate_config
from signalsage.llm.base import LLMRateLimitError
from signalsage.llm.gemini import GeminiLLM

URL = "https://generativelanguage.googleapis.com/v1beta/models/test-model:generateContent"


def _ok(text: str, reason: str = "STOP") -> httpx.Response:
    return httpx.Response(
        200,
        json={"candidates": [{"content": {"parts": [{"text": text}]}, "finishReason": reason}]},
    )


def _llm(**kwargs) -> GeminiLLM:
    return GeminiLLM(api_key="k", model="test-model", min_interval=0, **kwargs)


@respx.mock
async def test_request_shape_and_json_schema():
    route = respx.post(URL).mock(return_value=_ok('{"relevant": true}'))
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"reason": {"type": "string", "maxLength": 160, "minLength": 1}},
        "required": ["reason"],
    }

    out = await _llm(thinking_budget=0).complete(
        "sys", "usr", max_tokens=99, json_mode=True, json_schema=schema
    )

    assert out == '{"relevant": true}'
    req = route.calls.last.request
    assert req.headers["x-goog-api-key"] == "k"
    sent = json.loads(req.content)
    assert sent["systemInstruction"]["parts"][0]["text"] == "sys"
    assert sent["contents"][0]["parts"][0]["text"] == "usr"
    cfg = sent["generationConfig"]
    assert cfg["maxOutputTokens"] == 99
    assert cfg["responseMimeType"] == "application/json"
    assert cfg["thinkingConfig"] == {"thinkingBudget": 0}
    # Unsupported keywords are stripped; property names are preserved.
    assert cfg["responseJsonSchema"]["properties"] == {"reason": {"type": "string"}}
    assert cfg["responseJsonSchema"]["additionalProperties"] is False


@respx.mock
async def test_plain_text_omits_json_and_thinking_by_default():
    route = respx.post(URL).mock(return_value=_ok("hello"))

    assert await _llm().complete("s", "u") == "hello"

    cfg = json.loads(route.calls.last.request.content)["generationConfig"]
    assert "responseMimeType" not in cfg
    assert "thinkingConfig" not in cfg


@respx.mock
async def test_thought_parts_are_skipped():
    respx.post(URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": "musing", "thought": True}, {"text": "answer"}]
                        },
                        "finishReason": "STOP",
                    }
                ]
            },
        )
    )
    assert await _llm().complete("s", "u") == "answer"


@respx.mock
async def test_max_tokens_raises():
    respx.post(URL).mock(return_value=_ok("{", reason="MAX_TOKENS"))
    with pytest.raises(ValueError):
        await _llm().complete("s", "u")


@respx.mock
async def test_short_429_is_retried(monkeypatch):
    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr("signalsage.llm.gemini.asyncio.sleep", fake_sleep)
    limited = httpx.Response(
        429,
        json={"error": {"message": "slow down", "details": [{"retryDelay": "3s"}]}},
    )
    route = respx.post(URL).mock(side_effect=[limited, _ok("done")])

    assert await _llm().complete("s", "u") == "done"
    assert route.call_count == 2
    assert 3.0 in slept


@respx.mock
async def test_daily_quota_raises_rate_limit_error():
    respx.post(URL).mock(
        return_value=httpx.Response(
            429, json={"error": {"message": "quota exceeded per day", "details": []}}
        )
    )
    with pytest.raises(LLMRateLimitError, match="quota"):
        await _llm().complete("s", "u")


@respx.mock
async def test_bad_key_message():
    respx.post(URL).mock(
        return_value=httpx.Response(400, json={"error": {"message": "API key not valid"}})
    )
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        await _llm().complete("s", "u")


def test_build_llm_builds_gemini():
    llm = build_llm(
        {"gemini_api_key": "k", "gemini_model": "models/m", "gemini_thinking_budget": None}
    )
    assert isinstance(llm, GeminiLLM)
    assert llm.model == "m"
    assert llm.thinking_budget is None


def test_no_key_means_no_llm_and_config_still_valid():
    # Without a key the bot still runs IOC enrichment; digests are disabled.
    assert build_llm({"gemini_api_key": ""}) is None
    assert validate_config({"digest": {}}) == {"digest": {}}


@respx.mock
async def test_transcribe_uploads_waits_generates_and_deletes(tmp_path, monkeypatch):
    monkeypatch.setattr("signalsage.llm.gemini.asyncio.sleep", AsyncMock())
    audio = tmp_path / "ep.mp3"
    audio.write_bytes(b"AUDIO")
    start = respx.post("https://generativelanguage.googleapis.com/upload/v1beta/files").mock(
        return_value=httpx.Response(200, headers={"x-goog-upload-url": "https://up.test/1"})
    )
    upload = respx.post("https://up.test/1").mock(
        return_value=httpx.Response(
            200,
            json={
                "file": {
                    "name": "files/f1",
                    "uri": "https://g.test/files/f1",
                    "state": "PROCESSING",
                }
            },
        )
    )
    poll = respx.get("https://generativelanguage.googleapis.com/v1beta/files/f1").mock(
        return_value=httpx.Response(200, json={"name": "files/f1", "state": "ACTIVE"})
    )
    gen = respx.post(URL).mock(return_value=_ok("Hello and welcome to the show."))
    delete = respx.delete("https://generativelanguage.googleapis.com/v1beta/files/f1").mock(
        return_value=httpx.Response(200, json={})
    )

    text = await _llm().transcribe(str(audio), "audio/mpeg")

    assert text == "Hello and welcome to the show."
    assert start.calls.last.request.headers["x-goog-upload-header-content-type"] == "audio/mpeg"
    assert start.calls.last.request.headers["x-goog-upload-header-content-length"] == "5"
    assert upload.calls.last.request.content == b"AUDIO"
    assert poll.called and delete.called
    part = json.loads(gen.calls.last.request.content)["contents"][0]["parts"][0]
    assert part == {"fileData": {"mimeType": "audio/mpeg", "fileUri": "https://g.test/files/f1"}}


@respx.mock
async def test_transcribe_deletes_file_even_when_generation_fails(tmp_path):
    audio = tmp_path / "ep.mp3"
    audio.write_bytes(b"AUDIO")
    respx.post("https://generativelanguage.googleapis.com/upload/v1beta/files").mock(
        return_value=httpx.Response(200, headers={"x-goog-upload-url": "https://up.test/1"})
    )
    respx.post("https://up.test/1").mock(
        return_value=httpx.Response(
            200, json={"file": {"name": "files/f1", "uri": "https://g.test/f1", "state": "ACTIVE"}}
        )
    )
    respx.post(URL).mock(
        return_value=httpx.Response(429, json={"error": {"message": "quota", "details": []}})
    )
    delete = respx.delete("https://generativelanguage.googleapis.com/v1beta/files/f1").mock(
        return_value=httpx.Response(200, json={})
    )
    with pytest.raises(LLMRateLimitError):
        await _llm().transcribe(str(audio), "audio/mpeg")
    assert delete.called
