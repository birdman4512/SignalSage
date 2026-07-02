"""Tests for the Ollama LLM backend."""

import json

import httpx
import respx

from signalsage.llm.ollama import OllamaLLM


@respx.mock
async def test_json_schema_sent_as_format():
    route = respx.post("http://ollama.test/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"content": "{}"}})
    )
    llm = OllamaLLM(base_url="http://ollama.test")
    schema = {"type": "object", "required": ["items"]}

    out = await llm.complete(system="s", user="u", json_mode=True, json_schema=schema)

    assert out == "{}"
    sent = json.loads(route.calls.last.request.content)
    assert sent["format"] == schema


@respx.mock
async def test_json_mode_without_schema_uses_bare_json():
    route = respx.post("http://ollama.test/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"content": "{}"}})
    )
    llm = OllamaLLM(base_url="http://ollama.test")

    await llm.complete(system="s", user="u", json_mode=True)

    sent = json.loads(route.calls.last.request.content)
    assert sent["format"] == "json"


@respx.mock
async def test_no_format_key_when_json_mode_off():
    route = respx.post("http://ollama.test/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"content": "hi"}})
    )
    llm = OllamaLLM(base_url="http://ollama.test")

    await llm.complete(system="s", user="u")

    sent = json.loads(route.calls.last.request.content)
    assert "format" not in sent
