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


@respx.mock
async def test_num_ctx_grows_only_for_oversized_prompt():
    route = respx.post("http://ollama.test/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"content": "{}"}})
    )
    llm = OllamaLLM(base_url="http://ollama.test", num_ctx=4096)

    await llm.complete(system="s", user="u" * 3000, max_tokens=1024)
    assert json.loads(route.calls.last.request.content)["options"]["num_ctx"] == 4096

    await llm.complete(system="s", user="u" * 30000, max_tokens=1024)
    assert json.loads(route.calls.last.request.content)["options"]["num_ctx"] == 12288


async def test_requests_are_serialised():
    import asyncio

    llm = OllamaLLM(base_url="http://ollama.test")
    active = 0
    peak = 0

    async def slow_post(request):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return httpx.Response(200, json={"message": {"content": "ok"}})

    with respx.mock:
        respx.post("http://ollama.test/api/chat").mock(side_effect=slow_post)
        await asyncio.gather(*(llm.complete(system="s", user="u") for _ in range(4)))
    assert peak == 1
