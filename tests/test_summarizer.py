import json
from unittest.mock import AsyncMock

import pytest

from signalsage.digest.summarizer import DigestSummarizer
from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC, IOCType

ARTICLE = {
    "id": "a123",
    "title": "Vendor fixes vulnerability",
    "summary": "The vendor released a patch for the vulnerability.",
    "link": "https://source.example/a",
}


def response(**updates):
    return json.dumps(
        {
            "art_id": "a123",
            "summary": "The vendor released a patch.",
            "evidence": "The vendor released a patch",
            **updates,
        }
    )


async def test_summary_is_bounded_and_grounded():
    llm = AsyncMock()
    llm.complete.return_value = response()
    result = await DigestSummarizer(llm).summarize_article(ARTICLE)
    assert result["evidence"] in ARTICLE["summary"]
    kwargs = llm.complete.call_args.kwargs
    assert kwargs["max_tokens"] == 350
    assert "url" not in kwargs["json_schema"]["properties"]
    assert "untrusted" in kwargs["system"]


@pytest.mark.parametrize(
    "bad",
    [
        response(art_id="invented"),
        response(evidence="No patch is available"),
        response(url="https://invented.example"),
        response(summary="See https://invented.example"),
        '{"art_id": "a123"}',
        "[]",
        "not json",
    ],
)
async def test_invalid_model_response_retries_once_then_raises(bad):
    llm = AsyncMock()
    llm.complete.return_value = bad
    with pytest.raises(ValueError):
        await DigestSummarizer(llm).summarize_article(ARTICLE)
    assert llm.complete.await_count == 2


async def test_valid_response_after_validation_retry():
    llm = AsyncMock()
    llm.complete.side_effect = [response(art_id="wrong"), response()]
    assert (await DigestSummarizer(llm).summarize_article(ARTICLE))["summary"]
    assert llm.complete.await_count == 2


async def test_model_unavailable_is_not_an_empty_success():
    llm = AsyncMock()
    llm.complete.side_effect = RuntimeError("offline")
    with pytest.raises(RuntimeError):
        await DigestSummarizer(llm).summarize_article(ARTICLE)
    llm.complete.assert_awaited_once()


async def test_empty_article_never_calls_model():
    llm = AsyncMock()
    with pytest.raises(ValueError):
        await DigestSummarizer(llm).summarize_article({**ARTICLE, "summary": ""})
    llm.complete.assert_not_awaited()


async def test_large_article_input_is_bounded():
    llm = AsyncMock()
    llm.complete.return_value = response()
    await DigestSummarizer(llm, max_chars=3000).summarize_article(
        {**ARTICLE, "body": ARTICLE["summary"] + "x" * 50000}
    )
    assert len(json.loads(llm.complete.call_args.kwargs["user"])["source_text"]) == 3000


@pytest.mark.parametrize("raw", ['{"relevant":"false","reason":"no"}', "[]", '{"relevant":false}'])
async def test_relevance_requires_boolean_and_reason(raw):
    llm = AsyncMock()
    llm.complete.return_value = raw
    with pytest.raises(ValueError):
        await DigestSummarizer(llm).judge_relevance(ARTICLE, {})


async def test_ioc_assessment_preserves_verdict_and_cache():
    llm = AsyncMock()
    llm.complete.return_value = "This IP is malicious; block and investigate."
    summarizer = DigestSummarizer(llm)
    ioc = IOC(value="8.8.8.8", type=IOCType.IPV4)
    intel = [
        IntelResult(
            provider="Example",
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=True,
            summary="Known command and control server",
        )
    ]
    assert await summarizer.summarize_ioc(ioc, intel) == llm.complete.return_value
    assert await summarizer.summarize_ioc(ioc, intel) == llm.complete.return_value
    llm.complete.assert_awaited_once()
    assert "MALICIOUS" in llm.complete.call_args.kwargs["user"]


async def test_ioc_rate_limit_still_applies():
    llm = AsyncMock()
    summarizer = DigestSummarizer(llm, ioc_assessment_capacity=0)
    assert "rate-limited" in await summarizer.summarize_ioc(
        IOC(value="8.8.8.8", type=IOCType.IPV4), []
    )
    llm.complete.assert_not_awaited()
