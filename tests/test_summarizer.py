from unittest.mock import AsyncMock

from signalsage.digest.summarizer import DigestSummarizer


async def test_summarize_topic_includes_source_url_and_fallback_guidance():
    llm = AsyncMock()
    llm.complete = AsyncMock(return_value='{"tldr":[],"items":[]}')
    summarizer = DigestSummarizer(llm=llm, max_chars=3000, max_total_chars=20000)

    sources = [
        {
            "name": "Example Source",
            "url": "https://example.com/source",
            "content": "Title: Example Story\nExample body without an article URL.",
        }
    ]

    await summarizer.summarize_topic("Test Topic", sources, lookback="24h")

    llm.complete.assert_awaited_once()
    kwargs = llm.complete.await_args.kwargs
    assert "fall back to the \"Source URL:\" line" in kwargs["system"]
    assert "Source URL: https://example.com/source" in kwargs["user"]
