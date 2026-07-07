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
    assert "art_id" in kwargs["system"]
    assert "[A" in kwargs["user"]  # articles are labelled [A1], [A2], etc.
    assert "Source URL: https://example.com/source" in kwargs["user"]
    assert kwargs["json_schema"] is not None  # Ollama structured-output schema


async def test_summarize_topic_retries_when_items_missing():
    """An overview-only response (no "items" key) triggers a retry; a later good
    response is returned."""
    good = '{"overview": "News.", "coverage_confidence": "high", "items": []}'
    llm = AsyncMock()
    llm.complete = AsyncMock(side_effect=['{"overview": "News tonight..."}', good])
    summarizer = DigestSummarizer(llm=llm, max_chars=3000, max_total_chars=20000)

    sources = [{"name": "S", "url": "https://example.com", "content": "Title: Story\nBody."}]
    result = await summarizer.summarize_topic("Test Topic", sources)

    assert llm.complete.await_count == 2
    assert result == good


async def test_summarize_topic_overview_only_returned_after_retries():
    """If every attempt lacks items, the last response is still returned so the
    formatter can render the overview instead of a raw-JSON fallback."""
    overview_only = '{"overview": "Only an overview."}'
    llm = AsyncMock()
    llm.complete = AsyncMock(return_value=overview_only)
    summarizer = DigestSummarizer(llm=llm, max_chars=3000, max_total_chars=20000)

    sources = [{"name": "S", "url": "https://example.com", "content": "Title: Story\nBody."}]
    result = await summarizer.summarize_topic("Test Topic", sources)

    assert llm.complete.await_count == 3  # initial + 2 retries
    assert result == overview_only


# ---------------------------------------------------------------------------
# summarize_watch_items
# ---------------------------------------------------------------------------


async def test_summarize_watch_items_passes_keywords_and_schema():
    llm = AsyncMock()
    llm.complete = AsyncMock(
        return_value='{"overview": "", "coverage_confidence": "high", "items": '
        '[{"art_id": "A1", "relevant": true, "icon": "🔴", "severity": "high", '
        '"headline": "H", "summary": "S.", "url": "https://example.com"}]}'
    )
    summarizer = DigestSummarizer(llm=llm, max_chars=3000, max_total_chars=20000)
    sources = [{"name": "S", "url": "https://example.com", "content": "Title: Story\nBody."}]

    result = await summarizer.summarize_watch_items(
        "Test Topic", sources, include_keywords=["ransomware"], exclude_keywords=["sponsored"]
    )

    llm.complete.assert_awaited_once()
    kwargs = llm.complete.await_args.kwargs
    assert "ransomware" in kwargs["system"]
    assert "sponsored" in kwargs["system"]
    assert kwargs["json_schema"] is not None
    assert '"relevant": true' in result


async def test_summarize_watch_items_no_content_returns_empty_items():
    llm = AsyncMock()
    summarizer = DigestSummarizer(llm=llm, max_chars=3000, max_total_chars=20000)

    result = await summarizer.summarize_watch_items(
        "Test Topic", [{"name": "S", "url": "https://x.com", "content": ""}], [], []
    )

    llm.complete.assert_not_awaited()
    import json

    assert json.loads(result)["items"] == []


async def test_summarize_watch_items_llm_error_returns_empty_items():
    llm = AsyncMock()
    llm.complete = AsyncMock(side_effect=RuntimeError("boom"))
    summarizer = DigestSummarizer(llm=llm, max_chars=3000, max_total_chars=20000)
    sources = [{"name": "S", "url": "https://example.com", "content": "Title: Story\nBody."}]

    result = await summarizer.summarize_watch_items("Test Topic", sources, [], [])

    import json

    assert json.loads(result)["items"] == []
