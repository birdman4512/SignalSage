"""Tests for the message formatter."""

import json

from signalsage.bots.formatter import (
    Platform,
    _parse_digest_json,
    format_digest_plain,
    format_digest_slack_message,
    format_results,
    split_message,
)
from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC, IOCType


def _ioc(value: str = "8.8.8.8", ioc_type: IOCType = IOCType.IPV4) -> IOC:
    return IOC(value=value, type=ioc_type)


def _result(
    malicious: bool | None = True,
    error: str | None = None,
    report_url: str | None = None,
    summary: str = "test summary",
) -> IntelResult:
    return IntelResult(
        provider="TestProvider",
        ioc_value="8.8.8.8",
        ioc_type=IOCType.IPV4,
        malicious=malicious,
        summary=summary,
        error=error,
        report_url=report_url,
    )


# ---------------------------------------------------------------------------
# Bold formatting
# ---------------------------------------------------------------------------


def test_slack_bold():
    msg = format_results(_ioc(), [_result()], Platform.SLACK)
    assert "*TestProvider*" in msg


def test_discord_bold():
    msg = format_results(_ioc(), [_result()], Platform.DISCORD)
    assert "**TestProvider**" in msg


# ---------------------------------------------------------------------------
# Link formatting
# ---------------------------------------------------------------------------


def test_slack_link():
    msg = format_results(_ioc(), [_result(report_url="https://vt.example/abc")], Platform.SLACK)
    assert "<https://vt.example/abc|view report>" in msg


def test_discord_link():
    msg = format_results(_ioc(), [_result(report_url="https://vt.example/abc")], Platform.DISCORD)
    assert "[view report](https://vt.example/abc)" in msg


def test_no_link_when_url_absent():
    msg = format_results(_ioc(), [_result(report_url=None)], Platform.DISCORD)
    assert "details" not in msg


# ---------------------------------------------------------------------------
# Risk emojis
# ---------------------------------------------------------------------------


def test_emoji_malicious():
    msg = format_results(_ioc(), [_result(malicious=True)], Platform.DISCORD)
    assert "🔴" in msg


def test_emoji_clean():
    msg = format_results(_ioc(), [_result(malicious=False)], Platform.DISCORD)
    assert "✅" in msg


def test_emoji_unknown():
    msg = format_results(_ioc(), [_result(malicious=None)], Platform.DISCORD)
    assert "⚪" in msg


def test_emoji_error():
    msg = format_results(_ioc(), [_result(error="Timeout")], Platform.DISCORD)
    assert "⚠️" in msg


# ---------------------------------------------------------------------------
# IOC header in output
# ---------------------------------------------------------------------------


def test_ioc_value_in_output():
    msg = format_results(_ioc("8.8.8.8"), [_result()], Platform.DISCORD)
    assert "8.8.8.8" in msg


def test_ioc_type_label_in_output():
    msg = format_results(_ioc("8.8.8.8"), [_result()], Platform.DISCORD)
    assert "IPv4" in msg


def test_cve_label():
    msg = format_results(_ioc("CVE-2023-1234", IOCType.CVE), [_result()], Platform.DISCORD)
    assert "CVE" in msg


# ---------------------------------------------------------------------------
# Empty results
# ---------------------------------------------------------------------------


def test_empty_results_still_has_header():
    msg = format_results(_ioc("8.8.8.8"), [], Platform.DISCORD)
    assert "8.8.8.8" in msg


# ---------------------------------------------------------------------------
# Multiple results
# ---------------------------------------------------------------------------


def test_multiple_results():
    results = [
        _result(malicious=True, summary="VT: 5/92"),
        IntelResult(
            provider="GreyNoise",
            ioc_value="8.8.8.8",
            ioc_type=IOCType.IPV4,
            malicious=False,
            summary="riot",
        ),
    ]
    msg = format_results(_ioc(), results, Platform.DISCORD)
    assert "TestProvider" in msg
    assert "GreyNoise" in msg


# ---------------------------------------------------------------------------
# split_message
# ---------------------------------------------------------------------------


def test_split_short_no_split():
    chunks = split_message("hello", limit=100)
    assert chunks == ["hello"]


def test_split_exactly_at_limit():
    text = "a" * 100
    chunks = split_message(text, limit=100)
    assert len(chunks) == 1


def test_split_long_message():
    text = "\n".join(["word"] * 200)
    chunks = split_message(text, limit=50)
    assert len(chunks) > 1
    for chunk in chunks:
        assert len(chunk) <= 50


def test_split_preserves_content():
    lines = [f"line{i}" for i in range(20)]
    text = "\n".join(lines)
    chunks = split_message(text, limit=50)
    rejoined = "\n".join(chunks)
    for line in lines:
        assert line in rejoined


# ---------------------------------------------------------------------------
# _parse_digest_json
# ---------------------------------------------------------------------------

_ITEM = {
    "icon": "🔴",
    "severity": "critical",
    "headline": "Test Headline",
    "summary": "Something bad happened and it matters because of reasons.",
    "url": "https://example.com",
}

# ---------------------------------------------------------------------------
# Helpers for multi-message assertions
# ---------------------------------------------------------------------------


def _all_slack_blocks(payloads: list[dict]) -> list[dict]:
    blocks = []
    for p in payloads:
        for att in p.get("attachments", []):
            blocks.extend(att.get("blocks", []))
    return blocks


def _all_section_texts(payloads: list[dict]) -> list[str]:
    return [
        b.get("text", {}).get("text", "")
        for b in _all_slack_blocks(payloads)
        if b.get("type") == "section"
    ]


def _joined_plain(messages: list[str]) -> str:
    return "\n".join(messages)


def test_parse_digest_json_structured_object_with_overview():
    summary = json.dumps(
        {"overview": "News today.", "coverage_confidence": "high", "items": [_ITEM]}
    )
    result = _parse_digest_json(summary)
    assert result is not None
    assert result["overview"] == "News today."
    assert result["coverage_confidence"] == "high"
    assert len(result["items"]) == 1


def test_parse_digest_json_structured_object_legacy_tldr():
    summary = json.dumps({"tldr": ["Key point"], "coverage_confidence": "high", "items": [_ITEM]})
    result = _parse_digest_json(summary)
    assert result is not None
    assert result["tldr"] == ["Key point"]
    assert result["overview"] is None
    assert result["coverage_confidence"] == "high"
    assert len(result["items"]) == 1


def test_parse_digest_json_strips_code_fence():
    summary = "```json\n" + json.dumps({"tldr": [], "items": []}) + "\n```"
    assert _parse_digest_json(summary) is not None


def test_parse_digest_json_bare_shortcode():
    summary = (
        '{"overview": "", "items": [{"icon": :shield:, "severity": "low", '
        '"headline": "X", "summary": "Y", "url": null}]}'
    )
    result = _parse_digest_json(summary)
    assert result is not None
    assert result["items"][0]["icon"] == "🛡️"


def test_parse_digest_json_unquoted_emoji_icon():
    """LLMs sometimes emit unquoted emoji: "icon": 🔴, — must still parse."""
    summary = (
        '{"overview": "", "items": [{"icon": 🔴, "severity": "critical", '
        '"headline": "X", "summary": "Y", "url": null}]}'
    )
    result = _parse_digest_json(summary)
    assert result is not None
    assert result["items"][0]["icon"] == "🔴"


def test_parse_digest_json_legacy_flat_array():
    summary = json.dumps([_ITEM])
    result = _parse_digest_json(summary)
    assert result is not None
    assert result["overview"] is None
    assert result["tldr"] == []
    assert result["coverage_confidence"] is None
    assert len(result["items"]) == 1


def test_parse_digest_json_invalid_returns_none():
    assert _parse_digest_json("not json at all") is None
    assert _parse_digest_json("") is None
    assert _parse_digest_json('{"no_items_key": true}') is None


# ---------------------------------------------------------------------------
# format_digest_slack_message
# ---------------------------------------------------------------------------


def _structured_summary(**kwargs) -> str:
    data = {
        "overview": "Top signal across all sources today.",
        "coverage_confidence": "high",
        "items": [_ITEM],
    }
    data.update(kwargs)
    return json.dumps(data)


def test_format_digest_slack_has_overview_block():
    payloads = format_digest_slack_message("Test Topic", _structured_summary())
    texts = _all_section_texts(payloads)
    assert any("Top signal" in t for t in texts)


def test_format_digest_slack_has_item_headline():
    payloads = format_digest_slack_message("Test Topic", _structured_summary())
    texts = _all_section_texts(payloads)
    assert any("Test Headline" in t for t in texts)


def test_format_digest_slack_read_more_button():
    payloads = format_digest_slack_message("Test Topic", _structured_summary())
    buttons = [
        b.get("accessory", {})
        for b in _all_slack_blocks(payloads)
        if b.get("type") == "section" and b.get("accessory")
    ]
    assert any(b.get("url") == "https://example.com" for b in buttons)


def test_format_digest_slack_source_label_shown():
    payloads = format_digest_slack_message("Test Topic", _structured_summary())
    texts = _all_section_texts(payloads)
    assert any("example.com" in t for t in texts)


def test_format_digest_slack_trend_badge():
    item_with_trend = {**_ITEM, "trend": "trending"}
    payloads = format_digest_slack_message(
        "Test Topic", json.dumps({"overview": "", "items": [item_with_trend]})
    )
    texts = _all_section_texts(payloads)
    assert any("🔥" in t for t in texts)


def test_format_digest_slack_meta_footer():
    meta = {
        "sources_ok": 3,
        "sources_total": 5,
        "empty_sources": ["Dead Feed"],
        "chronically_failing": ["Broken Feed"],
        "deduped_count": 2,
        "coverage_confidence": "low",
    }
    summary_no_conf = json.dumps({"overview": "Summary.", "items": [_ITEM]})
    payloads = format_digest_slack_message("Test Topic", summary_no_conf, meta=meta)
    context_texts = [
        e["text"]
        for b in _all_slack_blocks(payloads)
        if b.get("type") == "context"
        for e in b.get("elements", [])
    ]
    footer = " ".join(context_texts)
    assert "3/5" in footer
    assert "Low" in footer
    assert "2 cross-topic" in footer
    assert "Dead Feed" in footer
    assert "Broken Feed" in footer


def test_format_digest_slack_fallback_plain_text():
    payloads = format_digest_slack_message("Test Topic", "This is plain text, not JSON.")
    texts = _all_section_texts(payloads)
    assert any("plain text" in t for t in texts)


def test_format_digest_slack_top_n_split():
    """Top-N stories become individual messages; extras go into the tail message."""
    items = [
        {
            "icon": "📰",
            "severity": "high",
            "headline": f"Story {i}",
            "summary": "Detail.",
            "url": f"https://example.com/{i}",
            "art_id": f"A{i}",
        }
        for i in range(1, 6)
    ]
    summary = json.dumps({"overview": "Overview.", "items": items})
    payloads = format_digest_slack_message("Test Topic", summary, meta={"top_stories_count": 3})
    # message 0 = header, messages 1-3 = top stories, message 4 = tail
    assert len(payloads) == 5
    tail_texts = _all_section_texts([payloads[-1]])
    assert "Story 4" in " ".join(tail_texts)
    assert "Story 5" in " ".join(tail_texts)


# ---------------------------------------------------------------------------
# format_digest_plain
# ---------------------------------------------------------------------------


def test_format_digest_plain_has_overview():
    messages = format_digest_plain("Test Topic", _structured_summary())
    assert "Top signal" in _joined_plain(messages)


def test_format_digest_plain_has_headline():
    messages = format_digest_plain("Test Topic", _structured_summary())
    assert "Test Headline" in _joined_plain(messages)


def test_format_digest_plain_has_url():
    messages = format_digest_plain("Test Topic", _structured_summary())
    assert "https://example.com" in _joined_plain(messages)


def test_format_digest_plain_trend_badge():
    item_with_trend = {**_ITEM, "trend": "trending"}
    messages = format_digest_plain(
        "Test Topic", json.dumps({"overview": "", "items": [item_with_trend]})
    )
    assert "🔥" in _joined_plain(messages)


def test_format_digest_plain_meta_footer():
    meta = {
        "sources_ok": 2,
        "sources_total": 4,
        "empty_sources": ["Bad Feed"],
        "chronically_failing": [],
        "deduped_count": 0,
        "coverage_confidence": "medium",
    }
    summary_no_conf = json.dumps({"overview": "Overview.", "items": [_ITEM]})
    messages = format_digest_plain("Test Topic", summary_no_conf, meta=meta)
    combined = _joined_plain(messages)
    assert "2/4" in combined
    assert "Medium" in combined
    assert "Bad Feed" in combined


def test_format_digest_plain_fallback():
    messages = format_digest_plain("Test Topic", "Plain text summary here.")
    assert "Plain text summary here." in _joined_plain(messages)


def test_format_digest_plain_top_n_split():
    """Returns separate messages for each top story and one tail message."""
    items = [
        {
            "icon": "📰",
            "severity": "high",
            "headline": f"Story {i}",
            "summary": "Detail.",
            "url": f"https://example.com/{i}",
            "art_id": f"A{i}",
        }
        for i in range(1, 6)
    ]
    summary = json.dumps({"overview": "Overview.", "items": items})
    messages = format_digest_plain("Test Topic", summary, meta={"top_stories_count": 3})
    # message 0 = header, messages 1-3 = top stories, message 4 = tail
    assert len(messages) == 5
    assert "Story 4" in messages[-1]
    assert "Story 5" in messages[-1]


def test_format_digest_slack_images():
    meta = {"sources_ok": 1, "sources_total": 1, "images": ["https://example.com/chart.png"]}
    payloads = format_digest_slack_message("Solar", _structured_summary(), meta=meta)
    image_blocks = [b for b in _all_slack_blocks(payloads) if b.get("type") == "image"]
    assert len(image_blocks) == 1
    assert image_blocks[0]["image_url"] == "https://example.com/chart.png"


def test_format_digest_slack_images_skips_non_http():
    meta = {"sources_ok": 1, "sources_total": 1, "images": ["not-a-url"]}
    payloads = format_digest_slack_message("Solar", _structured_summary(), meta=meta)
    assert not any(b.get("type") == "image" for b in _all_slack_blocks(payloads))


def test_format_digest_plain_images():
    meta = {"sources_ok": 1, "sources_total": 1, "images": ["https://example.com/chart.png"]}
    messages = format_digest_plain("Solar", _structured_summary(), meta=meta)
    assert "https://example.com/chart.png" in _joined_plain(messages)
