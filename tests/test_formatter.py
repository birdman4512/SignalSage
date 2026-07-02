"""Tests for the message formatter."""

import json

from signalsage.bots.formatter import (
    _clean_icon,
    _parse_digest_json,
    format_digest_plain,
    format_digest_slack_message,
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


def test_parse_digest_json_overview_only_object():
    """Small models sometimes stop after the overview — render it, not raw JSON."""
    summary = '{"overview": "Tonight we look at solar activity."}'
    result = _parse_digest_json(summary)
    assert result is not None
    assert result["overview"] == "Tonight we look at solar activity."
    assert result["items"] == []


def test_parse_digest_json_truncated_overview_recovered():
    """JSON cut off mid-overview by a token limit still yields the overview text."""
    summary = '{"overview": "We begin tonight with news out of the AI world that'
    result = _parse_digest_json(summary)
    assert result is not None
    assert result["overview"].startswith("We begin tonight")
    assert result["items"] == []


def test_parse_digest_json_truncated_items_keeps_overview():
    """Truncation recovery salvages complete items AND the overview."""
    item = '{"art_id": "A1", "icon": "🔴", "headline": "X", "summary": "Y", "url": ""}'
    summary = '{"overview": "The big picture.", "items": [' + item + ', {"art_id": "A2", "head'
    result = _parse_digest_json(summary)
    assert result is not None
    assert result["overview"] == "The big picture."
    assert len(result["items"]) == 1


def test_clean_icon_strips_junk_wrapping():
    assert _clean_icon("%(🔴)%") == "🔴"
    assert _clean_icon("🛡️") == "🛡️"
    assert _clean_icon("⚠️ advisory") == "⚠️"
    assert _clean_icon("critical") == "📰"
    assert _clean_icon("") == "📰"
    assert _clean_icon(None) == "📰"


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
    """Top-N stories become individual messages; extras become links in the header."""
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
    # message 0 = header (overview + remaining-story links), messages 1-3 = top stories
    assert len(payloads) == 4
    header_texts = " ".join(_all_section_texts([payloads[0]]))
    assert "More Stories" in header_texts
    assert "Story 4" in header_texts
    assert "Story 5" in header_texts


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
    """Returns a header message (with remaining-story links) plus one message per top story."""
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
    # message 0 = header (overview + remaining-story links), messages 1-3 = top stories
    assert len(messages) == 4
    assert "More Stories" in messages[0]
    assert "Story 4" in messages[0]
    assert "Story 5" in messages[0]


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
