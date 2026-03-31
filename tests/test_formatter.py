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
    "blurb": "Something bad.",
    "url": "https://example.com",
}


def test_parse_digest_json_structured_object():
    summary = json.dumps({"tldr": ["Key point"], "coverage_confidence": "high", "items": [_ITEM]})
    result = _parse_digest_json(summary)
    assert result is not None
    assert result["tldr"] == ["Key point"]
    assert result["coverage_confidence"] == "high"
    assert len(result["items"]) == 1


def test_parse_digest_json_strips_code_fence():
    summary = "```json\n" + json.dumps({"tldr": [], "items": []}) + "\n```"
    assert _parse_digest_json(summary) is not None


def test_parse_digest_json_bare_shortcode():
    summary = (
        '{"tldr": [], "items": [{"icon": :shield:, "severity": "low", '
        '"headline": "X", "blurb": "Y", "url": null}]}'
    )
    result = _parse_digest_json(summary)
    assert result is not None
    assert result["items"][0]["icon"] == "🛡️"


def test_parse_digest_json_legacy_flat_array():
    summary = json.dumps([_ITEM])
    result = _parse_digest_json(summary)
    assert result is not None
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
    data = {"tldr": ["Top signal"], "coverage_confidence": "high", "items": [_ITEM]}
    data.update(kwargs)
    return json.dumps(data)


def test_format_digest_slack_has_tldr_block():
    payload = format_digest_slack_message("Test Topic", _structured_summary())
    blocks = payload["attachments"][0]["blocks"]
    texts = [b.get("text", {}).get("text", "") for b in blocks if b.get("type") == "section"]
    assert any("Top signal" in t for t in texts)


def test_format_digest_slack_has_item_headline():
    payload = format_digest_slack_message("Test Topic", _structured_summary())
    blocks = payload["attachments"][0]["blocks"]
    texts = [b.get("text", {}).get("text", "") for b in blocks if b.get("type") == "section"]
    assert any("Test Headline" in t for t in texts)


def test_format_digest_slack_read_more_button():
    payload = format_digest_slack_message("Test Topic", _structured_summary())
    blocks = payload["attachments"][0]["blocks"]
    buttons = [
        b.get("accessory", {}) for b in blocks if b.get("type") == "section" and b.get("accessory")
    ]
    assert any(b.get("url") == "https://example.com" for b in buttons)


def test_format_digest_slack_severity_shown():
    payload = format_digest_slack_message("Test Topic", _structured_summary())
    blocks = payload["attachments"][0]["blocks"]
    texts = [b.get("text", {}).get("text", "") for b in blocks if b.get("type") == "section"]
    assert any("Critical" in t for t in texts)


def test_format_digest_slack_trend_badge():
    item_with_trend = {**_ITEM, "trend": "trending"}
    payload = format_digest_slack_message(
        "Test Topic", json.dumps({"tldr": [], "items": [item_with_trend]})
    )
    blocks = payload["attachments"][0]["blocks"]
    texts = [b.get("text", {}).get("text", "") for b in blocks if b.get("type") == "section"]
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
    # Summary without coverage_confidence so meta value is used for the footer
    summary_no_conf = json.dumps({"tldr": ["Top signal"], "items": [_ITEM]})
    payload = format_digest_slack_message("Test Topic", summary_no_conf, meta=meta)
    blocks = payload["attachments"][0]["blocks"]
    context_texts = [
        e["text"] for b in blocks if b.get("type") == "context" for e in b.get("elements", [])
    ]
    footer = " ".join(context_texts)
    assert "3/5" in footer
    assert "Low" in footer
    assert "2 cross-topic" in footer
    assert "Dead Feed" in footer
    assert "Broken Feed" in footer


def test_format_digest_slack_fallback_plain_text():
    payload = format_digest_slack_message("Test Topic", "This is plain text, not JSON.")
    blocks = payload["attachments"][0]["blocks"]
    texts = [b.get("text", {}).get("text", "") for b in blocks if b.get("type") == "section"]
    assert any("plain text" in t for t in texts)


# ---------------------------------------------------------------------------
# format_digest_plain
# ---------------------------------------------------------------------------


def test_format_digest_plain_has_tldr():
    result = format_digest_plain("Test Topic", _structured_summary())
    assert "Top signal" in result


def test_format_digest_plain_has_headline():
    result = format_digest_plain("Test Topic", _structured_summary())
    assert "Test Headline" in result


def test_format_digest_plain_has_url():
    result = format_digest_plain("Test Topic", _structured_summary())
    assert "https://example.com" in result


def test_format_digest_plain_trend_badge():
    item_with_trend = {**_ITEM, "trend": "trending"}
    result = format_digest_plain("Test Topic", json.dumps({"tldr": [], "items": [item_with_trend]}))
    assert "🔥" in result


def test_format_digest_plain_meta_footer():
    meta = {
        "sources_ok": 2,
        "sources_total": 4,
        "empty_sources": ["Bad Feed"],
        "chronically_failing": [],
        "deduped_count": 0,
        "coverage_confidence": "medium",
    }
    # Summary without coverage_confidence so meta value is used for the footer
    summary_no_conf = json.dumps({"tldr": ["Top signal"], "items": [_ITEM]})
    result = format_digest_plain("Test Topic", summary_no_conf, meta=meta)
    assert "2/4" in result
    assert "Medium" in result
    assert "Bad Feed" in result


def test_format_digest_plain_fallback():
    result = format_digest_plain("Test Topic", "Plain text summary here.")
    assert "Plain text summary here." in result
