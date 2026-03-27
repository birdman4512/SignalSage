"""Tests for the message formatter."""

import pytest
from signalsage.ioc.models import IOC, IOCType
from signalsage.intel.base import IntelResult
from signalsage.bots.formatter import Platform, format_results, split_message


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
    assert "<https://vt.example/abc|details>" in msg


def test_discord_link():
    msg = format_results(_ioc(), [_result(report_url="https://vt.example/abc")], Platform.DISCORD)
    assert "[details](https://vt.example/abc)" in msg


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
