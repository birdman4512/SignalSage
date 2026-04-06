"""Tests for bot command parsing and dispatch."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

from signalsage.bots.commands import (
    Platform,
    _normalize_value,
    handle_digest_command,
    handle_osint_command,
    parse_command,
)

# ---------------------------------------------------------------------------
# parse_command
# ---------------------------------------------------------------------------


def test_parse_command_basic():
    assert parse_command("!digest") == ("digest", [])


def test_parse_command_with_args():
    assert parse_command("!digest cyber") == ("digest", ["cyber"])


def test_parse_command_multiple_args():
    assert parse_command("!digest threat intel") == ("digest", ["threat", "intel"])


def test_parse_command_no_prefix_returns_none():
    assert parse_command("hello world") is None


def test_parse_command_empty_after_prefix_returns_none():
    assert parse_command("!") is None


def test_parse_command_case_normalised():
    cmd, _ = parse_command("!DIGEST")
    assert cmd == "digest"


def test_parse_command_strips_whitespace():
    assert parse_command("  !digest  ") == ("digest", [])


def test_parse_command_slack_mention_prefix():
    assert parse_command("<@U12345> !digest") == ("digest", [])


def test_parse_command_slack_mention_with_args():
    assert parse_command("<@U12345> !digest list") == ("digest", ["list"])


def test_parse_command_slack_mention_no_command():
    # @mention with no command prefix — not a command
    assert parse_command("<@U12345> hello") is None


def test_parse_command_slack_autolinked_domain_arg():
    # Slack wraps typed domains as <http://domain|domain> — display text is extracted
    assert parse_command("!osint domain <http://quirkyit.com.au|quirkyit.com.au>") == (
        "osint",
        ["domain", "quirkyit.com.au"],
    )


def test_parse_command_slack_bare_angle_url():
    # Slack bare URL without display text: <https://evil.com>
    assert parse_command("!osint domain <https://evil.com>") == (
        "osint",
        ["domain", "https://evil.com"],
    )


# ---------------------------------------------------------------------------
# handle_digest_command — no scheduler
# ---------------------------------------------------------------------------


async def test_handle_digest_no_scheduler_warns():
    reply = AsyncMock()
    await handle_digest_command([], None, reply)
    reply.assert_called_once()
    assert "not running" in reply.call_args[0][0].lower()


# ---------------------------------------------------------------------------
# handle_digest_command — list
# ---------------------------------------------------------------------------


async def test_handle_digest_list_shows_topics():
    reply = AsyncMock()
    scheduler = MagicMock()
    next_run = datetime(2026, 4, 1, 6, 0, tzinfo=UTC)
    scheduler.get_topics.return_value = [("Cyber News", ["cyber", "sec"], next_run)]
    await handle_digest_command(["list"], scheduler, reply)
    reply.assert_called_once()
    text = reply.call_args[0][0]
    assert "Cyber News" in text
    assert "cyber" in text
    assert "6:00" in text


async def test_handle_digest_list_empty():
    reply = AsyncMock()
    scheduler = MagicMock()
    scheduler.get_topics.return_value = []
    await handle_digest_command(["list"], scheduler, reply)
    reply.assert_called_once()
    assert "No topics" in reply.call_args[0][0]


# ---------------------------------------------------------------------------
# handle_digest_command — run all
# ---------------------------------------------------------------------------


async def test_handle_digest_all_triggers_run_all():
    reply = AsyncMock()
    scheduler = MagicMock()
    scheduler.get_topic_names.return_value = ["Topic A", "Topic B"]
    scheduler.run_all_now = AsyncMock()
    await handle_digest_command([], scheduler, reply)
    scheduler.run_all_now.assert_called_once()


async def test_handle_digest_explicit_all():
    reply = AsyncMock()
    scheduler = MagicMock()
    scheduler.get_topic_names.return_value = ["Topic A"]
    scheduler.run_all_now = AsyncMock()
    await handle_digest_command(["all"], scheduler, reply)
    scheduler.run_all_now.assert_called_once()


# ---------------------------------------------------------------------------
# handle_digest_command — run by tag/name
# ---------------------------------------------------------------------------


async def test_handle_digest_by_tag_found():
    reply = AsyncMock()
    scheduler = MagicMock()
    scheduler.run_topic_now = AsyncMock(return_value=True)
    await handle_digest_command(["cyber"], scheduler, reply)
    scheduler.run_topic_now.assert_called_once_with("cyber", progress=reply, override_channel=None)


async def test_handle_digest_by_tag_not_found_lists_available():
    reply = AsyncMock()
    scheduler = MagicMock()
    scheduler.run_topic_now = AsyncMock(return_value=False)
    scheduler.get_topic_names.return_value = ["Cyber News", "Vuln Alerts"]
    await handle_digest_command(["missing"], scheduler, reply)
    # First call: "running…", second call: "no match" with listing
    assert reply.call_count == 2
    final_msg = reply.call_args[0][0]
    assert "Cyber News" in final_msg


# ---------------------------------------------------------------------------
# handle_digest_command — help
# ---------------------------------------------------------------------------


async def test_handle_digest_help():
    reply = AsyncMock()
    scheduler = MagicMock()
    await handle_digest_command(["help"], scheduler, reply)
    reply.assert_called_once()
    assert "digest" in reply.call_args[0][0].lower()


# ---------------------------------------------------------------------------
# _normalize_value — URL scheme stripping for !osint domain / ip
# ---------------------------------------------------------------------------


def test_normalize_domain_strips_https():
    assert _normalize_value("domain", "https://quirkyit.com.au") == "quirkyit.com.au"


def test_normalize_domain_strips_http():
    assert _normalize_value("domain", "http://evil.com") == "evil.com"


def test_normalize_domain_strips_path():
    assert _normalize_value("domain", "https://evil.com/some/path?q=1") == "evil.com"


def test_normalize_domain_bare_unchanged():
    assert _normalize_value("domain", "quirkyit.com.au") == "quirkyit.com.au"


def test_normalize_ip_strips_scheme():
    assert _normalize_value("ip", "https://185.220.101.45") == "185.220.101.45"


def test_normalize_ip_bare_unchanged():
    assert _normalize_value("ip", "8.8.8.8") == "8.8.8.8"


def test_normalize_email_unchanged():
    # email subcommand should not strip anything
    assert _normalize_value("email", "https://notanemail@example.com") == "https://notanemail@example.com"


# ---------------------------------------------------------------------------
# handle_osint_command — platform-aware formatting
# ---------------------------------------------------------------------------


async def test_osint_discord_uses_markdown_bold():
    """Discord responses should use **bold** not *bold*."""
    reply = AsyncMock()
    processor = MagicMock()
    from signalsage.intel.base import IntelResult
    from signalsage.ioc.models import IOCType

    processor.lookup_ioc = AsyncMock(
        return_value=[
            IntelResult(
                provider="URLScan",
                ioc_value="evil.com",
                ioc_type=IOCType.DOMAIN,
                malicious=False,
                summary="No scans found",
                report_url="https://urlscan.io/result/abc/",
            )
        ]
    )
    await handle_osint_command(["domain", "evil.com"], processor, reply, platform=Platform.DISCORD)
    full_text = " ".join(call[0][0] for call in reply.call_args_list)
    assert "**URLScan**" in full_text
    assert "[View report]" in full_text  # Discord markdown link, not Slack <url|text>


async def test_osint_slack_uses_mrkdwn_bold():
    """Slack responses should use *bold* and <url|text> links."""
    reply = AsyncMock()
    processor = MagicMock()
    from signalsage.intel.base import IntelResult
    from signalsage.ioc.models import IOCType

    processor.lookup_ioc = AsyncMock(
        return_value=[
            IntelResult(
                provider="URLScan",
                ioc_value="evil.com",
                ioc_type=IOCType.DOMAIN,
                malicious=False,
                summary="No scans found",
                report_url="https://urlscan.io/result/abc/",
            )
        ]
    )
    await handle_osint_command(["domain", "evil.com"], processor, reply, platform=Platform.SLACK)
    full_text = " ".join(call[0][0] for call in reply.call_args_list)
    assert "*URLScan*" in full_text
    assert "<https://urlscan.io/result/abc/|View report>" in full_text


async def test_osint_domain_normalises_https_input():
    """!osint domain https://evil.com should look up evil.com, not the full URL."""
    reply = AsyncMock()
    processor = MagicMock()
    from signalsage.intel.base import IntelResult
    from signalsage.ioc.models import IOCType

    captured = []

    async def fake_lookup(ioc):
        captured.append(ioc)
        return [IntelResult(provider="Test", ioc_value=ioc.value, ioc_type=ioc.type, summary="ok")]

    processor.lookup_ioc = fake_lookup
    await handle_osint_command(
        ["domain", "https://evil.com/path?q=1"], processor, reply, platform=Platform.DISCORD
    )
    assert captured[0].value == "evil.com"
