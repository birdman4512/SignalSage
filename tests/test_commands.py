"""Tests for bot command parsing and dispatch."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

from signalsage.bots.commands import handle_digest_command, parse_command

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
    scheduler.run_topic_now.assert_called_once_with("cyber", progress=reply)


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
