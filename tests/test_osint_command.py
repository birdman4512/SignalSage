"""Tests for the !osint command handler."""

from unittest.mock import AsyncMock, MagicMock

from signalsage.bots.commands import handle_osint_command
from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOCType


def _make_processor(results=None):
    processor = MagicMock()
    processor.lookup_ioc = AsyncMock(return_value=results or [])
    return processor


async def test_osint_no_args_shows_usage():
    reply = AsyncMock()
    await handle_osint_command([], _make_processor(), reply)
    reply.assert_called_once()
    assert "Usage" in reply.call_args[0][0]


async def test_osint_one_arg_shows_usage():
    reply = AsyncMock()
    await handle_osint_command(["email"], _make_processor(), reply)
    reply.assert_called_once()
    assert "Usage" in reply.call_args[0][0]


async def test_osint_unknown_subcommand():
    reply = AsyncMock()
    await handle_osint_command(["phone", "123"], _make_processor(), reply)
    reply.assert_called_once()
    assert "Unknown" in reply.call_args[0][0]


async def test_osint_no_results():
    reply = AsyncMock()
    await handle_osint_command(["email", "user@example.com"], _make_processor([]), reply)
    assert reply.call_count == 2  # "running…" + "no results"
    assert "No OSINT results" in reply.call_args[0][0]


async def test_osint_email_calls_lookup_with_email_type():
    reply = AsyncMock()
    processor = _make_processor()
    await handle_osint_command(["email", "user@example.com"], processor, reply)
    called_ioc = processor.lookup_ioc.call_args[0][0]
    assert called_ioc.type == IOCType.EMAIL
    assert called_ioc.value == "user@example.com"


async def test_osint_domain_calls_lookup_with_domain_type():
    reply = AsyncMock()
    processor = _make_processor()
    await handle_osint_command(["domain", "example.com"], processor, reply)
    called_ioc = processor.lookup_ioc.call_args[0][0]
    assert called_ioc.type == IOCType.DOMAIN


async def test_osint_ip_calls_lookup_with_ipv4_type():
    reply = AsyncMock()
    processor = _make_processor()
    await handle_osint_command(["ip", "1.2.3.4"], processor, reply)
    called_ioc = processor.lookup_ioc.call_args[0][0]
    assert called_ioc.type == IOCType.IPV4


async def test_osint_formats_results():
    result = IntelResult(
        provider="HIBP",
        ioc_value="user@example.com",
        ioc_type=IOCType.EMAIL,
        malicious=True,
        summary="Found in 3 breaches: Adobe, LinkedIn, Yahoo",
        report_url="https://haveibeenpwned.com/account/user@example.com",
    )
    reply = AsyncMock()
    await handle_osint_command(["email", "user@example.com"], _make_processor([result]), reply)
    # First call: "running…", second: results
    final = reply.call_args[0][0]
    assert "HIBP" in final
    assert "Found in 3 breaches" in final


async def test_osint_formats_errors():
    result = IntelResult(
        provider="HIBP",
        ioc_value="user@example.com",
        ioc_type=IOCType.EMAIL,
        error="Rate limited",
    )
    reply = AsyncMock()
    await handle_osint_command(["email", "user@example.com"], _make_processor([result]), reply)
    final = reply.call_args[0][0]
    assert "Rate limited" in final
