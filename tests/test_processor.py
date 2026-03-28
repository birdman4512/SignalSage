"""Tests for the IOC processor."""

from unittest.mock import AsyncMock, MagicMock

from signalsage.intel.base import BaseProvider, IntelResult
from signalsage.ioc.models import IOCType
from signalsage.ioc.processor import IOCProcessor


def _make_provider(name: str = "Mock", malicious: bool = True) -> MagicMock:
    provider = MagicMock(spec=BaseProvider)
    provider.enabled = True
    provider.name = name
    provider.supports.return_value = True
    provider.lookup = AsyncMock(
        return_value=IntelResult(
            provider=name,
            ioc_value="8.8.8.8",
            ioc_type=IOCType.IPV4,
            malicious=malicious,
            summary=f"{name} result",
        )
    )
    return provider


# ---------------------------------------------------------------------------
# Basic processing
# ---------------------------------------------------------------------------


async def test_process_no_iocs():
    processor = IOCProcessor([_make_provider()])
    results = await processor.process("hello world, nothing suspicious here")
    assert results == []


async def test_process_finds_ip():
    provider = _make_provider()
    processor = IOCProcessor([provider])
    results = await processor.process("C2 server: 185.220.101.45")
    assert len(results) == 1
    ioc, intel = results[0]
    assert ioc.type == IOCType.IPV4
    assert ioc.value == "185.220.101.45"


async def test_process_returns_intel_results():
    provider = _make_provider("VT")
    processor = IOCProcessor([provider])
    results = await processor.process("bad IP: 185.220.101.45")
    _, intel = results[0]
    assert len(intel) == 1
    assert intel[0].provider == "VT"


# ---------------------------------------------------------------------------
# IOC limit
# ---------------------------------------------------------------------------


async def test_max_iocs_per_message():
    provider = _make_provider()
    processor = IOCProcessor([provider], max_per_msg=2)
    text = "IPs: 8.8.8.8 1.1.1.1 185.220.101.45 91.108.4.1"
    results = await processor.process(text)
    assert len(results) <= 2


async def test_max_iocs_default_is_five():
    provider = _make_provider()
    processor = IOCProcessor([provider])
    # 7 distinct public IPs
    ips = [
        "8.8.8.8",
        "1.1.1.1",
        "185.220.101.45",
        "91.108.4.1",
        "104.21.0.1",
        "172.217.0.1",
        "13.107.42.14",
    ]
    text = " ".join(ips)
    results = await processor.process(text)
    assert len(results) <= 5


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


async def test_cache_avoids_duplicate_lookups():
    provider = _make_provider()
    processor = IOCProcessor([provider], cache_ttl=60)

    await processor.process("IP: 8.8.8.8")
    await processor.process("IP: 8.8.8.8")

    # Provider should have been called only once despite two process() calls
    assert provider.lookup.call_count == 1


# ---------------------------------------------------------------------------
# Provider errors are handled gracefully
# ---------------------------------------------------------------------------


async def test_provider_exception_handled():
    provider = _make_provider()
    provider.lookup = AsyncMock(side_effect=RuntimeError("network error"))

    processor = IOCProcessor([provider])
    results = await processor.process("IP: 8.8.8.8")
    # Should still return a result entry, just with empty intel
    assert len(results) == 1
    _, intel = results[0]
    assert intel == []


# ---------------------------------------------------------------------------
# Disabled provider is skipped
# ---------------------------------------------------------------------------


async def test_disabled_provider_skipped():
    provider = _make_provider()
    provider.enabled = False

    processor = IOCProcessor([provider])
    results = await processor.process("IP: 8.8.8.8")
    # No applicable providers → IOC is suppressed entirely
    assert results == []
    provider.lookup.assert_not_called()


# ---------------------------------------------------------------------------
# Provider that doesn't support IOC type is skipped
# ---------------------------------------------------------------------------


async def test_provider_unsupported_type_skipped():
    provider = _make_provider()
    provider.supports.return_value = False  # doesn't support anything

    processor = IOCProcessor([provider])
    results = await processor.process("IP: 8.8.8.8")
    # No applicable providers → IOC is suppressed entirely
    assert results == []
    provider.lookup.assert_not_called()
