"""Tests for VirusTotal provider — including passive DNS enrichment."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

from signalsage.intel.virustotal import VirusTotalProvider
from signalsage.ioc.models import IOC, IOCType


def _mock_response(status: int, body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body
    resp.text = json.dumps(body)
    resp.raise_for_status = MagicMock()
    return resp


_IP_DATA = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 3,
                "suspicious": 1,
                "harmless": 60,
                "undetected": 10,
            },
            "country": "US",
            "as_owner": "CLOUDFLARENET",
            "network": "1.1.1.0/24",
        }
    }
}

_IP_RESOLUTIONS = {
    "data": [
        {"attributes": {"host_name": "evil.example.com", "date": "2024-01-01"}},
        {"attributes": {"host_name": "also-evil.example.com", "date": "2023-12-01"}},
    ]
}

_DOMAIN_DATA = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 70,
                "undetected": 5,
            },
            "registrar": "GoDaddy",
            "creation_date": 1577836800,
            "categories": {},
        }
    }
}

_DOMAIN_RESOLUTIONS = {
    "data": [
        {"attributes": {"ip_address": "185.220.101.45", "date": "2024-01-01"}},
        {"attributes": {"ip_address": "91.108.4.1", "date": "2023-11-01"}},
    ]
}


async def test_ip_lookup_includes_passive_dns():
    provider = VirusTotalProvider(api_key="test-key")
    ioc = IOC(value="1.1.1.1", type=IOCType.IPV4)
    with patch("httpx.AsyncClient") as mock_cls:
        client = mock_cls.return_value.__aenter__.return_value
        client.get = AsyncMock(
            side_effect=[
                _mock_response(200, _IP_DATA),
                _mock_response(200, _IP_RESOLUTIONS),
            ]
        )
        result = await provider.lookup(ioc)
    assert result is not None
    assert result.error is None
    assert "evil.example.com" in result.summary
    assert "passive_dns" in result.details
    assert "evil.example.com" in result.details["passive_dns"]


async def test_domain_lookup_includes_passive_dns():
    provider = VirusTotalProvider(api_key="test-key")
    ioc = IOC(value="example.com", type=IOCType.DOMAIN)
    with patch("httpx.AsyncClient") as mock_cls:
        client = mock_cls.return_value.__aenter__.return_value
        client.get = AsyncMock(
            side_effect=[
                _mock_response(200, _DOMAIN_DATA),
                _mock_response(200, _DOMAIN_RESOLUTIONS),
            ]
        )
        result = await provider.lookup(ioc)
    assert result is not None
    assert result.error is None
    assert "185.220.101.45" in result.summary
    assert "passive_dns" in result.details


async def test_passive_dns_silently_skipped_on_rate_limit():
    """A 429 on the resolutions endpoint should not break the main result."""
    provider = VirusTotalProvider(api_key="test-key")
    ioc = IOC(value="1.1.1.1", type=IOCType.IPV4)
    with patch("httpx.AsyncClient") as mock_cls:
        client = mock_cls.return_value.__aenter__.return_value
        client.get = AsyncMock(
            side_effect=[
                _mock_response(200, _IP_DATA),
                _mock_response(429, {}),
            ]
        )
        result = await provider.lookup(ioc)
    assert result is not None
    assert result.error is None
    # No passive DNS added, but main result still present
    assert "passive_dns" not in result.details


async def test_passive_dns_silently_skipped_on_exception():
    """An exception on the resolutions endpoint should not break the main result."""
    provider = VirusTotalProvider(api_key="test-key")
    ioc = IOC(value="1.1.1.1", type=IOCType.IPV4)

    async def _side_effect(url, **kwargs):
        if "resolutions" in url:
            raise RuntimeError("network failure")
        return _mock_response(200, _IP_DATA)

    with patch("httpx.AsyncClient") as mock_cls:
        client = mock_cls.return_value.__aenter__.return_value
        client.get = AsyncMock(side_effect=_side_effect)
        result = await provider.lookup(ioc)
    assert result is not None
    assert result.error is None
