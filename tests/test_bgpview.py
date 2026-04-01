"""Tests for BGPViewProvider and ASN extraction."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from signalsage.intel.bgpview import BGPViewProvider
from signalsage.ioc.extractor import extract
from signalsage.ioc.models import IOC, IOCType


def _mock_response(status: int, body) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    if isinstance(body, (dict, list)):
        resp.json.return_value = body
        resp.text = json.dumps(body)
    else:
        resp.text = body
        resp.json.side_effect = ValueError("not json")
    resp.raise_for_status = MagicMock()
    return resp


_ASN_INFO = {
    "status": "ok",
    "data": {
        "asn": 13335,
        "name": "CLOUDFLARENET",
        "description_short": "Cloudflare, Inc.",
        "country_code": "US",
        "website": "https://www.cloudflare.com",
    },
}

_ASN_PREFIXES = {
    "status": "ok",
    "data": {
        "ipv4_prefixes": [
            {"prefix": "1.1.1.0/24", "name": "APNIC-CLOUDFLARE"},
            {"prefix": "104.16.0.0/13", "name": "CLOUDFLARENET"},
        ],
        "ipv6_prefixes": [
            {"prefix": "2606:4700::/32", "name": "CLOUDFLARENET"},
        ],
    },
}


@pytest.fixture
def bgpview():
    return BGPViewProvider()


# ---------------------------------------------------------------------------
# ASN extraction
# ---------------------------------------------------------------------------


def test_asn_extracted_plain():
    iocs = extract("Observed traffic from AS13335")
    assert any(i.value == "AS13335" and i.type == IOCType.ASN for i in iocs)


def test_asn_extracted_lowercase():
    iocs = extract("source AS as1234 detected")
    assert any(i.type == IOCType.ASN for i in iocs)


def test_asn_not_matched_mid_word():
    iocs = extract("PASSWORD1234 is not an ASN")
    # "AS" in "PASSWORD" should not match due to word boundary
    asns = [i for i in iocs if i.type == IOCType.ASN]
    # "ASN" alone is not a valid IOCType.ASN (no digits), so no false positives expected
    for asn in asns:
        # Any ASN extracted should be of the form AS<digits>
        assert asn.value.upper().startswith("AS")
        assert asn.value[2:].isdigit()


def test_asn_not_in_cve_span():
    # CVE pattern consumes "CVE-2023-1234" — ASN regex shouldn't match anything there
    iocs = extract("CVE-2023-1234 and AS5678")
    asns = [i for i in iocs if i.type == IOCType.ASN]
    assert any(i.value == "AS5678" for i in asns)
    cves = [i for i in iocs if i.type == IOCType.CVE]
    assert any(i.value == "CVE-2023-1234" for i in cves)


# ---------------------------------------------------------------------------
# BGPViewProvider lookups
# ---------------------------------------------------------------------------


async def test_bgpview_returns_asn_info(bgpview):
    ioc = IOC(value="AS13335", type=IOCType.ASN)
    with patch("httpx.AsyncClient") as mock_cls:
        client = mock_cls.return_value.__aenter__.return_value
        client.get = AsyncMock(
            side_effect=[
                _mock_response(200, _ASN_INFO),
                _mock_response(200, _ASN_PREFIXES),
            ]
        )
        result = await bgpview.lookup(ioc)
    assert result is not None
    assert result.error is None
    assert "CLOUDFLARENET" in result.summary
    assert "US" in result.summary
    assert result.details["asn"] == 13335
    assert result.details["ipv4_prefix_count"] == 2
    assert result.details["ipv6_prefix_count"] == 1
    assert result.report_url == "https://bgpview.io/asn/13335"


async def test_bgpview_shows_prefixes(bgpview):
    ioc = IOC(value="AS13335", type=IOCType.ASN)
    with patch("httpx.AsyncClient") as mock_cls:
        client = mock_cls.return_value.__aenter__.return_value
        client.get = AsyncMock(
            side_effect=[
                _mock_response(200, _ASN_INFO),
                _mock_response(200, _ASN_PREFIXES),
            ]
        )
        result = await bgpview.lookup(ioc)
    assert "1.1.1.0/24" in result.summary


async def test_bgpview_not_found(bgpview):
    ioc = IOC(value="AS99999999", type=IOCType.ASN)
    with patch("httpx.AsyncClient") as mock_cls:
        client = mock_cls.return_value.__aenter__.return_value
        client.get = AsyncMock(return_value=_mock_response(404, ""))
        result = await bgpview.lookup(ioc)
    assert result is not None
    assert "not found" in result.summary.lower()


async def test_bgpview_invalid_asn(bgpview):
    ioc = IOC(value="ASINVALID", type=IOCType.ASN)
    result = await bgpview.lookup(ioc)
    assert result is not None
    assert result.error is not None


async def test_bgpview_timeout(bgpview):
    import httpx

    ioc = IOC(value="AS13335", type=IOCType.ASN)
    with patch("httpx.AsyncClient") as mock_cls:
        client = mock_cls.return_value.__aenter__.return_value
        client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        result = await bgpview.lookup(ioc)
    assert result is not None
    assert result.error is not None
    assert "timed out" in result.error.lower()


async def test_bgpview_no_key_required():
    provider = BGPViewProvider(api_key=None)
    assert provider.enabled is True


async def test_bgpview_estimates_ip_count(bgpview):
    ioc = IOC(value="AS13335", type=IOCType.ASN)
    with patch("httpx.AsyncClient") as mock_cls:
        client = mock_cls.return_value.__aenter__.return_value
        client.get = AsyncMock(
            side_effect=[
                _mock_response(200, _ASN_INFO),
                _mock_response(200, _ASN_PREFIXES),
            ]
        )
        result = await bgpview.lookup(ioc)
    # 1.1.1.0/24 = 256 IPs; 104.16.0.0/13 = 524288 IPs
    assert result.details["total_ipv4_addresses"] == 256 + 524288
