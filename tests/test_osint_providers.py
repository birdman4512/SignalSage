"""Tests for the four OSINT providers: crt.sh, WHOIS age, CIRCL PDNS, HIBP."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from signalsage.ioc.models import IOC, IOCType
from signalsage.intel.circl_pdns import CIRCLPDNSProvider
from signalsage.intel.crtsh import CRTShProvider
from signalsage.intel.hibp import HIBPProvider
from signalsage.intel.whois_age import WHOISAgeProvider


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


# ---------------------------------------------------------------------------
# crt.sh
# ---------------------------------------------------------------------------


@pytest.fixture
def crtsh():
    return CRTShProvider()


async def test_crtsh_no_certs(crtsh):
    ioc = IOC(value="example.com", type=IOCType.DOMAIN)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=_mock_response(200, [])
        )
        result = await crtsh.lookup(ioc)
    assert result is not None
    assert "No certificates" in result.summary


async def test_crtsh_returns_subdomains(crtsh):
    entries = [
        {"name_value": "mail.example.com\nwww.example.com", "not_before": "2020-01-01T00:00:00Z"},
        {"name_value": "api.example.com", "not_before": "2021-06-01T00:00:00Z"},
    ]
    ioc = IOC(value="example.com", type=IOCType.DOMAIN)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=_mock_response(200, entries)
        )
        result = await crtsh.lookup(ioc)
    assert result is not None
    assert "2 certs" in result.summary
    assert result.details["total_certs"] == 2
    assert "mail.example.com" in result.details["subdomains"]


async def test_crtsh_flags_wildcard(crtsh):
    entries = [{"name_value": "*.example.com", "not_before": "2023-01-01T00:00:00Z"}]
    ioc = IOC(value="example.com", type=IOCType.DOMAIN)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=_mock_response(200, entries)
        )
        result = await crtsh.lookup(ioc)
    assert result is not None
    assert result.details["has_wildcard"] is True
    assert "Wildcard" in result.summary


async def test_crtsh_timeout_returns_error(crtsh):
    import httpx

    ioc = IOC(value="example.com", type=IOCType.DOMAIN)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            side_effect=httpx.TimeoutException("timeout")
        )
        result = await crtsh.lookup(ioc)
    assert result is not None
    assert result.error is not None


# ---------------------------------------------------------------------------
# WHOIS Age
# ---------------------------------------------------------------------------


@pytest.fixture
def whois():
    return WHOISAgeProvider()


_RDAP_RESPONSE = {
    "events": [
        {"eventAction": "registration", "eventDate": "2024-12-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2025-12-01T00:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy"]]],
        }
    ],
}


async def test_whois_age_new_domain_flagged(whois):
    ioc = IOC(value="brandnew.com", type=IOCType.DOMAIN)
    with patch.object(whois, "_lookup_rdap", new=AsyncMock(return_value=(
        __import__("datetime").datetime(2026, 3, 20, tzinfo=__import__("datetime").timezone.utc),
        "GoDaddy",
        "2027-03-20",
    ))):
        result = await whois.lookup(ioc)
    assert result is not None
    assert result.malicious is True
    assert "less than 30 days" in result.summary


async def test_whois_age_old_domain_not_flagged(whois):
    from datetime import UTC, datetime, timedelta

    ioc = IOC(value="old.com", type=IOCType.DOMAIN)
    old_date = datetime.now(UTC) - timedelta(days=3650)
    with patch.object(whois, "_lookup_rdap", new=AsyncMock(return_value=(old_date, "Registrar", ""))):
        result = await whois.lookup(ioc)
    assert result is not None
    assert result.malicious is False


async def test_whois_age_unavailable(whois):
    ioc = IOC(value="unknown.com", type=IOCType.DOMAIN)
    with patch.object(whois, "_lookup_rdap", new=AsyncMock(return_value=(None, "", ""))):
        result = await whois.lookup(ioc)
    assert result is not None
    assert result.malicious is None
    assert "unavailable" in result.summary


# ---------------------------------------------------------------------------
# CIRCL PDNS
# ---------------------------------------------------------------------------


@pytest.fixture
def pdns():
    return CIRCLPDNSProvider(api_key="user:pass")


_PDNS_RECORDS = "\n".join([
    json.dumps({"rdata": "1.2.3.4", "rrtype": "A", "time_first": "2023-01-01", "time_last": "2024-01-01"}),
    json.dumps({"rdata": "5.6.7.8", "rrtype": "A", "time_first": "2022-01-01", "time_last": "2023-06-01"}),
])


async def test_pdns_domain_returns_resolutions(pdns):
    ioc = IOC(value="example.com", type=IOCType.DOMAIN)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=_mock_response(200, _PDNS_RECORDS)
        )
        result = await pdns.lookup(ioc)
    assert result is not None
    assert "1.2.3.4" in result.summary
    assert result.details["total_records"] == 2


async def test_pdns_ip_returns_domains(pdns):
    records = "\n".join([
        json.dumps({"rdata": "evil.com.", "rrtype": "A", "time_first": "2023-01-01", "time_last": "2024-01-01"}),
    ])
    ioc = IOC(value="1.2.3.4", type=IOCType.IPV4)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=_mock_response(200, records)
        )
        result = await pdns.lookup(ioc)
    assert result is not None
    assert "evil.com" in result.summary


async def test_pdns_not_found(pdns):
    ioc = IOC(value="nobody.example", type=IOCType.DOMAIN)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=_mock_response(404, "")
        )
        result = await pdns.lookup(ioc)
    assert result is not None
    assert result.malicious is None
    assert "No passive DNS" in result.summary


async def test_pdns_empty_body(pdns):
    ioc = IOC(value="empty.example", type=IOCType.DOMAIN)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=_mock_response(200, "")
        )
        result = await pdns.lookup(ioc)
    assert result is not None
    assert "No passive DNS" in result.summary


# ---------------------------------------------------------------------------
# HIBP
# ---------------------------------------------------------------------------


@pytest.fixture
def hibp():
    return HIBPProvider(api_key="test-key")


_BREACHES = [
    {
        "Name": "Adobe",
        "BreachDate": "2013-10-04",
        "DataClasses": ["Email addresses", "Passwords"],
        "IsVerified": True,
        "IsSensitive": False,
    },
    {
        "Name": "LinkedIn",
        "BreachDate": "2012-05-05",
        "DataClasses": ["Email addresses", "Passwords", "Usernames"],
        "IsVerified": True,
        "IsSensitive": False,
    },
]


async def test_hibp_found_breaches(hibp):
    ioc = IOC(value="user@example.com", type=IOCType.EMAIL)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=_mock_response(200, _BREACHES)
        )
        result = await hibp.lookup(ioc)
    assert result is not None
    assert result.malicious is True
    assert "2 breach" in result.summary
    assert "Adobe" in result.summary
    assert "Email addresses" in result.summary


async def test_hibp_not_found(hibp):
    ioc = IOC(value="clean@example.com", type=IOCType.EMAIL)
    with patch("httpx.AsyncClient") as mock_cls:
        resp = _mock_response(404, "")
        resp.raise_for_status = MagicMock()
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(return_value=resp)
        result = await hibp.lookup(ioc)
    assert result is not None
    assert result.malicious is False
    assert "No breaches" in result.summary


async def test_hibp_rate_limited(hibp):
    ioc = IOC(value="user@example.com", type=IOCType.EMAIL)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=_mock_response(429, "")
        )
        result = await hibp.lookup(ioc)
    assert result is not None
    assert result.error is not None
    assert "Rate limited" in result.error


async def test_hibp_sensitive_breach_flagged(hibp):
    breaches = [{**_BREACHES[0], "IsSensitive": True}]
    ioc = IOC(value="user@example.com", type=IOCType.EMAIL)
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value.get = AsyncMock(
            return_value=_mock_response(200, breaches)
        )
        result = await hibp.lookup(ioc)
    assert result is not None
    assert "sensitive" in result.summary.lower()


async def test_hibp_disabled_without_key():
    provider = HIBPProvider(api_key=None)
    assert provider.enabled is False


def test_circl_pdns_disabled_without_key():
    provider = CIRCLPDNSProvider(api_key=None)
    assert provider.enabled is False
