"""WHOIS domain age provider — flags newly-registered domains."""

import logging
from datetime import UTC, datetime

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

# WhoisXML API — free tier: 500 requests/month. No key = RDAP fallback.
_WHOISXML_URL = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
_RDAP_URL = "https://rdap.org/domain/{domain}"

# Domain younger than this is suspicious
_NEW_DOMAIN_DAYS = 30


def _parse_date(value: str) -> datetime | None:
    """Try common date formats returned by WHOIS/RDAP."""
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%Y/%m/%d",
    ):
        try:
            return datetime.strptime(value[:26], fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


class WHOISAgeProvider(BaseProvider):
    name = "WHOIS Age"
    supported_types = [IOCType.DOMAIN]
    requires_key = False  # uses RDAP by default; WhoisXML key lifts rate limits

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        created: datetime | None = None
        registrar: str = ""
        expires: str = ""

        if self.api_key:
            created, registrar, expires = await self._lookup_whoisxml(ioc)
        else:
            created, registrar, expires = await self._lookup_rdap(ioc)

        if created is None:
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=None,
                summary="Registration date unavailable",
            )

        age_days = (datetime.now(UTC) - created).days
        is_new = age_days < _NEW_DOMAIN_DAYS

        parts = [f"Registered {age_days} days ago ({created.strftime('%Y-%m-%d')})."]
        if registrar:
            parts.append(f" Registrar: {registrar}.")
        if expires:
            parts.append(f" Expires: {expires}.")
        if is_new:
            parts.append(f" ⚠️ Domain is less than {_NEW_DOMAIN_DAYS} days old.")

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=is_new,  # flag new domains as suspicious
            score=max(0, 100 - age_days * 2) if is_new else 0,
            summary="".join(parts),
            details={
                "created": created.isoformat(),
                "age_days": age_days,
                "registrar": registrar,
                "expires": expires,
                "is_new": is_new,
            },
            report_url=f"https://who.is/whois/{ioc.value}",
        )

    async def _lookup_rdap(self, ioc: IOC) -> tuple[datetime | None, str, str]:
        """Use the free RDAP protocol — no key needed."""
        url = _RDAP_URL.format(domain=ioc.value)
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            ) as client:
                resp = await client.get(url)
                if resp.status_code == 404:
                    return None, "", ""
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.debug("RDAP lookup failed for %s: %s", ioc.value, exc)
            return None, "", ""

        created: datetime | None = None
        expires: str = ""
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date_str = event.get("eventDate", "")
            if action == "registration" and date_str:
                created = _parse_date(date_str)
            elif action == "expiration" and date_str:
                expires = date_str[:10]

        registrar = ""
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if isinstance(vcard, list) and len(vcard) > 1:
                    for prop in vcard[1]:
                        if prop[0] == "fn":
                            registrar = prop[3]
                            break

        return created, registrar, expires

    async def _lookup_whoisxml(self, ioc: IOC) -> tuple[datetime | None, str, str]:
        """Use WhoisXML API when a key is configured."""
        params = {
            "apiKey": self.api_key,
            "domainName": ioc.value,
            "outputFormat": "JSON",
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(_WHOISXML_URL, params=params)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.debug("WhoisXML lookup failed for %s: %s", ioc.value, exc)
            return None, "", ""

        record = data.get("WhoisRecord", {})
        reg_data = record.get("registryData", record)

        created_str = reg_data.get("createdDate", "") or record.get("createdDate", "")
        expires_str = reg_data.get("expiresDate", "") or record.get("expiresDate", "")
        registrar = (
            record.get("registrarName", "")
            or reg_data.get("registrarName", "")
        )

        created = _parse_date(created_str) if created_str else None
        expires = expires_str[:10] if expires_str else ""
        return created, registrar, expires
