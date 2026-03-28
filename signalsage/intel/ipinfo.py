"""IPInfo threat intelligence provider."""

import logging

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://ipinfo.io"


class IPInfoProvider(BaseProvider):
    name = "IPInfo"
    supported_types = [IOCType.IPV4, IOCType.IPV6]
    requires_key = False  # Works without key, optional for higher rate limits

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        params = {}
        if self.api_key:
            params["token"] = self.api_key

        url = f"{_BASE}/{ioc.value}/json"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 404:
                    return IntelResult(
                        provider=self.name,
                        ioc_value=ioc.value,
                        ioc_type=ioc.type,
                        malicious=None,
                        summary="Not found",
                    )
                if resp.status_code == 429:
                    return self._error(ioc, "Rate limit exceeded — provide an API key")
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("IPInfo lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        # Check for bogon IP
        if data.get("bogon"):
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=False,
                summary="Bogon/reserved IP address",
                details={"bogon": True},
            )

        org: str = data.get("org", "Unknown") or "Unknown"
        city: str = data.get("city", "") or ""
        region: str = data.get("region", "") or ""
        country: str = data.get("country", "XX") or "XX"
        hostname: str = data.get("hostname", "") or ""
        timezone: str = data.get("timezone", "") or ""

        location_parts = [p for p in [city, region, country] if p]
        summary = f"{' | '.join(location_parts)} | {org}"
        if hostname:
            summary += f" | {hostname}"

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=None,  # IPInfo doesn't classify as malicious
            summary=summary,
            details={
                "org": org,
                "city": city,
                "region": region,
                "country": country,
                "hostname": hostname,
                "timezone": timezone,
                "loc": data.get("loc", ""),
                "postal": data.get("postal", ""),
            },
            report_url=f"https://ipinfo.io/{ioc.value}",
        )
