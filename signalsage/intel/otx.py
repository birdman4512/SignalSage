"""AlienVault OTX threat intelligence provider."""

import logging
from typing import Optional

import httpx

from signalsage.ioc.models import IOC, IOCType
from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://otx.alienvault.com/api/v1/indicators"


class OTXProvider(BaseProvider):
    name = "AlienVault OTX"
    supported_types = [
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
        IOCType.URL,
    ]
    requires_key = False  # Works unauthenticated but with rate limits

    async def lookup(self, ioc: IOC) -> Optional[IntelResult]:
        url = self._build_url(ioc)
        if not url:
            return None

        headers = {}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 404:
                    return IntelResult(
                        provider=self.name,
                        ioc_value=ioc.value,
                        ioc_type=ioc.type,
                        malicious=False,
                        summary="No pulses found",
                    )
                if resp.status_code == 403:
                    return self._error(ioc, "Access denied — check API key")
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("OTX lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        pulse_info = data.get("pulse_info", {})
        pulse_count: int = pulse_info.get("count", 0)
        reputation: int = data.get("reputation", 0)
        is_malicious = pulse_count > 0

        summary = f"{pulse_count} pulses"
        if reputation:
            summary += f" | reputation score: {reputation}"

        report_url = self._report_url(ioc)

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=is_malicious,
            score=min(pulse_count * 5, 100),
            summary=summary,
            details={
                "pulse_count": pulse_count,
                "reputation": reputation,
                "pulses": [
                    p.get("name", "") for p in pulse_info.get("pulses", [])[:5]
                ],
            },
            report_url=report_url,
        )

    def _build_url(self, ioc: IOC) -> Optional[str]:
        t = ioc.type
        v = ioc.value
        if t == IOCType.IPV4:
            return f"{_BASE}/IPv4/{v}/general"
        if t == IOCType.IPV6:
            return f"{_BASE}/IPv6/{v}/general"
        if t == IOCType.DOMAIN:
            return f"{_BASE}/domain/{v}/general"
        if t in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return f"{_BASE}/file/{v}/general"
        if t == IOCType.URL:
            return f"{_BASE}/url/{v}/general"
        return None

    def _report_url(self, ioc: IOC) -> str:
        t = ioc.type
        v = ioc.value
        base = "https://otx.alienvault.com/indicator"
        if t == IOCType.IPV4:
            return f"{base}/ip/{v}"
        if t == IOCType.IPV6:
            return f"{base}/ip/{v}"
        if t == IOCType.DOMAIN:
            return f"{base}/domain/{v}"
        if t in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return f"{base}/file/{v}"
        if t == IOCType.URL:
            return f"{base}/url/{v}"
        return "https://otx.alienvault.com"
