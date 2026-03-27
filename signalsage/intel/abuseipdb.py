"""AbuseIPDB threat intelligence provider."""

import logging
from typing import Optional

import httpx

from signalsage.ioc.models import IOC, IOCType
from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBProvider(BaseProvider):
    name = "AbuseIPDB"
    supported_types = [IOCType.IPV4, IOCType.IPV6]
    requires_key = True

    async def lookup(self, ioc: IOC) -> Optional[IntelResult]:
        if not self.api_key:
            return self._error(ioc, "No API key configured")

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ioc.value,
            "maxAgeInDays": 90,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{_BASE}/check", headers=headers, params=params
                )
                if resp.status_code == 422:
                    return self._error(ioc, "Invalid IP address")
                if resp.status_code == 401:
                    return self._error(ioc, "Invalid API key")
                resp.raise_for_status()
                payload = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("AbuseIPDB lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        data = payload.get("data", {})
        score: int = data.get("abuseConfidenceScore", 0)
        usage_type: str = data.get("usageType", "Unknown") or "Unknown"
        country: str = data.get("countryCode", "XX")
        total_reports: int = data.get("totalReports", 0)
        isp: str = data.get("isp", "Unknown") or "Unknown"
        is_malicious = score > 50

        summary = (
            f"{score}% confidence | {total_reports} reports | "
            f"{usage_type} | {country}"
        )
        if isp:
            summary += f" | {isp}"

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=is_malicious,
            score=score,
            summary=summary,
            details={
                "abuseConfidenceScore": score,
                "usageType": usage_type,
                "countryCode": country,
                "totalReports": total_reports,
                "isp": isp,
                "domain": data.get("domain", ""),
                "isWhitelisted": data.get("isWhitelisted", False),
            },
            report_url=f"https://www.abuseipdb.com/check/{ioc.value}",
        )
