"""CIRCL CVE Search threat intelligence provider."""

import logging
from typing import Optional

import httpx

from signalsage.ioc.models import IOC, IOCType
from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://cve.circl.lu/api/cve"


class CIRCLCVEProvider(BaseProvider):
    name = "CIRCL CVE"
    supported_types = [IOCType.CVE]
    requires_key = False

    async def lookup(self, ioc: IOC) -> Optional[IntelResult]:
        url = f"{_BASE}/{ioc.value.upper()}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
                if resp.status_code == 404:
                    return IntelResult(
                        provider=self.name,
                        ioc_value=ioc.value,
                        ioc_type=ioc.type,
                        malicious=None,
                        summary="CVE not found in CIRCL database",
                    )
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("CIRCL CVE lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        if not data:
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=None,
                summary="No data returned",
            )

        # Parse CVSS score — try CVSSv3 first, then CVSSv2
        cvss_score: Optional[float] = None
        cvss_str = ""
        if data.get("cvss3"):
            cvss_score = float(data["cvss3"])
            cvss_str = f"CVSSv3 {cvss_score}"
        elif data.get("cvss"):
            cvss_score = float(data["cvss"])
            cvss_str = f"CVSSv2 {cvss_score}"

        description: str = data.get("summary", "") or ""
        references: list = data.get("references", [])[:3]
        cwe: str = data.get("cwe", "") or ""

        summary = ""
        if cvss_str:
            summary += f"{cvss_str} — "
        summary += description[:200]
        if not summary:
            summary = "No description available"

        is_malicious = (cvss_score is not None and cvss_score >= 7.0)

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=is_malicious,
            score=int(cvss_score * 10) if cvss_score is not None else None,
            summary=summary,
            details={
                "cvss": cvss_score,
                "cwe": cwe,
                "references": references,
                "published": data.get("Published", ""),
                "modified": data.get("Modified", ""),
                "vulnerable_products": data.get("vulnerable_product", [])[:5],
            },
            report_url=f"https://cve.circl.lu/cve/{ioc.value.upper()}",
        )
