"""Shodan threat intelligence provider."""

import logging

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://api.shodan.io"


class ShodanProvider(BaseProvider):
    name = "Shodan"
    supported_types = [IOCType.IPV4]
    requires_key = True

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        if not self.api_key:
            return self._error(ioc, "No API key configured")

        url = f"{_BASE}/shodan/host/{ioc.value}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, params={"key": self.api_key})
                if resp.status_code == 404:
                    return IntelResult(
                        provider=self.name,
                        ioc_value=ioc.value,
                        ioc_type=ioc.type,
                        malicious=False,
                        summary="No information found",
                    )
                if resp.status_code == 401:
                    return self._error(ioc, "Invalid API key")
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("Shodan lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        ports = data.get("ports", [])
        org = data.get("org", "Unknown")
        country = data.get("country_name", "Unknown")
        tags = data.get("tags", [])
        vulns: dict = data.get("vulns", {})

        ports_str = ", ".join(str(p) for p in sorted(ports)[:10])
        summary = f"Ports: {ports_str} | Org: {org} | Country: {country}"
        if tags:
            summary += f" | Tags: {', '.join(tags[:5])}"
        if vulns:
            cve_list = ", ".join(list(vulns.keys())[:5])
            summary += f" | CVEs: {cve_list}"

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=bool(vulns),
            score=min(len(vulns) * 10, 100) if vulns else 0,
            summary=summary,
            details={
                "ports": ports,
                "org": org,
                "country": country,
                "tags": tags,
                "vulns": list(vulns.keys()),
                "hostnames": data.get("hostnames", []),
            },
            report_url=f"https://www.shodan.io/host/{ioc.value}",
        )
