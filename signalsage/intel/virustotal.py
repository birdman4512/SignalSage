"""VirusTotal threat intelligence provider."""

import base64
import logging

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://www.virustotal.com/api/v3"
_GUI_BASE = "https://www.virustotal.com/gui"


class VirusTotalProvider(BaseProvider):
    name = "VirusTotal"
    supported_types = [
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
        IOCType.SHA512,
    ]
    requires_key = True

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        if not self.api_key:
            return self._error(ioc, "No API key configured")

        headers = {"x-apikey": self.api_key}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if ioc.type in (IOCType.IPV4, IOCType.IPV6):
                    return await self._lookup_ip(client, ioc, headers)
                elif ioc.type == IOCType.DOMAIN:
                    return await self._lookup_domain(client, ioc, headers)
                elif ioc.type == IOCType.URL:
                    return await self._lookup_url(client, ioc, headers)
                else:
                    return await self._lookup_hash(client, ioc, headers)
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("VirusTotal lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

    async def _lookup_ip(self, client: httpx.AsyncClient, ioc: IOC, headers: dict) -> IntelResult:
        resp = await client.get(f"{_BASE}/ip_addresses/{ioc.value}", headers=headers)
        if resp.status_code == 404:
            return self._error(ioc, "Not found")
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        result = self._parse_stats(ioc, stats)
        result.report_url = f"{_GUI_BASE}/ip-address/{ioc.value}"
        result.details = {
            "country": data.get("country", ""),
            "as_owner": data.get("as_owner", ""),
            "network": data.get("network", ""),
        }
        return result

    async def _lookup_domain(
        self, client: httpx.AsyncClient, ioc: IOC, headers: dict
    ) -> IntelResult:
        resp = await client.get(f"{_BASE}/domains/{ioc.value}", headers=headers)
        if resp.status_code == 404:
            return self._error(ioc, "Not found")
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        result = self._parse_stats(ioc, stats)
        result.report_url = f"{_GUI_BASE}/domain/{ioc.value}"
        result.details = {
            "registrar": data.get("registrar", ""),
            "creation_date": data.get("creation_date", ""),
            "categories": data.get("categories", {}),
        }
        return result

    async def _lookup_url(self, client: httpx.AsyncClient, ioc: IOC, headers: dict) -> IntelResult:
        url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
        resp = await client.get(f"{_BASE}/urls/{url_id}", headers=headers)
        if resp.status_code == 404:
            return self._error(ioc, "Not found")
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        result = self._parse_stats(ioc, stats)
        result.report_url = f"{_GUI_BASE}/url/{url_id}"
        return result

    async def _lookup_hash(self, client: httpx.AsyncClient, ioc: IOC, headers: dict) -> IntelResult:
        resp = await client.get(f"{_BASE}/files/{ioc.value}", headers=headers)
        if resp.status_code == 404:
            return self._error(ioc, "Not found")
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        result = self._parse_stats(ioc, stats)
        result.report_url = f"{_GUI_BASE}/file/{ioc.value}"
        result.details = {
            "type_description": data.get("type_description", ""),
            "name": (data.get("names") or [""])[0],
            "size": data.get("size", 0),
            "signature_info": data.get("signature_info", {}),
        }
        return result

    def _parse_stats(self, ioc: IOC, stats: dict) -> IntelResult:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        score = int((malicious / total) * 100) if total else 0
        is_malicious = malicious > 0

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=is_malicious,
            score=score,
            summary=f"{malicious}/{total} detections"
            + (f" ({suspicious} suspicious)" if suspicious else ""),
            details={"stats": stats},
        )
