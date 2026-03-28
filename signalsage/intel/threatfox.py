"""ThreatFox threat intelligence provider (abuse.ch)."""

import logging

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_API_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxProvider(BaseProvider):
    name = "ThreatFox"
    supported_types = [
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
        IOCType.URL,
    ]
    requires_key = False

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        # Format value for ThreatFox search
        search_term = self._format_value(ioc)

        payload = {"query": "search_ioc", "search_term": search_term}

        headers = {"Auth-Key": self.api_key} if self.api_key else {}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(_API_URL, json=payload, headers=headers)
                if err := self._check_status(resp, ioc):
                    return err
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("ThreatFox lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        status = data.get("query_status", "no_result")
        if status == "no_result" or not data.get("data"):
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=False,
                summary="Not found in ThreatFox",
            )

        first = data["data"][0]
        malware: str = first.get("malware", "Unknown")
        confidence: int = first.get("confidence_level", 0)
        threat_type: str = first.get("threat_type", "")
        tags = first.get("tags") or []

        summary = f"Malware: {malware}"
        if threat_type:
            summary += f" | Type: {threat_type}"
        summary += f" | Confidence: {confidence}%"
        if tags:
            summary += f" | Tags: {', '.join(str(t) for t in tags[:5])}"

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=True,
            score=confidence,
            summary=summary,
            details={
                "malware": malware,
                "confidence_level": confidence,
                "threat_type": threat_type,
                "tags": tags,
                "ioc_type": first.get("ioc_type", ""),
                "first_seen": first.get("first_seen", ""),
                "last_seen": first.get("last_seen", ""),
            },
            report_url=f"https://threatfox.abuse.ch/ioc/{first.get('id', '')}",
        )

    def _format_value(self, ioc: IOC) -> str:
        """Format IOC value for ThreatFox API search."""
        if ioc.type == IOCType.IPV4:
            # ThreatFox stores IPs as ip:port, search by IP prefix
            return ioc.value
        return ioc.value
