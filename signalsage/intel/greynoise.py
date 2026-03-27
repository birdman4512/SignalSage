"""GreyNoise threat intelligence provider."""

import logging
from typing import Optional

import httpx

from signalsage.ioc.models import IOC, IOCType
from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_COMMUNITY_BASE = "https://api.greynoise.io/v3/community"


class GreyNoiseProvider(BaseProvider):
    name = "GreyNoise"
    supported_types = [IOCType.IPV4]
    requires_key = False  # Community API works without key (rate-limited)

    async def lookup(self, ioc: IOC) -> Optional[IntelResult]:
        url = f"{_COMMUNITY_BASE}/{ioc.value}"
        headers = {}
        if self.api_key:
            headers["key"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers)

                if resp.status_code == 404:
                    return IntelResult(
                        provider=self.name,
                        ioc_value=ioc.value,
                        ioc_type=ioc.type,
                        malicious=False,
                        summary="Not seen by GreyNoise",
                    )
                if resp.status_code == 429:
                    return self._error(ioc, "Rate limit exceeded")
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("GreyNoise lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        noise: bool = data.get("noise", False)
        riot: bool = data.get("riot", False)
        classification: str = data.get("classification", "unknown")
        name: str = data.get("name", "Unknown")
        last_seen: str = data.get("last_seen", "Unknown")
        link: str = data.get("link", "")

        is_malicious = classification == "malicious"
        summary = f"{classification} | {name} | last seen {last_seen}"
        if riot:
            summary += " | RIOT (known benign)"

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=is_malicious,
            score=80 if is_malicious else (0 if riot else 20),
            summary=summary,
            details={
                "noise": noise,
                "riot": riot,
                "classification": classification,
                "name": name,
                "last_seen": last_seen,
            },
            report_url=link or f"https://viz.greynoise.io/ip/{ioc.value}",
        )
