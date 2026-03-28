"""URLScan.io threat intelligence provider — free internet search for IOCs."""

import logging

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://urlscan.io/api/v1"


class URLScanProvider(BaseProvider):
    """Search URLScan.io's database of scanned pages for an IOC.

    Free tier: 10 req/min, 10k/day. No API key required.
    Optional key lifts rate limits — https://urlscan.io/user/profile/
    """

    name = "URLScan"
    supported_types = [IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL]
    requires_key = False

    def _headers(self) -> dict:
        if self.api_key:
            return {"API-Key": self.api_key}
        return {}

    def _query(self, ioc: IOC) -> str:
        if ioc.type == IOCType.IPV4:
            return f"ip:{ioc.value}"
        if ioc.type == IOCType.IPV6:
            return f"ip:{ioc.value}"
        if ioc.type == IOCType.DOMAIN:
            return f"domain:{ioc.value}"
        # URL — search by page URL
        return f'page.url:"{ioc.value}"'

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        query = self._query(ioc)
        params = {"q": query, "size": "10"}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{_BASE}/search/",
                    params=params,
                    headers=self._headers(),
                )
                if err := self._check_status(resp, ioc):
                    return err
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("URLScan lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        results = data.get("results", [])
        total = data.get("total", 0)

        if not results:
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=False,
                summary="No scans found in URLScan.io",
            )

        # Count malicious verdicts across returned scans
        malicious_count = sum(
            1 for r in results if r.get("verdicts", {}).get("overall", {}).get("malicious", False)
        )
        tags: list[str] = []
        for r in results[:3]:
            tags.extend(r.get("verdicts", {}).get("overall", {}).get("tags", []))
        unique_tags = list(dict.fromkeys(tags))[:5]  # deduplicate, keep order

        is_malicious = malicious_count > 0
        summary = f"{total} scan(s) found"
        if malicious_count:
            summary += f" · {malicious_count} flagged malicious"
        if unique_tags:
            summary += f" · Tags: {', '.join(unique_tags)}"

        # Link to the most recent scan result
        latest = results[0]
        report_url = (
            f"https://urlscan.io/result/{latest.get('_id', '')}/" if latest.get("_id") else ""
        )

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=is_malicious,
            score=min(malicious_count * 20, 100),
            summary=summary,
            details={"total_scans": total, "malicious_count": malicious_count, "tags": unique_tags},
            report_url=report_url,
        )
