"""Have I Been Pwned provider — email breach lookups."""

import logging

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://haveibeenpwned.com/api/v3"
_USER_AGENT = "SignalSage-ThreatIntel/1.0"


class HIBPProvider(BaseProvider):
    name = "HIBP"
    supported_types = [IOCType.EMAIL]
    requires_key = True

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        url = f"{_BASE}/breachedaccount/{ioc.value}"
        headers = {
            "hibp-api-key": self.api_key,
            "user-agent": _USER_AGENT,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, params={"truncateResponse": "false"}, headers=headers)
                if resp.status_code == 404:
                    return IntelResult(
                        provider=self.name,
                        ioc_value=ioc.value,
                        ioc_type=ioc.type,
                        malicious=False,
                        score=0,
                        summary="No breaches found for this email address",
                    )
                if err := self._check_status(resp, ioc):
                    return err
                resp.raise_for_status()
                breaches: list[dict] = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("HIBP lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        if not breaches:
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=False,
                score=0,
                summary="No breaches found",
            )

        total = len(breaches)
        # Sort by breach date descending
        breaches_sorted = sorted(breaches, key=lambda b: b.get("BreachDate", ""), reverse=True)
        recent = breaches_sorted[:5]

        names = [b["Name"] for b in recent]
        extra = total - len(names)

        # Collect data classes across all breaches
        data_classes: set[str] = set()
        for b in breaches:
            for dc in b.get("DataClasses", []):
                data_classes.add(dc)

        sensitive = any(b.get("IsSensitive") for b in breaches)
        verified = sum(1 for b in breaches if b.get("IsVerified"))

        summary = f"Found in {total} breach{'es' if total != 1 else ''}: {', '.join(names)}"
        if extra:
            summary += f" +{extra} more"
        if data_classes:
            dc_list = sorted(data_classes)[:6]
            summary += f". Exposed data: {', '.join(dc_list)}"
        if sensitive:
            summary += ". ⚠️ Includes sensitive breach."

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=True,
            score=min(100, total * 10),
            summary=summary,
            details={
                "total_breaches": total,
                "verified_breaches": verified,
                "sensitive": sensitive,
                "breaches": [
                    {
                        "name": b["Name"],
                        "date": b.get("BreachDate", ""),
                        "data_classes": b.get("DataClasses", []),
                    }
                    for b in breaches_sorted[:10]
                ],
                "data_classes": sorted(data_classes),
            },
            report_url=f"https://haveibeenpwned.com/account/{ioc.value}",
        )
