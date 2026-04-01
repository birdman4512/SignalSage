"""crt.sh certificate transparency provider — free, no key required."""

import logging
from datetime import UTC, datetime

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://crt.sh"


class CRTShProvider(BaseProvider):
    name = "crt.sh"
    supported_types = [IOCType.DOMAIN]
    requires_key = False

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        # Query for the domain and all subdomains
        params = {"q": f"%.{ioc.value}", "output": "json"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(_BASE, params=params)
                if err := self._check_status(resp, ioc):
                    return err
                resp.raise_for_status()
                entries: list[dict] = resp.json()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("crt.sh lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        if not entries:
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=None,
                summary="No certificates found in transparency logs",
            )

        # Collect unique SANs / CNs
        names: set[str] = set()
        issuers: set[str] = set()
        earliest: datetime | None = None

        for entry in entries:
            name_val = entry.get("name_value", "")
            for n in name_val.splitlines():
                n = n.strip().lstrip("*.")
                if n:
                    names.add(n.lower())
            issuer = entry.get("issuer_ca_id")
            if issuer:
                issuers.add(str(issuer))
            # Track earliest cert issuance
            not_before = entry.get("not_before", "")
            if not_before:
                try:
                    dt = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                    if earliest is None or dt < earliest:
                        earliest = dt
                except ValueError:
                    pass

        subdomains = sorted(n for n in names if n != ioc.value)
        total_certs = len(entries)
        unique_names = len(names)

        # Flag wildcard certs
        has_wildcard = any(
            ("*." + ioc.value) in (e.get("name_value", "")) for e in entries
        )

        age_str = ""
        if earliest:
            days_old = (datetime.now(UTC) - earliest).days
            age_str = f"First cert {days_old} days ago. "

        summary_parts = [f"{total_certs} certs, {unique_names} unique names. {age_str}"]
        if has_wildcard:
            summary_parts.append("⚠️ Wildcard cert found. ")
        if subdomains:
            shown = subdomains[:8]
            extra = len(subdomains) - len(shown)
            summary_parts.append(
                "Subdomains: " + ", ".join(shown) + (f" +{extra} more" if extra else "")
            )

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=None,
            summary="".join(summary_parts),
            details={
                "total_certs": total_certs,
                "unique_names": unique_names,
                "subdomains": subdomains[:20],
                "has_wildcard": has_wildcard,
                "first_seen": earliest.isoformat() if earliest else None,
            },
            report_url=f"https://crt.sh/?q=%.{ioc.value}",
        )
