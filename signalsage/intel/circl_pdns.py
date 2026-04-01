"""CIRCL Passive DNS provider — free, no key required."""

import logging

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://www.circl.lu/pdns/query"


class CIRCLPDNSProvider(BaseProvider):
    name = "CIRCL PDNS"
    supported_types = [IOCType.DOMAIN, IOCType.IPV4]
    # CIRCL PDNS requires a free account — register at https://www.circl.lu/services/passive-dns/
    requires_key = True

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        url = f"{_BASE}/{ioc.value}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                # CIRCL PDNS returns newline-delimited JSON, not a JSON array
                headers={"Accept": "application/json"},
                auth=(self.api_key.split(":", 1)[0], self.api_key.split(":", 1)[1])
                if ":" in (self.api_key or "")
                else None,
            ) as client:
                resp = await client.get(url)
                if resp.status_code == 404:
                    return IntelResult(
                        provider=self.name,
                        ioc_value=ioc.value,
                        ioc_type=ioc.type,
                        malicious=None,
                        summary="No passive DNS records found",
                    )
                if err := self._check_status(resp, ioc):
                    return err
                resp.raise_for_status()
                raw = resp.text.strip()
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("CIRCL PDNS lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        if not raw:
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=None,
                summary="No passive DNS records found",
            )

        # Parse newline-delimited JSON records
        import json

        records: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if not records:
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=None,
                summary="No passive DNS records found",
            )

        # Collect unique rdata values (IPs for domain lookups, domains for IP lookups)
        seen: set[str] = set()
        entries: list[dict] = []
        for r in records:
            rdata = r.get("rdata", "")
            if rdata and rdata not in seen:
                seen.add(rdata)
                entries.append(r)

        # Sort by last_seen descending if available
        entries.sort(key=lambda r: r.get("time_last", ""), reverse=True)

        total = len(entries)
        recent = entries[:6]

        if ioc.type == IOCType.DOMAIN:
            label = "resolved to"
        else:
            label = "hosted"

        values = [e["rdata"].rstrip(".") for e in recent]
        extra = total - len(recent)
        summary = f"{total} unique resolution(s). Recently {label}: {', '.join(values)}"
        if extra:
            summary += f" +{extra} more"

        first_seen = min((r.get("time_first", "") for r in records), default="")
        last_seen = max((r.get("time_last", "") for r in records), default="")

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=None,
            summary=summary,
            details={
                "total_records": total,
                "resolutions": [e["rdata"].rstrip(".") for e in entries[:20]],
                "first_seen": first_seen,
                "last_seen": last_seen,
            },
            report_url=f"https://www.circl.lu/pdns/query/{ioc.value}",
        )
