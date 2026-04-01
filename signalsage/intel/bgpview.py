"""BGPView ASN enrichment provider — free, no key required."""

import logging

import httpx

from signalsage.ioc.models import IOC, IOCType

from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://api.bgpview.io"


class BGPViewProvider(BaseProvider):
    name = "BGPView"
    supported_types = [IOCType.ASN]
    requires_key = False

    async def lookup(self, ioc: IOC) -> IntelResult | None:
        # Normalize: strip "AS" prefix to get the number
        raw_val = ioc.value.upper()
        asn_str = raw_val.lstrip("AS").strip()
        try:
            asn_num = int(asn_str)
        except ValueError:
            return self._error(ioc, f"Invalid ASN: {ioc.value}")

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                info_resp = await client.get(f"{_BASE}/asn/{asn_num}")
                if info_resp.status_code == 404:
                    return IntelResult(
                        provider=self.name,
                        ioc_value=ioc.value,
                        ioc_type=ioc.type,
                        malicious=None,
                        summary="ASN not found",
                    )
                if err := self._check_status(info_resp, ioc):
                    return err
                info_resp.raise_for_status()
                info = info_resp.json().get("data", {})

                prefix_resp = await client.get(f"{_BASE}/asn/{asn_num}/prefixes")
                prefix_resp.raise_for_status()
                prefix_data = prefix_resp.json().get("data", {})
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("BGPView lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

        name = info.get("name", "")
        description = info.get("description_short", "") or (info.get("description_full") or [""])[0]
        country = info.get("country_code", "")

        ipv4_prefixes: list[dict] = prefix_data.get("ipv4_prefixes", [])
        ipv6_prefixes: list[dict] = prefix_data.get("ipv6_prefixes", [])

        # Estimate total IPs from IPv4 prefix sizes
        total_ipv4 = 0
        for p in ipv4_prefixes:
            prefix = p.get("prefix", "")
            if "/" in prefix:
                try:
                    bits = int(prefix.split("/")[1])
                    total_ipv4 += 2 ** (32 - bits)
                except (ValueError, IndexError):
                    pass

        prefix_list = [p.get("prefix", "") for p in ipv4_prefixes[:10]]
        extra = len(ipv4_prefixes) - len(prefix_list)

        summary = f"{name} ({country})"
        if description and description != name:
            summary += f" — {description}"
        summary += f"\nIPv4 prefixes: {len(ipv4_prefixes)}"
        if total_ipv4:
            summary += f" (~{total_ipv4:,} IPs)"
        if prefix_list:
            summary += f"\n{', '.join(prefix_list)}"
            if extra:
                summary += f" +{extra} more"
        if ipv6_prefixes:
            summary += f"\nIPv6 prefixes: {len(ipv6_prefixes)}"

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=None,
            summary=summary,
            details={
                "asn": asn_num,
                "name": name,
                "description": description,
                "country": country,
                "ipv4_prefix_count": len(ipv4_prefixes),
                "ipv6_prefix_count": len(ipv6_prefixes),
                "ipv4_prefixes": [p.get("prefix") for p in ipv4_prefixes[:20]],
                "total_ipv4_addresses": total_ipv4,
            },
            report_url=f"https://bgpview.io/asn/{asn_num}",
        )
