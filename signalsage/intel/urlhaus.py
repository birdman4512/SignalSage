"""URLhaus threat intelligence provider (abuse.ch)."""

import logging
from typing import Optional

import httpx

from signalsage.ioc.models import IOC, IOCType
from .base import BaseProvider, IntelResult

logger = logging.getLogger(__name__)

_BASE = "https://urlhaus-api.abuse.ch/v1"


class URLhausProvider(BaseProvider):
    name = "URLhaus"
    supported_types = [
        IOCType.URL,
        IOCType.DOMAIN,
        IOCType.IPV4,
        IOCType.MD5,
        IOCType.SHA256,
    ]
    requires_key = False

    async def lookup(self, ioc: IOC) -> Optional[IntelResult]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if ioc.type == IOCType.URL:
                    return await self._lookup_url(client, ioc)
                elif ioc.type in (IOCType.DOMAIN, IOCType.IPV4):
                    return await self._lookup_host(client, ioc)
                else:
                    return await self._lookup_hash(client, ioc)
        except httpx.TimeoutException:
            return self._error(ioc, "Request timed out")
        except Exception as exc:
            logger.exception("URLhaus lookup failed for %s", ioc.value)
            return self._error(ioc, str(exc))

    async def _lookup_url(
        self, client: httpx.AsyncClient, ioc: IOC
    ) -> IntelResult:
        resp = await client.post(
            f"{_BASE}/url/", data={"url": ioc.value}
        )
        resp.raise_for_status()
        data = resp.json()

        status = data.get("query_status", "no_results")
        if status == "no_results":
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=False,
                summary="Not found in URLhaus",
            )

        url_status = data.get("url_status", "")
        threat = data.get("threat", "")
        tags = data.get("tags") or []
        summary = f"Status: {url_status}"
        if threat:
            summary += f" | Threat: {threat}"
        if tags:
            summary += f" | Tags: {', '.join(tags[:5])}"

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=url_status == "online",
            summary=summary,
            details={"url_status": url_status, "threat": threat, "tags": tags},
            report_url=data.get("urlhaus_reference", ""),
        )

    async def _lookup_host(
        self, client: httpx.AsyncClient, ioc: IOC
    ) -> IntelResult:
        resp = await client.post(
            f"{_BASE}/host/", data={"host": ioc.value}
        )
        resp.raise_for_status()
        data = resp.json()

        status = data.get("query_status", "no_results")
        if status == "no_results":
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=False,
                summary="Not found in URLhaus",
            )

        urls_count: int = data.get("urls_count", 0)
        url_list = data.get("urls", [])
        first_threat = (url_list[0].get("threat", "") if url_list else "")
        summary = f"{urls_count} malicious URLs"
        if first_threat:
            summary += f" | Threat: {first_threat}"

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=urls_count > 0,
            score=min(urls_count * 5, 100),
            summary=summary,
            details={"urls_count": urls_count},
            report_url=data.get("urlhaus_reference", ""),
        )

    async def _lookup_hash(
        self, client: httpx.AsyncClient, ioc: IOC
    ) -> IntelResult:
        if ioc.type == IOCType.MD5:
            form_data = {"md5_hash": ioc.value}
        else:
            form_data = {"sha256_hash": ioc.value}

        resp = await client.post(f"{_BASE}/payload/", data=form_data)
        resp.raise_for_status()
        data = resp.json()

        status = data.get("query_status", "no_results")
        if status == "no_results":
            return IntelResult(
                provider=self.name,
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                malicious=False,
                summary="Not found in URLhaus",
            )

        file_type = data.get("file_type", "")
        signature = data.get("signature") or ""
        urls_count = len(data.get("urls", []))
        summary = f"File type: {file_type}"
        if signature:
            summary += f" | Signature: {signature}"
        summary += f" | {urls_count} URLs"

        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            malicious=True,
            score=90,
            summary=summary,
            details={"file_type": file_type, "signature": signature},
            report_url=data.get("urlhaus_reference", ""),
        )
