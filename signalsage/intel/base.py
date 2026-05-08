"""Base classes for threat intelligence providers."""

import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import httpx

from signalsage.ioc.models import IOC, IOCType

# Some providers (IPInfo, Shodan, WhoisXML, ...) put the API key in the request
# URL as a query parameter. When httpx raises, str(exc) embeds that URL — and
# the resulting error string is rendered into Slack/Discord channels. Strip any
# sensitive query-string parameter before the message escapes the provider.
_SENSITIVE_PARAMS = frozenset(
    {"token", "key", "apikey", "api_key", "auth", "secret", "password", "access_token"}
)
_QUERY_PARAM_RE = re.compile(r"([?&])([\w.\-]+)=([^\s&'\"]+)")


def _scrub(msg: str) -> str:
    """Redact API keys and other sensitive query params from an error message."""

    def _redact(m: re.Match) -> str:
        if m.group(2).lower() in _SENSITIVE_PARAMS:
            return f"{m.group(1)}{m.group(2)}=***"
        return m.group(0)

    return _QUERY_PARAM_RE.sub(_redact, msg)


@dataclass
class IntelResult:
    """Standardized result from a threat intelligence provider."""

    provider: str
    ioc_value: str
    ioc_type: IOCType
    malicious: bool | None = None
    score: int | None = None  # 0-100
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    report_url: str | None = None


class BaseProvider(ABC):
    """Abstract base class for all threat intel providers."""

    name: str = ""
    supported_types: list[IOCType] = []
    requires_key: bool = True

    def __init__(
        self,
        api_key: str | None = None,
        timeout: int = 10,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key or ""
        self.timeout = timeout
        # Optional shared httpx.AsyncClient. When set, providers reuse it via
        # _http() so we get one TCP/TLS handshake amortised across all lookups
        # instead of one per IOC × per provider.
        self._shared_client = http_client
        self.enabled = bool(self.api_key) if self.requires_key else True

    def supports(self, ioc_type: IOCType) -> bool:
        """Return True if this provider can look up the given IOC type."""
        return ioc_type in self.supported_types

    @asynccontextmanager
    async def _http(self) -> AsyncIterator[httpx.AsyncClient]:
        """Yield an httpx.AsyncClient — the shared one when available, else a
        fresh per-call client. Per-request kwargs (headers, auth, follow_redirects)
        should be passed to the verb method (``client.get(url, headers=...)``).
        """
        if self._shared_client is not None:
            yield self._shared_client
        else:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                yield client

    @abstractmethod
    async def lookup(self, ioc: IOC) -> IntelResult | None:
        """Perform the actual lookup and return a result or None."""

    def _error(self, ioc: IOC, msg: str | Exception) -> IntelResult:
        """Create a standardized error result, scrubbing any leaked secrets."""
        text = f"{type(msg).__name__}: {msg}" if isinstance(msg, Exception) else msg
        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            error=_scrub(text),
        )

    def _check_status(self, resp: Any, ioc: IOC) -> IntelResult | None:
        """Map common HTTP error statuses to a standard error IntelResult.

        Returns None for 200 (caller proceeds with the body) and for 404
        (caller handles "not found" themselves — typically by returning a
        non-error IntelResult that says the indicator is unknown to this
        provider). The common error codes (401/403/429/4xx/5xx) become
        readable errors that won't leak any URL details.
        """
        if resp.status_code == 200 or resp.status_code == 404:
            return None
        if resp.status_code == 429:
            return self._error(ioc, "Rate limited — free tier quota reached")
        if resp.status_code in (401, 403):
            return self._error(ioc, "Unauthorized — check API key")
        if resp.status_code >= 500:
            return self._error(ioc, f"Service unavailable ({resp.status_code})")
        if resp.status_code >= 400:
            return self._error(ioc, f"Request failed ({resp.status_code})")
        return None
