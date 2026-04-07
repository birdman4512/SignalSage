"""Base classes for threat intelligence providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from signalsage.ioc.models import IOC, IOCType


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
    ) -> None:
        self.api_key = api_key or ""
        self.timeout = timeout
        self.enabled = bool(self.api_key) if self.requires_key else True

    def supports(self, ioc_type: IOCType) -> bool:
        """Return True if this provider can look up the given IOC type."""
        return ioc_type in self.supported_types

    @abstractmethod
    async def lookup(self, ioc: IOC) -> IntelResult | None:
        """Perform the actual lookup and return a result or None."""

    def _error(self, ioc: IOC, msg: str) -> IntelResult:
        """Create a standardized error result."""
        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            error=msg,
        )

    def _check_status(self, resp: Any, ioc: IOC) -> IntelResult | None:
        """Return a clean error result for common HTTP error codes, or None if OK."""
        if resp.status_code == 200:
            return None
        if resp.status_code == 429:
            return self._error(ioc, "Rate limited — free tier quota reached")
        if resp.status_code in (401, 403):
            return self._error(ioc, "Unauthorized — check API key")
        if resp.status_code == 404:
            return None  # callers handle 404 themselves
        if resp.status_code >= 500:
            return self._error(ioc, f"Service unavailable ({resp.status_code})")
        if resp.status_code >= 400:
            return self._error(ioc, f"Request failed ({resp.status_code})")
        return None
