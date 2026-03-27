"""Base classes for threat intelligence providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, List, Optional

from signalsage.ioc.models import IOC, IOCType


@dataclass
class IntelResult:
    """Standardized result from a threat intelligence provider."""

    provider: str
    ioc_value: str
    ioc_type: IOCType
    malicious: Optional[bool] = None
    score: Optional[int] = None  # 0-100
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    report_url: Optional[str] = None


class BaseProvider(ABC):
    """Abstract base class for all threat intel providers."""

    name: str = ""
    supported_types: List[IOCType] = []
    requires_key: bool = True

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 10,
    ) -> None:
        self.api_key = api_key or ""
        self.timeout = timeout
        self.enabled = bool(self.api_key) if self.requires_key else True

    def supports(self, ioc_type: IOCType) -> bool:
        """Return True if this provider can look up the given IOC type."""
        return ioc_type in self.supported_types

    @abstractmethod
    async def lookup(self, ioc: IOC) -> Optional[IntelResult]:
        """Perform the actual lookup and return a result or None."""

    def _error(self, ioc: IOC, msg: str) -> IntelResult:
        """Create a standardized error result."""
        return IntelResult(
            provider=self.name,
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            error=msg,
        )
