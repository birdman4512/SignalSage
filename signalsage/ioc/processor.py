"""IOC processing pipeline: extraction + intel lookup + caching."""

import asyncio
import logging

from cachetools import TTLCache

from signalsage.intel.base import BaseProvider, IntelResult

from .extractor import extract
from .models import IOC

logger = logging.getLogger(__name__)


class IOCProcessor:
    """Orchestrates IOC extraction and parallel intel lookups with caching."""

    def __init__(
        self,
        providers: list[BaseProvider],
        cache_ttl: int = 3600,
        max_per_msg: int = 5,
    ) -> None:
        self.providers = providers
        self.cache: TTLCache = TTLCache(maxsize=1000, ttl=cache_ttl)
        self.max_per_msg = max_per_msg

    async def process(self, text: str) -> list[tuple[IOC, list[IntelResult]]]:
        """Extract IOCs from text and look them up against all applicable providers."""
        iocs = extract(text)
        if not iocs:
            return []

        # Deduplicate by value, preserving first occurrence
        seen: dict = {}
        for ioc in iocs:
            if ioc.value not in seen:
                seen[ioc.value] = ioc
        unique = list(seen.values())[: self.max_per_msg]

        results: list[tuple[IOC, list[IntelResult]]] = []
        for ioc in unique:
            intel = await self._lookup(ioc)
            if intel is not None:  # None means no providers support this type
                results.append((ioc, intel))
        return results

    async def lookup_ioc(self, ioc: IOC) -> list[IntelResult]:
        """Look up a single IOC directly (skips extraction and message-level cache).

        Used by on-demand OSINT commands. Returns an empty list if no providers
        support the IOC type or all providers return None.
        """
        result = await self._lookup(ioc)
        return result or []

    async def _lookup(self, ioc: IOC) -> list[IntelResult] | None:
        """Look up a single IOC across all applicable providers, using cache."""
        key = f"{ioc.type.value}:{ioc.value}"
        if key in self.cache:
            logger.debug("Cache hit for %s", key)
            return self.cache[key]  # type: ignore[return-value]

        applicable = [p for p in self.providers if p.enabled and p.supports(ioc.type)]
        if not applicable:
            return None

        logger.info(
            "Looking up %s (%s) via %d providers", ioc.value, ioc.type.value, len(applicable)
        )
        raw = await asyncio.gather(
            *[p.lookup(ioc) for p in applicable],
            return_exceptions=True,
        )

        results: list[IntelResult] = []
        for item in raw:
            if isinstance(item, IntelResult):
                results.append(item)
            elif isinstance(item, Exception):
                logger.warning("Provider lookup raised exception: %s", item)

        self.cache[key] = results
        return results
