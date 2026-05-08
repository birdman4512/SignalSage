"""User-ID allowlist + per-user cooldown for !digest and !osint commands.

IOC enrichment (which is automatic and already cache-protected) is intentionally
NOT gated by this module — only explicit commands.

If an allowlist for a platform is empty, that platform is treated as "open" and
anyone in a monitored channel can run commands. The cooldown applies regardless.
"""

import logging
import time
from collections.abc import Iterable

logger = logging.getLogger(__name__)


class CommandAuth:
    """Per-platform user allowlist with a shared per-user cooldown timer."""

    def __init__(
        self,
        slack_users: Iterable[str] | None = None,
        discord_users: Iterable[int | str] | None = None,
        cooldown_seconds: int = 30,
    ) -> None:
        self._slack: set[str] = {str(u) for u in (slack_users or []) if str(u).strip()}
        self._discord: set[int] = set()
        for u in discord_users or []:
            try:
                self._discord.add(int(u))
            except (TypeError, ValueError):
                logger.warning("Ignoring non-integer Discord user id in allowlist: %r", u)
        self._cooldown = max(0, int(cooldown_seconds))
        # (platform, user_id) -> monotonic timestamp of last accepted command
        self._last_seen: dict[tuple[str, str], float] = {}

    def authorized_slack(self, user_id: str) -> bool:
        if not self._slack:
            return True
        return user_id in self._slack

    def authorized_discord(self, user_id: int) -> bool:
        if not self._discord:
            return True
        return user_id in self._discord

    def cooldown_remaining(self, platform: str, user_id: str) -> int:
        """Return remaining cooldown seconds (0 if user may issue another command now)."""
        if self._cooldown <= 0:
            return 0
        last = self._last_seen.get((platform, user_id))
        if last is None:
            return 0
        elapsed = time.monotonic() - last
        if elapsed >= self._cooldown:
            return 0
        return int(self._cooldown - elapsed) + 1

    def record(self, platform: str, user_id: str) -> None:
        """Mark that *user_id* has just successfully issued a command."""
        if self._cooldown > 0:
            self._last_seen[(platform, user_id)] = time.monotonic()
