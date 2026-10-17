"""Running-version info for the ``!version`` command.

The Docker image has no ``.git`` directory, so the build resolves the commit
once (``python -m signalsage.version <context-dir>``) and writes it next to
this module. A bare checkout falls back to reading ``.git`` directly.
"""

import sys
import time
from pathlib import Path

from signalsage import __version__

_STARTED = time.monotonic()
_BUILD_COMMIT_FILE = Path(__file__).with_name("BUILD_COMMIT")
_REPO_ROOT = Path(__file__).resolve().parent.parent


def resolve_git_commit(root: Path) -> str | None:
    """Return the full commit SHA checked out in *root*, read without the git binary."""
    git = root / ".git"
    try:
        head = (git / "HEAD").read_text().strip()
    except OSError:
        return None
    if not head.startswith("ref: "):
        return head or None  # detached HEAD
    ref = head[5:]
    try:
        return (git / ref).read_text().strip() or None
    except OSError:
        pass
    try:
        for line in (git / "packed-refs").read_text().splitlines():
            sha, _, name = line.partition(" ")
            if name == ref:
                return sha
    except OSError:
        pass
    return None


def build_commit() -> str | None:
    try:
        return _BUILD_COMMIT_FILE.read_text().strip() or None
    except OSError:
        return resolve_git_commit(_REPO_ROOT)


def _uptime(seconds: float) -> str:
    minutes, _ = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def version_text() -> str:
    commit = build_commit()
    commit_str = f"`{commit[:7]}`" if commit else "unknown"
    python = ".".join(str(part) for part in sys.version_info[:3])
    return (
        f"🏷️ *SignalSage* {__version__}  ·  commit {commit_str}  ·  "
        f"up {_uptime(time.monotonic() - _STARTED)}  ·  Python {python}"
    )


if __name__ == "__main__":
    # Docker build step: record the build context's commit (or nothing).
    context = Path(sys.argv[1]) if len(sys.argv) > 1 else _REPO_ROOT
    _BUILD_COMMIT_FILE.write_text(resolve_git_commit(context) or "")
