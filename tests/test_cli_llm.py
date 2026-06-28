"""Tests for the CLI (Codex / Claude Code) LLM backend."""

import pytest

from signalsage.llm.base import LLMRateLimitError
from signalsage.llm.cli_llm import CliLLM, _detect_rate_limit

# ---------------------------------------------------------------------------
# Rate-limit detection
# ---------------------------------------------------------------------------

_CODEX_LIMIT = (
    "Reading additional input from stdin...\n"
    "ERROR: You've hit your usage limit. Upgrade to Pro (https://chatgpt.com/explore/pro), "
    "visit https://chatgpt.com/codex/settings/usage to purchase more credits or try again "
    "at Jun 29th, 2026 8:23 AM."
)


def test_detect_rate_limit_codex_message():
    msg = _detect_rate_limit(_CODEX_LIMIT)
    assert msg is not None
    # "ERROR:" prefix stripped, and the actionable reset time preserved.
    assert msg.startswith("You've hit your usage limit")
    assert "try again at Jun 29th, 2026 8:23 AM." in msg


@pytest.mark.parametrize(
    "text",
    [
        "rate limit exceeded",
        "Rate-limit hit, slow down",
        "HTTP 429 Too Many Requests",
        "quota exhausted for today",
    ],
)
def test_detect_rate_limit_variants(text):
    assert _detect_rate_limit(text) is not None


@pytest.mark.parametrize(
    "text",
    [
        "Not inside a trusted directory",
        "some normal error: file not found",
        "",
    ],
)
def test_detect_rate_limit_negatives(text):
    assert _detect_rate_limit(text) is None


# ---------------------------------------------------------------------------
# complete() maps a limit-flavoured non-zero exit to LLMRateLimitError
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, returncode, stdout=b"", stderr=b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr


async def test_complete_raises_rate_limit(monkeypatch):
    async def fake_exec(*args, **kwargs):
        return _FakeProc(1, stderr=_CODEX_LIMIT.encode())

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    llm = CliLLM(command="codex")
    with pytest.raises(LLMRateLimitError) as ei:
        await llm.complete(system="s", user="u")
    assert "usage limit" in str(ei.value).lower()


async def test_complete_other_failure_is_generic(monkeypatch):
    async def fake_exec(*args, **kwargs):
        return _FakeProc(1, stderr=b"boom: something broke")

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    llm = CliLLM(command="codex")
    with pytest.raises(RuntimeError) as ei:
        await llm.complete(system="s", user="u")
    assert not isinstance(ei.value, LLMRateLimitError)
    assert "exited 1" in str(ei.value)
