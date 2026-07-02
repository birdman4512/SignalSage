"""CLI-backed LLM (Claude Code CLI or Codex CLI) running in headless mode.

This shells out to an agentic coding CLI instead of calling a completion API.
The main reason to use it is to bill digest generation against an existing
Claude Code / Codex subscription rather than a per-token API key.

Caveats vs. the OllamaLLM / AnthropicLLM backends:
  * Slower per call — each completion boots a fresh agent process.
  * No temperature / max_tokens control (the prompt drives output length).
  * The CLI must be installed and authenticated on the host. It is NOT present
    in the default Docker image, so this backend only works when running
    SignalSage directly on a machine where `claude` / `codex` is on PATH.
"""

import asyncio
import logging
import re
import shutil

from .base import BaseLLM, LLMRateLimitError

logger = logging.getLogger(__name__)

# Markers a CLI prints when it has hit a subscription/quota limit (codex: "You've
# hit your usage limit … try again at …"; claude: "usage limit reached"). Matched
# case-insensitively against the CLI's combined output on a non-zero exit.
_RATE_LIMIT_RE = re.compile(
    r"usage limit|rate.?limit|too many requests|\b429\b|quota|purchase more credits",
    re.IGNORECASE,
)


def _detect_rate_limit(output: str) -> str | None:
    """Return a cleaned, user-facing limit message if *output* looks like a
    usage/rate-limit error, else None."""
    if not _RATE_LIMIT_RE.search(output):
        return None
    # Prefer the specific line mentioning the limit (it usually also carries the
    # "try again at …" reset time) over the whole noisy dump.
    line = next(
        (ln.strip() for ln in output.splitlines() if _RATE_LIMIT_RE.search(ln)),
        "LLM usage limit reached.",
    )
    for prefix in ("ERROR:", "Error:", "error:"):
        if line.startswith(prefix):
            line = line[len(prefix) :].strip()
    return line


class CliLLM(BaseLLM):
    """Drives `claude` (Claude Code) or `codex` (Codex CLI) in non-interactive mode."""

    def __init__(
        self,
        command: str = "claude",
        extra_args: list[str] | None = None,
        timeout: int = 600,
    ) -> None:
        # Resolve via PATH so Windows .cmd/.exe shims are found (create_subprocess_exec
        # does not apply PATHEXT). Fall back to the raw name if not resolvable yet.
        self.command = shutil.which(command) or command
        self.mode = "codex" if "codex" in command.lower() else "claude"
        self.extra_args = extra_args or []
        self.timeout = timeout
        logger.info("CLI LLM: command=%s mode=%s timeout=%ds", self.command, self.mode, timeout)

    def _build_argv(self, prompt: str) -> list[str]:
        if self.mode == "codex":
            # `codex exec` runs a single non-interactive turn and prints the result.
            # Two flags are required for headless use (esp. inside the container):
            #   --skip-git-repo-check: the working dir (/app) isn't a git repo, and
            #     codex otherwise refuses to run outside a "trusted" git directory.
            #   --dangerously-bypass-approvals-and-sandbox: digest generation is
            #     pure text (no tool/command execution) and codex's Landlock/seccomp
            #     sandbox isn't available in the container, so skip it rather than
            #     fail. Safe here because nothing is executed.
            return [
                self.command,
                "exec",
                "--skip-git-repo-check",
                "--dangerously-bypass-approvals-and-sandbox",
                *self.extra_args,
                prompt,
            ]
        # `claude -p` headless print mode; text output is the raw final message.
        return [self.command, "-p", prompt, "--output-format", "text", *self.extra_args]

    async def complete(
        self, system: str, user: str, max_tokens: int = 1024, json_mode: bool = False
    ) -> str:
        # These CLIs take a single prompt; fold the system prompt in so it is honoured
        # regardless of CLI-version flag differences.
        prompt = f"{system}\n\n{user}" if system else user
        argv = self._build_argv(prompt)

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                # The prompt is passed as an argument; close stdin so the CLI does
                # not block waiting to read additional input from a non-tty stdin.
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            raise RuntimeError(
                f"CLI '{self.command}' not found on PATH. Install the Claude Code or "
                "Codex CLI, or set digest.cli_command to its full path."
            )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError(
                f"CLI '{self.command}' timed out after {self.timeout}s — "
                "raise digest.cli_timeout or shorten the prompt"
            )

        out = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")

        if proc.returncode != 0:
            # A usage/quota limit surfaces as a non-zero exit; the message may land
            # on stdout or stderr depending on the CLI, so scan both.
            limit_msg = _detect_rate_limit(f"{err}\n{out}")
            if limit_msg:
                raise LLMRateLimitError(limit_msg)
            raise RuntimeError(
                f"CLI '{self.command}' exited {proc.returncode}: {err.strip() or '(no stderr)'}"
            )

        text = out.strip()
        if not text:
            raise RuntimeError(f"CLI '{self.command}' returned empty output")
        return text
