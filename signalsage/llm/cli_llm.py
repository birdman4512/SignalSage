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
import shutil

from .base import BaseLLM

logger = logging.getLogger(__name__)


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
            return [self.command, "exec", *self.extra_args, prompt]
        # `claude -p` headless print mode; text output is the raw final message.
        return [self.command, "-p", prompt, "--output-format", "text", *self.extra_args]

    async def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        # These CLIs take a single prompt; fold the system prompt in so it is honoured
        # regardless of CLI-version flag differences.
        prompt = f"{system}\n\n{user}" if system else user
        argv = self._build_argv(prompt)

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
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

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip() or "(no stderr)"
            raise RuntimeError(f"CLI '{self.command}' exited {proc.returncode}: {err}")

        text = stdout.decode(errors="replace").strip()
        if not text:
            raise RuntimeError(f"CLI '{self.command}' returned empty output")
        return text
