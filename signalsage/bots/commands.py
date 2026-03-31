"""Command parsing and dispatch shared by Slack and Discord bots."""

import logging
from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)

COMMAND_PREFIX = "!"

HELP_TEXT = """\
📋 *SignalSage commands*
• `!digest` — run all digest topics right now
• `!digest list` — show scheduled topics and their tags
• `!digest <tag>` — run a topic by tag (e.g. `!digest cyber`, `!digest vuln`, `!digest ti`)
• `!digest <name>` — run a topic by partial name match (case-insensitive)

*IOC enrichment* happens automatically — just post any IP, hash, domain, URL or CVE.\
"""


def parse_command(text: str) -> tuple[str, list[str]] | None:
    """Return *(command, args)* if *text* starts with the command prefix, else None."""
    stripped = text.strip()
    # Handle Slack @-mention prefix: "<@UXXXXXXX> digest ..."
    if stripped.startswith("<@"):
        end = stripped.find(">")
        if end != -1:
            stripped = stripped[end + 1 :].strip()

    if not stripped.startswith(COMMAND_PREFIX):
        return None

    parts = stripped[len(COMMAND_PREFIX) :].split()
    if not parts:
        return None
    return parts[0].lower(), parts[1:]


async def handle_digest_command(
    args: list[str],
    scheduler,
    reply: Callable[[str], Awaitable[None]],
) -> None:
    """Execute a parsed digest command and send feedback via *reply*."""
    if scheduler is None:
        await reply("⚠️ Digest scheduler is not running (LLM not configured).")
        return

    if not args or args[0] == "all":
        names = scheduler.get_topic_names()
        await reply(f"⏳ Running digest for all {len(names)} topic(s)…")
        await scheduler.run_all_now()

    elif args[0] == "list":
        topics = scheduler.get_topics()
        if topics:
            lines = []
            for name, tags, next_run in topics:
                tag_str = f"  `{', '.join(tags)}`" if tags else ""
                if next_run is not None:
                    next_str = f"  ·  next run {next_run.strftime('%-d %b %H:%M %Z')}"
                else:
                    next_str = ""
                lines.append(f"• {name}{tag_str}{next_str}")
            await reply("📋 *Scheduled topics:*\n" + "\n".join(lines))
        else:
            await reply("No topics scheduled.")

    elif args[0] in ("help", "?"):
        await reply(HELP_TEXT)

    else:
        topic_query = " ".join(args)
        await reply(f"⏳ Running digest for *{topic_query}*…")
        found = await scheduler.run_topic_now(topic_query)
        if not found:
            names = scheduler.get_topic_names()
            listing = "\n".join(f"• {n}" for n in names) if names else "  (none)"
            await reply(f"⚠️ No topic matching *{topic_query}*. Available topics:\n{listing}")
