"""Command parsing and dispatch shared by Slack and Discord bots."""

import logging
from collections.abc import Awaitable, Callable

from signalsage.ioc.models import IOC, IOCType

logger = logging.getLogger(__name__)

COMMAND_PREFIX = "!"

HELP_TEXT = """\
📋 *SignalSage commands*
• `!digest` — run all digest topics right now
• `!digest list` — show scheduled topics and their tags
• `!digest <tag>` — run a topic by tag (e.g. `!digest cyber`, `!digest vuln`, `!digest ti`)
• `!digest <name>` — run a topic by partial name match (case-insensitive)

• `!osint email <address>` — breach check via Have I Been Pwned
• `!osint domain <domain>` — crt.sh, WHOIS age & passive DNS lookup
• `!osint ip <address>` — passive DNS lookup for an IP
• `!osint asn <AS1234>` — BGPView ASN lookup (prefixes, IP ranges, org info)

*IOC enrichment* happens automatically — just post any IP, hash, domain, URL, CVE or ASN.\
"""


def _strip_slack_link(token: str) -> str:
    """Unwrap Slack auto-linked tokens.

    Slack formats URLs/domains as ``<http://example.com|example.com>`` or
    bare ``<http://example.com>``.  Extract the display text (after ``|``) when
    present, otherwise the raw URL between the angle brackets.
    """
    if token.startswith("<") and token.endswith(">"):
        inner = token[1:-1]
        if "|" in inner:
            return inner.split("|", 1)[1]
        return inner
    return token


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
    # Strip Slack auto-link formatting from every argument token
    args = [_strip_slack_link(p) for p in parts[1:]]
    return parts[0].lower(), args


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
                    next_str = f"  ·  next run {next_run.day} {next_run.strftime('%b %H:%M %Z')}"
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
        found = await scheduler.run_topic_now(topic_query, progress=reply)
        if not found:
            names = scheduler.get_topic_names()
            listing = "\n".join(f"• {n}" for n in names) if names else "  (none)"
            await reply(f"⚠️ No topic matching *{topic_query}*. Available topics:\n{listing}")


_OSINT_USAGE = (
    "Usage:\n"
    "• `!osint email <address>` — breach check\n"
    "• `!osint domain <domain>` — crt.sh + WHOIS age + passive DNS\n"
    "• `!osint ip <address>` — passive DNS\n"
    "• `!osint asn <AS1234>` — BGPView ASN info\n"
)

_OSINT_TYPE_MAP = {
    "email": IOCType.EMAIL,
    "domain": IOCType.DOMAIN,
    "ip": IOCType.IPV4,
    "asn": IOCType.ASN,
}


async def handle_osint_command(
    args: list[str],
    processor,
    reply: Callable[[str], Awaitable[None]],
) -> None:
    """Run an on-demand OSINT lookup and post results via *reply*."""
    if len(args) < 2:
        await reply(_OSINT_USAGE)
        return

    subcommand = args[0].lower()
    value = args[1].strip()

    ioc_type = _OSINT_TYPE_MAP.get(subcommand)
    if ioc_type is None:
        await reply(f"⚠️ Unknown OSINT subcommand `{subcommand}`.\n{_OSINT_USAGE}")
        return

    await reply(f"🔍 Running OSINT lookup for `{value}`…")

    ioc = IOC(value=value, type=ioc_type, raw=value)
    results = await processor.lookup_ioc(ioc)

    if not results:
        await reply(f"No OSINT results found for `{value}`.")
        return

    sep = "─" * 36
    lines = [f"🔍 *OSINT: `{value}`*", sep]
    for result in results:
        if result.error:
            lines.append(f"⚠️ *{result.provider}*: {result.error}")
        else:
            lines.append(f"*{result.provider}*: {result.summary}")
            if result.report_url:
                lines.append(f"  <{result.report_url}|View report>")
    await reply("\n".join(lines))
