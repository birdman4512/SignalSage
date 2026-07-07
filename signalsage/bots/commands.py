"""Command parsing and dispatch shared by Slack and Discord bots."""

import logging
import re
import shlex
from collections.abc import Awaitable, Callable

from signalsage.ioc.models import IOC, IOCType

from .formatter import Platform

logger = logging.getLogger(__name__)

COMMAND_PREFIX = "!"

HELP_TEXT = """\
📋 *SignalSage commands*

*Digest*
• `!digest` — run all digest topics right now
• `!digest list` — show scheduled topics, tags, and next run time
• `!digest <tag>` — run a topic by tag (e.g. `!digest cyber`, `!digest vuln`, `!digest ti`)
• `!digest <name>` — run a topic by partial name match (case-insensitive)
• `!digest top <N>` — set how many top stories get full summaries this session (1–20, default 10)
• `!digest help` — show this reference

*Watch-mode keywords* (topics that poll continuously instead of a daily digest)
• `!digest keywords <topic>` — show a watch topic's include/exclude keywords
• `!digest keywords <topic> add <word>` — only post items mentioning this word
• `!digest keywords <topic> remove <word>` — remove an include keyword
• `!digest keywords <topic> exclude <word>` — never post items mentioning this word
• `!digest keywords <topic> unexclude <word>` — remove an exclude keyword
• Quote multi-word keywords (`add "open weight"`) and add several at once by
  separating them with spaces or commas (`add "open weight" llm`)

*OSINT*
• `!osint email <address>` — breach check via Have I Been Pwned
• `!osint domain <domain>` — crt.sh cert transparency + WHOIS age + passive DNS
• `!osint ip <address>` — passive DNS lookup for an IP address
• `!osint asn <AS1234>` — BGPView ASN lookup (prefixes, IP ranges, org info)

*IOC enrichment* is automatic — just post any IP, domain, URL, hash, CVE or ASN in a monitored channel.\
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

    body = stripped[len(COMMAND_PREFIX) :]
    try:
        # shlex respects "quoted phrases" so multi-word keywords/topics can be
        # passed as a single argument; fall back to a plain split on unbalanced
        # quotes rather than erroring out.
        parts = shlex.split(body)
    except ValueError:
        parts = body.split()
    if not parts:
        return None
    # Strip Slack auto-link formatting from every argument token
    args = [_strip_slack_link(p) for p in parts[1:]]
    return parts[0].lower(), args


_KEYWORDS_USAGE = (
    "Usage:\n"
    "• `!digest keywords <topic>` — show include/exclude keywords\n"
    "• `!digest keywords <topic> add <word> [<word2> ...]` — add include keyword(s)\n"
    "• `!digest keywords <topic> remove <word> [<word2> ...]` — remove include keyword(s)\n"
    "• `!digest keywords <topic> exclude <word> [<word2> ...]` — add exclude keyword(s)\n"
    "• `!digest keywords <topic> unexclude <word> [<word2> ...]` — remove exclude keyword(s)\n"
    'Multi-word keywords need quotes (e.g. `add "open weight"`); multiple '
    "keywords can be comma- or space-separated.\n"
)

_KEYWORD_ACTIONS = ("add", "remove", "exclude", "unexclude")


def _split_keyword_tokens(tokens: list[str]) -> list[str]:
    """Split *tokens* (each possibly a quoted phrase) on commas into individual keywords."""
    words = []
    for tok in tokens:
        for part in tok.split(","):
            part = part.strip()
            if part:
                words.append(part)
    return words


async def _handle_keywords_command(
    args: list[str],
    scheduler,
    reply: Callable[[str], Awaitable[None]],
) -> None:
    """Handle `!digest keywords <topic> [add|remove|exclude|unexclude <word>]`."""
    if not args:
        names = scheduler.get_watch_topic_names()
        listing = "\n".join(f"• {n}" for n in names) if names else "  (none)"
        await reply(f"{_KEYWORDS_USAGE}\nWatch-mode topics:\n{listing}")
        return

    action = None
    action_idx = None
    for i, tok in enumerate(args):
        if i > 0 and tok.lower() in _KEYWORD_ACTIONS:
            action = tok.lower()
            action_idx = i
            break

    if action is not None:
        topic_query = " ".join(args[:action_idx])
        words = _split_keyword_tokens(args[action_idx + 1 :])
    else:
        topic_query = " ".join(args)
        words = []

    topic = scheduler.find_watch_topic(topic_query)
    if topic is None:
        names = scheduler.get_watch_topic_names()
        listing = "\n".join(f"• {n}" for n in names) if names else "  (none)"
        await reply(
            f"⚠️ No watch-mode topic matching *{topic_query}*. Watch-mode topics:\n{listing}"
        )
        return

    name = topic["name"]
    keywords = scheduler.watch_keywords

    if action is None:
        include, exclude = keywords.get(name)
        include_str = (
            ", ".join(f"`{w}`" for w in include) if include else "_(none — matches everything)_"
        )
        exclude_str = ", ".join(f"`{w}`" for w in exclude) if exclude else "_(none)_"
        await reply(
            f"🔑 Keywords for *{name}*:\n• Include: {include_str}\n• Exclude: {exclude_str}"
        )
        return

    if not words:
        await reply(f"⚠️ No keyword given. Usage: `!digest keywords <topic> {action} <word>`")
        return

    is_remove = action in ("remove", "unexclude")
    is_exclude_list = action in ("exclude", "unexclude")
    verb = "Removed" if is_remove else "Added"
    kind = "exclude" if is_exclude_list else "include"

    ok, failed = [], []
    for word in words:
        if is_remove:
            success = keywords.remove(name, word, exclude=is_exclude_list)
        else:
            success = keywords.add(name, word, exclude=is_exclude_list)
        (ok if success else failed).append(word)

    parts = []
    if ok:
        parts.append(f"✅ {verb} {kind} keyword(s) `{'`, `'.join(ok)}` for *{name}*.")
    if failed:
        reason = "not present" if is_remove else "already present"
        parts.append(f"⚠️ `{'`, `'.join(failed)}` {reason} ({kind}) for *{name}*.")
    await reply("\n".join(parts))


async def handle_digest_command(
    args: list[str],
    scheduler,
    reply: Callable[[str], Awaitable[None]],
    reply_channel=None,
) -> None:
    """Execute a parsed digest command and send feedback via *reply*.

    Args:
        reply_channel: The channel ID/name where the command was typed.  Passed
                       as ``override_channel`` to the scheduler so on-demand
                       digests are delivered there when no digest_channel is
                       configured for the topic or the bot.
    """
    if scheduler is None:
        await reply("⚠️ Digest scheduler is not running (LLM not configured).")
        return

    if not args or args[0] == "all":
        names = scheduler.get_topic_names()
        await reply(f"⏳ Running digest for all {len(names)} topic(s)…")
        await scheduler.run_all_now(override_channel=reply_channel)

    elif args[0] == "top":
        if len(args) >= 2:
            try:
                n = int(args[1])
                if n < 1 or n > 20:
                    await reply("⚠️ Top stories count must be between 1 and 20.")
                    return
                scheduler.set_top_stories_count(n)
                await reply(f"✅ Top stories count set to *{n}* for this session.")
            except ValueError:
                await reply(f"⚠️ Invalid number: `{args[1]}`. Usage: `!digest top <N>`")
        else:
            current = scheduler.top_stories_count
            await reply(
                f"Current top stories count: *{current}*. Use `!digest top <N>` to change (1–20)."
            )

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

    elif args[0] == "keywords":
        await _handle_keywords_command(args[1:], scheduler, reply)

    else:
        topic_query = " ".join(args)
        await reply(f"⏳ Running digest for *{topic_query}*…")
        found = await scheduler.run_topic_now(
            topic_query, progress=reply, override_channel=reply_channel
        )
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


_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)


def _normalize_value(subcommand: str, value: str) -> str:
    """Strip URL scheme and path from domain/IP arguments.

    Handles cases where a user passes a full URL to ``!osint domain`` or
    ``!osint ip``, e.g. ``!osint domain https://evil.com/path`` → ``evil.com``.
    """
    if subcommand in ("domain", "ip") and _SCHEME_RE.match(value):
        # Strip scheme, then take only the host portion (drop path/query)
        host = _SCHEME_RE.sub("", value).split("/")[0].split("?")[0].split("#")[0]
        return host.lower()
    return value


async def handle_osint_command(
    args: list[str],
    processor,
    reply: Callable[[str], Awaitable[None]],
    platform: Platform = Platform.SLACK,
) -> None:
    """Run an on-demand OSINT lookup and post results via *reply*."""
    if len(args) < 2:
        await reply(_OSINT_USAGE)
        return

    subcommand = args[0].lower()
    raw_value = args[1].strip()
    value = _normalize_value(subcommand, raw_value)

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

    def _bold(text: str) -> str:
        return f"*{text}*" if platform == Platform.SLACK else f"**{text}**"

    def _link(url: str, label: str) -> str:
        if platform == Platform.SLACK:
            return f"<{url}|{label}>"
        return f"[{label}]({url})"

    sep = "─" * 36
    lines = [f"🔍 {_bold(f'OSINT: `{value}`')}", sep]
    for result in results:
        name = _bold(result.provider)
        if result.error:
            lines.append(f"⚠️ {name}: {result.error}")
        else:
            line = f"{name}: {result.summary}"
            if result.report_url:
                line += f"  ·  {_link(result.report_url, 'View report')}"
            lines.append(line)
    await reply("\n".join(lines))
