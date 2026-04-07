"""Discord bot using discord.py v2 with message_content intent."""

import logging

import discord

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC
from signalsage.ioc.processor import IOCProcessor

from .commands import (
    HELP_TEXT,
    Platform,
    handle_digest_command,
    handle_osint_command,
    parse_command,
)
from .formatter import (
    IOC_TYPE_LABEL,
    _overall_verdict,
    _provider_icon,
    _risk_emoji,
    format_digest_plain,
    split_message,
)

logger = logging.getLogger(__name__)

# Verdict colours as Discord-compatible integers
_EMBED_COLOUR = {
    "malicious": 0xE01E5A,  # red
    "clean": 0x2EB67D,  # green
    "unknown": 0x4A4A4A,  # dark grey
}


def _ioc_embed(ioc: IOC, results: list[IntelResult]) -> discord.Embed:
    """Build a rich Discord Embed for a single IOC intelligence result."""
    label = IOC_TYPE_LABEL.get(ioc.type, ioc.type.value)
    verdict_emoji, verdict_text = _overall_verdict(results)

    malicious = any(r.malicious is True and not r.error for r in results)
    clean = any(r.malicious is False and not r.error for r in results)
    colour = (
        _EMBED_COLOUR["malicious"]
        if malicious
        else (_EMBED_COLOUR["clean"] if clean else _EMBED_COLOUR["unknown"])
    )

    lines = []
    for result in results[:25]:
        icon = _provider_icon(result.provider)
        risk = _risk_emoji(result)
        if result.error:
            lines.append(f"{icon} **{result.provider}**  {risk}  {result.error}")
        else:
            line = f"{icon} **{result.provider}**  {risk}  {result.summary or 'No details'}"
            if result.report_url:
                line += f"  ·  [report]({result.report_url})"
            lines.append(line)

    provider_block = "\n\n".join(lines)
    total = len([r for r in results if not r.error])
    description = f"-# {label}\n{verdict_emoji}  **{verdict_text}**\n\n{provider_block}"

    embed = discord.Embed(
        title=f"🔍  {ioc.value}",
        description=description[:4096],
        colour=colour,
    )
    embed.set_footer(text=f"SignalSage  ·  {total} provider{'s' if total != 1 else ''} checked")
    return embed


class DiscordBot(discord.Client):
    """Discord client that monitors messages and enriches IOCs."""

    def __init__(self, config: dict, ioc_processor: IOCProcessor, summarizer=None) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(intents=intents)
        self.cfg = config["platforms"]["discord"]
        self.ioc_processor = ioc_processor
        self.summarizer = summarizer  # optional DigestSummarizer for IOC assessment
        self.scheduler = None  # set by main.py after scheduler creation

    async def on_ready(self) -> None:
        logger.info(
            "Discord bot ready as %s (ID: %s)", self.user, self.user.id if self.user else "unknown"
        )

    async def on_message(self, message: discord.Message) -> None:
        if message.author.bot:
            return

        monitor = self.cfg.get("monitor_channels") or []
        if monitor and message.channel.id not in monitor:
            return

        content = message.content
        if not content:
            return

        # --- Command handling ---
        cmd = parse_command(content)
        if cmd is not None:
            cmd_name, cmd_args = cmd
            if cmd_name == "digest":
                await handle_digest_command(
                    cmd_args,
                    self.scheduler,
                    reply=message.channel.send,
                    reply_channel=message.channel.id,
                )
            elif cmd_name == "osint":
                await handle_osint_command(
                    cmd_args,
                    self.ioc_processor,
                    reply=message.channel.send,
                    platform=Platform.DISCORD,
                )
            elif cmd_name in ("help", "?"):
                await message.channel.send(HELP_TEXT)
            return  # don't also process commands as IOCs

        # --- IOC enrichment ---
        logger.info(
            "Discord message in channel %s from %s: %r",
            message.channel.id,
            message.author,
            content[:120],
        )
        results = await self.ioc_processor.process(content)
        if not results:
            logger.info("No IOCs extracted from message")
        else:
            logger.info(
                "Extracted IOCs: %s",
                ", ".join(f"{ioc.type.value}:{ioc.value}" for ioc, _ in results),
            )
        for ioc, intel in results:
            embed = _ioc_embed(ioc, intel)
            sent: discord.Message | None = None
            try:
                sent = await message.channel.send(embed=embed)
            except discord.HTTPException as exc:
                logger.error("Failed to send Discord message: %s", exc)

            if not (self.summarizer and intel and sent):
                continue

            try:
                assessment = await self.summarizer.summarize_ioc(ioc, intel)
                embed.add_field(name="💡 Assessment", value=assessment[:1024], inline=False)
                await sent.edit(embed=embed)
            except Exception as exc:
                logger.warning("Discord IOC assessment failed for %s: %s", ioc.value, exc)

    async def on_error(self, event_method: str, *args, **kwargs) -> None:
        logger.exception("Discord error in %s", event_method)

    async def send_digest(
        self,
        topic_name: str,
        summary: str,
        lookback: str | None = None,
        channel: str | None = None,
        meta: dict | None = None,
    ) -> None:
        """Send a digest message to a channel."""
        # `channel` may be a Slack channel name when called from a cross-platform
        # on-demand digest — try to parse it as a Discord integer ID first, then
        # fall back to the configured digest_channel.
        ch_id_int: int | None = None
        if channel is not None:
            try:
                ch_id_int = int(channel)
            except (ValueError, TypeError):
                pass  # Not a Discord channel ID (e.g. Slack "#general") — ignore

        if ch_id_int is None:
            cfg_ch = self.cfg.get("digest_channel")
            if not cfg_ch:
                logger.warning("No digest_channel configured for Discord")
                return
            try:
                ch_id_int = int(cfg_ch)
            except (ValueError, TypeError):
                logger.warning(
                    "Discord digest_channel '%s' is not a valid channel ID — "
                    "Discord requires an integer channel ID, not a channel name. "
                    "Right-click the channel and choose 'Copy Channel ID'.",
                    cfg_ch,
                )
                return
        ch = self.get_channel(ch_id_int)
        if not ch:
            logger.warning("Discord channel %s not found or not accessible", ch_id_int)
            return
        text = format_digest_plain(topic_name, summary, lookback, meta=meta)
        for chunk in split_message(text, 2000):
            try:
                await ch.send(chunk)  # type: ignore[attr-defined]
            except discord.HTTPException as exc:
                logger.error("Failed to send Discord digest chunk: %s", exc)

    async def start_bot(self) -> None:
        """Start the Discord bot (blocks until stopped)."""
        token = self.cfg.get("bot_token", "")
        if not token:
            raise ValueError("Discord bot_token is required")
        logger.info("Starting Discord bot...")
        await self.start(token)
