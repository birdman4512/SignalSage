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
    _SEVERITY_ORDER,
    IOC_TYPE_LABEL,
    _digest_footer_parts,
    _overall_verdict,
    _overview_text,
    _parse_digest_json,
    _provider_icon,
    _risk_emoji,
    _source_label,
    _topic_icon,
)

logger = logging.getLogger(__name__)

# Verdict colours as Discord-compatible integers
_EMBED_COLOUR = {
    "malicious": 0xE01E5A,  # red
    "clean": 0x2EB67D,  # green
    "unknown": 0x4A4A4A,  # dark grey
}

_DIGEST_COLOUR = 0x3B82F6  # blue

_SEVERITY_COLOUR = {
    "critical": 0xE01E5A,
    "high": 0xF97316,
    "medium": 0xEAB308,
    "low": 0x2EB67D,
}


def _digest_embeds(
    topic_name: str,
    summary: str,
    lookback: str | None = None,
    meta: dict | None = None,
) -> list[discord.Embed]:
    """Build Discord Embeds for a digest topic (header + per-story cards + tail list)."""
    from datetime import date

    icon = _topic_icon(topic_name)
    window = f"last {lookback}" if lookback else date.today().strftime("%B %d, %Y")
    top_n = int((meta or {}).get("top_stories_count", 10))

    parsed = _parse_digest_json(summary)
    if not parsed:
        embed = discord.Embed(
            title=f"{icon}  {topic_name}",
            description=summary[:4096],
            color=_DIGEST_COLOUR,
        )
        embed.set_footer(text=window)
        return [embed]

    sorted_items = sorted(
        parsed["items"],
        key=lambda i: _SEVERITY_ORDER.get(str(i.get("severity") or "").lower(), 4),
    )
    valid_items = [i for i in sorted_items[:20] if str(i.get("headline", "")).strip()]
    top_items = valid_items[:top_n]
    tail_items = valid_items[top_n:]

    embeds: list[discord.Embed] = []

    # ── Header embed: overview + metadata ────────────────────────────────────
    overview = _overview_text(parsed, valid_items)
    header = discord.Embed(
        title=f"{icon}  {topic_name}",
        description=overview[:4096] if overview else None,
        color=_DIGEST_COLOUR,
    )
    footer_parts = _digest_footer_parts(parsed, meta)
    header.set_footer(
        text=f"Digest  ·  {window}" + (f"  ·  {'  ·  '.join(footer_parts)}" if footer_parts else "")
    )

    extra_image_embeds: list[discord.Embed] = []
    header_image_set = False
    for img_url in (meta or {}).get("images", []):
        if not img_url or not str(img_url).startswith("http"):
            continue
        if not header_image_set:
            header.set_image(url=img_url)
            header_image_set = True
        else:
            img_embed = discord.Embed(color=_DIGEST_COLOUR)
            img_embed.set_image(url=img_url)
            extra_image_embeds.append(img_embed)

    embeds.append(header)
    embeds.extend(extra_image_embeds)

    # ── Story card embeds ─────────────────────────────────────────────────────
    for item in top_items:
        headline = str(item.get("headline", "")).strip()
        item_summary = str(item.get("summary", "") or item.get("blurb", "")).strip()
        url = str(item.get("url") or "").strip()
        item_icon = (str(item.get("icon") or "").strip().split() or ["📰"])[0]
        severity = str(item.get("severity") or "").lower()
        trend = str(item.get("trend") or "").lower()

        title = f"{item_icon}  {headline}"
        if trend == "trending":
            title += "  🔥"

        embed = discord.Embed(
            title=title[:256],
            url=url if url.startswith("http") else None,
            description=item_summary[:4096] if item_summary else None,
            color=_SEVERITY_COLOUR.get(severity, _DIGEST_COLOUR),
        )
        source = _source_label(url)
        if source:
            embed.set_footer(text=source)
        embeds.append(embed)

    # ── Tail stories embed ────────────────────────────────────────────────────
    if tail_items:
        lines: list[str] = []
        for item in tail_items:
            headline = str(item.get("headline", "")).strip()
            url = str(item.get("url") or "").strip()
            item_icon = (str(item.get("icon") or "").strip().split() or ["📰"])[0]
            if not headline:
                continue
            source = _source_label(url)
            source_suffix = f" · {source}" if source else ""
            if url.startswith("http"):
                lines.append(f"• {item_icon} [{headline}]({url}){source_suffix}")
            else:
                lines.append(f"• {item_icon} {headline}{source_suffix}")
        if lines:
            tail_embed = discord.Embed(
                title=f"📋 More Stories ({len(tail_items)})",
                description="\n\n".join(lines)[:4096],
                color=_DIGEST_COLOUR,
            )
            embeds.append(tail_embed)

    return embeds


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
            logger.debug("No IOCs extracted from message")
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
        for embed in _digest_embeds(topic_name, summary, lookback, meta=meta):
            try:
                await ch.send(embed=embed)  # type: ignore[attr-defined]
            except discord.HTTPException as exc:
                logger.error("Failed to send Discord digest embed: %s", exc)
                break

    async def start_bot(self) -> None:
        """Start the Discord bot (blocks until stopped)."""
        token = self.cfg.get("bot_token", "")
        if not token:
            raise ValueError("Discord bot_token is required")
        logger.info("Starting Discord bot...")
        await self.start(token)
