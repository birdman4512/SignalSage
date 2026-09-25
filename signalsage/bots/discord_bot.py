"""Discord bot using discord.py v2 with message_content intent."""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from signalsage.scheduler import DigestScheduler

import discord

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC
from signalsage.ioc.processor import IOCProcessor

from .auth import CommandAuth
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
    _clean_icon,
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
    """Build Discord Embeds for a digest topic.

    Header embed (overview + remaining-story links as fields) followed by one
    embed per top story — 1 + top_n messages total.
    """
    from datetime import date

    icon = _topic_icon(topic_name)
    window = f"last {lookback}" if lookback else date.today().strftime("%B %d, %Y")
    top_n = int((meta or {}).get("top_stories_count", 10))
    bare = bool((meta or {}).get("bare"))

    parsed = _parse_digest_json(summary)
    if not parsed:
        embed = discord.Embed(
            title=f"{icon}  {topic_name}",
            description=summary[:4096],
            color=_DIGEST_COLOUR,
        )
        embed.set_footer(text=window)
        return [embed]

    if (meta or {}).get("compact"):
        # One embed per story; send_digest posts each embed as its own message.
        from signalsage.digest.ranking import canonical_url

        compact_embeds = []
        for item in parsed["items"]:
            source = canonical_url(str(item.get("url", "")))
            description = (
                str(item.get("summary", ""))[:600]
                + f"\n\nWhy selected: {str(item.get('relevance_reason', ''))[:160]}"
                + f"\nBased on {item.get('content_kind', 'feed excerpt')}"
                + (f" · [Read source]({source})" if source else "")
                + f"\nReact 👍 / 👎 to tune rankings · id {str(item.get('art_id', ''))[:12]}"
            )
            embed = discord.Embed(
                title=str(item.get("headline", ""))[:256] or None,
                url=source or None,
                description=description[:4096],
                color=_DIGEST_COLOUR,
            )
            embed.set_author(name=f"{icon}  {topic_name}"[:256])
            compact_embeds.append(embed)
        return compact_embeds

    sorted_items = sorted(
        parsed["items"],
        key=lambda i: _SEVERITY_ORDER.get(str(i.get("severity") or "").lower(), 4),
    )
    valid_items = [i for i in sorted_items[:20] if str(i.get("headline", "")).strip()]
    top_items = valid_items[:top_n]
    tail_items = valid_items[top_n:]

    embeds: list[discord.Embed] = []

    # ── Header embed: overview + metadata ────────────────────────────────────
    # Skipped entirely in "bare" mode (watch-mode alerts) — just the story card(s).
    if not bare:
        overview = _overview_text(parsed, valid_items)
        header = discord.Embed(
            title=f"{icon}  {topic_name}",
            description=overview[:4096] if overview else None,
            color=_DIGEST_COLOUR,
        )
        footer_parts = _digest_footer_parts(parsed, meta)
        header.set_footer(
            text=f"Digest  ·  {window}"
            + (f"  ·  {'  ·  '.join(footer_parts)}" if footer_parts else "")
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
        item_icon = _clean_icon(item.get("icon"))
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
        if bare:
            embed.set_author(name=f"{icon}  {topic_name}")
        source = _source_label(url)
        if source:
            embed.set_footer(text=source)
        embeds.append(embed)

    # ── Remaining stories — fields on the header embed ────────────────────────
    # Riding along in the header (rather than a separate trailing embed) keeps
    # the digest to 1 + top_n messages total. Not applicable in bare mode since
    # there's no header embed and top_n already equals the full matched-item count.
    if tail_items and not bare:
        lines: list[str] = []
        for item in tail_items:
            headline = str(item.get("headline", "")).strip()
            url = str(item.get("url") or "").strip()
            item_icon = _clean_icon(item.get("icon"))
            if not headline:
                continue
            source = _source_label(url)
            source_suffix = f" · {source}" if source else ""
            if url.startswith("http"):
                lines.append(f"• {item_icon} [{headline}]({url}){source_suffix}")
            else:
                lines.append(f"• {item_icon} {headline}{source_suffix}")
        # Discord embed fields cap at 1024 chars — chunk lines across fields.
        field_name = f"📋 More Stories ({len(lines)})"
        chunk: list[str] = []
        chunk_len = 0
        for line in lines:
            if chunk_len + len(line) + 1 > 1024 and chunk:
                header.add_field(name=field_name, value="\n".join(chunk), inline=False)
                field_name = "​"  # zero-width name for continuation fields
                chunk = []
                chunk_len = 0
            chunk.append(line[:1024])
            chunk_len += len(line) + 1
        if chunk:
            header.add_field(name=field_name, value="\n".join(chunk), inline=False)

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

    platform_name = "discord"

    def __init__(
        self,
        config: dict,
        ioc_processor: IOCProcessor,
        summarizer=None,
        auth: CommandAuth | None = None,
    ) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        # Nothing the bot posts should ever ping anyone. Digest text comes from
        # RSS feeds + LLM output and OSINT replies echo third-party data, so an
        # "@everyone" smuggled into either must render inert.
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())
        self.cfg = config["platforms"]["discord"]
        self.ioc_processor = ioc_processor
        self.summarizer = summarizer  # optional DigestSummarizer for IOC assessment
        self.auth = auth or CommandAuth()
        self.scheduler: DigestScheduler | None = None  # set by main.py

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
            user_id = message.author.id
            if cmd_name in ("digest", "osint", "help", "?"):
                if not self.auth.authorized_discord(user_id):
                    logger.info(
                        "Discord user %s denied command %r — not in allowlist",
                        user_id,
                        cmd_name,
                    )
                    return
                cd = self.auth.cooldown_remaining("discord", str(user_id))
                if cd:
                    await message.channel.send(f"⏳ Slow down — try again in {cd}s.")
                    return
                self.auth.record("discord", str(user_id))
            if cmd_name == "digest":
                await handle_digest_command(
                    cmd_args,
                    self.scheduler,
                    reply=message.channel.send,
                    reply_channel=message.channel.id,
                    actor=str(user_id),
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

    def digest_destination(self, channel=None):
        try:
            value = (
                int(channel) if channel is not None else int(self.cfg.get("digest_channel") or 0)
            )
        except (TypeError, ValueError):
            value = int(self.cfg.get("digest_channel") or 0)
        if value <= 0:
            raise ValueError("Discord digest channel must be a channel ID")
        return self.platform_name, str(value)

    def digest_payloads(self, topic, summary, meta):
        return [embed.to_dict() for embed in _digest_embeds(topic, summary, meta=meta)]

    async def send_digest(
        self, topic_name: str, summary: str, lookback=None, channel=None, meta=None
    ):
        """Propagate failures to the outbox and acknowledge each delivered part."""
        _, channel_id = self.digest_destination(channel)
        ch = self.get_channel(int(channel_id))
        if ch is None:
            ch = await self.fetch_channel(int(channel_id))
        meta = meta or {}
        if not isinstance(ch, discord.abc.Messageable):
            raise ValueError("Discord digest destination does not support messages")
        embeds = (
            [discord.Embed.from_dict(payload) for payload in meta["_payloads"]]
            if "_payloads" in meta
            else _digest_embeds(topic_name, summary, lookback, meta=meta)
        )
        for index, embed in enumerate(embeds):
            if index < meta.get("_offset", 0):
                continue
            sent = await ch.send(embed=embed)
            if index < len(meta.get("articles") or []):
                await self._seed_votes(sent, meta, index)
            if meta.get("_ack"):
                meta["_ack"](index + 1)

    async def _seed_votes(self, message: discord.Message, meta: dict, index: int) -> None:
        """Map a story message to its article and pre-add 👍/👎 so rating is one click.

        Best effort: the message is already posted, so a failure here must not
        fail the delivery (which would re-post it).
        """
        if meta.get("_sent"):
            meta["_sent"](index, str(message.id))
        for emoji in ("👍", "👎"):
            try:
                await message.add_reaction(emoji)
            except Exception as exc:
                logger.debug("Could not add %s to digest story: %s", emoji, exc)

    async def on_raw_reaction_add(self, payload: discord.RawReactionActionEvent) -> None:
        await self._on_vote(payload, removed=False)

    async def on_raw_reaction_remove(self, payload: discord.RawReactionActionEvent) -> None:
        await self._on_vote(payload, removed=True)

    async def _on_vote(self, payload: discord.RawReactionActionEvent, removed: bool) -> None:
        name = payload.emoji.name or ""
        # startswith() also accepts skin-tone variants.
        useful = True if name.startswith("👍") else False if name.startswith("👎") else None
        if (
            useful is None
            or (self.user is not None and payload.user_id == self.user.id)
            or self.scheduler is None
            or not self.auth.authorized_discord(payload.user_id)
        ):
            return
        if self.scheduler.store.react_feedback(
            self.platform_name, str(payload.message_id), str(payload.user_id), useful, removed
        ):
            logger.info(
                "Discord feedback from %s on %s: %s", payload.user_id, payload.message_id, useful
            )

    async def start_bot(self) -> None:
        """Start the Discord bot (blocks until stopped)."""
        token = self.cfg.get("bot_token", "")
        if not token:
            raise ValueError("Discord bot_token is required")
        logger.info("Starting Discord bot...")
        await self.start(token)
