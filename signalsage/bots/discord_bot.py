"""Discord bot using discord.py v2 with message_content intent."""

import logging

import discord

from signalsage.ioc.processor import IOCProcessor

from .commands import HELP_TEXT, handle_digest_command, parse_command
from .formatter import Platform, format_digest_plain, format_results, split_message

logger = logging.getLogger(__name__)


class DiscordBot(discord.Client):
    """Discord client that monitors messages and enriches IOCs."""

    def __init__(self, config: dict, ioc_processor: IOCProcessor) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(intents=intents)
        self.cfg = config["platforms"]["discord"]
        self.ioc_processor = ioc_processor
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
                )
            elif cmd_name in ("help", "?"):
                await message.channel.send(HELP_TEXT)
            return  # don't also process commands as IOCs

        # --- IOC enrichment ---
        logger.debug(
            "Processing Discord message in channel %s from %s",
            message.channel.id,
            message.author,
        )
        results = await self.ioc_processor.process(content)
        for ioc, intel in results:
            msg = format_results(ioc, intel, Platform.DISCORD)
            for chunk in split_message(msg, 2000):
                try:
                    await message.channel.send(chunk)
                except discord.HTTPException as exc:
                    logger.error("Failed to send Discord message: %s", exc)

    async def on_error(self, event_method: str, *args, **kwargs) -> None:
        logger.exception("Discord error in %s", event_method)

    async def send_digest(
        self,
        topic_name: str,
        summary: str,
        lookback: str | None = None,
        channel: str | None = None,
    ) -> None:
        """Send a digest message to a channel."""
        ch_id = channel or self.cfg.get("digest_channel")
        if not ch_id:
            logger.warning("No digest_channel configured for Discord")
            return
        ch = self.get_channel(int(ch_id))
        if not ch:
            logger.warning("Discord channel %s not found or not accessible", ch_id)
            return
        text = format_digest_plain(topic_name, summary, lookback)
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
