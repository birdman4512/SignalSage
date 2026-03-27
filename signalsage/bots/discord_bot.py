"""Discord bot using discord.py v2 with message_content intent."""

import logging
from typing import Optional

import discord

from signalsage.ioc.processor import IOCProcessor
from .formatter import format_results, split_message, Platform

logger = logging.getLogger(__name__)


class DiscordBot(discord.Client):
    """Discord client that monitors messages and enriches IOCs."""

    def __init__(self, config: dict, ioc_processor: IOCProcessor) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(intents=intents)
        self.cfg = config["platforms"]["discord"]
        self.ioc_processor = ioc_processor

    async def on_ready(self) -> None:
        logger.info("Discord bot ready as %s (ID: %s)", self.user, self.user.id if self.user else "unknown")

    async def on_message(self, message: discord.Message) -> None:
        # Ignore messages from bots (including ourselves)
        if message.author.bot:
            return

        monitor = self.cfg.get("monitor_channels") or []
        if monitor and message.channel.id not in monitor:
            return

        content = message.content
        if not content:
            return

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

    async def send_digest(self, text: str) -> None:
        """Send a digest message to the configured digest channel."""
        ch_id = self.cfg.get("digest_channel")
        if not ch_id:
            logger.warning("No digest_channel configured for Discord")
            return
        ch = self.get_channel(int(ch_id))
        if not ch:
            logger.warning("Discord channel %s not found or not accessible", ch_id)
            return
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
