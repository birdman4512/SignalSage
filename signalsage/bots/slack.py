"""Slack bot using Socket Mode (no public URL required)."""

import logging
from typing import Optional

from slack_bolt.async_app import AsyncApp
from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler

from signalsage.ioc.processor import IOCProcessor
from .formatter import format_results, split_message, Platform

logger = logging.getLogger(__name__)


class SlackBot:
    """Async Slack bot that monitors messages and enriches IOCs."""

    def __init__(self, config: dict, ioc_processor: IOCProcessor) -> None:
        self.cfg = config["platforms"]["slack"]
        self.ioc_processor = ioc_processor
        self.app = AsyncApp(token=self.cfg["bot_token"])
        self._bot_user_id: Optional[str] = None
        self._register()

    def _register(self) -> None:
        """Register Slack event handlers."""

        @self.app.event("message")
        async def on_message(event: dict, say, client) -> None:
            # Ignore bot messages and message subtypes (edits, deletes, etc.)
            if event.get("bot_id") or event.get("subtype"):
                return

            channel = event.get("channel", "")
            monitor = self.cfg.get("monitor_channels") or []

            if monitor:
                # Resolve channel name and check against the monitor list
                try:
                    info = await client.conversations_info(channel=channel)
                    ch_name = f"#{info['channel']['name']}"
                    if channel not in monitor and ch_name not in monitor:
                        return
                except Exception as exc:
                    logger.debug("Could not resolve channel %s: %s", channel, exc)
                    return

            text = event.get("text", "")
            if not text:
                return

            logger.debug("Processing message in channel %s", channel)
            results = await self.ioc_processor.process(text)
            for ioc, intel in results:
                msg = format_results(ioc, intel, Platform.SLACK)
                for chunk in split_message(msg, 3000):
                    await say(text=chunk)

        @self.app.error
        async def on_error(error: Exception) -> None:
            logger.error("Slack bolt error: %s", error)

    async def send_digest(self, text: str, channel: Optional[str] = None) -> None:
        """Send a digest message to a channel.

        Args:
            text: The message to send.
            channel: Channel name/ID override. Falls back to platforms.slack.digest_channel.
        """
        ch = channel or self.cfg.get("digest_channel")
        if not ch:
            logger.warning("No digest_channel configured for Slack")
            return
        for chunk in split_message(text, 3000):
            try:
                await self.app.client.chat_postMessage(channel=ch, text=chunk)
            except Exception as exc:
                logger.error("Failed to send Slack digest chunk: %s", exc)

    async def start(self) -> None:
        """Start the Socket Mode handler (blocks until stopped)."""
        app_token = self.cfg.get("app_token", "")
        if not app_token:
            raise ValueError("Slack app_token is required for Socket Mode")
        logger.info("Starting Slack Socket Mode handler...")
        handler = AsyncSocketModeHandler(self.app, app_token)
        await handler.start_async()
