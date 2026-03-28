"""Slack bot using Socket Mode (no public URL required)."""

import logging

from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler
from slack_bolt.async_app import AsyncApp

from signalsage.ioc.processor import IOCProcessor

from .commands import HELP_TEXT, handle_digest_command, parse_command
from .formatter import format_digest_slack_message, format_slack_message

logger = logging.getLogger(__name__)


class SlackBot:
    """Async Slack bot that monitors messages and enriches IOCs."""

    def __init__(self, config: dict, ioc_processor: IOCProcessor, summarizer=None) -> None:
        self.cfg = config["platforms"]["slack"]
        self.ioc_processor = ioc_processor
        self.summarizer = summarizer  # optional DigestSummarizer for IOC assessment
        self.app = AsyncApp(token=self.cfg["bot_token"])
        self._bot_user_id: str | None = None
        self.scheduler = None  # set by main.py after scheduler creation
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

            # --- Command handling ---
            cmd = parse_command(text)
            if cmd is not None:
                cmd_name, cmd_args = cmd
                if cmd_name == "digest":
                    await handle_digest_command(
                        cmd_args,
                        self.scheduler,
                        reply=lambda msg: say(text=msg),
                    )
                elif cmd_name in ("help", "?"):
                    await say(text=HELP_TEXT)
                return  # don't also process commands as IOCs

            # --- IOC enrichment ---
            logger.info("Message received in channel %s: %r", channel, text[:80])
            results = await self.ioc_processor.process(text)
            for ioc, intel in results:
                pending = self.summarizer is not None and bool(intel)

                # Post immediately with a "generating…" placeholder
                resp = await say(**format_slack_message(ioc, intel, assessment_pending=pending))

                if not pending:
                    continue

                # Generate LLM summary and update the posted message in-place
                msg_ts = resp.get("ts")
                msg_channel = resp.get("channel")
                llm_summary: str | None = None
                try:
                    llm_summary = await self.summarizer.summarize_ioc(ioc, intel)
                except Exception as exc:
                    logger.warning("IOC LLM summary failed for %s: %s", ioc.value, exc)

                if msg_ts and msg_channel:
                    try:
                        await client.chat_update(
                            channel=msg_channel,
                            ts=msg_ts,
                            **format_slack_message(ioc, intel, llm_summary=llm_summary),
                        )
                    except Exception as exc:
                        logger.warning("Failed to update IOC message: %s", exc)

        @self.app.event("app_mention")
        async def on_mention(event: dict, say) -> None:
            """Handle @SignalSage mentions as commands."""
            text = event.get("text", "")
            cmd = parse_command(text)
            if cmd is not None:
                cmd_name, cmd_args = cmd
                if cmd_name == "digest":
                    await handle_digest_command(
                        cmd_args,
                        self.scheduler,
                        reply=lambda msg: say(text=msg),
                    )
                    return
            await say(text=HELP_TEXT)

        @self.app.error
        async def on_error(error: Exception) -> None:
            logger.error("Slack bolt error: %s", error)

    async def send_digest(
        self,
        topic_name: str,
        summary: str,
        lookback: str | None = None,
        channel: str | None = None,
    ) -> None:
        """Send a digest message to a channel using Block Kit formatting."""
        ch = channel or self.cfg.get("digest_channel")
        if not ch:
            logger.warning("No digest_channel configured for Slack")
            return
        payload = format_digest_slack_message(topic_name, summary, lookback)
        try:
            await self.app.client.chat_postMessage(channel=ch, **payload)
        except Exception as exc:
            logger.error("Failed to send Slack digest for '%s': %s", topic_name, exc)

    async def start(self) -> None:
        """Start the Socket Mode handler (blocks until stopped)."""
        app_token = self.cfg.get("app_token", "")
        if not app_token:
            raise ValueError("Slack app_token is required for Socket Mode")
        logger.info("Starting Slack Socket Mode handler...")
        handler = AsyncSocketModeHandler(self.app, app_token)
        await handler.start_async()
