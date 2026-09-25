"""Slack bot using Socket Mode (no public URL required)."""

import logging
import re
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from signalsage.scheduler import DigestScheduler

from slack_bolt.adapter.socket_mode.aiohttp import AsyncSocketModeHandler
from slack_bolt.async_app import AsyncApp

from signalsage.ioc.processor import IOCProcessor

from .auth import CommandAuth
from .commands import (
    HELP_TEXT,
    Platform,
    handle_digest_command,
    handle_osint_command,
    parse_command,
)
from .formatter import format_digest_slack_message, format_slack_message

logger = logging.getLogger(__name__)

# Reaction names (skin-tone suffix stripped) that rate a digest story.
_VOTES = {"+1": True, "thumbsup": True, "-1": False, "thumbsdown": False}


class SlackBot:
    """Async Slack bot that monitors messages and enriches IOCs."""

    platform_name = "slack"

    def __init__(
        self,
        config: dict,
        ioc_processor: IOCProcessor,
        summarizer=None,
        auth: CommandAuth | None = None,
    ) -> None:
        self.cfg = config["platforms"]["slack"]
        self.ioc_processor = ioc_processor
        self.summarizer = summarizer  # optional DigestSummarizer for IOC assessment
        self.auth = auth or CommandAuth()
        self.app = AsyncApp(token=self.cfg["bot_token"])
        self._bot_user_id: str | None = None
        self.scheduler: DigestScheduler | None = None  # set by main.py
        self._register()

    def _register(self) -> None:
        """Register Slack event handlers."""

        @self.app.event("message")
        async def on_message(event: dict, say, client) -> None:
            # Ignore bot messages and message subtypes (edits, deletes, etc.)
            if event.get("bot_id") or event.get("subtype"):
                return

            channel = event.get("channel", "")
            is_dm = channel.startswith("D")
            monitor = self.cfg.get("monitor_channels") or []

            if monitor and not is_dm:
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
                user_id = event.get("user", "") or ""
                if cmd_name in ("digest", "osint", "help", "?"):
                    if not self.auth.authorized_slack(user_id):
                        logger.info(
                            "Slack user %s denied command %r — not in allowlist",
                            user_id,
                            cmd_name,
                        )
                        return
                    cd = self.auth.cooldown_remaining("slack", user_id)
                    if cd:
                        await say(text=f"⏳ Slow down — try again in {cd}s.")
                        return
                    self.auth.record("slack", user_id)
                if cmd_name == "digest":
                    await handle_digest_command(
                        cmd_args,
                        self.scheduler,
                        reply=lambda msg: say(text=msg),
                        reply_channel=channel,
                        actor=user_id,
                    )
                elif cmd_name == "osint":
                    await handle_osint_command(
                        cmd_args,
                        self.ioc_processor,
                        reply=lambda msg: say(text=msg),
                        platform=Platform.SLACK,
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
                llm_summary: str = "⚠️ Assessment unavailable — summarizer did not respond"
                try:
                    llm_summary = await self.summarizer.summarize_ioc(ioc, intel)
                except Exception as exc:
                    logger.warning("IOC LLM summary failed for %s: %s", ioc.value, exc)
                    llm_summary = f"⚠️ Assessment unavailable — {exc}"

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
            user_id = event.get("user", "") or ""
            cmd = parse_command(text)
            if cmd is not None:
                cmd_name, cmd_args = cmd
                if cmd_name in ("digest", "osint", "help", "?"):
                    if not self.auth.authorized_slack(user_id):
                        logger.info(
                            "Slack user %s denied @mention command %r — not in allowlist",
                            user_id,
                            cmd_name,
                        )
                        return
                    cd = self.auth.cooldown_remaining("slack", user_id)
                    if cd:
                        await say(text=f"⏳ Slow down — try again in {cd}s.")
                        return
                    self.auth.record("slack", user_id)
                if cmd_name == "digest":
                    await handle_digest_command(
                        cmd_args,
                        self.scheduler,
                        reply=lambda msg: say(text=msg),
                        reply_channel=event.get("channel"),
                        actor=user_id,
                    )
                    return
                if cmd_name == "osint":
                    await handle_osint_command(
                        cmd_args,
                        self.ioc_processor,
                        reply=lambda msg: say(text=msg),
                        platform=Platform.SLACK,
                    )
                    return
            await say(text=HELP_TEXT)

        async def on_reaction(event: dict, context, removed: bool) -> None:
            item = event.get("item") or {}
            user = event.get("user", "")
            useful = _VOTES.get(str(event.get("reaction", "")).split("::")[0])
            if (
                useful is None
                or item.get("type") != "message"
                or not user
                or user == context.get("bot_user_id")
                or self.scheduler is None
                or not self.auth.authorized_slack(user)
            ):
                return
            message = f"{item.get('channel')}:{item.get('ts')}"
            if self.scheduler.store.react_feedback(
                self.platform_name, message, user, useful, removed=removed
            ):
                logger.info("Slack feedback from %s on %s: %s", user, message, useful)

        @self.app.event("reaction_added")
        async def on_reaction_added(event: dict, context) -> None:
            await on_reaction(event, context, removed=False)

        @self.app.event("reaction_removed")
        async def on_reaction_removed(event: dict, context) -> None:
            await on_reaction(event, context, removed=True)

        @self.app.action(re.compile(".*"))
        async def on_any_action(ack) -> None:
            """Acknowledge all block_actions (e.g. URL buttons) to suppress 404 warnings."""
            await ack()

        @self.app.error
        async def on_error(error: Exception) -> None:
            logger.error("Slack bolt error: %s", error)

    def digest_destination(self, channel=None):
        ch = channel or self.cfg.get("digest_channel")
        if not ch or str(ch).isdigit():
            ch = self.cfg.get("digest_channel")
        if not ch:
            raise ValueError("No Slack digest channel configured")
        return self.platform_name, str(ch)

    def digest_payloads(self, topic, summary, meta):
        return format_digest_slack_message(topic, summary, meta=meta)

    async def send_digest(
        self,
        topic_name: str,
        summary: str,
        lookback: str | None = None,
        channel: str | None = None,
        meta: dict | None = None,
    ) -> None:
        """Send a digest message to a channel using Block Kit formatting."""
        _, ch = self.digest_destination(channel)
        meta = meta or {}
        payloads = meta.get("_payloads")
        if payloads is None:
            payloads = format_digest_slack_message(topic_name, summary, lookback, meta=meta)
        for index, payload in enumerate(payloads):
            if index < meta.get("_offset", 0):
                continue
            if meta.get("_delivery_id"):
                payload["client_msg_id"] = str(
                    uuid.uuid5(uuid.NAMESPACE_URL, f"{meta['_delivery_id']}:{index}")
                )
            response = await self.app.client.chat_postMessage(channel=ch, **payload)
            if index < len(meta.get("articles") or []):
                await self._seed_votes(response, meta, index)
            if meta.get("_ack"):
                meta["_ack"](index + 1)

    async def _seed_votes(self, response, meta: dict, index: int) -> None:
        """Map a story message to its article and pre-add 👍/👎 so rating is one click.

        Best effort: the message is already posted, so a failure here must not
        fail the delivery (which would re-post it).
        """
        channel, ts = response.get("channel"), response.get("ts")
        if not channel or not ts:
            return
        if meta.get("_sent"):
            meta["_sent"](index, f"{channel}:{ts}")
        for name in ("+1", "-1"):
            try:
                await self.app.client.reactions_add(channel=channel, timestamp=ts, name=name)
            except Exception as exc:
                logger.debug("Could not add %s to digest story: %s", name, exc)

    async def start(self) -> None:
        """Start the Socket Mode handler (blocks until stopped)."""
        app_token = self.cfg.get("app_token", "")
        if not app_token:
            raise ValueError("Slack app_token is required for Socket Mode")
        logger.info("Starting Slack Socket Mode handler...")
        handler = AsyncSocketModeHandler(self.app, app_token)
        await handler.start_async()
