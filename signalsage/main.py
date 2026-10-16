"""SignalSage main entry point."""

import asyncio
import logging
import os
import sys
from collections.abc import Callable

from signalsage.observability import HealthServer, configure_logging, supervise

configure_logging()
logger = logging.getLogger(__name__)


async def main() -> None:
    # ------------------------------------------------------------------ #
    # Config                                                               #
    # ------------------------------------------------------------------ #
    from signalsage.config import (
        ConfigError,
        load_config,
        load_digests,
        validate_config,
        validate_digests,
    )

    try:
        cfg = validate_config(load_config())
        watchlist = validate_digests(
            load_digests(), (cfg.get("digest", {}) or {}).get("timezone", "UTC")
        )
    except (FileNotFoundError, ConfigError) as exc:
        logger.error("Configuration error: %s", exc)
        sys.exit(1)

    intel_cfg = cfg.get("intel", {})
    timeout: int = intel_cfg.get("timeout", 10)

    # ------------------------------------------------------------------ #
    # Intel providers                                                      #
    # ------------------------------------------------------------------ #
    import httpx

    from signalsage.bootstrap import build_llm, build_providers

    # One shared httpx.AsyncClient is reused by every provider so consecutive IOC
    # lookups skip the TCP/TLS handshake. Limits chosen for the typical workload:
    # ~16 providers × max_iocs_per_message=5 burst.
    shared_http_client = httpx.AsyncClient(
        timeout=timeout,
        limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
    )

    providers = build_providers(cfg, shared_http_client)

    # ------------------------------------------------------------------ #
    # IOC Processor                                                        #
    # ------------------------------------------------------------------ #
    from signalsage.ioc.processor import IOCProcessor

    processor = IOCProcessor(
        providers=providers,
        cache_ttl=intel_cfg.get("cache_ttl", 3600),
        max_per_msg=intel_cfg.get("max_iocs_per_message", 5),
    )

    # ------------------------------------------------------------------ #
    # LLM + Digest Summarizer                                             #
    # ------------------------------------------------------------------ #
    digest_cfg = cfg.get("digest", {})
    summarizer = None
    llm_provider = (digest_cfg.get("llm_provider") or "ollama").lower()
    try:
        llm = build_llm(digest_cfg)
    except Exception as exc:
        logger.error("Failed to initialize LLM (%s): %s", llm_provider, exc)
        llm = None

    if llm:
        from signalsage.digest.summarizer import DigestSummarizer

        summarizer = DigestSummarizer(
            llm=llm,
            max_chars=digest_cfg.get("article_chars", 6000),
            max_total_chars=digest_cfg.get("max_prompt_chars", 8000),
            interest_topics=digest_cfg.get("interest_topics") or [],
        )
        logger.info("Digest summarizer ready (provider: %s)", llm_provider)
    else:
        logger.warning("Digest summarizer not started — no LLM available")

    # ------------------------------------------------------------------ #
    # Bot initialization                                                   #
    # ------------------------------------------------------------------ #
    tasks: list[asyncio.Task] = []
    notifiers: list[Callable] = []
    scheduler = None
    slack_bot = None
    discord_bot = None

    platforms_cfg = cfg.get("platforms", {})

    # Shared command-auth gate. Empty allowlists = open (anyone in monitored channels).
    from signalsage.bots.auth import CommandAuth

    auth_cfg = cfg.get("auth", {}) or {}
    command_auth = CommandAuth(
        slack_users=(platforms_cfg.get("slack", {}) or {}).get("command_allowlist") or [],
        discord_users=(platforms_cfg.get("discord", {}) or {}).get("command_allowlist") or [],
        cooldown_seconds=int(auth_cfg.get("command_cooldown_seconds", 30)),
    )

    # Slack
    if platforms_cfg.get("slack", {}).get("enabled"):
        try:
            from signalsage.bots.slack import SlackBot

            slack_bot = SlackBot(cfg, processor, summarizer=summarizer, auth=command_auth)
            notifiers.append(slack_bot.send_digest)
            tasks.append(asyncio.create_task(supervise("slack", slack_bot.start), name="slack"))
            logger.info("Slack bot task created")
        except Exception as exc:
            logger.error("Failed to initialize Slack bot: %s", exc)

    # Discord
    if platforms_cfg.get("discord", {}).get("enabled"):
        try:
            from signalsage.bots.discord_bot import DiscordBot

            discord_bot = DiscordBot(cfg, processor, summarizer=summarizer, auth=command_auth)
            notifiers.append(discord_bot.send_digest)
            tasks.append(
                asyncio.create_task(supervise("discord", discord_bot.start_bot), name="discord")
            )
            logger.info("Discord bot task created")
        except Exception as exc:
            logger.error("Failed to initialize Discord bot: %s", exc)

    if not tasks:
        logger.error("No platforms enabled. Enable at least one platform in config/config.yaml.")
        return

    # ------------------------------------------------------------------ #
    # Scheduler                                                            #
    # ------------------------------------------------------------------ #
    if summarizer and notifiers:
        from signalsage.scheduler import DigestScheduler

        whisper_cfg = cfg.get("whisper", {})
        whisper_base_url: str | None = None
        if whisper_cfg.get("enabled"):
            whisper_base_url = whisper_cfg.get("base_url") or "http://whisper:8000"
            logger.info("Whisper transcription enabled at %s", whisper_base_url)
        else:
            logger.info("Whisper transcription disabled")

        try:
            scheduler = DigestScheduler(
                summarizer=summarizer,
                watchlist=watchlist,
                notifiers=notifiers,
                default_schedule=digest_cfg.get("default_schedule", "0 6 * * *"),
                timezone=digest_cfg.get("timezone", "UTC"),
                whisper_base_url=whisper_base_url,
                data_dir=digest_cfg.get("data_dir", "data"),
                top_stories_count=int(digest_cfg.get("top_stories_count", 10)),
                lookback_buffer_hours=float(digest_cfg.get("lookback_buffer_hours", 2)),
                watch_default_poll_minutes=int(digest_cfg.get("watch_default_poll_minutes", 15)),
                active_hours=digest_cfg.get("active_hours"),
                profile={
                    "topics": dict.fromkeys(digest_cfg.get("interest_topics") or [], 3),
                    **(digest_cfg.get("profile") or {}),
                },
                processor=processor,
                pipeline_settings=digest_cfg,
            )
            scheduler.start()
            # Give bots a scheduler reference so !digest commands work
            if slack_bot is not None:
                slack_bot.scheduler = scheduler
            if discord_bot is not None:
                discord_bot.scheduler = scheduler
        except Exception as exc:
            logger.error("Failed to start digest scheduler: %s", exc)
    elif not summarizer:
        logger.info("Digest scheduler not started — no LLM configured")
    elif not notifiers:
        logger.info("Digest scheduler not started — no notifiers available")

    # ------------------------------------------------------------------ #
    # Run                                                                  #
    # ------------------------------------------------------------------ #
    health = HealthServer(
        lambda: (
            scheduler.pipeline.store.status()
            if scheduler is not None and hasattr(scheduler, "pipeline")
            else {"components": len(tasks)}
        )
    )
    health_port = int(os.getenv("HEALTH_PORT", "8080"))
    await health.start(port=health_port)
    health.ready = True
    logger.info("SignalSage started. Running %d bot(s); health port=%d", len(tasks), health_port)
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.info("Bot tasks cancelled")
    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
    finally:
        health.ready = False
        await health.close()
        if scheduler:
            scheduler.shutdown()
        await shared_http_client.aclose()
        logger.info("SignalSage shutting down")


def run() -> None:
    """Console-script entry point."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, exiting")


if __name__ == "__main__":
    run()
