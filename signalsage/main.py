"""SignalSage main entry point."""

import asyncio
import logging
import sys
from typing import Callable, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


async def main() -> None:
    # ------------------------------------------------------------------ #
    # Config                                                               #
    # ------------------------------------------------------------------ #
    from signalsage.config import load_config, load_watchlist

    try:
        cfg = load_config()
        watchlist = load_watchlist()
    except FileNotFoundError as exc:
        logger.error("Configuration file missing: %s", exc)
        sys.exit(1)

    intel_cfg = cfg.get("intel", {})
    timeout: int = intel_cfg.get("timeout", 10)
    providers_cfg = intel_cfg.get("providers", {})

    # ------------------------------------------------------------------ #
    # Intel providers                                                      #
    # ------------------------------------------------------------------ #
    from signalsage.intel.virustotal import VirusTotalProvider
    from signalsage.intel.shodan import ShodanProvider
    from signalsage.intel.greynoise import GreyNoiseProvider
    from signalsage.intel.abuseipdb import AbuseIPDBProvider
    from signalsage.intel.otx import OTXProvider
    from signalsage.intel.urlhaus import URLhausProvider
    from signalsage.intel.threatfox import ThreatFoxProvider
    from signalsage.intel.malwarebazaar import MalwareBazaarProvider
    from signalsage.intel.ipinfo import IPInfoProvider
    from signalsage.intel.circl_cve import CIRCLCVEProvider
    from signalsage.intel.base import BaseProvider

    providers: List[BaseProvider] = []

    def add_provider(cls, key: str) -> None:
        pcfg = providers_cfg.get(key, {})
        if pcfg.get("enabled", True):
            provider = cls(api_key=pcfg.get("api_key"), timeout=timeout)
            providers.append(provider)
            status = "enabled" if provider.enabled else "disabled (missing API key)"
            logger.info("Provider %s: %s", provider.name, status)

    add_provider(VirusTotalProvider, "virustotal")
    add_provider(ShodanProvider, "shodan")
    add_provider(GreyNoiseProvider, "greynoise")
    add_provider(AbuseIPDBProvider, "abuseipdb")
    add_provider(OTXProvider, "otx")
    add_provider(URLhausProvider, "urlhaus")
    add_provider(ThreatFoxProvider, "threatfox")
    add_provider(MalwareBazaarProvider, "malwarebazaar")
    add_provider(IPInfoProvider, "ipinfo")
    add_provider(CIRCLCVEProvider, "circl_cve")

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
    # Digest Summarizer                                                    #
    # ------------------------------------------------------------------ #
    digest_cfg = cfg.get("digest", {})
    summarizer = None
    llm_api_key = digest_cfg.get("llm_api_key", "")

    if llm_api_key:
        from signalsage.digest.summarizer import DigestSummarizer

        summarizer = DigestSummarizer(
            llm_model=digest_cfg.get("llm_model", "claude-haiku-4-5-20251001"),
            llm_api_key=llm_api_key,
            max_chars=digest_cfg.get("max_chars_per_source", 3000),
        )
        logger.info("Digest summarizer initialized with model %s", summarizer.llm_model)
    else:
        logger.warning("No ANTHROPIC_API_KEY set — daily digest summarizer disabled")

    # ------------------------------------------------------------------ #
    # Bot initialization                                                   #
    # ------------------------------------------------------------------ #
    tasks: List[asyncio.Task] = []
    notifiers: List[Callable] = []
    scheduler = None

    platforms_cfg = cfg.get("platforms", {})

    # Slack
    if platforms_cfg.get("slack", {}).get("enabled"):
        try:
            from signalsage.bots.slack import SlackBot

            slack_bot = SlackBot(cfg, processor)
            notifiers.append(slack_bot.send_digest)
            tasks.append(asyncio.create_task(slack_bot.start(), name="slack"))
            logger.info("Slack bot task created")
        except Exception as exc:
            logger.error("Failed to initialize Slack bot: %s", exc)

    # Discord
    if platforms_cfg.get("discord", {}).get("enabled"):
        try:
            from signalsage.bots.discord_bot import DiscordBot

            discord_bot = DiscordBot(cfg, processor)
            notifiers.append(discord_bot.send_digest)
            tasks.append(asyncio.create_task(discord_bot.start_bot(), name="discord"))
            logger.info("Discord bot task created")
        except Exception as exc:
            logger.error("Failed to initialize Discord bot: %s", exc)

    if not tasks:
        logger.error(
            "No platforms enabled. Enable at least one platform in config/config.yaml."
        )
        return

    # ------------------------------------------------------------------ #
    # Scheduler                                                            #
    # ------------------------------------------------------------------ #
    if summarizer and notifiers:
        from signalsage.scheduler import DigestScheduler

        try:
            scheduler = DigestScheduler(
                summarizer=summarizer,
                watchlist=watchlist,
                notifiers=notifiers,
                default_schedule=digest_cfg.get("default_schedule", "0 6 * * *"),
                timezone=digest_cfg.get("timezone", "UTC"),
            )
            scheduler.start()
        except Exception as exc:
            logger.error("Failed to start digest scheduler: %s", exc)
    elif not summarizer:
        logger.info("Digest scheduler not started — no LLM configured")
    elif not notifiers:
        logger.info("Digest scheduler not started — no notifiers available")

    # ------------------------------------------------------------------ #
    # Run                                                                  #
    # ------------------------------------------------------------------ #
    logger.info("SignalSage started. Running %d bot(s)...", len(tasks))
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.info("Bot tasks cancelled")
    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
    finally:
        if scheduler:
            scheduler.shutdown()
        logger.info("SignalSage shutting down")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, exiting")
