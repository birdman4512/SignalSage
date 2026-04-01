"""SignalSage main entry point."""

import asyncio
import logging
import sys
from collections.abc import Callable

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
    from signalsage.intel.abuseipdb import AbuseIPDBProvider
    from signalsage.intel.base import BaseProvider
    from signalsage.intel.circl_cve import CIRCLCVEProvider
    from signalsage.intel.circl_pdns import CIRCLPDNSProvider
    from signalsage.intel.crtsh import CRTShProvider
    from signalsage.intel.greynoise import GreyNoiseProvider
    from signalsage.intel.hibp import HIBPProvider
    from signalsage.intel.ipinfo import IPInfoProvider
    from signalsage.intel.malwarebazaar import MalwareBazaarProvider
    from signalsage.intel.otx import OTXProvider
    from signalsage.intel.shodan import ShodanProvider
    from signalsage.intel.threatfox import ThreatFoxProvider
    from signalsage.intel.urlhaus import URLhausProvider
    from signalsage.intel.urlscan import URLScanProvider
    from signalsage.intel.virustotal import VirusTotalProvider
    from signalsage.intel.whois_age import WHOISAgeProvider

    providers: list[BaseProvider] = []

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
    add_provider(URLScanProvider, "urlscan")
    add_provider(CRTShProvider, "crtsh")
    add_provider(WHOISAgeProvider, "whois_age")
    add_provider(CIRCLPDNSProvider, "circl_pdns")
    add_provider(HIBPProvider, "hibp")

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
        if llm_provider == "anthropic":
            from signalsage.llm.anthropic_llm import AnthropicLLM

            api_key = digest_cfg.get("anthropic_api_key", "")
            if not api_key:
                logger.warning(
                    "llm_provider=anthropic but ANTHROPIC_API_KEY not set — digest disabled"
                )
                llm = None
            else:
                llm = AnthropicLLM(
                    api_key=api_key,
                    model=digest_cfg.get("anthropic_model", "claude-haiku-4-5-20251001"),
                )
        else:
            from signalsage.llm.ollama import OllamaLLM

            llm = OllamaLLM(
                base_url=digest_cfg.get("ollama_base_url") or "http://localhost:11434",
                model=digest_cfg.get("ollama_model") or "llama3.2",
                num_ctx=digest_cfg.get("ollama_num_ctx", 8192),
            )
    except Exception as exc:
        logger.error("Failed to initialize LLM (%s): %s", llm_provider, exc)
        llm = None

    if llm:
        from signalsage.digest.summarizer import DigestSummarizer

        summarizer = DigestSummarizer(
            llm=llm,
            max_chars=digest_cfg.get("max_chars_per_source", 3000),
            max_total_chars=digest_cfg.get("max_total_chars_per_topic", 20000),
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

    # Slack
    if platforms_cfg.get("slack", {}).get("enabled"):
        try:
            from signalsage.bots.slack import SlackBot

            slack_bot = SlackBot(cfg, processor, summarizer=summarizer)
            notifiers.append(slack_bot.send_digest)
            tasks.append(asyncio.create_task(slack_bot.start(), name="slack"))
            logger.info("Slack bot task created")
        except Exception as exc:
            logger.error("Failed to initialize Slack bot: %s", exc)

    # Discord
    if platforms_cfg.get("discord", {}).get("enabled"):
        try:
            from signalsage.bots.discord_bot import DiscordBot

            discord_bot = DiscordBot(cfg, processor, summarizer=summarizer)
            notifiers.append(discord_bot.send_digest)
            tasks.append(asyncio.create_task(discord_bot.start_bot(), name="discord"))
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
