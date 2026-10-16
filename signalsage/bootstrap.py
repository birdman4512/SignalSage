"""Application component factories kept separate from process orchestration."""

import logging

import httpx

from signalsage.intel.abuseipdb import AbuseIPDBProvider
from signalsage.intel.base import BaseProvider
from signalsage.intel.bgpview import BGPViewProvider
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
from signalsage.llm.anthropic_llm import AnthropicLLM
from signalsage.llm.base import BaseLLM
from signalsage.llm.cli_llm import CliLLM
from signalsage.llm.ollama import OllamaLLM

logger = logging.getLogger(__name__)

PROVIDERS = (
    (VirusTotalProvider, "virustotal"),
    (ShodanProvider, "shodan"),
    (GreyNoiseProvider, "greynoise"),
    (AbuseIPDBProvider, "abuseipdb"),
    (OTXProvider, "otx"),
    (URLhausProvider, "urlhaus"),
    (ThreatFoxProvider, "threatfox"),
    (MalwareBazaarProvider, "malwarebazaar"),
    (IPInfoProvider, "ipinfo"),
    (CIRCLCVEProvider, "circl_cve"),
    (URLScanProvider, "urlscan"),
    (CRTShProvider, "crtsh"),
    (WHOISAgeProvider, "whois_age"),
    (CIRCLPDNSProvider, "circl_pdns"),
    (HIBPProvider, "hibp"),
    (BGPViewProvider, "bgpview"),
)


def build_providers(config: dict, client: httpx.AsyncClient) -> list[BaseProvider]:
    intel = config.get("intel", {})
    timeout = int(intel.get("timeout", 10))
    configured = intel.get("providers", {})
    providers: list[BaseProvider] = []
    for provider_class, key in PROVIDERS:
        settings = configured.get(key, {})
        if not settings.get("enabled", True):
            continue
        provider = provider_class(
            api_key=settings.get("api_key"), timeout=timeout, http_client=client
        )
        providers.append(provider)
        status = "enabled" if provider.enabled else "disabled (missing API key)"
        logger.info("Provider %s: %s", provider.name, status)
    return providers


def build_llm(digest: dict) -> BaseLLM | None:
    provider = str(digest.get("llm_provider") or "ollama").lower()
    if provider == "anthropic":
        return AnthropicLLM(
            api_key=digest["anthropic_api_key"],
            model=digest.get("anthropic_model", "claude-haiku-4-5-20251001"),
        )
    if provider == "cli":
        return CliLLM(
            command=digest.get("cli_command") or "claude",
            extra_args=digest.get("cli_extra_args") or [],
            timeout=digest.get("cli_timeout", 600),
        )
    return OllamaLLM(
        base_url=digest.get("ollama_base_url") or "http://localhost:11434",
        model=digest.get("ollama_model") or "gemma2:2b",
        num_ctx=digest.get("ollama_num_ctx", 4096),
        timeout=digest.get("ollama_timeout", 600),
        temperature=float(digest.get("temperature", 0)),
        think=digest.get("ollama_think"),
    )
