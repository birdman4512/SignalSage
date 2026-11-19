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
from signalsage.llm.base import BaseLLM
from signalsage.llm.gemini import GeminiLLM

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
    """The digest/IOC-assessment model, or None when no Gemini key is configured."""
    api_key = digest.get("gemini_api_key")
    if not api_key:
        return None
    budget = digest.get("gemini_thinking_budget")
    return GeminiLLM(
        api_key=api_key,
        model=digest.get("gemini_model") or "gemini-flash-lite-latest",
        timeout=digest.get("gemini_timeout", 120),
        temperature=float(digest.get("temperature", 0)),
        min_interval=float(digest.get("gemini_min_interval", 6)),
        thinking_budget=None if budget is None or budget == "" else int(budget),
    )
