"""Custom regex-based IOC extractor with defanging support."""

import ipaddress
import logging
import re

import tldextract

from .models import IOC, IOCType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Benign domains to skip
# ---------------------------------------------------------------------------
BENIGN_DOMAINS: set[str] = {
    "google.com",
    "microsoft.com",
    "github.com",
    "youtube.com",
    "facebook.com",
    "twitter.com",
    "amazon.com",
    "cloudflare.com",
    "slack.com",
    "discord.com",
    "example.com",
    "x.com",
    "linkedin.com",
    "apple.com",
    "office.com",
    "windows.com",
    "live.com",
    "outlook.com",
}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Strip code blocks before extraction
_CODE_BLOCK_RE = re.compile(r"```.*?```|`[^`]+`", re.DOTALL)

# IPv4: standard and defanged variants
# Matches: 1.2.3.4, 1.2.3[.]4, 1[.]2[.]3[.]4, 1(.)2(.)3(.)4
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)"
_DOT = r"(?:\[?\.\]?|\(\.\))"
_IPV4_RE = re.compile(
    rf"\b({_IPV4_OCTET}{_DOT}{_IPV4_OCTET}{_DOT}{_IPV4_OCTET}{_DOT}{_IPV4_OCTET})\b"
)

# IPv6 - simplified pattern for full and compressed forms
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}"
)

# Hash patterns (128, 64, 40, 32 hex chars) — checked in order to avoid partial matches
_SHA512_RE = re.compile(r"\b([0-9a-fA-F]{128})\b")
_SHA256_RE = re.compile(r"\b([0-9a-fA-F]{64})\b")
_SHA1_RE = re.compile(r"\b([0-9a-fA-F]{40})\b")
_MD5_RE = re.compile(r"\b([0-9a-fA-F]{32})\b")

# CVE
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)

# URLs (standard + defanged hxxp/hxxps, also [.] and (.) in domain)
_URL_RE = re.compile(
    r"(?:https?|hxxps?)"  # scheme (including defanged)
    r"(?:://|://)?"  # optional ://
    r"(?:\[?\.\]?|\(\.\)|[^\s<>\"'()[\]{}|\\^`]){3,}",
    re.IGNORECASE,
)

# Email
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

# Domain (standalone, not part of URL/email)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\[?\.\]?)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\[?\.\]?)*"
    r"[a-zA-Z]{2,}\b"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _refang(value: str) -> str:
    """Remove common defanging patterns."""
    value = value.replace("[.]", ".").replace("(.)", ".")
    value = value.replace("[", "").replace("]", "")
    value = re.sub(
        r"^hxxps?", lambda m: m.group(0).replace("hxxp", "http"), value, flags=re.IGNORECASE
    )
    return value


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        )
    except ValueError:
        return True


def _root_domain(domain: str) -> str:
    """Return the registered domain (e.g. sub.example.com -> example.com)."""
    ext = tldextract.extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain


def _is_benign_domain(domain: str) -> bool:
    """Return True if domain (or its root) is on the benign list."""
    root = _root_domain(domain)
    return root in BENIGN_DOMAINS or domain in BENIGN_DOMAINS


# ---------------------------------------------------------------------------
# Main extraction function
# ---------------------------------------------------------------------------


def extract(text: str) -> list[IOC]:
    """Extract IOCs from text, handling defanging and filtering benign values."""
    # Strip code blocks first
    clean = _CODE_BLOCK_RE.sub(" ", text)

    iocs: list[IOC] = []
    used_spans: list[tuple[int, int]] = []

    def _span_used(match: re.Match) -> bool:
        start, end = match.span()
        for s, e in used_spans:
            if start < e and end > s:
                return True
        return False

    def _mark(match: re.Match) -> None:
        used_spans.append(match.span())

    # --- CVEs (high confidence, extract first) ---
    for m in _CVE_RE.finditer(clean):
        if _span_used(m):
            continue
        _mark(m)
        iocs.append(IOC(value=m.group(1).upper(), type=IOCType.CVE, raw=m.group(0)))

    # --- URLs ---
    for m in _URL_RE.finditer(clean):
        if _span_used(m):
            continue
        raw = m.group(0)
        url = _refang(raw).rstrip(".,;)")
        if len(url) < 10:
            continue
        _mark(m)
        iocs.append(IOC(value=url, type=IOCType.URL, raw=raw))
        # Also extract domain from URL
        try:
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                domain = f"{ext.domain}.{ext.suffix}"
                if ext.subdomain:
                    full = f"{ext.subdomain}.{domain}"
                else:
                    full = domain
                if not _is_benign_domain(full):
                    iocs.append(IOC(value=full, type=IOCType.DOMAIN, raw=raw))
        except Exception:
            pass

    # --- Emails ---
    for m in _EMAIL_RE.finditer(clean):
        if _span_used(m):
            continue
        _mark(m)
        iocs.append(IOC(value=m.group(0).lower(), type=IOCType.EMAIL, raw=m.group(0)))

    # --- IPv4 ---
    for m in _IPV4_RE.finditer(clean):
        if _span_used(m):
            continue
        raw = m.group(0)
        ip = _refang(raw)
        if _is_private_ip(ip):
            continue
        _mark(m)
        iocs.append(IOC(value=ip, type=IOCType.IPV4, raw=raw))

    # --- IPv6 ---
    for m in _IPV6_RE.finditer(clean):
        if _span_used(m):
            continue
        raw = m.group(0)
        ip = _refang(raw)
        if _is_private_ip(ip):
            continue
        _mark(m)
        iocs.append(IOC(value=ip, type=IOCType.IPV6, raw=raw))

    # --- Hashes (longest first to avoid partial matches) ---
    for pattern, ioc_type in [
        (_SHA512_RE, IOCType.SHA512),
        (_SHA256_RE, IOCType.SHA256),
        (_SHA1_RE, IOCType.SHA1),
        (_MD5_RE, IOCType.MD5),
    ]:
        for m in pattern.finditer(clean):
            if _span_used(m):
                continue
            _mark(m)
            iocs.append(IOC(value=m.group(1).lower(), type=ioc_type, raw=m.group(0)))

    # --- Standalone domains (not already captured via URL/email) ---
    for m in _DOMAIN_RE.finditer(clean):
        if _span_used(m):
            continue
        raw = m.group(0)
        domain = _refang(raw).lower().rstrip(".")
        # Must have a valid TLD
        ext = tldextract.extract(domain)
        if not ext.domain or not ext.suffix:
            continue
        if _is_benign_domain(domain):
            continue
        _mark(m)
        iocs.append(IOC(value=domain, type=IOCType.DOMAIN, raw=raw))

    return iocs
