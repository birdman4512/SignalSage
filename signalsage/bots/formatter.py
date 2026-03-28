"""Message formatting for Slack and Discord platforms."""

from enum import Enum

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC, IOCType


class Platform(Enum):
    SLACK = "slack"
    DISCORD = "discord"


IOC_TYPE_LABEL = {
    IOCType.IPV4: "IPv4 Address",
    IOCType.IPV6: "IPv6 Address",
    IOCType.DOMAIN: "Domain",
    IOCType.URL: "URL",
    IOCType.MD5: "MD5 Hash",
    IOCType.SHA1: "SHA-1 Hash",
    IOCType.SHA256: "SHA-256 Hash",
    IOCType.SHA512: "SHA-512 Hash",
    IOCType.EMAIL: "Email Address",
    IOCType.CVE: "CVE",
}


def _bold(text: str, platform: Platform) -> str:
    if platform == Platform.SLACK:
        return f"*{text}*"
    return f"**{text}**"


def _link(url: str, label: str, platform: Platform) -> str:
    if not url:
        return label
    if platform == Platform.SLACK:
        return f"<{url}|{label}>"
    return f"[{label}]({url})"


def _risk_emoji(result: IntelResult) -> str:
    if result.error:
        return "⚠️"
    if result.malicious is True:
        return "🔴"
    if result.malicious is False:
        return "✅"
    return "⚪"


def format_results(
    ioc: IOC,
    results: list[IntelResult],
    platform: Platform,
) -> str:
    """Format a list of IntelResults for a given IOC into a readable message."""
    label = IOC_TYPE_LABEL.get(ioc.type, ioc.type.value)
    separator = "━" * 35

    lines: list[str] = [
        separator,
        f"🔍 `{ioc.value}` ({label})",
        "",
    ]

    for result in results:
        emoji = _risk_emoji(result)
        provider_bold = _bold(result.provider, platform)

        if result.error:
            line = f"{emoji} {provider_bold}: Error — {result.error}"
        else:
            line = f"{emoji} {provider_bold}: {result.summary}"
            if result.report_url:
                link = _link(result.report_url, "details", platform)
                line += f" — {link}"

        lines.append(line)

    return "\n".join(lines)


def split_message(text: str, limit: int = 2000) -> list[str]:
    """
    Split a long message into chunks that fit within the character limit.

    Splits on newlines where possible to avoid breaking mid-line.
    """
    if len(text) <= limit:
        return [text]

    chunks: list[str] = []
    current_lines: list[str] = []
    current_len = 0

    for line in text.split("\n"):
        # +1 for the newline character
        line_len = len(line) + 1

        if current_len + line_len > limit:
            if current_lines:
                chunks.append("\n".join(current_lines))
            # Handle lines longer than limit by hard splitting
            if line_len > limit:
                while line:
                    chunks.append(line[:limit])
                    line = line[limit:]
                current_lines = []
                current_len = 0
            else:
                current_lines = [line]
                current_len = line_len
        else:
            current_lines.append(line)
            current_len += line_len

    if current_lines:
        chunks.append("\n".join(current_lines))

    return chunks
