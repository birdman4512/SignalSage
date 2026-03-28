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


def _risk_emoji(result: IntelResult) -> str:
    if result.error:
        return "⚠️"
    if result.malicious is True:
        return "🔴"
    if result.malicious is False:
        return "✅"
    return "⚪"


def _overall_verdict(results: list[IntelResult]) -> tuple[str, str]:
    """Return (emoji, label) for the overall verdict across all provider results."""
    malicious = [r for r in results if r.malicious is True and not r.error]
    clean = [r for r in results if r.malicious is False and not r.error]
    total = len([r for r in results if not r.error])

    if not total:
        return "⚪", "UNKNOWN"
    if malicious:
        pct = int(len(malicious) / total * 100)
        return "🔴", f"MALICIOUS  ({len(malicious)}/{total} providers flagged, {pct}%)"
    if clean:
        return "✅", f"CLEAN  ({len(clean)}/{total} providers)"
    return "⚪", "UNKNOWN"


def _link(url: str, label: str, platform: Platform) -> str:
    if not url:
        return label
    if platform == Platform.SLACK:
        return f"<{url}|{label}>"
    return f"[{label}]({url})"


# ---------------------------------------------------------------------------
# Slack Block Kit
# ---------------------------------------------------------------------------

def format_slack_blocks(ioc: IOC, results: list[IntelResult]) -> list[dict]:
    """Build a Slack Block Kit payload for an IOC report."""
    label = IOC_TYPE_LABEL.get(ioc.type, ioc.type.value)
    verdict_emoji, verdict_text = _overall_verdict(results)

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"🔍  IOC Report", "emoji": True},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Indicator*\n`{ioc.value}`"},
                {"type": "mrkdwn", "text": f"*Type*\n{label}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Overall Verdict:*  {verdict_emoji}  {verdict_text}",
            },
        },
        {"type": "divider"},
    ]

    for result in results:
        emoji = _risk_emoji(result)
        if result.error:
            body = f"Error — {result.error}"
        else:
            body = result.summary or "No details available"

        text = f"{emoji}  *{result.provider}*\n{body}"
        block: dict = {"type": "section", "text": {"type": "mrkdwn", "text": text}}

        if result.report_url and not result.error:
            block["accessory"] = {
                "type": "button",
                "text": {"type": "plain_text", "text": "View Report", "emoji": False},
                "url": result.report_url,
                "action_id": f"report_{result.provider.lower().replace(' ', '_')}",
            }

        blocks.append(block)

    blocks.append({"type": "divider"})
    return blocks


# ---------------------------------------------------------------------------
# Discord / plain-text fallback
# ---------------------------------------------------------------------------

def format_results(ioc: IOC, results: list[IntelResult], platform: Platform) -> str:
    """Format IOC results as plain text (used for Discord and as Slack fallback)."""
    label = IOC_TYPE_LABEL.get(ioc.type, ioc.type.value)
    verdict_emoji, verdict_text = _overall_verdict(results)
    sep = "━" * 38

    lines: list[str] = [
        sep,
        f"🔍  **{ioc.value}**  —  {label}" if platform == Platform.DISCORD
        else f"🔍  *{ioc.value}*  —  {label}",
        f"Verdict:  {verdict_emoji}  {verdict_text}",
        sep,
    ]

    for result in results:
        emoji = _risk_emoji(result)
        name = f"**{result.provider}**" if platform == Platform.DISCORD else f"*{result.provider}*"

        if result.error:
            lines.append(f"{emoji}  {name}  —  Error: {result.error}")
        else:
            line = f"{emoji}  {name}  —  {result.summary or 'No details'}"
            if result.report_url:
                line += f"  ·  {_link(result.report_url, 'view report', platform)}"
            lines.append(line)

    return "\n".join(lines)


def split_message(text: str, limit: int = 2000) -> list[str]:
    """Split a long message into chunks that fit within the character limit."""
    if len(text) <= limit:
        return [text]

    chunks: list[str] = []
    current_lines: list[str] = []
    current_len = 0

    for line in text.split("\n"):
        line_len = len(line) + 1
        if current_len + line_len > limit:
            if current_lines:
                chunks.append("\n".join(current_lines))
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
