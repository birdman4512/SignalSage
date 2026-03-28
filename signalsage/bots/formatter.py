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


_PROVIDER_ICON: dict[str, str] = {
    "VirusTotal": "🔬",
    "Shodan": "🌐",
    "GreyNoise": "📡",
    "AbuseIPDB": "🚨",
    "OTX": "👽",
    "URLhaus": "🔗",
    "ThreatFox": "🦊",
    "MalwareBazaar": "🦠",
    "IPInfo": "ℹ️",
    "CIRCL CVE": "📋",
    "URLScan": "🔍",
}


def _provider_icon(name: str) -> str:
    return _PROVIDER_ICON.get(name, "🔎")


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
# Slack Block Kit (attachment-style card with coloured left border)
# ---------------------------------------------------------------------------

_VERDICT_COLOUR = {
    "malicious": "#e01e5a",  # red
    "clean": "#2eb67d",  # green
    "unknown": "#868686",  # grey
}


def _verdict_colour(results: list[IntelResult]) -> str:
    malicious = [r for r in results if r.malicious is True and not r.error]
    clean = [r for r in results if r.malicious is False and not r.error]
    if malicious:
        return _VERDICT_COLOUR["malicious"]
    if clean:
        return _VERDICT_COLOUR["clean"]
    return _VERDICT_COLOUR["unknown"]


def format_slack_message(
    ioc: IOC,
    results: list[IntelResult],
    llm_summary: str | None = None,
    assessment_pending: bool = False,
) -> dict:
    """
    Return a dict ready to be spread into ``say(**payload)`` for Slack.

    Uses a legacy attachment wrapper (for the coloured left border) containing
    Block Kit blocks (for rich formatting).  Fallback plain-text is included
    for notifications.

    Args:
        llm_summary: Optional LLM-generated plain-English assessment to include
                     below the verdict.
    """
    label = IOC_TYPE_LABEL.get(ioc.type, ioc.type.value)
    verdict_emoji, verdict_text = _overall_verdict(results)
    colour = _verdict_colour(results)
    total_providers = len([r for r in results if not r.error])

    # ── header: IOC value + type context ────────────────────────────────────
    blocks: list[dict] = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*🔍  `{ioc.value}`*"},
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"*{label}*  ·  checked by {total_providers} provider{'s' if total_providers != 1 else ''}",
                }
            ],
        },
        {"type": "divider"},
        # ── verdict ─────────────────────────────────────────────────────────
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Verdict:*   {verdict_emoji}  {verdict_text}"},
        },
    ]

    # ── LLM assessment ───────────────────────────────────────────────────────
    if llm_summary:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Assessment:*\n{llm_summary}"},
            }
        )
    elif assessment_pending:
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": "💭  _Generating assessment…_"}],
            }
        )

    blocks.append({"type": "divider"})

    # ── provider results — one full-width block per provider ─────────────────
    for result in results:
        icon = _provider_icon(result.provider)
        verdict = _risk_emoji(result)
        if result.error:
            body = f"{verdict}  _{result.error}_"
        else:
            body = f"{verdict}  {result.summary or 'No details'}"

        block: dict = {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{icon}  *{result.provider}*\n{body}",
            },
        }
        if result.report_url and not result.error:
            block["accessory"] = {
                "type": "button",
                "text": {"type": "plain_text", "text": "View Report", "emoji": False},
                "url": result.report_url,
                "action_id": f"report_{result.provider.lower().replace(' ', '_')}",
            }
        blocks.append(block)

    blocks.append({"type": "divider"})

    fallback = f"IOC Report: {ioc.value} ({label}) — {verdict_emoji} {verdict_text}"
    if llm_summary:
        fallback += f"\n{llm_summary}"

    return {
        "text": fallback,
        "attachments": [{"color": colour, "blocks": blocks}],
    }


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
        f"🔍  **{ioc.value}**  —  {label}"
        if platform == Platform.DISCORD
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
