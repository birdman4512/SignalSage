"""Message formatting for Slack and Discord platforms."""

import json
import re
from datetime import date
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


# ---------------------------------------------------------------------------
# Digest formatting
# ---------------------------------------------------------------------------

# Topic icon map — falls back to 📰
_TOPIC_ICON: dict[str, str] = {
    "cybersecurity news": "🔐",
    "vulnerability alerts": "🚨",
    "threat intelligence": "🕵️",
    "hf amateur radio": "📻",
    "cybersecurity community": "💬",
}

_DIGEST_COLOUR = "#3b82f6"  # blue — distinct from IOC red/green


def _topic_icon(name: str) -> str:
    key = name.lower()
    for k, icon in _TOPIC_ICON.items():
        if k in key:
            return icon
    return "📰"


def _md_to_mrkdwn(text: str) -> str:
    """Convert common LLM markdown output to Slack mrkdwn."""
    # Bold: **text** or __text__ → *text*
    text = re.sub(r"\*\*(.+?)\*\*", r"*\1*", text)
    text = re.sub(r"__(.+?)__", r"*\1*", text)
    # Headings: ### text → *text*
    text = re.sub(r"^#{1,6}\s+(.+)$", r"*\1*", text, flags=re.MULTILINE)
    # Unordered list markers: "- " or "* " at line start → "• "
    text = re.sub(r"^[\-\*]\s+", "• ", text, flags=re.MULTILINE)
    return text.strip()


def _parse_digest_items(summary: str) -> list[dict] | None:
    """
    Try to parse LLM output as a JSON array of digest items.

    Each item should have 'headline', 'blurb', and 'url' keys.
    Returns None if parsing fails (caller falls back to plain text).
    """
    try:
        text = summary.strip()
        # Strip markdown code fences if the model adds them
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
        items = json.loads(text)
        if isinstance(items, list) and items and isinstance(items[0], dict):
            return items
    except (json.JSONDecodeError, ValueError, IndexError):
        pass
    return None


def format_digest_slack_message(
    topic_name: str,
    summary: str,
    lookback: str | None = None,
) -> dict:
    """
    Return a ``chat_postMessage`` payload for a digest topic.

    Uses a blue left-border attachment with Block Kit blocks inside.
    When the LLM returns structured JSON, each item gets its own section block
    with a headline, blurb, and optional 'Read More' button.
    Falls back to paragraph rendering if JSON parsing fails.
    """
    icon = _topic_icon(topic_name)
    today = date.today().strftime("%B %d, %Y")
    window = f"last {lookback}" if lookback else today

    blocks: list[dict] = [
        # ── header ──────────────────────────────────────────────────────────
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{icon}  *{topic_name}*"},
        },
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Digest  ·  {window}"}],
        },
        {"type": "divider"},
    ]

    items = _parse_digest_items(summary)

    if items:
        # ── structured item rendering ────────────────────────────────────────
        # Cap at 20 items to stay within Slack's 50-block limit
        # Each item uses 2 blocks (section + divider), header uses 3 → max ~46 items safe
        valid_items = [i for i in items[:20] if str(i.get("headline", "")).strip()]
        for idx, item in enumerate(valid_items):
            headline = str(item.get("headline", "")).strip()
            blurb = str(item.get("blurb", "")).strip()
            url = str(item.get("url") or "").strip()
            item_icon = str(item.get("icon") or "📰").strip()

            text = f"{item_icon}  *{headline}*\n{blurb}" if blurb else f"{item_icon}  *{headline}*"
            block: dict = {
                "type": "section",
                "text": {"type": "mrkdwn", "text": text},
            }
            if url and url.startswith("http"):
                block["accessory"] = {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Read More", "emoji": False},
                    "url": url,
                    "action_id": f"digest_link_{len(blocks)}",
                }
            blocks.append(block)
            if idx < len(valid_items) - 1:
                blocks.append({"type": "divider"})
    else:
        # ── fallback: paragraph rendering ────────────────────────────────────
        summary_mrkdwn = _md_to_mrkdwn(summary)
        paragraphs = re.split(r"\n{2,}", summary_mrkdwn)
        current_chunk: list[str] = []
        current_len = 0

        for para in paragraphs:
            para = para.strip()
            if not para:
                continue
            if current_len + len(para) + 2 > 2900 and current_chunk:
                blocks.append(
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": "\n\n".join(current_chunk)},
                    }
                )
                current_chunk = []
                current_len = 0
            current_chunk.append(para)
            current_len += len(para) + 2

        if current_chunk:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "\n\n".join(current_chunk)},
                }
            )

    return {
        "text": f"{icon} {topic_name} digest — {window}",
        "attachments": [{"color": _DIGEST_COLOUR, "blocks": blocks}],
    }


def format_digest_plain(topic_name: str, summary: str, lookback: str | None = None) -> str:
    """Plain-text digest for Discord (2000-char chunks handled by caller)."""
    today = date.today().strftime("%B %d, %Y")
    window = f"last {lookback}" if lookback else today
    icon = _topic_icon(topic_name)
    header = f"{icon}  **{topic_name}**  ·  {window}\n{'━' * 40}\n"

    items = _parse_digest_items(summary)
    if not items:
        return header + summary

    sep = "─" * 36
    lines: list[str] = []
    for item in items:
        headline = str(item.get("headline", "")).strip()
        blurb = str(item.get("blurb", "")).strip()
        url = str(item.get("url") or "").strip()
        item_icon = str(item.get("icon") or "📰").strip()
        if not headline:
            continue
        lines.append(f"{item_icon}  **{headline}**")
        if blurb:
            lines.append(blurb)
        if url and url.startswith("http"):
            lines.append(f"<{url}>")
        lines.append(sep)

    return header + "\n".join(lines).rstrip(sep).strip()
