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

_SEVERITY_ORDER: dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_EMOJI: dict[str, str] = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


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


_SHORTCODE_TO_EMOJI: dict[str, str] = {
    ":shield:": "🛡️",
    ":red_circle:": "🔴",
    ":warning:": "⚠️",
    ":newspaper:": "📰",
    ":bug:": "🦠",
    ":link:": "🔗",
    ":mag:": "🔍",
    ":loudspeaker:": "📢",
    ":satellite:": "📡",
    ":classical_building:": "🏛️",
    ":radio:": "📻",
    ":sunny:": "☀️",
    ":rotating_light:": "🚨",
    ":clipboard:": "📋",
    ":ghost:": "👻",
    ":lock:": "🔐",
    ":fire:": "🔥",
    ":skull:": "💀",
    ":injection:": "💉",
}


def _fix_shortcodes(text: str) -> str:
    """Replace Slack/emoji shortcodes with actual emoji characters."""
    for code, emoji in _SHORTCODE_TO_EMOJI.items():
        text = text.replace(code, emoji)
    return text


def _parse_digest_json(summary: str) -> dict | None:
    """
    Parse LLM output into {"tldr": [...], "items": [...]}.

    Handles the structured object format and falls back to the legacy flat-array
    format for backward compatibility. Returns None if parsing fails entirely
    (caller falls back to plain-text rendering).
    """
    try:
        text = summary.strip()
        # Strip markdown code fences if the model adds them
        text = re.sub(r"^```[a-z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text).strip()
        # Quote bare shortcodes used as JSON values (e.g. "icon": :shield: → "icon": ":shield:")
        text = re.sub(r'(?<!["\w]):([\w]+):(?!["\w])', r'":\1:"', text)
        # Fix emoji shortcodes that some models emit (e.g. :shield: → 🛡️)
        text = _fix_shortcodes(text)
        # Quote unquoted emoji/non-string values in "icon" fields
        # e.g. "icon": 🔴, → "icon": "🔴",
        text = re.sub(r'("icon"\s*:\s*)(?!")(\S+?)(\s*[,}\]])', r'\1"\2"\3', text)
        parsed = json.loads(text)
        if isinstance(parsed, dict) and "items" in parsed:
            tldr = [str(b) for b in parsed.get("tldr", []) if str(b).strip()]
            items = [i for i in parsed["items"] if isinstance(i, dict)]
            return {
                "tldr": tldr,
                "items": items,
                "coverage_confidence": parsed.get("coverage_confidence") or None,
            }
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            # Legacy flat-array format
            return {"tldr": [], "items": parsed, "coverage_confidence": None}
    except (json.JSONDecodeError, ValueError, IndexError):
        pass
    return None


def format_digest_slack_message(
    topic_name: str,
    summary: str,
    lookback: str | None = None,
    meta: dict | None = None,
) -> dict:
    """
    Return a ``chat_postMessage`` payload for a digest topic.

    Uses a blue left-border attachment with Block Kit blocks inside.
    When the LLM returns structured JSON, renders a TLDR block followed by
    individual story items sorted by severity with optional 'Read More' buttons.
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

    parsed = _parse_digest_json(summary)

    if parsed:
        # ── TLDR / top signals ───────────────────────────────────────────────
        if parsed["tldr"]:
            bullets = "\n".join(f"• {b}" for b in parsed["tldr"])
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*📌 Summary*\n{bullets}"},
                }
            )
            blocks.append({"type": "divider"})

        # ── structured item rendering — sorted by severity ───────────────────
        # Cap at 20 items; each uses ~2 blocks + header 3 + tldr 2 + footer 1 ≤ 50
        sorted_items = sorted(
            parsed["items"],
            key=lambda i: _SEVERITY_ORDER.get(str(i.get("severity") or "").lower(), 4),
        )
        valid_items = [i for i in sorted_items[:20] if str(i.get("headline", "")).strip()]
        for idx, item in enumerate(valid_items):
            headline = str(item.get("headline", "")).strip()
            blurb = str(item.get("blurb", "")).strip()
            url = str(item.get("url") or "").strip()
            item_icon = str(item.get("icon") or "📰").strip()
            severity = str(item.get("severity") or "").lower()
            sev_emoji = _SEVERITY_EMOJI.get(severity, "")

            sev_str = f"  ·  {sev_emoji} {severity.title()}" if sev_emoji else ""
            trend = str(item.get("trend") or "").lower()
            trend_str = "  🔥 Trending" if trend == "trending" else ""
            text = f"{item_icon}  *{headline}*{sev_str}{trend_str}"
            if blurb:
                text += f"\n{blurb}"

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

    # ── metadata footer ──────────────────────────────────────────────────────
    footer_parts: list[str] = []
    if meta:
        sources_ok = meta.get("sources_ok", 0)
        sources_total = meta.get("sources_total", 0)
        footer_parts.append(f"📡 {sources_ok}/{sources_total} sources")

        confidence = (parsed or {}).get("coverage_confidence") or meta.get("coverage_confidence")
        if confidence:
            conf_emoji = {"high": "🟢", "medium": "🟡", "low": "🔴"}.get(
                str(confidence).lower(), "⚪"
            )
            footer_parts.append(f"{conf_emoji} {confidence.title()} coverage")

        deduped = meta.get("deduped_count", 0)
        if deduped:
            footer_parts.append(
                f"🔁 {deduped} cross-topic duplicate{'s' if deduped != 1 else ''} removed"
            )

        empty = meta.get("empty_sources", [])
        if empty:
            names = ", ".join(empty[:3])
            if len(empty) > 3:
                names += f" +{len(empty) - 3} more"
            footer_parts.append(f"⚠️ Empty: {names}")

        chronic = meta.get("chronically_failing", [])
        if chronic:
            names = ", ".join(chronic[:3])
            footer_parts.append(f"🚨 Failing 3+ days: {names}")

    if footer_parts:
        blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": "  ·  ".join(footer_parts)}],
            }
        )

    # ── images ───────────────────────────────────────────────────────────────
    for img_url in (meta or {}).get("images", []):
        if img_url and str(img_url).startswith("http"):
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "image",
                    "image_url": img_url,
                    "alt_text": f"{topic_name} chart",
                }
            )

    return {
        "text": f"{icon} {topic_name} digest — {window}",
        "attachments": [{"color": _DIGEST_COLOUR, "blocks": blocks}],
    }


def format_digest_plain(
    topic_name: str,
    summary: str,
    lookback: str | None = None,
    meta: dict | None = None,
) -> str:
    """Plain-text digest for Discord (2000-char chunks handled by caller)."""
    today = date.today().strftime("%B %d, %Y")
    window = f"last {lookback}" if lookback else today
    icon = _topic_icon(topic_name)
    header = f"{icon}  **{topic_name}**  ·  {window}\n{'━' * 40}\n"

    parsed = _parse_digest_json(summary)
    if not parsed:
        return header + summary

    sep = "─" * 36
    lines: list[str] = []

    # TLDR
    if parsed["tldr"]:
        lines.append("📌 **Summary**")
        for bullet in parsed["tldr"]:
            lines.append(f"• {bullet}")
        lines.append(sep)

    # Items sorted by severity
    sorted_items = sorted(
        parsed["items"],
        key=lambda i: _SEVERITY_ORDER.get(str(i.get("severity") or "").lower(), 4),
    )
    for item in sorted_items:
        headline = str(item.get("headline", "")).strip()
        blurb = str(item.get("blurb", "")).strip()
        url = str(item.get("url") or "").strip()
        item_icon = str(item.get("icon") or "📰").strip()
        severity = str(item.get("severity") or "").lower()
        sev_emoji = _SEVERITY_EMOJI.get(severity, "")
        if not headline:
            continue
        sev_str = f" · {sev_emoji} {severity.title()}" if sev_emoji else ""
        trend = str(item.get("trend") or "").lower()
        trend_str = "  🔥 Trending" if trend == "trending" else ""
        lines.append(f"{item_icon}  **{headline}**{sev_str}{trend_str}")
        if blurb:
            lines.append(blurb)
        if url and url.startswith("http"):
            lines.append(f"<{url}>")
        lines.append(sep)

    # Metadata footer
    footer_parts: list[str] = []
    if meta:
        sources_ok = meta.get("sources_ok", 0)
        sources_total = meta.get("sources_total", 0)
        footer_parts.append(f"📡 {sources_ok}/{sources_total} sources")

        confidence = parsed.get("coverage_confidence") or meta.get("coverage_confidence")
        if confidence:
            conf_emoji = {"high": "🟢", "medium": "🟡", "low": "🔴"}.get(
                str(confidence).lower(), "⚪"
            )
            footer_parts.append(f"{conf_emoji} {confidence.title()} coverage")

        deduped = meta.get("deduped_count", 0)
        if deduped:
            footer_parts.append(f"🔁 {deduped} duplicate{'s' if deduped != 1 else ''} removed")

        empty = meta.get("empty_sources", [])
        if empty:
            names = ", ".join(empty[:3])
            if len(empty) > 3:
                names += f" +{len(empty) - 3} more"
            footer_parts.append(f"⚠️ Empty: {names}")

        chronic = meta.get("chronically_failing", [])
        if chronic:
            footer_parts.append(f"🚨 Failing 3+ days: {', '.join(chronic[:3])}")

    if footer_parts:
        lines.append(" · ".join(footer_parts))

    # Images — Discord auto-embeds bare URLs
    for img_url in (meta or {}).get("images", []):
        if img_url and str(img_url).startswith("http"):
            lines.append(img_url)

    return header + "\n".join(lines).rstrip(sep).strip()
