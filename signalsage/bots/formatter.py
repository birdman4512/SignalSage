"""Message formatting for Slack and Discord platforms."""

import json
import logging
import re
from datetime import date
from enum import Enum
from urllib.parse import urlparse

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC, IOCType

logger = logging.getLogger(__name__)


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
    IOCType.ASN: "ASN",
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


def _source_label(url: str) -> str:
    """Return a short host label for a URL (e.g. 'reddit.com'). Empty if unparseable."""
    if not url:
        return ""
    try:
        host = urlparse(url).netloc.lower()
    except ValueError:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host


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
    Parse LLM output into {"overview": str|None, "tldr": [...], "items": [...]}.

    Handles the new structured format (overview string) and falls back to the
    legacy tldr-array format for backward compatibility. Returns None if parsing
    fails entirely (caller falls back to plain-text rendering).
    """

    def _try_parse(text: str) -> dict | None:
        # Quote bare shortcodes used as JSON values (e.g. "icon": :shield: → "icon": ":shield:")
        text = re.sub(r'(?<!["\w]):([\w]+):(?!["\w])', r'":\1:"', text)
        # Fix emoji shortcodes that some models emit (e.g. :shield: → 🛡️)
        text = _fix_shortcodes(text)
        # Quote unquoted emoji/non-string values in "icon" fields
        # e.g. "icon": 🔴, → "icon": "🔴",
        text = re.sub(r'("icon"\s*:\s*)(?!")(\S+?)(\s*[,}\]])', r'\1"\2"\3', text)
        parsed = json.loads(text)
        if isinstance(parsed, dict) and "items" in parsed:
            overview = str(parsed.get("overview") or "").strip() or None
            tldr = [str(b) for b in parsed.get("tldr", []) if str(b).strip()]
            items = [i for i in parsed["items"] if isinstance(i, dict)]
            return {
                "overview": overview,
                "tldr": tldr,
                "items": items,
                "coverage_confidence": parsed.get("coverage_confidence") or None,
            }
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            return {"overview": None, "tldr": [], "items": parsed, "coverage_confidence": None}
        return None

    text = summary.strip()

    # 1. Strip leading/trailing markdown code fences (handles ```json, ```JSON, ``` etc.)
    text = re.sub(r"^```[a-zA-Z]*\s*", "", text)
    text = re.sub(r"\s*```$", "", text).strip()

    # 2. If there's still an embedded code fence (LLM added preamble text), extract it
    fence_match = re.search(r"```[a-zA-Z]*\s*(.*?)```", text, re.DOTALL)
    if fence_match:
        text = fence_match.group(1).strip()

    # 3. If text still doesn't start with { or [, find the first JSON object/array
    if text and text[0] not in ("{", "["):
        obj_match = re.search(r"[{\[].*", text, re.DOTALL)
        if obj_match:
            text = obj_match.group(0).strip()

    try:
        return _try_parse(text)
    except (json.JSONDecodeError, ValueError, IndexError):
        pass

    # 4. Some models URL-encode JSON structural characters after URL values
    #    e.g. "url": "https://..."  %7D,  instead of  "url": "https://..."},
    #    Decode only the structural chars that appear outside quoted strings.
    decoded = re.sub(
        r"%7[Dd]", "}", re.sub(r"%7[Bb]", "{", re.sub(r"%5[Bb]", "[", re.sub(r"%5[Dd]", "]", text)))
    )
    if decoded != text:
        try:
            return _try_parse(decoded)
        except (json.JSONDecodeError, ValueError, IndexError):
            pass

    # 5. Truncation recovery — LLM hit token limit mid-JSON.
    #    Find all complete item objects and reconstruct a minimal valid response.
    item_texts = re.findall(r"\{[^{}]*\"art_id\"[^{}]*\}", text, re.DOTALL)
    if item_texts:
        recovered_items = []
        for raw_item in item_texts:
            try:
                obj = json.loads(raw_item)
                if isinstance(obj, dict) and "art_id" in obj:
                    recovered_items.append(obj)
            except (json.JSONDecodeError, ValueError):
                continue
        if recovered_items:
            tldr_match = re.search(r'"tldr"\s*:\s*\[([^\]]*)\]', text, re.DOTALL)
            tldr: list[str] = []
            if tldr_match:
                try:
                    tldr = [s for s in json.loads(f"[{tldr_match.group(1)}]") if isinstance(s, str)]
                except (json.JSONDecodeError, ValueError):
                    pass
            logger.warning(
                "Truncation recovery: salvaged %d item(s) from incomplete JSON",
                len(recovered_items),
            )
            return {
                "overview": None,
                "tldr": tldr,
                "items": recovered_items,
                "coverage_confidence": None,
            }

    logger.warning("Failed to parse digest JSON (length=%d): %r…", len(summary), summary[:120])
    return None


def _digest_footer_parts(parsed: dict | None, meta: dict | None) -> list[str]:
    """Build the metadata footer strings shared by Slack and Discord formatters."""
    parts: list[str] = []
    if not meta:
        return parts
    sources_ok = meta.get("sources_ok", 0)
    sources_total = meta.get("sources_total", 0)
    parts.append(f"📡 {sources_ok}/{sources_total} sources")

    confidence = (parsed or {}).get("coverage_confidence") or meta.get("coverage_confidence")
    if confidence:
        conf_emoji = {"high": "🟢", "medium": "🟡", "low": "🔴"}.get(str(confidence).lower(), "⚪")
        parts.append(f"{conf_emoji} {confidence.title()} coverage")

    deduped = meta.get("deduped_count", 0)
    if deduped:
        parts.append(f"🔁 {deduped} cross-topic duplicate{'s' if deduped != 1 else ''} removed")

    empty = meta.get("empty_sources", [])
    if empty:
        names = ", ".join(empty[:3])
        if len(empty) > 3:
            names += f" +{len(empty) - 3} more"
        parts.append(f"⚠️ Empty: {names}")

    chronic = meta.get("chronically_failing", [])
    if chronic:
        parts.append(f"🚨 Failing 3+ days: {', '.join(chronic[:3])}")

    return parts


def _overview_text(parsed: dict, valid_items: list[dict]) -> str:
    """Return the best available overview text, falling back to item headlines."""
    text = str(parsed.get("overview") or "").strip()
    if not text and parsed.get("tldr"):
        text = "\n".join(f"• {b}" for b in parsed["tldr"])
    if not text and valid_items:
        headlines = [
            str(i.get("headline", "")).strip()
            for i in valid_items[:6]
            if str(i.get("headline", "")).strip()
        ]
        text = "\n".join(f"• {h}" for h in headlines)
    return text


def format_digest_slack_message(
    topic_name: str,
    summary: str,
    lookback: str | None = None,
    meta: dict | None = None,
) -> list[dict]:
    """
    Return a list of ``chat_postMessage`` payloads for a digest topic.

    Message 0: topic header + overview narrative + metadata footer + images.
    Messages 1..top_n: one card per top story (headline + full summary + Read More button).
    Message top_n+1: remaining stories as a compact headline+link list (if any).

    Falls back to a single-message plain rendering when JSON parsing fails.
    """
    icon = _topic_icon(topic_name)
    today = date.today().strftime("%B %d, %Y")
    window = f"last {lookback}" if lookback else today
    top_n = int((meta or {}).get("top_stories_count", 10))

    parsed = _parse_digest_json(summary)

    # ── fallback: JSON parse failed — single plain-text message ─────────────
    if not parsed:
        blocks: list[dict] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"{icon}  *{topic_name}*"}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Digest  ·  {window}"}]},
            {"type": "divider"},
        ]
        summary_mrkdwn = _md_to_mrkdwn(summary)
        current_chunk: list[str] = []
        current_len = 0
        for para in re.split(r"\n{2,}", summary_mrkdwn):
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
                {"type": "section", "text": {"type": "mrkdwn", "text": "\n\n".join(current_chunk)}}
            )
        return [
            {
                "text": f"{icon} {topic_name} digest — {window}",
                "attachments": [{"color": _DIGEST_COLOUR, "blocks": blocks}],
            }
        ]

    # Sort items by severity, then take top_n / tail
    sorted_items = sorted(
        parsed["items"],
        key=lambda i: _SEVERITY_ORDER.get(str(i.get("severity") or "").lower(), 4),
    )
    valid_items = [i for i in sorted_items[:20] if str(i.get("headline", "")).strip()]
    top_items = valid_items[:top_n]
    tail_items = valid_items[top_n:]

    messages: list[dict] = []

    # ── Message 0: header + overview + metadata + images ─────────────────────
    header_blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{icon}  *{topic_name}*"}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Digest  ·  {window}"}]},
        {"type": "divider"},
    ]

    overview_text = _overview_text(parsed, valid_items)

    if overview_text:
        header_blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*📰 Overview*\n{overview_text}"},
            }
        )
        header_blocks.append({"type": "divider"})

    footer_parts = _digest_footer_parts(parsed, meta)
    if footer_parts:
        header_blocks.append(
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": "  ·  ".join(footer_parts)}],
            }
        )

    for img_url in (meta or {}).get("images", []):
        if img_url and str(img_url).startswith("http"):
            header_blocks.append({"type": "divider"})
            header_blocks.append(
                {"type": "image", "image_url": img_url, "alt_text": f"{topic_name} chart"}
            )

    messages.append(
        {
            "text": f"{icon} {topic_name} digest — {window}",
            "attachments": [{"color": _DIGEST_COLOUR, "blocks": header_blocks}],
        }
    )

    # ── Messages 1..top_n: individual story cards ────────────────────────────
    for idx, item in enumerate(top_items):
        headline = str(item.get("headline", "")).strip()
        item_summary = str(item.get("summary", "") or item.get("blurb", "")).strip()
        url = str(item.get("url") or "").strip()
        item_icon = (str(item.get("icon") or "").strip().split() or ["📰"])[0]
        trend = str(item.get("trend") or "").lower()

        source = _source_label(url)
        source_str = f"  ·  {source}" if source else ""
        trend_str = "  🔥 Trending" if trend == "trending" else ""
        text = f"{item_icon}  *{headline}*{source_str}{trend_str}"
        if item_summary:
            text += f"\n{item_summary}"

        block: dict = {"type": "section", "text": {"type": "mrkdwn", "text": text}}
        if url and url.startswith("http"):
            block["accessory"] = {
                "type": "button",
                "text": {"type": "plain_text", "text": "Read More", "emoji": False},
                "url": url,
                "action_id": f"digest_story_{idx}",
            }
        messages.append(
            {
                "text": headline,
                "attachments": [{"color": _DIGEST_COLOUR, "blocks": [block]}],
            }
        )

    # ── Message top_n+1: remaining stories (headline + link only) ────────────
    if tail_items:
        tail_blocks: list[dict] = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*📋 More Stories ({len(tail_items)})*"},
            },
        ]
        current_lines: list[str] = []
        current_len = 0
        for item in tail_items:
            headline = str(item.get("headline", "")).strip()
            url = str(item.get("url") or "").strip()
            item_icon = (str(item.get("icon") or "").strip().split() or ["📰"])[0]
            if not headline:
                continue
            source = _source_label(url)
            source_suffix = f"  ·  {source}" if source else ""
            line = (
                f"• {item_icon} <{url}|{headline}>{source_suffix}"
                if url.startswith("http")
                else f"• {item_icon} {headline}{source_suffix}"
            )
            if current_len + len(line) + 2 > 2900 and current_lines:
                tail_blocks.append(
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": "\n\n".join(current_lines)},
                    }
                )
                current_lines = []
                current_len = 0
            current_lines.append(line)
            current_len += len(line) + 2
        if current_lines:
            tail_blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": "\n\n".join(current_lines)}}
            )
        messages.append(
            {
                "text": f"📋 {len(tail_items)} more stories",
                "attachments": [{"color": _DIGEST_COLOUR, "blocks": tail_blocks}],
            }
        )

    return messages


def format_digest_plain(
    topic_name: str,
    summary: str,
    lookback: str | None = None,
    meta: dict | None = None,
) -> list[str]:
    """
    Return a list of plain-text messages for Discord.

    Message 0: topic header + overview + metadata footer + images.
    Messages 1..top_n: one message per top story (headline + full summary + link).
    Message top_n+1: remaining stories as a compact headline+link list (if any).

    Each message may still exceed 2000 chars for very long summaries; callers
    should apply split_message() per item if needed.
    """
    today = date.today().strftime("%B %d, %Y")
    window = f"last {lookback}" if lookback else today
    icon = _topic_icon(topic_name)
    top_n = int((meta or {}).get("top_stories_count", 10))
    sep = "─" * 36

    parsed = _parse_digest_json(summary)
    if not parsed:
        header = f"{icon}  **{topic_name}**  ·  {window}\n{'━' * 40}\n"
        return [header + summary]

    items_with_url = [i for i in parsed["items"] if str(i.get("url") or "").startswith("http")]
    logger.info(
        "Digest '%s': %d items, %d have URLs",
        topic_name,
        len(parsed["items"]),
        len(items_with_url),
    )

    sorted_items = sorted(
        parsed["items"],
        key=lambda i: _SEVERITY_ORDER.get(str(i.get("severity") or "").lower(), 4),
    )
    valid_items = [i for i in sorted_items[:20] if str(i.get("headline", "")).strip()]
    top_items = valid_items[:top_n]
    tail_items = valid_items[top_n:]

    messages: list[str] = []

    # ── Message 0: header + overview + metadata ───────────────────────────────
    header_lines: list[str] = [
        f"{icon}  **{topic_name}**  ·  {window}",
        "━" * 40,
    ]

    overview_text = _overview_text(parsed, valid_items)

    if overview_text:
        header_lines.append("")
        header_lines.append(overview_text)

    footer_parts = _digest_footer_parts(parsed, meta)
    if footer_parts:
        header_lines.append("")
        header_lines.append(sep)
        header_lines.append(" · ".join(footer_parts))

    for img_url in (meta or {}).get("images", []):
        if img_url and str(img_url).startswith("http"):
            header_lines.append(img_url)

    messages.append("\n".join(header_lines))

    # ── Messages 1..top_n: individual story cards ─────────────────────────────
    for item in top_items:
        headline = str(item.get("headline", "")).strip()
        item_summary = str(item.get("summary", "") or item.get("blurb", "")).strip()
        url = str(item.get("url") or "").strip()
        item_icon = (str(item.get("icon") or "").strip().split() or ["📰"])[0]
        trend = str(item.get("trend") or "").lower()

        source = _source_label(url)
        source_str = f" · {source}" if source else ""
        trend_str = "  🔥 Trending" if trend == "trending" else ""
        story_lines = [f"{item_icon}  **{headline}**{source_str}{trend_str}"]
        if item_summary:
            story_lines.append(item_summary)
        if url and url.startswith("http"):
            story_lines.append(f"<{url}>")
        messages.append("\n".join(story_lines))

    # ── Message top_n+1: remaining stories (headline + link only) ────────────
    if tail_items:
        tail_header = "\n".join([f"**📋 More Stories ({len(tail_items)})**", sep])
        tail_item_lines: list[str] = []
        for item in tail_items:
            headline = str(item.get("headline", "")).strip()
            url = str(item.get("url") or "").strip()
            item_icon = (str(item.get("icon") or "").strip().split() or ["📰"])[0]
            if not headline:
                continue
            source = _source_label(url)
            source_suffix = f" · {source}" if source else ""
            if url and url.startswith("http"):
                tail_item_lines.append(f"• {item_icon} [{headline}]({url}){source_suffix}")
            else:
                tail_item_lines.append(f"• {item_icon} {headline}{source_suffix}")
        messages.append(tail_header + "\n" + "\n\n".join(tail_item_lines))

    return messages
