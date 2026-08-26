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


def _escape_mrkdwn(text: str) -> str:
    """Escape Slack mrkdwn metacharacters in attacker-influenced strings.

    Slack's documented escape policy is: ``&`` → ``&amp;``, ``<`` → ``&lt;``,
    ``>`` → ``&gt;``. That alone prevents `<url|label>` injection (the most
    impactful exploit — see https://api.slack.com/reference/surfaces/formatting).
    Use this on any string sourced from a third-party (cert transparency, RSS
    headlines, AbuseIPDB ISP names, BGPView descriptions) before interpolating
    it into a Slack ``mrkdwn`` text block.
    """
    if not text:
        return ""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


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
        # Provider summaries can contain third-party-influenced content (cert SANs,
        # ISP names, BGP descriptions). Escape Slack mrkdwn metacharacters so a
        # crafted value can't fake a <url|label> button or break formatting.
        if result.error:
            body = f"{verdict}  _{_escape_mrkdwn(result.error)}_"
        else:
            body = f"{verdict}  {_escape_mrkdwn(result.summary or 'No details')}"

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


# One emoji-ish character (pictographs, symbols, dingbats) plus an optional
# variation selector. Used to pull the emoji out of junk-decorated icon values
# some small models emit (e.g. "%(🔴)%" → "🔴").
_EMOJI_RE = re.compile(
    "["
    "🀀-🫿"  # pictographs, emoticons, transport, supplemental
    "←-⇿"  # arrows
    "⌀-⏿"  # misc technical (alarm clock, hourglass, ...)
    "■-➿"  # geometric shapes, misc symbols (sun, warning), dingbats
    "⬀-⯿"  # misc symbols and arrows
    "]️?"  # optional trailing variation selector (e.g. shield emoji)
)


def _clean_icon(value: object, default: str = "📰") -> str:
    """Extract the first emoji from an LLM-provided icon value; fall back to *default*."""
    m = _EMOJI_RE.search(str(value or ""))
    return m.group(0) if m else default


def _extract_overview(text: str) -> str | None:
    """Regex-extract the "overview" string value from (possibly truncated) JSON.

    Tolerates a missing closing quote so an overview cut off by a token limit is
    still recovered. Returns None when no overview is present.
    """
    m = re.search(r'"overview"\s*:\s*"((?:[^"\\]|\\.)*)', text)
    if not m:
        return None
    raw = m.group(1)
    try:
        value = json.loads(f'"{raw}"')  # decode \n, \", \uXXXX escapes
    except (json.JSONDecodeError, ValueError):
        value = raw
    value = str(value).strip()
    return value or None


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
        # Accept an overview-only object (small models sometimes stop after the
        # overview even in JSON mode) — rendering just the overview beats the
        # plain-text fallback dumping raw JSON into the channel.
        if isinstance(parsed, dict) and (
            "items" in parsed or str(parsed.get("overview") or "").strip()
        ):
            overview = str(parsed.get("overview") or "").strip() or None
            tldr = [str(b) for b in parsed.get("tldr", []) if str(b).strip()]
            items = [i for i in parsed.get("items") or [] if isinstance(i, dict)]
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
                "overview": _extract_overview(text),
                "tldr": tldr,
                "items": recovered_items,
                "coverage_confidence": None,
            }

    # 6. Last resort — no items were salvageable, but if an overview string is
    #    present, render that alone rather than dumping raw JSON into the channel.
    overview = _extract_overview(text)
    if overview:
        logger.warning(
            "Digest JSON unparseable (length=%d) — recovered overview text only", len(summary)
        )
        return {"overview": overview, "tldr": [], "items": [], "coverage_confidence": None}

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
    Return a single-element list containing one ``chat_postMessage`` payload for
    a digest topic run (kept as a list for a uniform call signature — the
    JSON-parse-failure fallback below is also always exactly one message).

    Layout: topic header + overview narrative, then each top story rendered as
    three lines — "<emoji> *headline>*", the blurb, and the URL — followed by
    any remaining stories as a compact headline+link list, then a metadata
    footer + images.
    """
    icon = _topic_icon(topic_name)
    today = date.today().strftime("%B %d, %Y")
    window = f"last {lookback}" if lookback else today
    top_n = int((meta or {}).get("top_stories_count", 10))
    bare = bool((meta or {}).get("bare"))

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

    # Sort items by severity, then take top_n / tail. Bare (watch-mode) items
    # are already relevance-filtered by the LLM, so all of them get the full
    # emoji/title/blurb/url treatment rather than being split into a tail.
    sorted_items = sorted(
        parsed["items"],
        key=lambda i: _SEVERITY_ORDER.get(str(i.get("severity") or "").lower(), 4),
    )
    valid_items = [i for i in sorted_items[:20] if str(i.get("headline", "")).strip()]
    if bare:
        top_items = valid_items
        tail_items: list[dict] = []
    else:
        top_items = valid_items[:top_n]
        tail_items = valid_items[top_n:]

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{icon}  *{topic_name}*"}},
    ]
    if not bare:
        blocks.append(
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Digest  ·  {window}"}]}
        )
    blocks.append({"type": "divider"})

    if not bare:
        overview_text = _overview_text(parsed, valid_items)
        if overview_text:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*📰 Overview*\n{overview_text}"},
                }
            )
            blocks.append({"type": "divider"})

    # ── each story: "<emoji> *headline>*" / blurb / URL ───────────────────────
    for item in top_items:
        # Headlines and summaries come from RSS feeds + LLM output — escape so a
        # crafted feed entry can't inject Slack <url|label> link syntax.
        headline = _escape_mrkdwn(str(item.get("headline", "")).strip())
        item_summary = _escape_mrkdwn(str(item.get("summary", "") or item.get("blurb", "")).strip())
        url = str(item.get("url") or "").strip()
        item_icon = _clean_icon(item.get("icon"))
        trend = str(item.get("trend") or "").lower()

        source = _source_label(url)
        source_str = f"  ·  {source}" if source else ""
        trend_str = "  🔥 Trending" if trend == "trending" else ""
        lines = [f"{item_icon}  *{headline}*{source_str}{trend_str}"]
        if item_summary:
            lines.append(item_summary)
        if url.startswith("http"):
            lines.append(f"<{url}>")
        blocks.append(
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)[:2900]}}
        )
        blocks.append({"type": "divider"})

    # Remaining stories ride along as a compact link list rather than getting
    # the full treatment, to keep the single message a reasonable size.
    if tail_items:
        tail_lines: list[str] = []
        for item in tail_items:
            headline = _escape_mrkdwn(str(item.get("headline", "")).strip())
            url = str(item.get("url") or "").strip()
            item_icon = _clean_icon(item.get("icon"))
            if not headline:
                continue
            source = _source_label(url)
            source_suffix = f"  ·  {source}" if source else ""
            tail_lines.append(
                f"• {item_icon} <{url}|{headline}>{source_suffix}"
                if url.startswith("http")
                else f"• {item_icon} {headline}{source_suffix}"
            )
        if tail_lines:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*📋 More Stories ({len(tail_lines)})*"},
                }
            )
            current_lines: list[str] = []
            current_len = 0
            for line in tail_lines:
                if current_len + len(line) + 1 > 2900 and current_lines:
                    blocks.append(
                        {
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": "\n".join(current_lines)},
                        }
                    )
                    current_lines = []
                    current_len = 0
                current_lines.append(line)
                current_len += len(line) + 1
            if current_lines:
                blocks.append(
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": "\n".join(current_lines)},
                    }
                )
            blocks.append({"type": "divider"})

    if not bare:
        footer_parts = _digest_footer_parts(parsed, meta)
        if footer_parts:
            blocks.append(
                {
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": "  ·  ".join(footer_parts)}],
                }
            )

        for img_url in (meta or {}).get("images", []):
            if img_url and str(img_url).startswith("http"):
                blocks.append({"type": "divider"})
                blocks.append(
                    {"type": "image", "image_url": img_url, "alt_text": f"{topic_name} chart"}
                )

    return [
        {
            "text": f"{icon} {topic_name} digest — {window}",
            "attachments": [{"color": _DIGEST_COLOUR, "blocks": blocks}],
        }
    ]


def format_digest_plain(
    topic_name: str,
    summary: str,
    lookback: str | None = None,
    meta: dict | None = None,
) -> list[str]:
    """
    Return a single-element list containing one plain-text message for a
    digest topic run (kept as a list for a uniform call signature with the
    JSON-parse-failure fallback below, which is also always exactly one
    message).

    Layout: topic header + overview, then each top story as three lines —
    "<emoji> headline", the blurb, and the URL — followed by any remaining
    stories as a compact headline+link list, then a metadata footer + images.

    The combined message may exceed Discord's 2000-char limit for very long
    digests; Discord clients truncate gracefully but the caller may want to
    chunk further.
    """
    today = date.today().strftime("%B %d, %Y")
    window = f"last {lookback}" if lookback else today
    icon = _topic_icon(topic_name)
    top_n = int((meta or {}).get("top_stories_count", 10))
    bare = bool((meta or {}).get("bare"))
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
    if bare:
        top_items = valid_items
        tail_items: list[dict] = []
    else:
        top_items = valid_items[:top_n]
        tail_items = valid_items[top_n:]

    lines: list[str] = [f"{icon}  **{topic_name}**" + ("" if bare else f"  ·  {window}")]
    if not bare:
        lines.append("━" * 40)

        overview_text = _overview_text(parsed, valid_items)
        if overview_text:
            lines.append("")
            lines.append(overview_text)
    lines.append("")

    # ── each story: "<emoji> headline" / blurb / URL ──────────────────────────
    for item in top_items:
        headline = str(item.get("headline", "")).strip()
        item_summary = str(item.get("summary", "") or item.get("blurb", "")).strip()
        url = str(item.get("url") or "").strip()
        item_icon = _clean_icon(item.get("icon"))
        trend = str(item.get("trend") or "").lower()

        source = _source_label(url)
        source_str = f" · {source}" if source else ""
        trend_str = "  🔥 Trending" if trend == "trending" else ""
        lines.append(f"{item_icon}  **{headline}**{source_str}{trend_str}")
        if item_summary:
            lines.append(item_summary)
        if url and url.startswith("http"):
            lines.append(f"<{url}>")
        lines.append("")

    # Remaining stories ride along as a compact link list rather than getting
    # the full treatment, to keep the single message a reasonable size.
    if tail_items:
        tail_item_lines: list[str] = []
        for item in tail_items:
            headline = str(item.get("headline", "")).strip()
            url = str(item.get("url") or "").strip()
            item_icon = _clean_icon(item.get("icon"))
            if not headline:
                continue
            source = _source_label(url)
            source_suffix = f" · {source}" if source else ""
            if url and url.startswith("http"):
                tail_item_lines.append(f"• {item_icon} [{headline}]({url}){source_suffix}")
            else:
                tail_item_lines.append(f"• {item_icon} {headline}{source_suffix}")
        if tail_item_lines:
            lines.append(f"**📋 More Stories ({len(tail_item_lines)})**")
            lines.extend(tail_item_lines)
            lines.append("")

    if not bare:
        footer_parts = _digest_footer_parts(parsed, meta)
        if footer_parts:
            lines.append(sep)
            lines.append(" · ".join(footer_parts))

        for img_url in (meta or {}).get("images", []):
            if img_url and str(img_url).startswith("http"):
                lines.append(img_url)

    return ["\n".join(lines).strip()]
