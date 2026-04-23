"""LLM-powered digest summarizer."""

import asyncio
import json
import logging
import re
from datetime import date

from signalsage.intel.base import IntelResult
from signalsage.ioc.models import IOC
from signalsage.llm.base import BaseLLM

_LLM_RETRIES = 2
_LLM_RETRY_DELAY = 5  # seconds between retries
_URL_MATCH_THRESHOLD = 0.35  # minimum Jaccard similarity to inject a URL

logger = logging.getLogger(__name__)

_PUNCT_RE = re.compile(r"[^\w\s]")


def _jaccard(a: str, b: str) -> float:
    wa = set(_PUNCT_RE.sub("", a.lower()).split())
    wb = set(_PUNCT_RE.sub("", b.lower()).split())
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


def _decode_url_encoded_json(text: str) -> str:
    """Decode structural characters that some LLMs URL-encode after URL values."""
    for enc, char in [("%7B", "{"), ("%7D", "}"), ("%5B", "["), ("%5D", "]")]:
        text = re.sub(enc, char, text, flags=re.IGNORECASE)
    return text


def _inject_urls(
    raw_json: str,
    url_map: dict[str, str],
    title_url_pairs: list[tuple[str, str]],
) -> str:
    """
    Post-process LLM JSON: resolve URLs from article IDs and/or title matching.

    Priority:
    1. LLM already returned a valid http URL — keep it.
    2. LLM returned an art_id (e.g. "A3") — look up in url_map.
    3. Fallback: Jaccard title match against title_url_pairs.
    """
    text = _decode_url_encoded_json(raw_json)

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return raw_json

    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return raw_json

    injected = 0
    no_url = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        existing = str(item.get("url") or "").strip()
        if existing.startswith("http"):
            continue  # already have a good URL

        # Try art_id lookup first
        art_id = str(item.get("art_id") or "").strip()
        if art_id and art_id in url_map:
            item["url"] = url_map[art_id]
            injected += 1
            continue

        # Jaccard title fallback
        headline = str(item.get("headline") or "")
        best_url, best_score = "", 0.0
        for title, url in title_url_pairs:
            if not url:
                continue
            score = _jaccard(headline, title)
            if score > best_score:
                best_score, best_url = score, url
        if best_score >= _URL_MATCH_THRESHOLD and best_url:
            item["url"] = best_url
            injected += 1
        else:
            no_url += 1
            logger.debug(
                "No URL resolved for item art_id=%r headline=%r (best_jaccard=%.2f, url_map_keys=%s)",
                art_id,
                headline[:60],
                best_score,
                list(url_map.keys()),
            )

    if injected:
        logger.info("URL injection: filled %d missing URL(s)", injected)
    if no_url:
        logger.warning("URL injection: %d item(s) have no URL after all fallbacks", no_url)
    return json.dumps(data)


_SYSTEM_PROMPT = """\
You are an analyst producing a structured news digest from pre-fetched source content.
Each article in the content is labelled with an ID like [A1], [A2], etc., and may have a URL line.
The source content is provided below - you do not need to access the internet.

Return a single JSON object with these keys:

"tldr": array of 3-5 one-sentence strings summarising the most important signals across ALL sources. Highlight cross-cutting themes. Do not repeat individual story headlines verbatim.

"coverage_confidence": "high" (many sources, rich overlapping content), "medium" (some sources, patchy), or "low" (few sources, sparse/off-topic).

"items": array of 5-20 individual story objects (MAXIMUM 20 — stop at 20 even if more articles exist), one per notable article. Each object has:
  "art_id": the [A<N>] label of the article this item is based on (e.g. "A3"). Required.
  "icon": ONE emoji character - output the emoji only, no words. Choose the closest match:
    🔴=critical-incident  🛡️=patch-or-fix  🦠=malware  🔗=phishing  📢=announcement
    🔍=research  ⚠️=advisory  📡=threat-intel  🏛️=policy-or-legal  📻=radio
    ☀️=space-weather  🤖=AI-or-ML  📰=general
  "severity": "critical", "high", "medium", or "low"
  "headline": title from or based on the article, max 80 characters
  "blurb": 1-2 sentences - what happened and why it matters
  "url": copy the URL exactly from the article's "URL:" line in the source content. If no URL line exists for that article, use null.

Rules:
- Output ONLY the JSON object. No markdown fences, no explanation, no extra text.
- Use ONLY content from the sources provided. Do not invent facts.
- "icon" must be a single emoji character - never include any words after it.
- "art_id" must match one of the [A<N>] labels in the source content.
- "url" must be copied verbatim from the source — do not paraphrase or invent URLs.
"""

_IOC_SYSTEM_PROMPT = (
    "You are a senior threat intelligence analyst. "
    "Given threat intelligence results for an indicator, write a concise 2-3 sentence assessment. "
    "State the overall verdict, what the indicator is associated with, and any recommended action. "
    "Be direct and factual. Do not repeat the raw numbers - interpret them."
)


class DigestSummarizer:
    """Fetches topic sources and summarizes them using a configured LLM."""

    def __init__(self, llm: BaseLLM, max_chars: int = 3000, max_total_chars: int = 20000) -> None:
        self.llm = llm
        self.max_chars = max_chars
        self.max_total_chars = max_total_chars

    async def summarize_topic(
        self, topic_name: str, sources: list[dict], lookback: str | None = None
    ) -> str:
        today = date.today().strftime("%B %d, %Y")

        source_blocks: list[str] = []
        url_map: dict[str, str] = {}  # art_id → url  (e.g. "A3" → "https://...")
        title_url_pairs: list[tuple[str, str]] = []  # Jaccard fallback
        art_counter = 0
        total_chars = 0
        skipped = 0
        for src in sources:
            content = src.get("content", "").strip()
            if not content:
                continue

            # Stamp each "Title: ..." line with a unique article ID and record its URL
            def _stamp_article(m: re.Match) -> str:
                nonlocal art_counter
                art_counter += 1
                art_id = f"A{art_counter}"
                title = m.group(1).strip()
                url_line = m.group(2) or ""
                url = re.search(r"URL:\s*(https?://\S+)", url_line)
                if url:
                    url_map[art_id] = url.group(1)
                    title_url_pairs.append((title, url.group(1)))
                return f"[{art_id}] Title: {title}\n{url_line}"

            labelled = re.sub(
                r"^(Title:\s*.+)\n(URL:\s*https?://\S+)?",
                _stamp_article,
                content,
                flags=re.MULTILINE,
            )

            block = f"### {src['name']}\nSource URL: {src['url']}\n{labelled}\n"
            if total_chars + len(block) > self.max_total_chars:
                skipped += 1
                continue
            source_blocks.append(block)
            total_chars += len(block)
        if skipped:
            logger.info(
                "Topic '%s': skipped %d source(s) - total content would exceed %d chars",
                topic_name,
                skipped,
                self.max_total_chars,
            )

        logger.info(
            "Topic '%s': %d articles labelled, %d have URLs (url_map)",
            topic_name,
            art_counter,
            len(url_map),
        )

        if not source_blocks:
            window = f"the last {lookback}" if lookback else today
            return f"No content found for {topic_name} covering {window}."

        window_phrase = f"from the last {lookback}" if lookback else f"for {today}"
        user_prompt = (
            f"The following content has been pre-fetched for you from {topic_name} sources "
            f"{window_phrase}. Summarize it.\n"
            + (
                f"Focus only on items published in the last {lookback}. Skip older content.\n"
                if lookback
                else ""
            )
            + "\n--- BEGIN CONTENT ---\n"
            + "\n".join(source_blocks)
            + "\n--- END CONTENT ---"
        )

        for attempt in range(1 + _LLM_RETRIES):
            try:
                raw = await self.llm.complete(
                    system=_SYSTEM_PROMPT, user=user_prompt, max_tokens=4096
                )
                logger.debug("LLM raw output for topic %r: %s", topic_name, raw[:500])
                return _inject_urls(raw, url_map, title_url_pairs)
            except Exception as exc:
                if attempt < _LLM_RETRIES:
                    logger.warning(
                        "LLM error for topic %s (attempt %d/%d): %s - retrying in %ds",
                        topic_name,
                        attempt + 1,
                        1 + _LLM_RETRIES,
                        exc,
                        _LLM_RETRY_DELAY,
                    )
                    await asyncio.sleep(_LLM_RETRY_DELAY)
                else:
                    logger.error(
                        "LLM error for topic %s after %d attempt(s): %s",
                        topic_name,
                        1 + _LLM_RETRIES,
                        exc,
                    )

        # All retries exhausted - produce a minimal fallback from raw headlines
        return self._fallback_summary(source_blocks)

    def _fallback_summary(self, source_blocks: list[str]) -> str:
        """
        Return a minimal plain-text summary built from raw source headlines
        when the LLM is unavailable. Extracts the first line of each source
        block (the ### Source Name heading) so users still see what was fetched.
        """
        lines = ["⚠️ LLM summary unavailable - showing raw source headlines:\n"]
        for block in source_blocks:
            for line in block.splitlines():
                line = line.strip()
                if line.startswith("### "):
                    lines.append(f"• {line[4:]}")
                    break
        return "\n".join(lines)

    async def summarize_ioc(self, ioc: IOC, results: list[IntelResult]) -> str:
        """Generate a plain-English assessment of an IOC from its enrichment results."""
        lines: list[str] = []
        for r in results:
            if r.error:
                lines.append(f"- {r.provider}: error - {r.error}")
            else:
                verdict = (
                    "MALICIOUS"
                    if r.malicious is True
                    else "CLEAN"
                    if r.malicious is False
                    else "UNKNOWN"
                )
                lines.append(f"- {r.provider}: {verdict} - {r.summary or 'no details'}")

        label = ioc.type.value.upper()
        user_prompt = (
            f"Indicator: {ioc.value} ({label})\n\nThreat intelligence results:\n" + "\n".join(lines)
        )
        try:
            return await self.llm.complete(system=_IOC_SYSTEM_PROMPT, user=user_prompt)
        except Exception as exc:
            logger.error("LLM error summarizing IOC %s: %s", ioc.value, exc)
            return f"⚠️ Assessment unavailable - {exc}"
