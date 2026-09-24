"""Published show transcripts, and picking the passages of a long transcript to summarize."""

import re

from .fetcher import _fetch_raw
from .ranking import contains

_DEFAULT_EPISODE_PATTERN = r"(\d+)"
_LEAD_CHARS = 1500  # opening kept verbatim: GRC's header + DESCRIPTION, or a show's intro
_WINDOW_CHARS = 600  # passage size when a transcript has no paragraph breaks (Whisper)
_STOPWORDS = {
    "about", "after", "again", "being", "from", "have", "into", "just", "more", "over",
    "that", "their", "there", "this", "what", "when", "which", "with", "your",
}  # fmt: skip


def transcript_url(source: dict, title: str) -> str | None:
    """The published transcript URL for an episode, from the source's template.

    A source opts in with ``transcript_url`` containing ``{episode}``, which is
    filled from the first capture group of ``episode_pattern`` matched against
    the item title (e.g. "SN 1097: ..." -> 1097). Only digits are ever
    substituted, so feed content cannot steer the request elsewhere.
    """
    template = source.get("transcript_url")
    if not template:
        return None
    match = re.search(source.get("episode_pattern") or _DEFAULT_EPISODE_PATTERN, title or "")
    if not match or not match.group(1).isdigit():
        return None
    return template.format(episode=match.group(1))


async def fetch_transcript(url: str) -> str | None:
    """Fetch a plain-text transcript; None until it has been published."""
    response = await _fetch_raw(url, 30)
    if response is None:
        return None
    text = response[0].strip()
    return text or None


def _passages(text: str) -> list[str]:
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    if len(paragraphs) >= 3:
        return paragraphs
    # One unbroken blob (Whisper output): group sentences into ~600-char windows.
    windows: list[str] = []
    current = ""
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if current and len(current) + len(sentence) > _WINDOW_CHARS:
            windows.append(current)
            current = ""
        current = f"{current} {sentence}".strip()
    if current:
        windows.append(current)
    return windows


def select_passages(text: str, title: str, focus_terms: list[str], budget: int) -> str:
    """Condense a long transcript to *budget* chars of its most on-topic passages.

    Keeps the opening (header/description or intro) plus the passages that
    mention the episode title's words and the topic's keywords most, in their
    original order. Passages are verbatim, so a summary's evidence quote can
    still be checked against the text the model was given.
    """
    if len(text) <= budget:
        return text
    passages = _passages(text)
    # The opening may use at most a quarter of the budget, leaving the rest
    # for on-topic passages.
    lead_cap = min(_LEAD_CHARS, budget // 4)
    lead: list[int] = []
    used = 0
    for index, passage in enumerate(passages):
        if used + len(passage) > lead_cap:
            break
        lead.append(index)
        used += len(passage) + 3
    title_terms = [
        w for w in re.findall(r"[A-Za-z][\w'-]{3,}", title or "") if w.lower() not in _STOPWORDS
    ]
    terms = list(dict.fromkeys([*title_terms, *(t for t in focus_terms if t.strip())]))

    def score(passage: str) -> int:
        return sum(1 for term in terms if contains(passage, term))

    ranked = sorted(
        (i for i in range(len(passages)) if i not in lead),
        key=lambda i: (-score(passages[i]), i),
    )
    chosen = list(lead)
    for index in ranked:
        if score(passages[index]) == 0:
            break
        if used + len(passages[index]) > budget:
            continue
        chosen.append(index)
        used += len(passages[index]) + 3
    if len(chosen) == len(lead):  # nothing on-topic: fall back to the opening
        return text[:budget]
    return "\n…\n".join(passages[i] for i in sorted(chosen))[:budget]
