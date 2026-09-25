"""Cheap, explainable relevance and conservative story deduplication."""

import hashlib
import json
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def canonical_url(value: str) -> str:
    try:
        url = urlsplit(value.strip())
        if url.scheme not in ("http", "https") or not url.hostname or url.username:
            return ""
        if any(c in value for c in "<>\"'|`{}\\^"):
            return ""
        query = [
            (k, v)
            for k, v in parse_qsl(url.query, keep_blank_values=True)
            if not k.lower().startswith("utm_") and k.lower() not in {"fbclid", "gclid"}
        ]
        return urlunsplit(
            (url.scheme.lower(), url.netloc.lower(), url.path or "/", urlencode(sorted(query)), "")
        )
    except ValueError:
        return ""


_INFLECTION = r"(?:s|es|ed|d|ing|er|ers|ation|ations)?"


def contains(text: str, phrase: str) -> bool:
    """Whole-word match that also accepts common English inflections.

    "apt" must not match "adaptation", but "llm" should match "LLMs" and
    "exploit" should match "exploited"/"exploitation" — keywords are written
    as base forms, while headlines use whatever form reads naturally.
    """
    phrase = phrase.strip()
    return bool(
        phrase and re.search(r"(?<!\w)" + re.escape(phrase) + _INFLECTION + r"(?!\w)", text, re.I)
    )


def fingerprint(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def article_identity(item: dict) -> tuple[str, str]:
    """Identity is stable; content revisions get a separate version."""
    url = canonical_url(str(item.get("link") or ""))
    identity = url or f"{item.get('source_url', '')}:{item.get('guid') or item.get('title', '')}"
    content = re.sub(r"\s+", " ", f"{item.get('title', '')} {item.get('summary', '')}").strip()
    return fingerprint(identity), fingerprint(content)


_EDITS_ARE_NOT_UPDATES = ("reddit.com", "lobste.rs")


def similar_story(a: dict, b: dict) -> bool:
    """Only collapse close headlines AND content; changed facts remain eligible."""
    title_a, title_b = str(a.get("title", "")).lower(), str(b.get("title", "")).lower()
    # Different versions of the same URL are updates, not syndication duplicates —
    # except on forum hosts, where a changed post is an edit rather than news
    # (measured: ~8% of Reddit posts change within a day), so re-posting it
    # would just repeat a story already sent.
    link = canonical_url(a.get("link", ""))
    if link == canonical_url(b.get("link", "")):
        host = urlsplit(link).hostname or ""
        if any(host == h or host.endswith("." + h) for h in _EDITS_ARE_NOT_UPDATES):
            return True
        return a.get("version") == b.get("version")
    if set(re.findall(r"\d+", title_a)) != set(re.findall(r"\d+", title_b)):
        return False

    def similarity(x, y):
        left, right = set(re.findall(r"\w+", x.lower())), set(re.findall(r"\w+", y.lower()))
        return len(left & right) / len(left | right) if left and right else 0

    return (
        similarity(title_a, title_b) >= 0.8
        and similarity(a.get("summary", ""), b.get("summary", "")) >= 0.7
    )


def score_article(
    item: dict,
    profile: dict,
    keywords: list[str],
    excludes: list[str],
    feedback: dict[str, float] | None = None,
) -> tuple[float, list[str], bool]:
    text = f"{item.get('title', '')} {item.get('summary', '')}"
    if any(contains(text, term) for term in [*excludes, *profile.get("exclude", [])]):
        return -100, ["Excluded subject"], True
    score = 0.0
    reasons = []
    weights = dict(profile.get("topics") or {})
    for term in keywords:
        weights[term] = max(float(weights.get(term, 0)), 3.0)
    for term in profile.get("products", []):
        weights[term] = max(float(weights.get(term, 0)), 4.0)
    for term in profile.get("geography", []):
        weights[term] = max(float(weights.get(term, 0)), 2.0)
    for term, weight in weights.items():
        if contains(text, term):
            in_title = contains(str(item.get("title", "")), term)
            score += float(weight) * (1 if in_title else 0.5)
            reasons.append(f"{'Matches' if in_title else 'Mentions'} {term}")
    if not weights:
        score = 3.0
        reasons.append("Selected topic source")
    # Source trust cannot make an unrelated story relevant on its own.
    if score > 0:
        host = urlsplit(item.get("link") or item.get("source_url", "")).hostname or ""
        score += float((profile.get("sources") or {}).get(host, 0))
        score += max(-2, min(2, (feedback or {}).get(host, 0)))
        published = item.get("published_ts")
        if published:
            age = max(0, time.time() - published)
            score += max(0, 0.5 * (1 - age / (7 * 86400)))
    return score, reasons, False
