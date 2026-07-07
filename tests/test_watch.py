"""Tests for watch-mode keyword filtering and seen-item tracking."""

from datetime import date, timedelta

from signalsage.digest.watch import (
    _KEEP_DAYS,
    WatchKeywords,
    WatchSeenItems,
    item_id,
    matches_keywords,
)

# ---------------------------------------------------------------------------
# item_id
# ---------------------------------------------------------------------------


def test_item_id_uses_link_when_present():
    item = {"title": "T", "link": "https://a.com/1", "summary": "s"}
    assert item_id(item) == "https://a.com/1"


def test_item_id_falls_back_to_content_hash_without_link():
    item = {"title": "T", "link": "", "summary": "s"}
    assert item_id(item) == item_id({"title": "T", "link": "", "summary": "s"})
    assert item_id(item).startswith("h:")


def test_item_id_changes_when_content_changes_without_link():
    a = item_id({"title": "T", "link": "", "summary": "old"})
    b = item_id({"title": "T", "link": "", "summary": "new"})
    assert a != b


# ---------------------------------------------------------------------------
# matches_keywords
# ---------------------------------------------------------------------------


def test_matches_keywords_empty_include_matches_everything():
    item = {"title": "Anything", "summary": ""}
    assert matches_keywords(item, [], []) is True


def test_matches_keywords_include_substring_case_insensitive():
    item = {"title": "New Ransomware Strain Found", "summary": ""}
    assert matches_keywords(item, ["ransomware"], []) is True
    assert matches_keywords(item, ["RANSOMWARE"], []) is True
    assert matches_keywords(item, ["phishing"], []) is False


def test_matches_keywords_checks_summary_too():
    item = {"title": "Weekly Roundup", "summary": "covers a new zero-day exploit"}
    assert matches_keywords(item, ["zero-day"], []) is True


def test_matches_keywords_exclude_vetoes():
    item = {"title": "Ransomware sponsored post", "summary": ""}
    assert matches_keywords(item, ["ransomware"], ["sponsored"]) is False


def test_matches_keywords_exclude_with_empty_include():
    item = {"title": "Sponsored content", "summary": ""}
    assert matches_keywords(item, [], ["sponsored"]) is False


# ---------------------------------------------------------------------------
# WatchKeywords
# ---------------------------------------------------------------------------


def test_seed_defaults_sets_initial_lists(tmp_path):
    kw = WatchKeywords(data_dir=str(tmp_path))
    kw.seed_defaults("Topic", ["ai"], ["sponsored"])
    include, exclude = kw.get("Topic")
    assert include == ["ai"]
    assert exclude == ["sponsored"]


def test_seed_defaults_does_not_overwrite_existing(tmp_path):
    kw = WatchKeywords(data_dir=str(tmp_path))
    kw.add("Topic", "manual-word")
    kw.seed_defaults("Topic", ["yaml-word"], [])
    include, _ = kw.get("Topic")
    assert include == ["manual-word"]


def test_seed_defaults_noop_when_yaml_lists_empty(tmp_path):
    kw = WatchKeywords(data_dir=str(tmp_path))
    kw.seed_defaults("Topic", [], [])
    include, exclude = kw.get("Topic")
    assert include == []
    assert exclude == []


def test_add_include_keyword(tmp_path):
    kw = WatchKeywords(data_dir=str(tmp_path))
    assert kw.add("Topic", "ransomware") is True
    include, _ = kw.get("Topic")
    assert include == ["ransomware"]


def test_add_duplicate_keyword_returns_false(tmp_path):
    kw = WatchKeywords(data_dir=str(tmp_path))
    kw.add("Topic", "ransomware")
    assert kw.add("Topic", "Ransomware") is False  # case-insensitive dup


def test_remove_keyword(tmp_path):
    kw = WatchKeywords(data_dir=str(tmp_path))
    kw.add("Topic", "ransomware")
    assert kw.remove("Topic", "ransomware") is True
    include, _ = kw.get("Topic")
    assert include == []


def test_remove_nonexistent_keyword_returns_false(tmp_path):
    kw = WatchKeywords(data_dir=str(tmp_path))
    assert kw.remove("Topic", "nope") is False


def test_exclude_keyword_add_remove(tmp_path):
    kw = WatchKeywords(data_dir=str(tmp_path))
    assert kw.add("Topic", "sponsored", exclude=True) is True
    _, exclude = kw.get("Topic")
    assert exclude == ["sponsored"]
    assert kw.remove("Topic", "sponsored", exclude=True) is True
    _, exclude = kw.get("Topic")
    assert exclude == []


def test_keywords_persist_across_instances(tmp_path):
    kw1 = WatchKeywords(data_dir=str(tmp_path))
    kw1.add("Topic", "ransomware")
    kw2 = WatchKeywords(data_dir=str(tmp_path))
    include, _ = kw2.get("Topic")
    assert include == ["ransomware"]


def test_get_unknown_topic_returns_empty_lists(tmp_path):
    kw = WatchKeywords(data_dir=str(tmp_path))
    assert kw.get("Nonexistent") == ([], [])


# ---------------------------------------------------------------------------
# WatchSeenItems
# ---------------------------------------------------------------------------


def test_filter_new_returns_unseen_items(tmp_path):
    seen = WatchSeenItems(data_dir=str(tmp_path))
    items = [{"title": "A", "link": "https://a.com/1"}]
    assert seen.filter_new("Topic", items) == items


def test_mark_seen_then_filter_new_excludes_it(tmp_path):
    seen = WatchSeenItems(data_dir=str(tmp_path))
    items = [{"title": "A", "link": "https://a.com/1"}]
    seen.mark_seen("Topic", items)
    assert seen.filter_new("Topic", items) == []


def test_mark_seen_persists_across_instances(tmp_path):
    seen1 = WatchSeenItems(data_dir=str(tmp_path))
    items = [{"title": "A", "link": "https://a.com/1"}]
    seen1.mark_seen("Topic", items)

    seen2 = WatchSeenItems(data_dir=str(tmp_path))
    assert seen2.filter_new("Topic", items) == []


def test_mark_seen_regardless_of_keyword_match(tmp_path):
    """Every fetched item is marked seen, whether or not it matched keywords."""
    seen = WatchSeenItems(data_dir=str(tmp_path))
    non_matching_item = [{"title": "Unrelated", "link": "https://a.com/2"}]
    seen.mark_seen("Topic", non_matching_item)
    assert seen.filter_new("Topic", non_matching_item) == []


def test_prune_removes_old_entries(tmp_path):
    seen = WatchSeenItems(data_dir=str(tmp_path))
    old_date = (date.today() - timedelta(days=_KEEP_DAYS + 1)).isoformat()
    seen._data["Topic"] = {"https://a.com/old": old_date}
    seen._last_prune_day = ""
    seen.mark_seen("Topic", [{"title": "New", "link": "https://a.com/new"}])
    assert "https://a.com/old" not in seen._data.get("Topic", {})


def test_prune_keeps_recent_entries(tmp_path):
    seen = WatchSeenItems(data_dir=str(tmp_path))
    recent_date = (date.today() - timedelta(days=_KEEP_DAYS - 1)).isoformat()
    seen._data["Topic"] = {"https://a.com/recent": recent_date}
    seen._last_prune_day = ""
    seen.mark_seen("Topic", [{"title": "New", "link": "https://a.com/new"}])
    assert "https://a.com/recent" in seen._data.get("Topic", {})
