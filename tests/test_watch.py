"""Tests for watch-mode keyword filtering and seen-item tracking."""

from signalsage.digest.watch import (
    WatchKeywords,
)

# ---------------------------------------------------------------------------
# item_id
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# matches_keywords
# ---------------------------------------------------------------------------


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
