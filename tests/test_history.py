"""Tests for digest history — trend detection and source health."""

from datetime import date, timedelta

from signalsage.digest.history import _KEEP_DAYS, DigestHistory, _headline_hash

# ---------------------------------------------------------------------------
# _headline_hash
# ---------------------------------------------------------------------------


def test_headline_hash_stable():
    assert _headline_hash("Test Headline") == _headline_hash("Test Headline")


def test_headline_hash_normalised():
    assert _headline_hash("  RANSOMWARE SURGE  ") == _headline_hash("ransomware surge")


def test_headline_hash_length():
    assert len(_headline_hash("anything")) == 12


# ---------------------------------------------------------------------------
# classify_items — new vs trending
# ---------------------------------------------------------------------------


def test_classify_items_all_new_with_empty_history(tmp_path):
    history = DigestHistory(data_dir=str(tmp_path))
    items = [{"headline": "Brand new story", "url": None}]
    result = history.classify_items("Topic", items)
    assert list(result.values()) == ["new"]


def test_classify_items_trending_after_prior_day(tmp_path):
    history = DigestHistory(data_dir=str(tmp_path))
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    headline = "Ransomware surge"
    history._history["Topic"] = {
        yesterday: [{"hash": _headline_hash(headline), "headline": headline}]
    }
    result = history.classify_items("Topic", [{"headline": headline, "url": None}])
    assert list(result.values()) == ["trending"]


def test_classify_items_today_not_trending(tmp_path):
    """Items recorded today should not be classified as trending today."""
    history = DigestHistory(data_dir=str(tmp_path))
    today = date.today().isoformat()
    headline = "Same day story"
    history._history["Topic"] = {today: [{"hash": _headline_hash(headline), "headline": headline}]}
    result = history.classify_items("Topic", [{"headline": headline, "url": None}])
    assert list(result.values()) == ["new"]


def test_classify_items_older_than_7_days_not_trending(tmp_path):
    history = DigestHistory(data_dir=str(tmp_path))
    old_date = (date.today() - timedelta(days=8)).isoformat()
    headline = "Old story"
    history._history["Topic"] = {
        old_date: [{"hash": _headline_hash(headline), "headline": headline}]
    }
    result = history.classify_items("Topic", [{"headline": headline, "url": None}])
    assert list(result.values()) == ["new"]


# ---------------------------------------------------------------------------
# record_items — persistence
# ---------------------------------------------------------------------------


def test_record_items_persists_to_disk(tmp_path):
    history1 = DigestHistory(data_dir=str(tmp_path))
    history1.record_items("Topic A", [{"headline": "Persistent Story", "url": None}])

    history2 = DigestHistory(data_dir=str(tmp_path))
    today = date.today().isoformat()
    assert "Topic A" in history2._history
    assert today in history2._history["Topic A"]
    assert len(history2._history["Topic A"][today]) == 1


def test_record_items_skips_empty_headlines(tmp_path):
    history = DigestHistory(data_dir=str(tmp_path))
    history.record_items("Topic", [{"headline": "", "url": None}, {"headline": "  ", "url": None}])
    today = date.today().isoformat()
    assert history._history.get("Topic", {}).get(today, []) == []


# ---------------------------------------------------------------------------
# source health
# ---------------------------------------------------------------------------


def test_record_source_results_persists(tmp_path):
    history = DigestHistory(data_dir=str(tmp_path))
    history.record_source_results({"Feed A": True, "Feed B": False})
    today = date.today().isoformat()
    assert history._health["Feed A"][today] is True
    assert history._health["Feed B"][today] is False


def test_chronic_failure_detected_after_3_days(tmp_path):
    history = DigestHistory(data_dir=str(tmp_path))
    today = date.today()
    for i in range(3):
        day = (today - timedelta(days=i)).isoformat()
        history._health.setdefault("Bad Feed", {})[day] = False
    assert "Bad Feed" in history.get_chronically_failing_sources(consecutive_days=3)


def test_chronic_failure_not_triggered_with_gap(tmp_path):
    """A healthy day in the streak should break it."""
    history = DigestHistory(data_dir=str(tmp_path))
    today = date.today()
    history._health["Intermittent"] = {
        (today - timedelta(days=0)).isoformat(): False,
        (today - timedelta(days=1)).isoformat(): True,  # healthy — breaks streak
        (today - timedelta(days=2)).isoformat(): False,
    }
    assert "Intermittent" not in history.get_chronically_failing_sources(consecutive_days=3)


def test_chronic_failure_not_triggered_after_only_2_days(tmp_path):
    history = DigestHistory(data_dir=str(tmp_path))
    today = date.today()
    for i in range(2):
        day = (today - timedelta(days=i)).isoformat()
        history._health.setdefault("Almost", {})[day] = False
    assert "Almost" not in history.get_chronically_failing_sources(consecutive_days=3)


# ---------------------------------------------------------------------------
# pruning
# ---------------------------------------------------------------------------


def test_prune_removes_old_history_entries(tmp_path):
    history = DigestHistory(data_dir=str(tmp_path))
    old_date = (date.today() - timedelta(days=_KEEP_DAYS + 1)).isoformat()
    history._history["Topic"] = {old_date: []}
    history.record_items("Topic", [])  # triggers _prune
    assert old_date not in history._history.get("Topic", {})


def test_prune_keeps_recent_entries(tmp_path):
    history = DigestHistory(data_dir=str(tmp_path))
    recent_date = (date.today() - timedelta(days=_KEEP_DAYS - 1)).isoformat()
    history._history["Topic"] = {recent_date: []}
    history.record_items("Topic", [])  # triggers _prune
    assert recent_date in history._history.get("Topic", {})
