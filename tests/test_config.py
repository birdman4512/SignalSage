"""Tests for config loading and env var expansion."""

import os
import tempfile
import textwrap
from unittest.mock import patch

import pytest

from signalsage.config import load_config, load_watchlist


def _write_yaml(content: str) -> str:
    """Write content to a temp YAML file, return path."""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    tmp.write(textwrap.dedent(content))
    tmp.flush()
    return tmp.name


# ---------------------------------------------------------------------------
# Env var expansion
# ---------------------------------------------------------------------------


def test_env_var_substituted():
    path = _write_yaml("""
        key: ${MY_TEST_VAR}
    """)
    with patch.dict(os.environ, {"MY_TEST_VAR": "hello"}):
        cfg = load_config(path)
    assert cfg["key"] == "hello"


def test_missing_env_var_is_empty_string():
    path = _write_yaml("""
        key: ${DEFINITELY_NOT_SET_XYZ}
    """)
    os.environ.pop("DEFINITELY_NOT_SET_XYZ", None)
    cfg = load_config(path)
    assert cfg["key"] == ""


def test_nested_env_var():
    path = _write_yaml("""
        outer:
          inner: ${NESTED_VAR}
    """)
    with patch.dict(os.environ, {"NESTED_VAR": "deep"}):
        cfg = load_config(path)
    assert cfg["outer"]["inner"] == "deep"


def test_list_env_var():
    path = _write_yaml("""
        items:
          - ${ITEM_ONE}
          - literal
    """)
    with patch.dict(os.environ, {"ITEM_ONE": "first"}):
        cfg = load_config(path)
    assert cfg["items"][0] == "first"
    assert cfg["items"][1] == "literal"


def test_non_string_values_unchanged():
    path = _write_yaml("""
        count: 42
        flag: true
        ratio: 3.14
    """)
    cfg = load_config(path)
    assert cfg["count"] == 42
    assert cfg["flag"] is True
    assert cfg["ratio"] == pytest.approx(3.14)


# ---------------------------------------------------------------------------
# Watchlist loading
# ---------------------------------------------------------------------------


def test_watchlist_topics_loaded():
    path = _write_yaml("""
        topics:
          - name: "Test Topic"
            schedule: "0 6 * * *"
            sources:
              - name: "Source A"
                url: "https://example.com/feed"
    """)
    wl = load_watchlist(path)
    assert len(wl["topics"]) == 1
    assert wl["topics"][0]["name"] == "Test Topic"
    assert wl["topics"][0]["schedule"] == "0 6 * * *"
    assert len(wl["topics"][0]["sources"]) == 1


def test_watchlist_multiple_topics():
    path = _write_yaml("""
        topics:
          - name: "A"
            sources: []
          - name: "B"
            sources: []
          - name: "C"
            sources: []
    """)
    wl = load_watchlist(path)
    assert len(wl["topics"]) == 3


def test_config_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.yaml")
