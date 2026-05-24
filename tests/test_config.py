"""Tests for config loading and env var expansion."""

import os
import tempfile
import textwrap
from unittest.mock import patch

import pytest

from signalsage.config import load_config, load_digests


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
# Digest loading
# ---------------------------------------------------------------------------


def _write_digest(dir_path, filename: str, content: str) -> None:
    """Write a digest YAML file into a directory."""
    (dir_path / filename).write_text(textwrap.dedent(content), encoding="utf-8")


def test_digest_single_file_is_one_topic(tmp_path):
    _write_digest(
        tmp_path,
        "test-topic.yaml",
        """
        name: "Test Topic"
        schedule: "0 6 * * *"
        sources:
          - name: "Source A"
            url: "https://example.com/feed"
        """,
    )
    wl = load_digests(str(tmp_path))
    assert len(wl["topics"]) == 1
    assert wl["topics"][0]["name"] == "Test Topic"
    assert wl["topics"][0]["schedule"] == "0 6 * * *"
    assert len(wl["topics"][0]["sources"]) == 1


def test_digest_one_topic_per_file(tmp_path):
    for name in ("a", "b", "c"):
        _write_digest(tmp_path, f"{name}.yaml", f'name: "{name.upper()}"\nsources: []\n')
    wl = load_digests(str(tmp_path))
    assert len(wl["topics"]) == 3
    assert sorted(t["name"] for t in wl["topics"]) == ["A", "B", "C"]


def test_digest_local_files_are_picked_up(tmp_path):
    _write_digest(tmp_path, "core.yaml", 'name: "Core"\nsources: []\n')
    _write_digest(tmp_path, "private.local.yaml", 'name: "Private"\nsources: []\n')
    wl = load_digests(str(tmp_path))
    assert sorted(t["name"] for t in wl["topics"]) == ["Core", "Private"]


def test_digest_example_files_are_ignored(tmp_path):
    _write_digest(tmp_path, "core.yaml", 'name: "Core"\nsources: []\n')
    _write_digest(tmp_path, "template.yaml.example", 'name: "Template"\nsources: []\n')
    wl = load_digests(str(tmp_path))
    assert [t["name"] for t in wl["topics"]] == ["Core"]


def test_digest_file_with_topics_list(tmp_path):
    _write_digest(
        tmp_path,
        "bundle.yaml",
        """
        topics:
          - name: "One"
            sources: []
          - name: "Two"
            sources: []
        """,
    )
    wl = load_digests(str(tmp_path))
    assert sorted(t["name"] for t in wl["topics"]) == ["One", "Two"]


def test_digest_empty_file_skipped(tmp_path):
    _write_digest(tmp_path, "core.yaml", 'name: "Core"\nsources: []\n')
    _write_digest(tmp_path, "empty.yaml", "")
    wl = load_digests(str(tmp_path))
    assert [t["name"] for t in wl["topics"]] == ["Core"]


def test_digest_env_var_expanded(tmp_path):
    _write_digest(
        tmp_path, "core.yaml", 'name: "Core"\ndigest_channel: ${DIGEST_CH}\nsources: []\n'
    )
    with patch.dict(os.environ, {"DIGEST_CH": "#secret"}):
        wl = load_digests(str(tmp_path))
    assert wl["topics"][0]["digest_channel"] == "#secret"


def test_digest_missing_directory_is_non_fatal(tmp_path):
    wl = load_digests(str(tmp_path / "does-not-exist"))
    assert wl == {"topics": []}


def test_config_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/path/config.yaml")
