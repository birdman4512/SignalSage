from signalsage import __version__, version

SHA = "0123456789abcdef0123456789abcdef01234567"


def git_dir(tmp_path, head):
    (tmp_path / ".git" / "refs" / "heads").mkdir(parents=True)
    (tmp_path / ".git" / "HEAD").write_text(head)
    return tmp_path


def test_resolves_loose_ref(tmp_path):
    root = git_dir(tmp_path, "ref: refs/heads/main\n")
    (root / ".git" / "refs" / "heads" / "main").write_text(SHA + "\n")
    assert version.resolve_git_commit(root) == SHA


def test_resolves_packed_ref(tmp_path):
    root = git_dir(tmp_path, "ref: refs/heads/main\n")
    (root / ".git" / "packed-refs").write_text(
        f"# pack-refs with: peeled fully-peeled sorted\n{SHA} refs/heads/main\n"
    )
    assert version.resolve_git_commit(root) == SHA


def test_resolves_detached_head(tmp_path):
    assert version.resolve_git_commit(git_dir(tmp_path, SHA + "\n")) == SHA


def test_missing_git_is_none(tmp_path):
    assert version.resolve_git_commit(tmp_path) is None
    assert version.resolve_git_commit(git_dir(tmp_path, "ref: refs/heads/gone\n")) is None


def test_version_text_uses_build_commit(tmp_path, monkeypatch):
    build_file = tmp_path / "BUILD_COMMIT"
    build_file.write_text(SHA)
    monkeypatch.setattr(version, "_BUILD_COMMIT_FILE", build_file)
    text = version.version_text()
    assert __version__ in text and "`0123456`" in text and "up " in text


def test_empty_build_commit_reports_unknown(tmp_path, monkeypatch):
    build_file = tmp_path / "BUILD_COMMIT"
    build_file.write_text("")
    monkeypatch.setattr(version, "_BUILD_COMMIT_FILE", build_file)
    assert "commit unknown" in version.version_text()


def test_uptime_format():
    assert version._uptime(59) == "0m"
    assert version._uptime(3 * 3600 + 120) == "3h 2m"
    assert version._uptime(2 * 86400 + 5 * 3600) == "2d 5h"
