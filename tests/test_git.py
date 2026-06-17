"""Regression tests for git metadata collection and base-branch detection (#186).

Exercises the environment-dependent half of ``vibeguard/git.py`` —
``get_git_metadata``, ``_detect_base_branch``, ``get_diff_text`` and their
failure paths — against real throwaway git repositories, the code that breaks in
users' CI (shallow clones, detached HEAD, missing remotes) rather than on a
maintainer's machine.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from vibeguard.git import (
    _detect_base_branch,
    _is_shallow,
    _ref_exists,
    get_diff_text,
    get_git_metadata,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(root: Path, *args: str) -> str:
    """Run a git command in ``root``, returning stdout (commit signing disabled).

    ``commit.gpgsign=false`` keeps these tests independent of any global signing
    configuration on the host/CI.
    """
    result = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _init_repo(root: Path, default_branch: str = "main") -> None:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", default_branch)
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "config", "core.autocrlf", "false")


def _commit(root: Path, name: str, content: str, message: str) -> None:
    (root / name).write_text(content, encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repo on ``main`` with one commit."""
    root = tmp_path / "repo"
    _init_repo(root)
    _commit(root, "app.py", "x = 1\nz = 3\n", "init")
    return root


class TestGetGitMetadata:
    def test_basic_repo_is_available(self, repo: Path):
        meta = get_git_metadata(repo)
        assert meta.is_available is True
        assert meta.error is None
        assert meta.branch == "main"
        assert meta.commit  # short SHA present
        assert meta.is_shallow is False

    def test_non_git_directory(self, tmp_path: Path):
        plain = tmp_path / "plain"
        plain.mkdir()
        meta = get_git_metadata(plain)
        assert meta.is_available is False
        assert meta.error == "Not a git repository"

    def test_changed_files_against_base(self, repo: Path):
        # Branch off main, change a file: base...HEAD should list it.
        _git(repo, "checkout", "-q", "-b", "feature")
        _commit(repo, "app.py", "x = 1\ny = 2\nz = 3\n", "edit")
        meta = get_git_metadata(repo)
        assert meta.base_branch == "main"
        assert meta.diff_strategy == "merge-base"
        assert "app.py" in meta.changed_files

    def test_explicit_valid_base_is_used(self, repo: Path):
        _git(repo, "checkout", "-q", "-b", "develop")
        _commit(repo, "feat.py", "a = 1\n", "feature")
        _git(repo, "checkout", "-q", "main")
        _git(repo, "checkout", "-q", "-b", "topic")
        _commit(repo, "topic.py", "b = 2\n", "topic")
        meta = get_git_metadata(repo, base_branch="develop")
        assert meta.base_branch == "develop"
        assert meta.diff_strategy == "merge-base"
        assert not meta.warnings

    def test_invalid_explicit_base_warns_and_falls_back(self, repo: Path):
        _git(repo, "checkout", "-q", "-b", "feature")
        _commit(repo, "app.py", "x = 1\ny = 2\nz = 3\n", "edit")
        meta = get_git_metadata(repo, base_branch="origin/nope")
        # Non-silent: a warning is recorded and detection falls back to main.
        assert meta.warnings
        assert "origin/nope" in meta.warnings[0]
        assert meta.base_branch == "main"
        assert meta.is_available is True

    def test_head_only_when_no_base_detected(self, tmp_path: Path):
        # A repo whose only branch is neither main/master nor an origin ref.
        root = tmp_path / "lonely"
        _init_repo(root, default_branch="trunk-x")
        _commit(root, "a.py", "v = 1\n", "init")
        meta = get_git_metadata(root)
        assert meta.base_branch is None
        assert meta.diff_strategy == "head-only"

    def test_detached_head(self, repo: Path):
        _commit(repo, "more.py", "m = 1\n", "second")
        head = _git(repo, "rev-parse", "HEAD").strip()
        _git(repo, "checkout", "-q", head)
        meta = get_git_metadata(repo)
        assert meta.is_available is True
        # abbrev-ref reports HEAD when detached; must not crash.
        assert meta.branch == "HEAD"

    def test_repo_with_no_commits(self, tmp_path: Path):
        root = tmp_path / "empty"
        _init_repo(root)
        meta = get_git_metadata(root)
        # git-dir resolves, so the context is available; there is just no commit.
        assert meta.is_available is True
        assert meta.changed_files == []

    def test_shallow_clone_detected(self, tmp_path: Path):
        src = tmp_path / "src"
        _init_repo(src)
        _commit(src, "a.py", "1\n", "c1")
        _commit(src, "a.py", "2\n", "c2")
        dst = tmp_path / "shallow"
        _git(tmp_path, "clone", "--depth=1", "-q", f"file://{src}", str(dst))
        assert _is_shallow(dst) is True
        meta = get_git_metadata(dst)
        assert meta.is_shallow is True


class TestDetectBaseBranch:
    def test_prefers_local_main(self, repo: Path):
        assert _detect_base_branch(repo) == "main"

    def test_prefers_origin_main_over_local(self, tmp_path: Path):
        src = tmp_path / "origin_src"
        _init_repo(src)
        _commit(src, "a.py", "1\n", "init")
        clone = tmp_path / "clone"
        _git(tmp_path, "clone", "-q", f"file://{src}", str(clone))
        # Clone has origin/main; detection prefers the remote-tracking ref.
        assert _detect_base_branch(clone) == "origin/main"

    def test_returns_none_when_no_candidate(self, tmp_path: Path):
        root = tmp_path / "nomain"
        _init_repo(root, default_branch="weird")
        _commit(root, "a.py", "1\n", "init")
        assert _detect_base_branch(root) is None


class TestRefExists:
    def test_known_ref(self, repo: Path):
        assert _ref_exists(repo, "main") is True

    def test_unknown_ref(self, repo: Path):
        assert _ref_exists(repo, "origin/does-not-exist") is False


class TestGetDiffText:
    def test_diff_against_base(self, repo: Path):
        _git(repo, "checkout", "-q", "-b", "feature")
        _commit(repo, "app.py", "x = 1\ny = 2\nz = 3\n", "edit")
        text = get_diff_text(repo, base_branch="main")
        assert "+++ b/app.py" in text
        assert "+y = 2" in text

    def test_none_base_falls_back_to_head(self, tmp_path: Path):
        # No detectable base; uncommitted change shows up via the HEAD fallback.
        root = tmp_path / "fallback"
        _init_repo(root, default_branch="weird")
        _commit(root, "app.py", "x = 1\n", "init")
        (root / "app.py").write_text("x = 1\ny = 2\n", encoding="utf-8")
        text = get_diff_text(root)
        assert "+y = 2" in text

    def test_diff_output_has_no_ansi_color(self, repo: Path):
        # color.diff=never is pinned, so output is plain even if a user sets
        # color.diff=always globally (we cannot here, but assert the contract).
        _git(repo, "checkout", "-q", "-b", "feature")
        _commit(repo, "app.py", "x = 1\ny = 2\nz = 3\n", "edit")
        text = get_diff_text(repo, base_branch="main")
        assert "\x1b[" not in text
