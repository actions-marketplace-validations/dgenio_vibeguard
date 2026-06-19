"""File-collection and ignore-handling tests (#216, #211, #219).

Covers the three changes that share ``scanner._collect_files`` and the ignore
resolution in ``run_scan``:

* #216 — ``ignore.paths`` uses one gitignore grammar (``pathspec``), so
  multi-segment patterns work and default directory patterns are unchanged.
* #219 — ignored directories are pruned during the walk; the resulting file set
  and its sort order match the old filter-after-walk behaviour.
* #211 — the scan root's ``.gitignore`` is honoured by default, with a
  git-tracked carve-out and a ``scanner.respect_gitignore: false`` opt-out.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from vibeguard.config import (
    VibeGuardConfig,
    compile_pathspec,
    load_gitignore,
    load_ignorefile,
)
from vibeguard.git import get_tracked_files
from vibeguard.scanner import _collect_files, run_scan


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _collect(root: Path, config: VibeGuardConfig | None = None) -> set[str]:
    """Collect the relative file set the scanner would scan under ``root``.

    Mirrors ``run_scan``'s ignore wiring so ``_collect_files`` can be unit
    tested directly; the end-to-end path is exercised by the SEC-ENV test.
    """
    config = config or VibeGuardConfig()
    ignore_spec = compile_pathspec((*config.ignore.paths, *load_ignorefile(root)))
    gitignore_spec = None
    tracked = None
    if config.scanner.respect_gitignore:
        gitignore_patterns = load_gitignore(root)
        if gitignore_patterns:
            gitignore_spec = compile_pathspec(tuple(gitignore_patterns))
            tracked = get_tracked_files(root)
    files, _ = _collect_files(root, config, ignore_spec, gitignore_spec, tracked)
    return {p.relative_to(root).as_posix() for p in files}


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _init_repo(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "config", "core.autocrlf", "false")


def _commit_all(root: Path, message: str) -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)


# ---------------------------------------------------------------------------
# #216 — unified ignore-pattern semantics
# ---------------------------------------------------------------------------
class TestUnifiedIgnoreSemantics:
    def test_default_directory_patterns_unchanged(self) -> None:
        cfg = VibeGuardConfig()
        assert cfg.is_path_ignored("node_modules/lodash/index.js")
        assert cfg.is_path_ignored(".git/config")
        assert cfg.is_path_ignored(".venv/lib/python3.11/site-packages/foo.py")
        assert cfg.is_path_ignored("pkg.egg-info/PKG-INFO")
        assert not cfg.is_path_ignored("src/main.py")
        assert not cfg.is_path_ignored("README.md")

    def test_multi_segment_pattern_now_matches(self) -> None:
        """The headline #216 fix: ``packages/*/build/`` matched nothing under the
        old per-component fnmatch; gitignore semantics make it work."""
        cfg = VibeGuardConfig(ignore={"paths": ["packages/*/build/"]})
        assert cfg.is_path_ignored("packages/api/build/out.js")
        assert not cfg.is_path_ignored("packages/api/src/app.js")
        # An unanchored bare segment must NOT match the mid-path "build".
        assert not cfg.is_path_ignored("build/out.js")

    def test_multi_segment_pattern_prunes_in_scan(self, tmp_path: Path) -> None:
        cfg = VibeGuardConfig(ignore={"paths": ["packages/*/build/"]})
        (tmp_path / "packages/api/build").mkdir(parents=True)
        (tmp_path / "packages/api/src").mkdir(parents=True)
        (tmp_path / "packages/api/build/out.js").write_text("module.exports = 1\n")
        (tmp_path / "packages/api/src/app.js").write_text("export const x = 1\n")
        assert _collect(tmp_path, cfg) == {"packages/api/src/app.js"}


# ---------------------------------------------------------------------------
# #219 — directory pruning during the walk
# ---------------------------------------------------------------------------
class TestDirectoryPruning:
    def test_ignored_directory_contents_excluded(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src/app.py").write_text("x = 1\n")
        (tmp_path / "node_modules/pkg").mkdir(parents=True)
        (tmp_path / "node_modules/pkg/index.js").write_text("module.exports = {}\n")
        (tmp_path / "node_modules/pkg/nested").mkdir()
        (tmp_path / "node_modules/pkg/nested/deep.js").write_text("0\n")
        assert _collect(tmp_path) == {"src/app.py"}

    def test_sorted_order_preserved(self, tmp_path: Path) -> None:
        for name in ("c.py", "a.py", "b.py"):
            (tmp_path / name).write_text("x = 1\n")
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg/z.py").write_text("x = 1\n")
        ignore_spec = compile_pathspec(tuple(VibeGuardConfig().ignore.paths))
        files, _ = _collect_files(tmp_path, VibeGuardConfig(), ignore_spec)
        rels = [p.relative_to(tmp_path).as_posix() for p in files]
        assert rels == sorted(rels)
        assert rels == ["a.py", "b.py", "c.py", "pkg/z.py"]

    def test_vibeguardignore_negation_overrides_config(self, tmp_path: Path) -> None:
        """A ``!`` negation in ``.vibeguardignore`` re-includes a path the
        config ignores — precedence: ``ignore.paths`` then ``.vibeguardignore``
        (both compiled into one ordered, last-match-wins spec)."""
        cfg = VibeGuardConfig(ignore={"paths": ["*.secret"]})
        (tmp_path / "a.secret").write_text("x = 1\n")
        (tmp_path / "b.secret").write_text("y = 2\n")
        (tmp_path / ".vibeguardignore").write_text("!a.secret\n")
        got = _collect(tmp_path, cfg)
        assert "a.secret" in got  # re-included by the negation
        assert "b.secret" not in got  # still ignored by ignore.paths
        assert ".vibeguardignore" in got

    @pytest.mark.skipif(
        not hasattr(Path, "symlink_to"), reason="symlinks unsupported on this platform"
    )
    def test_symlinked_directory_not_descended(self, tmp_path: Path) -> None:
        (tmp_path / "real").mkdir()
        (tmp_path / "real/app.py").write_text("x = 1\n")
        try:
            (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation not permitted here")
        # The symlinked directory is not traversed (matches the previous rglob
        # behaviour), so app.py is collected exactly once via its real path.
        assert _collect(tmp_path) == {"real/app.py"}


# ---------------------------------------------------------------------------
# #211 — respect .gitignore with a git-tracked carve-out
# ---------------------------------------------------------------------------
class TestRespectGitignore:
    def test_gitignored_untracked_file_skipped(self, tmp_path: Path) -> None:
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / ".gitignore").write_text("coverage/\n")
        _commit_all(tmp_path, "init")
        # Created after the commit and gitignored -> untracked + ignored.
        (tmp_path / "coverage").mkdir()
        (tmp_path / "coverage/report.py").write_text("y = 2\n")
        collected = _collect(tmp_path)
        assert "coverage/report.py" not in collected
        assert "app.py" in collected

    def test_tracked_but_gitignored_file_still_scanned(self, tmp_path: Path) -> None:
        """The carve-out: a committed file that is also gitignored is scanned."""
        _init_repo(tmp_path)
        (tmp_path / ".gitignore").write_text(".env\n")
        (tmp_path / "app.py").write_text("x = 1\n")
        # Force-add the gitignored file so git tracks it.
        (tmp_path / ".env").write_text("SECRET=abc\n")
        _git(tmp_path, "add", "-f", ".env")
        _commit_all(tmp_path, "init")
        assert ".env" in _collect(tmp_path)

    def test_committed_env_still_triggers_sec_env(self, tmp_path: Path) -> None:
        """End-to-end: SEC-ENV must still fire on a committed, gitignored .env."""
        _init_repo(tmp_path)
        (tmp_path / ".gitignore").write_text(".env\n")
        (tmp_path / ".env").write_text("API_KEY=supersecret\n")
        _git(tmp_path, "add", "-f", ".env", ".gitignore")
        _commit_all(tmp_path, "init")
        result = run_scan(tmp_path, VibeGuardConfig())
        assert "SEC-ENV" in {f.id for f in result.findings}

    def test_opt_out_restores_gitignored_files(self, tmp_path: Path) -> None:
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / ".gitignore").write_text("coverage/\n")
        _commit_all(tmp_path, "init")
        (tmp_path / "coverage").mkdir()
        (tmp_path / "coverage/report.py").write_text("y = 2\n")
        cfg = VibeGuardConfig(scanner={"respect_gitignore": False})
        assert "coverage/report.py" in _collect(tmp_path, cfg)

    def test_skip_notice_counts_gitignored_files(self, tmp_path: Path) -> None:
        _init_repo(tmp_path)
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / ".gitignore").write_text("coverage/\n")
        _commit_all(tmp_path, "init")
        (tmp_path / "coverage").mkdir()
        (tmp_path / "coverage/a.py").write_text("a = 1\n")
        ignore_spec = compile_pathspec(tuple(VibeGuardConfig().ignore.paths))
        gitignore_spec = compile_pathspec(tuple(load_gitignore(tmp_path)))
        tracked = get_tracked_files(tmp_path)
        _, skipped = _collect_files(
            tmp_path, VibeGuardConfig(), ignore_spec, gitignore_spec, tracked
        )
        assert any("1 gitignored file(s)" in line for line in skipped)

    def test_no_git_directory_falls_back_to_pathspec(self, tmp_path: Path) -> None:
        """Without git, the carve-out is disabled: .gitignore is applied as a
        pure pathspec and tracked-file detection returns None."""
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / ".gitignore").write_text("ignored.py\n")
        (tmp_path / "ignored.py").write_text("y = 2\n")
        assert get_tracked_files(tmp_path) is None
        collected = _collect(tmp_path)
        assert "app.py" in collected
        assert "ignored.py" not in collected
