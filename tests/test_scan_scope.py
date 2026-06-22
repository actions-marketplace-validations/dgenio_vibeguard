"""Scan-scope and input-mode tests (#213, #209, #153, #240).

Covers the four scan-input features that share the scope-resolution path:

- #213: positional PATH arguments — files and directories, multiple targets.
- #209: ``--staged`` mode (``git diff --cached``) and the pre-commit hook.
- #153: ``--patch`` — scanning a unified diff from a file or stdin standalone.

The git-backed cases run against throwaway repositories (the pattern from
``test_git.py``); the patch and positional cases need no git.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vibeguard.cli import app
from vibeguard.git import reconstruct_patch_files

runner = CliRunner()

# A high-severity secret that trips the gate at --fail-on high.
_SECRET_LINE = 'key = "AKIAIOSFODNN7EXAMPLE"\n'


def _findings(result_stdout: str) -> list[dict]:
    return json.loads(result_stdout)["findings"]


def _paths(result_stdout: str) -> set[str]:
    return {f["path"] for f in _findings(result_stdout)}


# ---------------------------------------------------------------------------
# #213 — positional path arguments (files + directories, multiple)
# ---------------------------------------------------------------------------
class TestPositionalPaths:
    def test_single_positional_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text(_SECRET_LINE)
        result = runner.invoke(app, ["scan", str(tmp_path), "--json"])
        assert result.exit_code == 0
        assert "a.py" in _paths(result.stdout)

    def test_multiple_positional_directories_relative_to_common_root(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "lib").mkdir()
        (tmp_path / "src" / "a.py").write_text(_SECRET_LINE)
        (tmp_path / "lib" / "b.py").write_text("print('clean')\n")
        result = runner.invoke(
            app, ["scan", str(tmp_path / "src"), str(tmp_path / "lib"), "--json"]
        )
        assert result.exit_code == 0
        # Reported relative to the common ancestor, not absolute.
        assert _paths(result.stdout) == {"src/a.py"}

    def test_single_file_target_is_scanned(self, tmp_path: Path) -> None:
        target = tmp_path / "a.py"
        target.write_text(_SECRET_LINE)
        (tmp_path / "other.py").write_text(_SECRET_LINE)
        result = runner.invoke(app, ["scan", str(target), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        # Only the named file is scanned, never the sibling.
        assert data["scanned_files"] == 1
        assert _paths(result.stdout) == {"a.py"}

    def test_explicit_file_target_bypasses_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("ignored.py\n")
        target = tmp_path / "ignored.py"
        target.write_text(_SECRET_LINE)
        result = runner.invoke(app, ["scan", str(target), "--json"])
        assert result.exit_code == 0
        assert _paths(result.stdout) == {"ignored.py"}

    def test_missing_positional_target_fails_closed(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["scan", str(tmp_path / "nope.py")])
        assert result.exit_code == 2
        assert "does not exist" in result.stdout + (result.stderr or "")

    def test_gate_on_file_target_blocks(self, tmp_path: Path) -> None:
        target = tmp_path / "a.py"
        target.write_text(_SECRET_LINE)
        result = runner.invoke(app, ["gate", str(target), "--fail-on", "high"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# #209 — --staged mode
# ---------------------------------------------------------------------------
def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "T")
    (root / "clean.py").write_text("print('ok')\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "init")
    return root


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
class TestStagedMode:
    def test_gate_staged_blocks_on_staged_secret(self, repo: Path) -> None:
        (repo / "new.py").write_text(_SECRET_LINE)
        _git(repo, "add", "new.py")
        result = runner.invoke(app, ["gate", "--path", str(repo), "--staged", "--fail-on", "high"])
        assert result.exit_code == 1

    def test_staged_scopes_to_index_only(self, repo: Path) -> None:
        # Staged file is in scope; an unstaged sibling is not.
        (repo / "staged.py").write_text(_SECRET_LINE)
        _git(repo, "add", "staged.py")
        (repo / "unstaged.py").write_text(_SECRET_LINE)
        result = runner.invoke(app, ["scan", "--path", str(repo), "--staged", "--json"])
        assert result.exit_code == 0
        assert _paths(result.stdout) == {"staged.py"}

    def test_staged_clean_index_passes(self, repo: Path) -> None:
        # Nothing staged → empty change set → gate passes.
        (repo / "unstaged.py").write_text(_SECRET_LINE)
        result = runner.invoke(app, ["gate", "--path", str(repo), "--staged", "--fail-on", "high"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# #153 — --patch (scan a unified diff standalone)
# ---------------------------------------------------------------------------
_PATCH_NEW_FILE = (
    '--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,2 @@\n+import os\n+key = "AKIAIOSFODNN7EXAMPLE"\n'
)


class TestPatchMode:
    def test_patch_from_stdin_finds_added_secret(self) -> None:
        result = runner.invoke(app, ["scan", "--patch", "-", "--json"], input=_PATCH_NEW_FILE)
        assert result.exit_code == 0
        findings = _findings(result.stdout)
        assert {f["path"] for f in findings} == {"new.py"}
        # The secret is on the added line; line number maps back to the new side.
        assert any(f["line"] == 2 for f in findings)

    def test_patch_from_file(self, tmp_path: Path) -> None:
        patch = tmp_path / "change.diff"
        patch.write_text(_PATCH_NEW_FILE)
        result = runner.invoke(app, ["gate", "--patch", str(patch), "--fail-on", "high"])
        assert result.exit_code == 1

    def test_patch_only_reports_added_lines(self) -> None:
        # The secret is a context line (unchanged), so it must NOT be reported;
        # only the genuinely added line counts.
        patch = (
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1,2 +1,3 @@\n"
            ' key = "AKIAIOSFODNN7EXAMPLE"\n'
            " x = 1\n"
            "+y = 2\n"
        )
        result = runner.invoke(app, ["scan", "--patch", "-", "--json"], input=patch)
        assert result.exit_code == 0
        assert _findings(result.stdout) == []

    def test_patch_clean_diff_passes(self) -> None:
        patch = "--- a/clean.py\n+++ b/clean.py\n@@ -1 +1,2 @@\n print('ok')\n+x = 1\n"
        result = runner.invoke(app, ["gate", "--patch", "-", "--fail-on", "high"], input=patch)
        assert result.exit_code == 0

    def test_missing_patch_file_fails_closed(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["scan", "--patch", str(tmp_path / "nope.diff")])
        assert result.exit_code == 2

    def test_patch_scan_path_does_not_leak_temp_dir(self) -> None:
        result = runner.invoke(app, ["scan", "--patch", "-", "--json"], input=_PATCH_NEW_FILE)
        assert result.exit_code == 0
        assert json.loads(result.stdout)["scan_path"] == "<patch>"

    def test_multi_file_patch_not_corrupted_by_metadata(self) -> None:
        # A realistic git diff carries per-file `diff --git`/`index` metadata
        # between files; it must not be injected into the previous file's
        # reconstructed content (only added/context lines count).
        patch = (
            "diff --git a/f1.py b/f1.py\n"
            "index 1111111..2222222 100644\n"
            "--- a/f1.py\n"
            "+++ b/f1.py\n"
            "@@ -1 +1,2 @@\n"
            " x = 1\n"
            "+y = 2\n"
            "diff --git a/f2.py b/f2.py\n"
            "index 3333333..4444444 100644\n"
            "--- a/f2.py\n"
            "+++ b/f2.py\n"
            "@@ -1 +1,2 @@\n"
            " a = 1\n"
            '+key = "AKIAIOSFODNN7EXAMPLE"\n'
        )
        files = reconstruct_patch_files(patch)
        assert files == {
            "f1.py": "x = 1\ny = 2\n",
            "f2.py": 'a = 1\nkey = "AKIAIOSFODNN7EXAMPLE"\n',
        }
        # And end-to-end the secret on f2 is still found, on its real line.
        result = runner.invoke(app, ["scan", "--patch", "-", "--json"], input=patch)
        assert result.exit_code == 0
        assert _paths(result.stdout) == {"f2.py"}


class TestReconstructPatchFiles:
    def test_reconstructs_new_side_with_line_numbers(self) -> None:
        files = reconstruct_patch_files(_PATCH_NEW_FILE)
        assert set(files) == {"new.py"}
        assert files["new.py"] == 'import os\nkey = "AKIAIOSFODNN7EXAMPLE"\n'

    def test_deletion_target_omitted(self) -> None:
        patch = "--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x = 1\n"
        assert reconstruct_patch_files(patch) == {}

    def test_hunk_offset_pads_leading_blank_lines(self) -> None:
        patch = "--- a/m.py\n+++ b/m.py\n@@ -3,0 +3,1 @@\n+added = 1\n"
        files = reconstruct_patch_files(patch)
        # Line 3 is the added line; lines 1-2 are blank padding so numbers align.
        assert files["m.py"] == "\n\nadded = 1\n"

    def test_trailing_metadata_not_injected(self) -> None:
        # `diff --git`/`index` lines after a file's last hunk must be dropped,
        # not appended to the file's reconstructed content.
        patch = (
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "@@ -1 +1,2 @@\n"
            " x = 1\n"
            "+y = 2\n"
            "diff --git a/g.py b/g.py\n"
            "index aaa..bbb 100644\n"
        )
        assert reconstruct_patch_files(patch) == {"f.py": "x = 1\ny = 2\n"}


# ---------------------------------------------------------------------------
# Mode exclusivity / validation
# ---------------------------------------------------------------------------
class TestScopeModeValidation:
    def test_diff_and_staged_mutually_exclusive(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--diff", "--staged"])
        assert result.exit_code == 2
        assert "mutually exclusive" in result.stdout + (result.stderr or "")

    def test_patch_with_positional_paths_rejected(self) -> None:
        result = runner.invoke(app, ["scan", "foo.py", "--patch", "-"], input="")
        assert result.exit_code == 2

    def test_diff_with_multiple_paths_rejected(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        result = runner.invoke(app, ["gate", str(tmp_path / "a"), str(tmp_path / "b"), "--diff"])
        assert result.exit_code == 2
        assert "single repository" in result.stdout + (result.stderr or "")
