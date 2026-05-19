"""Tests for diff scope checks (DIFF-BREADTH, DIFF-SIZE, DIFF-RISK-FILES)."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import GitMetadata, ScanContext
from vibeguard.rules.risky_diff import RiskyDiffRule


def _diff_ctx(tmp_path: Path, changed_files: list[str]) -> ScanContext:
    """Create a diff-mode context with given changed file paths."""
    for name in changed_files:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# placeholder\n")
    all_files = [tmp_path / n for n in changed_files]
    return ScanContext(
        root=tmp_path,
        config=VibeGuardConfig(),
        files=all_files,
        changed_files=all_files,
        diff_only=True,
        git=GitMetadata(is_available=True, changed_files=changed_files),
    )


class TestDiffScope:
    rule = RiskyDiffRule()

    def test_diff_size_fires_above_threshold(self, tmp_path: Path):
        # Default threshold is 30 files
        files = [f"src/file{i}.py" for i in range(35)]
        ctx = _diff_ctx(tmp_path, files)
        findings = self.rule.scan(ctx)
        assert any(f.id == "DIFF-SIZE" for f in findings)

    def test_diff_size_not_fires_below_threshold(self, tmp_path: Path):
        files = [f"src/file{i}.py" for i in range(5)]
        ctx = _diff_ctx(tmp_path, files)
        findings = self.rule.scan(ctx)
        assert not any(f.id == "DIFF-SIZE" for f in findings)

    def test_diff_breadth_fires_above_threshold(self, tmp_path: Path):
        # Default threshold is 5 top-level directories
        files = [
            "src/a.py",
            "lib/b.py",
            "api/c.py",
            "cli/d.py",
            "tests/e.py",
            "docs/f.py",
        ]
        ctx = _diff_ctx(tmp_path, files)
        findings = self.rule.scan(ctx)
        assert any(f.id == "DIFF-BREADTH" for f in findings)

    def test_diff_breadth_not_fires_below_threshold(self, tmp_path: Path):
        files = ["src/a.py", "src/b.py", "tests/c.py"]
        ctx = _diff_ctx(tmp_path, files)
        findings = self.rule.scan(ctx)
        assert not any(f.id == "DIFF-BREADTH" for f in findings)

    def test_diff_risk_files_fires_on_dockerfile(self, tmp_path: Path):
        files = ["src/main.py", "Dockerfile"]
        ctx = _diff_ctx(tmp_path, files)
        findings = self.rule.scan(ctx)
        assert any(f.id == "DIFF-RISK-FILES" for f in findings)

    def test_diff_risk_files_fires_on_auth(self, tmp_path: Path):
        files = ["src/auth_handler.py", "src/main.py"]
        ctx = _diff_ctx(tmp_path, files)
        findings = self.rule.scan(ctx)
        assert any(f.id == "DIFF-RISK-FILES" for f in findings)

    def test_no_diff_scope_in_non_diff_mode(self, tmp_path: Path):
        files = [f"dir{i}/file.py" for i in range(10)]
        for name in files:
            p = tmp_path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("# placeholder\n")
        all_files = [tmp_path / n for n in files]
        ctx = ScanContext(
            root=tmp_path,
            config=VibeGuardConfig(),
            files=all_files,
            diff_only=False,
        )
        findings = self.rule.scan(ctx)
        assert not any(f.id in ("DIFF-SIZE", "DIFF-BREADTH", "DIFF-RISK-FILES") for f in findings)
