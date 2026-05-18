"""Tests for missing tests rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.tests import MissingTestsRule


def _make_ctx(
    tmp_path: Path,
    source_files: list[str],
    test_files: list[str],
    policy: str = "balanced",
) -> ScanContext:
    all_names = source_files + test_files
    for name in all_names:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# content\n")

    changed = [tmp_path / n for n in all_names]
    cfg = VibeGuardConfig(policy=policy)
    return ScanContext(
        root=tmp_path,
        config=cfg,
        files=changed,
        changed_files=changed,
        diff_only=True,
    )


class TestMissingTestsRule:
    rule = MissingTestsRule()

    def test_source_changed_no_tests_emits_finding(self, tmp_path: Path):
        ctx = _make_ctx(tmp_path, ["src/auth.py"], [])
        findings = self.rule.scan(ctx)
        assert any(f.id == "TEST-MISSING" for f in findings)

    def test_source_and_tests_changed_no_finding(self, tmp_path: Path):
        ctx = _make_ctx(tmp_path, ["src/auth.py"], ["tests/test_auth.py"])
        findings = self.rule.scan(ctx)
        assert not any(f.id == "TEST-MISSING" for f in findings)

    def test_only_tests_changed_no_finding(self, tmp_path: Path):
        ctx = _make_ctx(tmp_path, [], ["tests/test_auth.py"])
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_strict_policy_gives_medium_severity(self, tmp_path: Path):
        ctx = _make_ctx(tmp_path, ["src/auth.py"], [], policy="strict")
        findings = self.rule.scan(ctx)
        missing = [f for f in findings if f.id == "TEST-MISSING"]
        assert missing
        assert missing[0].severity == Severity.MEDIUM

    def test_balanced_policy_gives_low_severity(self, tmp_path: Path):
        ctx = _make_ctx(tmp_path, ["src/auth.py"], [], policy="balanced")
        findings = self.rule.scan(ctx)
        missing = [f for f in findings if f.id == "TEST-MISSING"]
        assert missing
        assert missing[0].severity == Severity.LOW

    def test_test_prefix_file_recognized(self, tmp_path: Path):
        ctx = _make_ctx(tmp_path, ["src/auth.py"], ["test_auth.py"])
        findings = self.rule.scan(ctx)
        assert not any(f.id == "TEST-MISSING" for f in findings)

    def test_spec_file_recognized(self, tmp_path: Path):
        ctx = _make_ctx(tmp_path, ["src/auth.js"], ["src/auth.spec.ts"])
        findings = self.rule.scan(ctx)
        assert not any(f.id == "TEST-MISSING" for f in findings)

    def test_no_changed_files_no_finding(self, tmp_path: Path):
        cfg = VibeGuardConfig()
        ctx = ScanContext(root=tmp_path, config=cfg, files=[], changed_files=[])
        findings = self.rule.scan(ctx)
        assert len(findings) == 0
