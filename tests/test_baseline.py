"""Tests for baseline file support."""

from __future__ import annotations

from pathlib import Path

import pytest

from vibeguard.baseline import (
    Baseline,
    BaselineLoadError,
    compute_fingerprint,
    create_baseline,
    filter_baselined,
)
from vibeguard.config import VibeGuardConfig
from vibeguard.models import Confidence, Finding, Severity
from vibeguard.scanner import run_scan


def _make_finding(
    finding_id: str = "SEC-ENV",
    path: str = "src/config.py",
    line: int | None = 5,
    evidence: str | None = "SECRET_KEY=abc123",
) -> Finding:
    return Finding(
        id=finding_id,
        rule="secrets",
        title="Test finding",
        description="Test description.",
        severity=Severity.HIGH,
        path=path,
        line=line,
        evidence=evidence,
        recommendation="Fix it.",
        tags=["test"],
        confidence=Confidence.HIGH,
    )


class TestFingerprint:
    def test_same_finding_same_fingerprint(self):
        f1 = _make_finding()
        f2 = _make_finding()
        assert compute_fingerprint(f1) == compute_fingerprint(f2)

    def test_different_line_same_fingerprint(self):
        """Line numbers are NOT part of the fingerprint — code moves."""
        f1 = _make_finding(line=5)
        f2 = _make_finding(line=100)
        assert compute_fingerprint(f1) == compute_fingerprint(f2)

    def test_different_path_different_fingerprint(self):
        f1 = _make_finding(path="src/a.py")
        f2 = _make_finding(path="src/b.py")
        assert compute_fingerprint(f1) != compute_fingerprint(f2)

    def test_different_evidence_different_fingerprint(self):
        f1 = _make_finding(evidence="key1")
        f2 = _make_finding(evidence="key2")
        assert compute_fingerprint(f1) != compute_fingerprint(f2)

    def test_no_evidence_stable(self):
        f1 = _make_finding(evidence=None)
        f2 = _make_finding(evidence=None)
        assert compute_fingerprint(f1) == compute_fingerprint(f2)


class TestBaseline:
    def test_create_baseline(self):
        findings = [_make_finding(), _make_finding(path="other.py")]
        baseline = create_baseline(findings)
        assert len(baseline.entries) == 2

    def test_filter_baselined(self):
        findings = [_make_finding(), _make_finding(path="other.py")]
        baseline = create_baseline(findings)
        # All findings should be filtered
        filtered = filter_baselined(findings, baseline)
        assert len(filtered) == 0

    def test_new_finding_not_filtered(self):
        old_findings = [_make_finding()]
        baseline = create_baseline(old_findings)
        # New finding with different path
        new_finding = _make_finding(path="new/file.py")
        filtered = filter_baselined([new_finding], baseline)
        assert len(filtered) == 1
        assert filtered[0].path == "new/file.py"

    def test_save_and_load(self, tmp_path: Path):
        findings = [_make_finding(), _make_finding(path="other.py")]
        baseline = create_baseline(findings)

        baseline_file = tmp_path / ".vibeguard-baseline.json"
        baseline.save(baseline_file)

        loaded = Baseline.load(baseline_file)
        assert len(loaded.entries) == 2
        assert loaded.entries == baseline.entries

    def test_load_nonexistent(self, tmp_path: Path):
        baseline = Baseline.load(tmp_path / "does_not_exist.json")
        assert len(baseline.entries) == 0

    def test_load_malformed_json_raises(self, tmp_path: Path):
        """A corrupted baseline file must surface a clear error, not a raw traceback."""
        bad = tmp_path / "bad-baseline.json"
        bad.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(BaselineLoadError, match="not valid JSON"):
            Baseline.load(bad)

    def test_load_wrong_schema_raises(self, tmp_path: Path):
        """JSON that parses but doesn't match the schema must also raise BaselineLoadError."""
        bad = tmp_path / "wrong-schema.json"
        bad.write_text('{"entries": "should-be-a-mapping-not-a-string"}', encoding="utf-8")
        with pytest.raises(BaselineLoadError, match="schema"):
            Baseline.load(bad)


class TestBaselineIntegration:
    def test_baseline_suppresses_known_findings(self, tmp_path: Path):
        # Create a file with a real finding
        (tmp_path / "secret.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')

        config = VibeGuardConfig()
        result = run_scan(tmp_path, config)
        assert len(result.findings) > 0

        # Create baseline from those findings
        baseline = create_baseline(result.findings)

        # Filter — all should be suppressed
        filtered = filter_baselined(result.findings, baseline)
        assert len(filtered) == 0

    def test_baseline_allows_new_findings(self, tmp_path: Path):
        # Create baseline from empty scan
        (tmp_path / "clean.py").write_text("x = 1\n")
        config = VibeGuardConfig()
        result = run_scan(tmp_path, config)
        baseline = create_baseline(result.findings)

        # Now add a finding
        (tmp_path / "secret.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        result2 = run_scan(tmp_path, config)

        filtered = filter_baselined(result2.findings, baseline)
        # New findings should remain
        assert any(f.id == "SEC-AWSACCESSKEY" for f in filtered)
