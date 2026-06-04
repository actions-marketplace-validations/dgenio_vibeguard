"""Tests for the weaver-spec ArtifactSafetyReport reporter (--weaver)."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from typer.testing import CliRunner

from vibeguard.cli import app
from vibeguard.models import Confidence, Finding, ScanResult, Severity
from vibeguard.reporters.weaver import REPORT_SCHEMA_ID, build_report, render_weaver

runner = CliRunner()

REPO_ROOT = Path(__file__).resolve().parent.parent
_REPORT_SCHEMA_PATH = REPO_ROOT / "docs" / "weaver" / "artifact_safety_report.schema.json"

# A fixed timestamp so the timestamped (otherwise non-deterministic) export
# can be asserted exactly.
_FIXED_TS = "2026-06-04T00:00:00+00:00"


def _make_result() -> ScanResult:
    return ScanResult(
        findings=[
            Finding(
                id="SEC-AWSACCESSKEY",
                rule="secrets",
                title="AWS Access Key detected",
                description="An AWS access key was found in source code.",
                severity=Severity.CRITICAL,
                path="src/config.py",
                line=10,
                evidence="AKIAIOSFODNN7EXAMPLE",
                recommendation="Remove and rotate the key.",
                tags=["secrets"],
                confidence=Confidence.HIGH,
            ),
            Finding(
                id="TEST-MISSING",
                rule="tests",
                title="Source changes without tests",
                description="Modified source files have no corresponding test changes.",
                severity=Severity.LOW,
                path="src/app.py",
                line=None,
                recommendation="Add tests for changed code.",
                tags=["tests"],
                confidence=Confidence.MEDIUM,
            ),
        ],
        scanned_files=5,
        policy="balanced",
    )


def _report(blocking: bool = False, threshold: Severity = Severity.HIGH) -> dict:
    return build_report(
        _make_result(), threshold=threshold, blocking=blocking, created_at=_FIXED_TS
    )


class TestWeaverReport:
    def test_valid_json(self):
        data = json.loads(render_weaver(_make_result(), threshold=Severity.HIGH, blocking=False))
        assert data["gate_id"] == "vibeguard"
        assert data["schema"] == REPORT_SCHEMA_ID

    def test_required_top_level_fields_present(self):
        report = _report()
        for field in ("report_id", "gate_id", "decision", "created_at"):
            assert report[field], f"missing required field {field}"

    def test_mode_reflects_blocking(self):
        assert _report(blocking=False)["mode"] == "advisory"
        assert _report(blocking=True)["mode"] == "blocking"

    def test_decision_fail_when_blocking_finding_present(self):
        # CRITICAL >= HIGH threshold -> fail.
        assert _report(threshold=Severity.HIGH)["decision"] == "fail"

    def test_decision_pass_when_no_blocking_finding(self):
        # Threshold above the highest finding -> pass. (CRITICAL is the max, so
        # use a result whose top severity is LOW.)
        result = ScanResult(
            findings=[
                Finding(
                    id="TEST-MISSING",
                    rule="tests",
                    title="t",
                    description="d",
                    severity=Severity.LOW,
                    path="a.py",
                    recommendation="r",
                )
            ],
            scanned_files=1,
        )
        report = build_report(result, threshold=Severity.HIGH, blocking=True, created_at=_FIXED_TS)
        assert report["decision"] == "pass"

    def test_findings_mapped_one_to_one(self):
        report = _report()
        assert len(report["findings"]) == 2
        first = report["findings"][0]
        assert first["finding_id"] == "SEC-AWSACCESSKEY"
        assert first["severity"] == "critical"
        assert first["message"].startswith("AWS Access Key detected: ")
        assert first["remediation"] == "Remove and rotate the key."
        assert first["rule"] == "secrets"

    def test_finding_fingerprint_matches_model(self):
        result = _make_result()
        report = build_report(result, threshold=Severity.HIGH, blocking=False, created_at=_FIXED_TS)
        assert report["findings"][0]["fingerprint"] == result.findings[0].fingerprint

    def test_created_at_is_injectable(self):
        assert _report()["created_at"] == _FIXED_TS

    def test_report_id_stable_across_runs_for_same_findings(self):
        a = build_report(_make_result(), threshold=Severity.HIGH, blocking=False, created_at="x")
        b = build_report(_make_result(), threshold=Severity.HIGH, blocking=False, created_at="y")
        # Identical findings -> identical report_id even though timestamps differ.
        assert a["report_id"] == b["report_id"]

    def test_report_id_independent_of_scan_path(self):
        # report_id is content-addressed: identical findings under different
        # scan paths (different machines/checkouts) must yield the same id.
        # Regression guard for the fix that dropped scan_path from the digest —
        # the stable-across-runs test above holds scan_path constant, so it
        # cannot catch scan_path leaking back into the hash.
        findings = _make_result().findings
        a = build_report(
            ScanResult(findings=findings, scanned_files=5, scan_path="/abs/one"),
            threshold=Severity.HIGH,
            blocking=False,
            created_at=_FIXED_TS,
        )
        b = build_report(
            ScanResult(findings=findings, scanned_files=5, scan_path="/abs/two"),
            threshold=Severity.HIGH,
            blocking=False,
            created_at=_FIXED_TS,
        )
        assert a["report_id"] == b["report_id"]

    def test_provenance_names_vibeguard(self):
        prov = _report()["provenance"]
        assert prov["tool"] == "VibeGuard"
        assert "version" in prov

    def test_empty_result_is_pass_with_no_findings(self):
        report = build_report(
            ScanResult(scanned_files=1),
            threshold=Severity.HIGH,
            blocking=True,
            created_at=_FIXED_TS,
        )
        assert report["decision"] == "pass"
        assert report["findings"] == []


class TestWeaverSchemaConformance:
    """Validate the export against the vendored upstream weaver-spec schema."""

    def test_report_validates_against_vendored_schema(self):
        schema = json.loads(_REPORT_SCHEMA_PATH.read_text())
        jsonschema.validate(instance=_report(), schema=schema)

    def test_empty_report_validates(self):
        schema = json.loads(_REPORT_SCHEMA_PATH.read_text())
        report = build_report(
            ScanResult(scanned_files=1),
            threshold=Severity.HIGH,
            blocking=False,
            created_at=_FIXED_TS,
        )
        jsonschema.validate(instance=report, schema=schema)

    def test_created_at_omitted_would_fail_schema(self):
        """created_at is a required field — proves the timestamp is load-bearing."""
        schema = json.loads(_REPORT_SCHEMA_PATH.read_text())
        report = _report()
        del report["created_at"]
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(instance=report, schema=schema)


class TestWeaverCLI:
    def test_scan_weaver_flag_is_advisory(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--weaver"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["mode"] == "advisory"
        assert data["gate_id"] == "vibeguard"

    def test_gate_weaver_flag_is_blocking(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(
            app, ["gate", "--path", str(tmp_path), "--weaver", "--fail-on", "high"]
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["mode"] == "blocking"

    def test_weaver_mutually_exclusive_with_json(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--weaver", "--json"])
        assert result.exit_code == 2

    def test_scan_weaver_output_validates_against_schema(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--weaver"])
        schema = json.loads(_REPORT_SCHEMA_PATH.read_text())
        jsonschema.validate(instance=json.loads(result.stdout), schema=schema)


class TestNativeOutputsUnchanged:
    """The weaver export is additive: native JSON/SARIF must be byte-for-byte
    what they were before --weaver existed (the reporter has no shared state)."""

    def test_json_output_has_no_weaver_keys(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--json"])
        data = json.loads(result.stdout)
        assert "gate_id" not in data
        assert "findings" in data  # native shape preserved

    def test_sarif_output_unchanged(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--sarif"])
        data = json.loads(result.stdout)
        assert data["version"] == "2.1.0"
        assert "gate_id" not in data
