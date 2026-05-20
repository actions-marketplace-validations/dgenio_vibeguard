"""Tests for SARIF reporter."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from vibeguard.cli import app
from vibeguard.models import Confidence, Finding, ScanResult, Severity
from vibeguard.reporters.sarif import render_sarif

runner = CliRunner()


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


class TestSarifReporter:
    def test_valid_json(self):
        result = _make_result()
        sarif_str = render_sarif(result)
        data = json.loads(sarif_str)
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_contains_runs(self):
        result = _make_result()
        data = json.loads(render_sarif(result))
        assert len(data["runs"]) == 1
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "VibeGuard"

    def test_results_have_rule_id(self):
        result = _make_result()
        data = json.loads(render_sarif(result))
        results = data["runs"][0]["results"]
        assert len(results) == 2
        assert results[0]["ruleId"] == "SEC-AWSACCESSKEY"
        assert results[1]["ruleId"] == "TEST-MISSING"

    def test_severity_mapping(self):
        result = _make_result()
        data = json.loads(render_sarif(result))
        results = data["runs"][0]["results"]
        # Critical → error
        assert results[0]["level"] == "error"
        # Low → note
        assert results[1]["level"] == "note"

    def test_physical_location(self):
        result = _make_result()
        data = json.loads(render_sarif(result))
        results = data["runs"][0]["results"]
        loc = results[0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/config.py"
        assert loc["region"]["startLine"] == 10
        # endLine makes the single-line span explicit for SARIF consumers.
        assert loc["region"]["endLine"] == 10

    def test_no_region_for_null_line(self):
        result = _make_result()
        data = json.loads(render_sarif(result))
        results = data["runs"][0]["results"]
        loc = results[1]["locations"][0]["physicalLocation"]
        assert "region" not in loc

    def test_results_have_partial_fingerprints(self):
        """partialFingerprints lets GitHub Code Scanning dedupe findings across runs."""
        result = _make_result()
        data = json.loads(render_sarif(result))
        results = data["runs"][0]["results"]
        for r in results:
            assert "partialFingerprints" in r
            fps = r["partialFingerprints"]
            assert "vibeguard/v1" in fps
            assert isinstance(fps["vibeguard/v1"], str)
            assert len(fps["vibeguard/v1"]) >= 16

    def test_partial_fingerprints_stable_across_line_moves(self):
        """The fingerprint must be the same for the same logical finding even if line moves."""
        from vibeguard.reporters.sarif import render_sarif as render

        f1 = Finding(
            id="SEC-ENV",
            rule="secrets",
            title="env",
            description="d",
            severity=Severity.HIGH,
            path="a.env",
            line=10,
            evidence="X",
            recommendation="r",
        )
        f2 = Finding(
            id="SEC-ENV",
            rule="secrets",
            title="env",
            description="d",
            severity=Severity.HIGH,
            path="a.env",
            line=99,
            evidence="X",
            recommendation="r",
        )
        d1 = json.loads(render(ScanResult(findings=[f1], scanned_files=1)))
        d2 = json.loads(render(ScanResult(findings=[f2], scanned_files=1)))
        fp1 = d1["runs"][0]["results"][0]["partialFingerprints"]["vibeguard/v1"]
        fp2 = d2["runs"][0]["results"][0]["partialFingerprints"]["vibeguard/v1"]
        assert fp1 == fp2

    def test_rules_deduplicated(self):
        result = ScanResult(
            findings=[
                Finding(
                    id="SEC-ENV",
                    rule="secrets",
                    title="Sensitive file",
                    description="Env file committed.",
                    severity=Severity.CRITICAL,
                    path=".env",
                    recommendation="Remove it.",
                ),
                Finding(
                    id="SEC-ENV",
                    rule="secrets",
                    title="Sensitive file",
                    description="Env file committed.",
                    severity=Severity.CRITICAL,
                    path="backup/.env",
                    recommendation="Remove it.",
                ),
            ],
            scanned_files=2,
        )
        data = json.loads(render_sarif(result))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "SEC-ENV"


class TestSarifCLI:
    def test_scan_sarif_flag(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--sarif"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["version"] == "2.1.0"

    def test_gate_sarif_flag(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(
            app, ["gate", "--path", str(tmp_path), "--sarif", "--fail-on", "high"]
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "runs" in data

    def test_sarif_mutually_exclusive_with_json(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--sarif", "--json"])
        assert result.exit_code == 2
