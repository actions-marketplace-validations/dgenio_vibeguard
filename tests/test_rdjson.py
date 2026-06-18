"""Tests for the reviewdog rdjson reporter (#237)."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from vibeguard.cli import app
from vibeguard.models import Confidence, Finding, ScanResult, Severity
from vibeguard.reporters.rdjson import render_rdjson

runner = CliRunner()


def _result(severity: Severity, *, line: int | None = 7) -> ScanResult:
    return ScanResult(
        findings=[
            Finding(
                id="AI-TRUSTALLCERTS",
                rule="auth",
                title="Trust-all certificates",
                description="TLS verification disabled.",
                severity=severity,
                path="src/client.py",
                line=line,
                recommendation="Re-enable verification.",
                tags=["security", "auth"],
                confidence=Confidence.HIGH,
            )
        ],
        scanned_files=1,
    )


class TestRdjsonReporter:
    def test_valid_json_with_source(self) -> None:
        data = json.loads(render_rdjson(_result(Severity.HIGH)))
        assert data["source"]["name"] == "vibeguard"
        assert data["source"]["url"].endswith("/vibeguard")

    def test_diagnostic_shape(self) -> None:
        data = json.loads(render_rdjson(_result(Severity.HIGH)))
        diag = data["diagnostics"][0]
        assert diag["location"]["path"] == "src/client.py"
        assert diag["location"]["range"]["start"] == {"line": 7, "column": 1}
        assert diag["code"]["value"] == "AI-TRUSTALLCERTS"
        assert diag["code"]["url"].endswith("docs/rules.md#auth")

    def test_severity_mapping(self) -> None:
        # INFO/LOW -> INFO, MEDIUM -> WARNING, HIGH/CRITICAL -> ERROR.
        cases = {
            Severity.INFO: "INFO",
            Severity.LOW: "INFO",
            Severity.MEDIUM: "WARNING",
            Severity.HIGH: "ERROR",
            Severity.CRITICAL: "ERROR",
        }
        for sev, expected in cases.items():
            data = json.loads(render_rdjson(_result(sev)))
            assert data["diagnostics"][0]["severity"] == expected

    def test_missing_line_defaults_to_one(self) -> None:
        data = json.loads(render_rdjson(_result(Severity.HIGH, line=None)))
        assert data["diagnostics"][0]["location"]["range"]["start"]["line"] == 1

    def test_empty_result_is_valid(self) -> None:
        data = json.loads(render_rdjson(ScanResult(findings=[], scanned_files=1)))
        assert data["diagnostics"] == []


class TestRdjsonCLI:
    def test_scan_rdjson_flag(self, tmp_path) -> None:
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--rdjson"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "diagnostics" in data

    def test_rdjson_mutually_exclusive_with_sarif(self, tmp_path) -> None:
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--rdjson", "--sarif"])
        assert result.exit_code == 2
