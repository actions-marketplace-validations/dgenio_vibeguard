"""Tests for the diagnostics reporter (issue #51)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vibeguard.cli import app
from vibeguard.models import Confidence, Finding, ScanResult, Severity
from vibeguard.reporters.diagnostics import (
    DIAGNOSTICS_SCHEMA,
    SEVERITY_TO_CODE,
    render_diagnostics,
)

runner = CliRunner()


def _result() -> ScanResult:
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
                tags=["secrets", "supply-chain"],
                confidence=Confidence.HIGH,
            ),
            Finding(
                id="RISK-EVALEXEC",
                rule="risky_diff",
                title="eval() with variable input",
                description="Dynamic code execution detected.",
                severity=Severity.MEDIUM,
                path="src/app.py",
                line=42,
                evidence="eval(user_input)",
                recommendation="Remove eval().",
                tags=["risky"],
                confidence=Confidence.MEDIUM,
            ),
            Finding(
                id="TEST-MISSING",
                rule="tests",
                title="Source changes without tests",
                description="No matching test changes.",
                severity=Severity.INFO,
                path="src/lib.py",
                line=None,
                evidence=None,
                recommendation="Add tests.",
                tags=[],
                confidence=Confidence.LOW,
            ),
        ],
        scanned_files=3,
        policy="balanced",
    )


class TestDiagnosticsShape:
    def test_renders_top_level_json_array(self):
        out = render_diagnostics(_result())
        parsed = json.loads(out)
        assert isinstance(parsed, list)
        assert len(parsed) == 3

    def test_each_record_has_required_keys(self):
        parsed = json.loads(render_diagnostics(_result()))
        required = {"severity", "code", "source", "message", "file", "range", "tags", "data"}
        for record in parsed:
            assert required.issubset(record.keys()), f"missing keys: {required - record.keys()}"
            assert record["source"] == "vibeguard"

    def test_range_uses_zero_based_lsp_offsets(self):
        parsed = json.loads(render_diagnostics(_result()))
        first = next(r for r in parsed if r["code"] == "SEC-AWSACCESSKEY")
        # line=10 (1-based) → 9 (0-based)
        assert first["range"]["start"] == {"line": 9, "character": 0}
        assert first["range"]["end"] == {"line": 9, "character": 0}

    def test_missing_line_falls_back_to_line_one(self):
        parsed = json.loads(render_diagnostics(_result()))
        no_line = next(r for r in parsed if r["code"] == "TEST-MISSING")
        # line=None → 0 (LSP 0-based for "line 1")
        assert no_line["range"]["start"]["line"] == 0


class TestDiagnosticsSeverityMapping:
    def test_critical_and_high_map_to_error(self):
        assert SEVERITY_TO_CODE[Severity.CRITICAL] == 0
        assert SEVERITY_TO_CODE[Severity.HIGH] == 0

    def test_medium_maps_to_warning(self):
        assert SEVERITY_TO_CODE[Severity.MEDIUM] == 1

    def test_low_maps_to_information(self):
        assert SEVERITY_TO_CODE[Severity.LOW] == 2

    def test_info_maps_to_hint(self):
        assert SEVERITY_TO_CODE[Severity.INFO] == 3

    def test_renderer_applies_mapping(self):
        parsed = json.loads(render_diagnostics(_result()))
        sev_by_code = {r["code"]: r["severity"] for r in parsed}
        assert sev_by_code["SEC-AWSACCESSKEY"] == 0  # critical → Error
        assert sev_by_code["RISK-EVALEXEC"] == 1  # medium → Warning
        assert sev_by_code["TEST-MISSING"] == 3  # info → Hint


class TestDiagnosticsData:
    def test_data_includes_schema_version(self):
        parsed = json.loads(render_diagnostics(_result()))
        for record in parsed:
            assert record["data"]["schema"] == DIAGNOSTICS_SCHEMA

    def test_data_includes_fingerprint_matching_finding(self):
        result = _result()
        parsed = json.loads(render_diagnostics(result))
        by_code = {r["code"]: r for r in parsed}
        for finding in result.findings:
            assert by_code[finding.id]["data"]["fingerprint"] == finding.fingerprint

    def test_data_includes_rule_and_confidence(self):
        parsed = json.loads(render_diagnostics(_result()))
        first = next(r for r in parsed if r["code"] == "SEC-AWSACCESSKEY")
        assert first["data"]["rule"] == "secrets"
        assert first["data"]["confidence"] == "high"
        assert first["data"]["severity_label"] == "critical"

    def test_evidence_only_when_present(self):
        parsed = json.loads(render_diagnostics(_result()))
        with_ev = next(r for r in parsed if r["code"] == "SEC-AWSACCESSKEY")
        without_ev = next(r for r in parsed if r["code"] == "TEST-MISSING")
        assert with_ev["data"]["evidence"] == "AKIAIOSFODNN7EXAMPLE"
        assert "evidence" not in without_ev["data"]

    def test_top_level_tags_is_empty_lsp_array(self):
        """Top-level ``tags`` follows LSP DiagnosticTag[] semantics — never
        VibeGuard category strings. Category tags live under ``data.tags``."""
        parsed = json.loads(render_diagnostics(_result()))
        for record in parsed:
            assert record["tags"] == [], (
                f"top-level tags must be empty (LSP DiagnosticTag[]); got {record['tags']!r}"
            )

    def test_data_tags_carry_finding_tags(self):
        parsed = json.loads(render_diagnostics(_result()))
        by_code = {r["code"]: r for r in parsed}
        assert by_code["SEC-AWSACCESSKEY"]["data"]["tags"] == ["secrets", "supply-chain"]
        assert by_code["RISK-EVALEXEC"]["data"]["tags"] == ["risky"]
        assert by_code["TEST-MISSING"]["data"]["tags"] == []

    def test_path_separator_normalized(self):
        result = ScanResult(
            findings=[
                Finding(
                    id="X",
                    rule="r",
                    title="t",
                    description="d",
                    severity=Severity.LOW,
                    path="src\\windows\\file.py",
                    line=1,
                    evidence=None,
                    recommendation="r",
                    tags=[],
                    confidence=Confidence.LOW,
                )
            ]
        )
        parsed = json.loads(render_diagnostics(result))
        assert parsed[0]["file"] == "src/windows/file.py"


class TestDiagnosticsEmpty:
    def test_empty_result_is_empty_array(self):
        out = render_diagnostics(ScanResult())
        assert json.loads(out) == []


class TestDiagnosticsCliIntegration:
    def test_scan_diagnostics_flag_emits_array(self, tmp_path: Path):
        (tmp_path / "secret.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--diagnostics"])
        assert result.exit_code == 0
        parsed = json.loads(result.stdout)
        assert isinstance(parsed, list)
        assert len(parsed) >= 1
        # Every record has the required keys
        for record in parsed:
            assert {"severity", "code", "source", "file", "range", "data"}.issubset(record.keys())
            assert record["data"]["schema"] == DIAGNOSTICS_SCHEMA

    def test_diagnostics_mutually_exclusive_with_json(self, tmp_path: Path):
        (tmp_path / "x.py").write_text("print(1)\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--diagnostics", "--json"])
        assert result.exit_code == 2

    def test_diagnostics_mutually_exclusive_with_sarif(self, tmp_path: Path):
        (tmp_path / "x.py").write_text("print(1)\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--diagnostics", "--sarif"])
        assert result.exit_code == 2

    def test_gate_diagnostics_emits_array(self, tmp_path: Path):
        (tmp_path / "secret.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        result = runner.invoke(
            app,
            ["gate", "--path", str(tmp_path), "--fail-on", "high", "--diagnostics"],
        )
        # gate may exit 1 because of the critical finding; the structured
        # output is still on stdout regardless of exit code.
        parsed = json.loads(result.stdout)
        assert isinstance(parsed, list)
        assert any(r["code"] == "SEC-AWSACCESSKEY" for r in parsed)
