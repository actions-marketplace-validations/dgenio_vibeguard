"""Tests for the SonarQube Generic Issue Import reporter (#244)."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from vibeguard.cli import app
from vibeguard.models import Confidence, Finding, ScanResult, Severity
from vibeguard.reporters.sonar import render_sonar

runner = CliRunner()


def _finding(fid: str, severity: Severity, tags: list[str], *, line: int | None = 12) -> Finding:
    return Finding(
        id=fid,
        rule="secrets",
        title=f"{fid} title",
        description="something",
        severity=severity,
        path="src/config.py",
        line=line,
        recommendation="fix",
        tags=tags,
        confidence=Confidence.HIGH,
    )


class TestSonarReporter:
    def test_top_level_issues_array(self) -> None:
        result = ScanResult(findings=[_finding("SEC-ENV", Severity.HIGH, ["secrets"])])
        data = json.loads(render_sonar(result))
        assert list(data.keys()) == ["issues"]
        assert len(data["issues"]) == 1

    def test_issue_shape(self) -> None:
        result = ScanResult(findings=[_finding("SEC-ENV", Severity.HIGH, ["secrets"])])
        issue = json.loads(render_sonar(result))["issues"][0]
        assert issue["engineId"] == "vibeguard"
        assert issue["ruleId"] == "SEC-ENV"
        assert issue["primaryLocation"]["filePath"] == "src/config.py"
        assert issue["primaryLocation"]["textRange"]["startLine"] == 12

    def test_severity_mapping(self) -> None:
        cases = {
            Severity.INFO: "INFO",
            Severity.LOW: "MINOR",
            Severity.MEDIUM: "MAJOR",
            Severity.HIGH: "CRITICAL",
            Severity.CRITICAL: "BLOCKER",
        }
        for sev, expected in cases.items():
            result = ScanResult(findings=[_finding("X", sev, ["secrets"])])
            assert json.loads(render_sonar(result))["issues"][0]["severity"] == expected

    def test_type_vulnerability_vs_code_smell(self) -> None:
        vuln = ScanResult(findings=[_finding("X", Severity.HIGH, ["secrets"])])
        smell = ScanResult(findings=[_finding("Y", Severity.LOW, ["tests", "coverage"])])
        assert json.loads(render_sonar(vuln))["issues"][0]["type"] == "VULNERABILITY"
        assert json.loads(render_sonar(smell))["issues"][0]["type"] == "CODE_SMELL"

    def test_no_textrange_when_line_missing(self) -> None:
        result = ScanResult(findings=[_finding("X", Severity.HIGH, ["secrets"], line=None)])
        issue = json.loads(render_sonar(result))["issues"][0]
        assert "textRange" not in issue["primaryLocation"]


class TestSonarCLI:
    def test_scan_sonar_flag(self, tmp_path) -> None:
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--sonar"])
        assert result.exit_code == 0
        assert "issues" in json.loads(result.stdout)
