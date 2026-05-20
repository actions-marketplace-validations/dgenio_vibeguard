"""Tests for PR-comment Markdown reporter."""

from __future__ import annotations

from typer.testing import CliRunner

from vibeguard.cli import app
from vibeguard.models import Confidence, Finding, ScanResult, Severity
from vibeguard.reporters.markdown import render_pr_comment

runner = CliRunner()


def _make_result(with_findings: bool = True) -> ScanResult:
    findings = []
    if with_findings:
        findings = [
            Finding(
                id="SEC-AWSACCESSKEY",
                rule="secrets",
                title="AWS Access Key detected",
                description="An AWS access key was found.",
                severity=Severity.CRITICAL,
                path="src/config.py",
                line=10,
                recommendation="Remove and rotate.",
                tags=["secrets"],
                confidence=Confidence.HIGH,
            ),
            Finding(
                id="AI-FOOTPRINT",
                rule="ai_footprints",
                title="AI footprint detected",
                description="Placeholder credential found.",
                severity=Severity.MEDIUM,
                path="src/app.py",
                line=5,
                recommendation="Replace with real implementation.",
                tags=["ai"],
                confidence=Confidence.MEDIUM,
            ),
        ]
    return ScanResult(findings=findings, scanned_files=5, policy="balanced")


class TestPrComment:
    def test_header_contains_pass(self):
        result = _make_result(with_findings=False)
        output = render_pr_comment(result, gate_passed=True)
        assert "🟢" in output
        assert "PASS" in output

    def test_header_contains_fail(self):
        result = _make_result()
        output = render_pr_comment(result, gate_passed=False)
        assert "🔴" in output
        assert "FAIL" in output

    def test_summary_table_present(self):
        result = _make_result()
        output = render_pr_comment(result, gate_passed=False)
        assert "| Severity | Count |" in output
        assert "Critical" in output

    def test_blocking_findings_section(self):
        result = _make_result()
        output = render_pr_comment(result, gate_passed=False)
        assert "### Blocking Findings" in output
        assert "SEC-AWSACCESSKEY" in output

    def test_non_blocking_collapsed(self):
        result = _make_result()
        output = render_pr_comment(result, gate_passed=False)
        assert "<details>" in output
        assert "additional findings" in output
        assert "AI-FOOTPRINT" in output

    def test_empty_findings(self):
        result = _make_result(with_findings=False)
        output = render_pr_comment(result, gate_passed=True)
        assert "No findings" in output

    def test_version_in_footer(self):
        from vibeguard import __version__

        result = _make_result()
        output = render_pr_comment(result, gate_passed=True)
        assert __version__ in output

    def test_truncation_cuts_at_line_boundary(self, monkeypatch):
        """When the body exceeds the byte budget, the cut must land at a newline so
        we never ship a half-closed `<details>` element to GitHub."""
        from vibeguard.reporters import markdown as md

        # Tighten the budget to force truncation on a small synthetic result.
        monkeypatch.setattr(md, "_MAX_PR_COMMENT_CHARS", 600)
        findings = [
            Finding(
                id=f"SEC-{i:02d}",
                rule="secrets",
                title=f"finding {i}",
                description="d",
                severity=Severity.CRITICAL,
                path=f"src/f{i}.py",
                line=1,
                recommendation="r",
            )
            for i in range(20)
        ]
        output = render_pr_comment(
            ScanResult(findings=findings, scanned_files=20), gate_passed=False
        )
        assert "Output truncated" in output
        # The truncation must land at a line boundary, so the prefix never ends
        # mid-tag (e.g. `<deta…`) — that's the structural guarantee we care
        # about. Higher-level element balancing is out of scope.
        notice_start = output.index("\n\n---\n⚠")
        prefix = output[:notice_start]
        # Last line of the prefix must be a complete line, not a partial one.
        last_line = prefix.rsplit("\n", 1)[-1]
        # A "complete" markdown/html line is one that doesn't end with `<` or
        # contain an unterminated `<` opener.
        opens = last_line.count("<")
        closes = last_line.count(">")
        assert opens == closes, f"truncated line has unbalanced angle brackets: {last_line!r}"


class TestPrCommentCLI:
    def test_scan_pr_comment_flag(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--pr-comment"])
        assert result.exit_code == 0
        assert "VibeGuard Scan Results" in result.stdout

    def test_gate_pr_comment_flag(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(
            app, ["gate", "--path", str(tmp_path), "--pr-comment", "--fail-on", "high"]
        )
        assert result.exit_code == 0
        assert "PASS" in result.stdout

    def test_pr_comment_mutually_exclusive(self, tmp_path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--pr-comment", "--markdown"])
        assert result.exit_code == 2
