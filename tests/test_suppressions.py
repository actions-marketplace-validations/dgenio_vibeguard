"""Tests for inline suppressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from vibeguard.config import VibeGuardConfig
from vibeguard.scanner import _supports_inline_suppression, run_scan
from vibeguard.suppressions import find_missing_reasons, parse_inline_suppressions


class TestParseInlineSuppressions:
    def test_single_id(self):
        content = 'api_key = "AKIAIOSFODNN7EXAMPLE"  # vibeguard: ignore SEC-AWSACCESSKEY reason="test fixture"'
        result = parse_inline_suppressions(content)
        assert 1 in result
        assert "SEC-AWSACCESSKEY" in result[1]

    def test_multiple_ids(self):
        content = 'x = y  # vibeguard: ignore SEC-ENV,AI-FOOTPRINT reason="example"'
        result = parse_inline_suppressions(content)
        assert 1 in result
        assert "SEC-ENV" in result[1]
        assert "AI-FOOTPRINT" in result[1]

    def test_js_comment_style(self):
        content = 'const key = "ghp_abc";  // vibeguard: ignore SEC-GITHUBTOKEN reason="docs"'
        result = parse_inline_suppressions(content)
        assert 1 in result
        assert "SEC-GITHUBTOKEN" in result[1]

    def test_sql_comment_style(self):
        # SQL `--` line comment (#210).
        content = 'SELECT * FROM t;  -- vibeguard: ignore SQL-PY-FSTRING reason="reviewed"'
        result = parse_inline_suppressions(content)
        assert 1 in result
        assert "SQL-PY-FSTRING" in result[1]

    def test_html_comment_style(self):
        # HTML/Markdown `<!-- ... -->` comment (#210); trailing `-->` is ignored.
        content = '<!-- vibeguard: ignore PI-HIDDENUNICODE reason="example" -->'
        result = parse_inline_suppressions(content)
        assert 1 in result
        assert "PI-HIDDENUNICODE" in result[1]

    def test_html_comment_missing_reason(self):
        content = "<!-- vibeguard: ignore PI-HIDDENUNICODE -->"
        missing = find_missing_reasons(content)
        assert len(missing) == 1
        assert "PI-HIDDENUNICODE" in missing[0][1]

    def test_no_suppressions(self):
        content = "normal code\nmore normal code\n"
        result = parse_inline_suppressions(content)
        assert len(result) == 0

    def test_missing_reason(self):
        content = 'api_key = "test"  # vibeguard: ignore SEC-ENV'
        missing = find_missing_reasons(content)
        assert len(missing) == 1
        assert missing[0][0] == 1
        assert "SEC-ENV" in missing[0][1]

    def test_with_reason_not_missing(self):
        content = 'x = y  # vibeguard: ignore SEC-ENV reason="intentional"'
        missing = find_missing_reasons(content)
        assert len(missing) == 0


class TestInlineSuppressionIntegration:
    def test_suppression_filters_finding(self, tmp_path: Path):
        # Create a file with a real secret + suppression
        content = (
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # vibeguard: ignore SEC-AWSACCESSKEY reason="test"\n'
        )
        (tmp_path / "config.py").write_text(content)

        config = VibeGuardConfig()
        result = run_scan(tmp_path, config)
        # The finding should be suppressed
        assert not any(f.id == "SEC-AWSACCESSKEY" for f in result.findings)

    def test_suppression_on_preceding_line_is_effective(self, tmp_path: Path):
        content = (
            '# vibeguard: ignore SEC-AWSACCESSKEY reason="test"\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        )
        (tmp_path / "config.py").write_text(content)

        config = VibeGuardConfig()
        result = run_scan(tmp_path, config)
        # Preceding-line suppression (line N-1) suppresses finding on line N
        assert not any(f.id == "SEC-AWSACCESSKEY" for f in result.findings)

    def test_suppression_two_lines_away_not_effective(self, tmp_path: Path):
        content = (
            '# vibeguard: ignore SEC-AWSACCESSKEY reason="test"\n'
            "x = 1\n"
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        )
        (tmp_path / "config.py").write_text(content)

        config = VibeGuardConfig()
        result = run_scan(tmp_path, config)
        # Suppression on line 1, finding on line 3 — too far, should NOT be suppressed
        assert any(f.id == "SEC-AWSACCESSKEY" for f in result.findings)

    def test_missing_reason_emits_warning(self, tmp_path: Path):
        content = 'x = "test"  # vibeguard: ignore SEC-ENV\n'
        (tmp_path / "config.py").write_text(content)

        config = VibeGuardConfig()
        result = run_scan(tmp_path, config)
        assert any(f.id == "SUPPRESSION-NO-REASON" for f in result.findings)

    def test_inline_suppression_honored_in_shell_file(self, tmp_path: Path):
        # #210: shell scripts were previously gated out of inline-suppression
        # parsing, so a finding there could not be suppressed in place.
        script = tmp_path / "deploy.sh"
        script.write_text(
            'rm -rf /tmp/build  # vibeguard: ignore RISK-FILEDELETE reason="cleanup"\n'
        )

        config = VibeGuardConfig()
        result = run_scan(tmp_path, config)
        assert not any(f.id == "RISK-FILEDELETE" for f in result.findings)

    def test_shell_finding_present_without_suppression(self, tmp_path: Path):
        # Guard: the finding really does fire here, so the test above proves
        # the suppression — not an absent finding.
        script = tmp_path / "deploy.sh"
        script.write_text("rm -rf /tmp/build\n")

        config = VibeGuardConfig()
        result = run_scan(tmp_path, config)
        assert any(f.id == "RISK-FILEDELETE" for f in result.findings)


class TestSuppressionFileTypeGate:
    @pytest.mark.parametrize(
        "name",
        [
            "app.yaml",
            "config.toml",
            "main.tf",
            "schema.sql",
            "README.md",
            "Dockerfile",
            "Dockerfile.prod",
            "run.sh",
        ],
    )
    def test_supported_file_types(self, name: str):
        assert _supports_inline_suppression(Path(name))

    @pytest.mark.parametrize(
        "name",
        ["image.png", "data.csv", "archive.zip", "dockerfile_notes.txt"],
    )
    def test_unsupported_file_types(self, name: str):
        # #268 review: the Dockerfile match is exact/dotted, so an unrelated
        # name that merely starts with "dockerfile" is not suppression-eligible.
        assert not _supports_inline_suppression(Path(name))
