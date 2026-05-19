"""Tests for inline suppressions."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.scanner import run_scan
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
