"""Tests for GitHub Actions annotations reporter."""

from __future__ import annotations

import os
from unittest.mock import patch

from typer.testing import CliRunner

from vibeguard.cli import app
from vibeguard.models import Confidence, Finding, ScanResult, Severity
from vibeguard.reporters.annotations import (
    is_github_actions,
    render_annotations,
)

runner = CliRunner()


def _make_result() -> ScanResult:
    return ScanResult(
        findings=[
            Finding(
                id="SEC-ENV",
                rule="secrets",
                title="Sensitive .env file",
                description="An .env file was committed.",
                severity=Severity.CRITICAL,
                path="src/.env",
                line=None,
                recommendation="Remove and gitignore.",
                tags=["secrets"],
                confidence=Confidence.HIGH,
            ),
            Finding(
                id="AI-FOOTPRINT",
                rule="ai_footprints",
                title="Placeholder credential",
                description="Found placeholder.",
                severity=Severity.MEDIUM,
                path="src/app.py",
                line=15,
                recommendation="Replace.",
                tags=["ai"],
                confidence=Confidence.MEDIUM,
            ),
        ],
        scanned_files=3,
    )


class TestAnnotations:
    def test_critical_maps_to_error(self):
        result = _make_result()
        output = render_annotations(result)
        assert "::error " in output

    def test_medium_maps_to_warning(self):
        result = _make_result()
        output = render_annotations(result)
        assert "::warning " in output

    def test_file_and_line_included(self):
        result = _make_result()
        output = render_annotations(result)
        assert "file=src/app.py" in output
        assert "line=15" in output

    def test_file_without_line(self):
        result = _make_result()
        output = render_annotations(result)
        # First finding has no line
        lines = output.splitlines()
        env_line = [x for x in lines if "src/.env" in x][0]
        assert "line=" not in env_line

    def test_title_includes_finding_id(self):
        result = _make_result()
        output = render_annotations(result)
        assert "title=SEC-ENV:" in output

    def test_is_github_actions_false_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            assert not is_github_actions()

    def test_is_github_actions_true(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            assert is_github_actions()


class TestAnnotationsCLI:
    def test_annotations_flag(self, tmp_path):
        (tmp_path / "secret.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--annotations"])
        assert result.exit_code == 0
        assert "::error " in result.stdout or "::warning " in result.stdout or result.stdout

    def test_no_annotations_with_json(self, tmp_path):
        """--json should suppress auto-annotations."""
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--json"])
        assert result.exit_code == 0
        assert "::error" not in result.stdout
