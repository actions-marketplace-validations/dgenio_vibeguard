"""Tests for CLI exit codes and commands."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vibeguard.cli import app

runner = CliRunner()


class TestCLIInit:
    def test_init_creates_config(self, tmp_path: Path):
        result = runner.invoke(app, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / "vibeguard.yaml").exists()

    def test_init_skips_existing(self, tmp_path: Path):
        (tmp_path / "vibeguard.yaml").write_text("policy: relaxed\n")
        result = runner.invoke(app, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 0
        # Content should not be overwritten
        assert (tmp_path / "vibeguard.yaml").read_text() == "policy: relaxed\n"


class TestCLIScan:
    def test_scan_clean_dir_exits_zero(self, tmp_path: Path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_json_output(self, tmp_path: Path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert "findings" in data

    def test_scan_markdown_output(self, tmp_path: Path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--markdown"])
        assert result.exit_code == 0
        assert "VibeGuard" in result.stdout

    def test_scan_always_exits_zero(self, tmp_path: Path):
        """scan command should exit 0 even with findings."""
        (tmp_path / "secret.py").write_text('token = "ghp_' + "A" * 36 + '"\n')
        result = runner.invoke(app, ["scan", "--path", str(tmp_path)])
        assert result.exit_code == 0


class TestCLIGate:
    def test_gate_clean_dir_exits_zero(self, tmp_path: Path):
        (tmp_path / "hello.py").write_text("print('hello')\n")
        result = runner.invoke(app, ["gate", "--path", str(tmp_path), "--fail-on", "high"])
        assert result.exit_code == 0

    def test_gate_with_critical_finding_exits_one(self, tmp_path: Path):
        (tmp_path / "secret.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"\n')
        result = runner.invoke(
            app,
            ["gate", "--path", str(tmp_path), "--fail-on", "high"],
        )
        assert result.exit_code == 1

    def test_gate_fail_on_low_exits_one_on_info(self, tmp_path: Path):
        """Gate with --fail-on low should fail when any non-info finding exists."""
        (tmp_path / "app.js.map").write_text('{"version":3}')
        result = runner.invoke(
            app,
            ["gate", "--path", str(tmp_path), "--fail-on", "low"],
        )
        assert result.exit_code == 1


class TestCLIExplain:
    def test_explain_known_id(self):
        result = runner.invoke(app, ["explain", "SEC-ENV"])
        assert result.exit_code == 0
        assert len(result.stdout) > 10

    def test_explain_unknown_id_exits_two(self):
        """Unknown finding IDs are a hard error (#90), not a silent pass."""
        result = runner.invoke(app, ["explain", "NOTREAL-999"])
        assert result.exit_code == 2
        # Message matches `rules explain` for consistency.
        combined = result.stdout + (result.stderr or "")
        assert "Unknown rule or finding ID" in combined
        assert "rules list" in combined

    def test_explain_and_rules_explain_share_unknown_message(self):
        """The two explain surfaces must agree on the unknown-ID UX (#90)."""
        bogus = "ZZZ-NOPE-999"
        a = runner.invoke(app, ["explain", bogus])
        b = runner.invoke(app, ["rules", "explain", bogus])
        assert a.exit_code == 2
        assert b.exit_code == 2

    def test_explain_uncurated_finding_id_renders_remediation(self):
        """Every registered finding ID should produce a remediation, not a stub (#88)."""
        # SEC-GITHUBTOKEN is in the bundled example output but never had a
        # curated entry; it must now render the rule-metadata remediation.
        result = runner.invoke(app, ["explain", "SEC-GITHUBTOKEN"])
        assert result.exit_code == 0
        # Structural check: the "How to fix" marker is present and the body
        # following it is non-empty. Avoids coupling to remediation prose
        # (e.g. "Revoke" / "rotate") that may be reworded over time.
        assert "How to fix" in result.stdout
        _, _, after = result.stdout.partition("How to fix")
        assert after.strip(), "Remediation body following 'How to fix' is empty"


class TestCLIVersion:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "vibeguard" in result.stdout.lower()
