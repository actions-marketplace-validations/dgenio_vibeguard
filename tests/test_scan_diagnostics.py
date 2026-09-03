"""Tests for structured scan diagnostics and fail-closed gating.

Covers four connected pieces of work that share the scan-diagnostics pipeline:

* #195 — the typed ``ScanDiagnostic`` model and ``ScanResult.diagnostics``,
  with ``errors`` derived from it.
* #191 — slopsquat surfacing registry-network failures as a ``network`` diagnostic.
* #218 — ``gate --strict-errors`` failing closed on a degraded scan.
* #183 — the exit-code constants (exercised here for the strict-error path).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from vibeguard.cli import EXIT_BLOCKED, EXIT_OK, app
from vibeguard.config import VibeGuardConfig
from vibeguard.models import GitMetadata, ScanDiagnostic, ScanResult
from vibeguard.scanner import run_scan

runner = CliRunner()


class TestScanDiagnosticModel:
    """The structured model and its derived/compatibility views (#195)."""

    def test_errors_view_mirrors_diagnostic_messages(self):
        diags = [
            ScanDiagnostic(category="rule_error", severity="error", message="Rule x failed: boom"),
            ScanDiagnostic(category="skipped_file", severity="info", message="Skipped (binary): a"),
        ]
        result = ScanResult(diagnostics=diags, errors=[d.message for d in diags])
        assert result.errors == ["Rule x failed: boom", "Skipped (binary): a"]

    def test_mismatched_errors_are_overridden_from_diagnostics(self):
        # The model validator enforces the no-drift contract (#195): when
        # diagnostics are present, errors is derived from them regardless of
        # what a caller passed, so the two channels can never disagree.
        diags = [
            ScanDiagnostic(category="network", severity="warning", message="registry timed out"),
        ]
        result = ScanResult(diagnostics=diags, errors=["stale", "mismatched", "values"])
        assert result.errors == ["registry timed out"]

    def test_legacy_errors_only_preserved_without_diagnostics(self):
        # Backward-compatible construction: with no diagnostics, an explicit
        # errors list is left untouched so existing callers keep working.
        result = ScanResult(errors=["legacy message"])
        assert result.diagnostics == []
        assert result.errors == ["legacy message"]

    def test_degraded_excludes_routine_skips_but_keeps_unreadable(self):
        result = ScanResult(
            diagnostics=[
                ScanDiagnostic(
                    category="skipped_file", severity="info", message="Skipped (binary): a"
                ),
                ScanDiagnostic(
                    category="skipped_file", severity="info", message="Skipped (>1 KB): b"
                ),
                ScanDiagnostic(
                    category="skipped_file", severity="warning", message="Cannot read: c"
                ),
                ScanDiagnostic(category="rule_error", severity="error", message="Rule r failed: x"),
                ScanDiagnostic(category="plugin_load", severity="error", message="Plugin p ..."),
                ScanDiagnostic(category="git_context", severity="warning", message="HEAD only ..."),
                ScanDiagnostic(category="network", severity="warning", message="registry ..."),
            ]
        )
        categories = {d.category for d in result.degraded_diagnostics()}
        # Routine binary/oversize skips are excluded; everything else is degraded.
        assert categories == {"skipped_file", "rule_error", "plugin_load", "git_context", "network"}
        messages = {d.message for d in result.degraded_diagnostics()}
        assert "Skipped (binary): a" not in messages
        assert "Cannot read: c" in messages


class TestScannerProducesDiagnostics:
    """Every former ``errors.append`` site now yields a categorized diagnostic (#195)."""

    def test_rule_crash_becomes_rule_error_diagnostic(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        from vibeguard.rules.secrets import SecretsRule

        def _raise(self, context):  # noqa: ANN001
            raise RuntimeError("boom")

        monkeypatch.setattr(SecretsRule, "scan", _raise)
        (tmp_path / "app.py").write_text("x = 1\n")

        result = run_scan(tmp_path, VibeGuardConfig())

        rule_errors = [d for d in result.diagnostics if d.category == "rule_error"]
        assert len(rule_errors) == 1
        assert rule_errors[0].rule == "secrets"
        assert rule_errors[0].severity == "error"
        assert "boom" in rule_errors[0].message
        # Derived string view still carries the same message.
        assert any("Rule secrets failed: boom" in e for e in result.errors)

    def test_plugin_failure_becomes_plugin_load_diagnostic(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        import vibeguard.scanner as scanner_mod
        from vibeguard.rules.plugins import PluginLoadFailure

        failure = PluginLoadFailure(
            name="broken-plugin", distribution="broken-dist", reason="ImportError: no module"
        )
        monkeypatch.setattr(
            scanner_mod, "discover_plugin_rules", lambda disabled=(): ([], [failure])
        )
        (tmp_path / "app.py").write_text("x = 1\n")

        result = run_scan(tmp_path, VibeGuardConfig())

        plugin_diags = [d for d in result.diagnostics if d.category == "plugin_load"]
        assert len(plugin_diags) == 1
        assert plugin_diags[0].rule == "broken-plugin"
        assert "failed to load" in plugin_diags[0].message

    def test_binary_skip_is_routine_info(self, tmp_path: Path):
        (tmp_path / "good.py").write_text("x = 1\n")
        (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02\x00")

        result = run_scan(tmp_path, VibeGuardConfig())

        binary = [d for d in result.diagnostics if d.message.startswith("Skipped (binary)")]
        assert len(binary) == 1
        assert binary[0].category == "skipped_file"
        assert binary[0].severity == "info"
        # A routine skip must not, on its own, count as a degraded scan.
        assert result.degraded_diagnostics() == []

    def test_head_only_git_context_is_categorized(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n")
        meta = GitMetadata(is_available=True, changed_files=[], diff_strategy="head-only")

        result = run_scan(tmp_path, VibeGuardConfig(), diff_only=True, git_meta=meta)

        git_diags = [d for d in result.diagnostics if d.category == "git_context"]
        assert git_diags and any("comparing against HEAD only" in d.message for d in git_diags)
        assert any(d.category == "git_context" for d in result.degraded_diagnostics())


class TestSlopsquatRegistryDiagnostic:
    """Slopsquat surfaces a degraded registry check instead of silent inconclusiveness (#191)."""

    def _pkg_ctx(self, tmp_path: Path):
        import vibeguard.rules.slopsquat as slop_mod

        cfg = VibeGuardConfig()
        cfg.slopsquat.registry_check = True
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"leftpad-ultimate": "^1.0.0", "react-helper-kit": "^2.0.0"}}'
        )
        from vibeguard.models import ScanContext

        files = [tmp_path / "package.json"]
        return slop_mod, ScanContext(root=tmp_path, config=cfg, files=files)

    def test_network_failure_emits_single_aggregated_diagnostic(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        slop_mod, ctx = self._pkg_ctx(tmp_path)
        monkeypatch.setattr(slop_mod, "_registry_lookup", lambda *a, **k: (None, None, "timeout"))

        findings = slop_mod.SlopsquatRule().scan(ctx)

        # Network failure must not invent findings, but must be visible as one
        # aggregated diagnostic on the shared context sink.
        assert all(not f.id.startswith("SLOP-REGISTRY") for f in findings)
        net = [d for d in ctx.diagnostics if d.category == "network"]
        assert len(net) == 1
        assert net[0].severity == "warning"
        assert net[0].rule == "slopsquat"
        assert "timeout" in net[0].message
        # Two distinct names were looked up; both failed.
        assert "2/2" in net[0].message

    def test_distinct_failure_kinds_are_listed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        slop_mod, ctx = self._pkg_ctx(tmp_path)
        outcomes = iter([(None, None, "timeout"), (None, None, "network")])
        monkeypatch.setattr(slop_mod, "_registry_lookup", lambda *a, **k: next(outcomes))

        slop_mod.SlopsquatRule().scan(ctx)

        net = [d for d in ctx.diagnostics if d.category == "network"]
        assert len(net) == 1
        assert "network, timeout" in net[0].message  # sorted, de-duplicated

    def test_successful_lookups_add_no_noise(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        slop_mod, ctx = self._pkg_ctx(tmp_path)
        monkeypatch.setattr(slop_mod, "_registry_lookup", lambda *a, **k: (True, 900, None))

        slop_mod.SlopsquatRule().scan(ctx)

        assert [d for d in ctx.diagnostics if d.category == "network"] == []


class TestGateStrictErrors:
    """`gate --strict-errors` fails closed on a degraded scan (#218)."""

    def _patch_scan(self, monkeypatch: pytest.MonkeyPatch, diagnostics: list[ScanDiagnostic]):
        import vibeguard.cli as cli_mod

        def fake_scan(path, config, diff_only=False, git_meta=None):  # noqa: ANN001
            return ScanResult(
                scanned_files=1,
                diagnostics=diagnostics,
                errors=[d.message for d in diagnostics],
            )

        monkeypatch.setattr(cli_mod, "run_scan", fake_scan)

    def test_rule_crash_fails_strict_with_zero_findings(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        self._patch_scan(
            monkeypatch,
            [ScanDiagnostic(category="rule_error", severity="error", message="Rule r failed: x")],
        )
        result = runner.invoke(app, ["gate", "--path", str(tmp_path), "--strict-errors"])
        assert result.exit_code == EXIT_BLOCKED
        assert "strict-errors" in (result.stdout + (result.stderr or ""))

    def test_default_is_fail_open_on_degradation(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        self._patch_scan(
            monkeypatch,
            [ScanDiagnostic(category="rule_error", severity="error", message="Rule r failed: x")],
        )
        result = runner.invoke(app, ["gate", "--path", str(tmp_path)])
        assert result.exit_code == EXIT_OK

    def test_routine_skip_does_not_trip_strict(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        self._patch_scan(
            monkeypatch,
            [
                ScanDiagnostic(
                    category="skipped_file", severity="info", message="Skipped (binary): a"
                )
            ],
        )
        result = runner.invoke(app, ["gate", "--path", str(tmp_path), "--strict-errors"])
        assert result.exit_code == EXIT_OK

    def test_config_enables_strict_without_flag(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        (tmp_path / "vibeguard.yaml").write_text("gate:\n  strict_errors: true\n")
        self._patch_scan(
            monkeypatch,
            [ScanDiagnostic(category="git_context", severity="warning", message="HEAD only ...")],
        )
        result = runner.invoke(app, ["gate", "--path", str(tmp_path)])
        assert result.exit_code == EXIT_BLOCKED

    def test_flag_overrides_config_to_disable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        (tmp_path / "vibeguard.yaml").write_text("gate:\n  strict_errors: true\n")
        self._patch_scan(
            monkeypatch,
            [ScanDiagnostic(category="rule_error", severity="error", message="Rule r failed: x")],
        )
        result = runner.invoke(app, ["gate", "--path", str(tmp_path), "--no-strict-errors"])
        assert result.exit_code == EXIT_OK
