"""Tests for severity overrides."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from vibeguard.config import SeverityOverride, VibeGuardConfig, apply_severity_overrides
from vibeguard.models import Finding, Severity


def _make_finding(
    finding_id: str = "SEC-ENV",
    rule: str = "secrets",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=finding_id,
        rule=rule,
        title="Test finding",
        description="Test.",
        severity=severity,
        path="src/config.py",
        recommendation="Fix it.",
    )


class TestSeverityOverrideModel:
    def test_valid_override_by_rule(self):
        override = SeverityOverride(rule_id="secrets", severity=Severity.LOW)
        assert override.rule_id == "secrets"

    def test_valid_override_by_finding(self):
        override = SeverityOverride(finding_id="SEC-ENV", severity=Severity.CRITICAL)
        assert override.finding_id == "SEC-ENV"

    def test_missing_both_ids_fails(self):
        with pytest.raises(ValidationError):
            SeverityOverride(severity=Severity.LOW)

    def test_invalid_severity_fails(self):
        with pytest.raises(ValidationError):
            SeverityOverride(rule_id="secrets", severity="invalid")  # type: ignore[arg-type]


class TestApplySeverityOverrides:
    def test_override_by_rule_id(self):
        findings = [_make_finding(severity=Severity.HIGH)]
        overrides = [SeverityOverride(rule_id="secrets", severity=Severity.LOW)]
        result = apply_severity_overrides(findings, overrides)
        assert result[0].severity == Severity.LOW

    def test_override_by_finding_id(self):
        findings = [_make_finding(finding_id="SEC-ENV", severity=Severity.HIGH)]
        overrides = [SeverityOverride(finding_id="SEC-ENV", severity=Severity.CRITICAL)]
        result = apply_severity_overrides(findings, overrides)
        assert result[0].severity == Severity.CRITICAL

    def test_finding_id_takes_precedence(self):
        findings = [_make_finding(finding_id="SEC-ENV", rule="secrets", severity=Severity.HIGH)]
        overrides = [
            SeverityOverride(rule_id="secrets", severity=Severity.LOW),
            SeverityOverride(finding_id="SEC-ENV", severity=Severity.CRITICAL),
        ]
        result = apply_severity_overrides(findings, overrides)
        assert result[0].severity == Severity.CRITICAL

    def test_no_match_unchanged(self):
        findings = [_make_finding(severity=Severity.HIGH)]
        overrides = [SeverityOverride(rule_id="other_rule", severity=Severity.LOW)]
        result = apply_severity_overrides(findings, overrides)
        assert result[0].severity == Severity.HIGH

    def test_empty_overrides(self):
        findings = [_make_finding()]
        result = apply_severity_overrides(findings, [])
        assert result == findings


class TestSeverityOverrideConfig:
    def test_config_with_overrides(self, tmp_path: Path):
        yaml_content = textwrap.dedent("""
            policy: balanced
            severity_overrides:
              - rule_id: "secrets"
                severity: low
              - finding_id: "SEC-ENV"
                severity: critical
        """)
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text(yaml_content)

        cfg = VibeGuardConfig.load(cfg_file)
        assert len(cfg.severity_overrides) == 2
        assert cfg.severity_overrides[0].rule_id == "secrets"
        assert cfg.severity_overrides[1].finding_id == "SEC-ENV"

    def test_invalid_override_in_config(self, tmp_path: Path):
        yaml_content = textwrap.dedent("""
            policy: balanced
            severity_overrides:
              - severity: low
        """)
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text(yaml_content)

        with pytest.raises(ValidationError):
            VibeGuardConfig.load(cfg_file)
