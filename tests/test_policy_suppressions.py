"""Tests for policy suppressions."""

from __future__ import annotations

import textwrap
from datetime import date, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from vibeguard.config import Suppression, VibeGuardConfig, apply_policy_suppressions
from vibeguard.models import Finding, Severity


def _make_finding(
    finding_id: str = "SEC-ENV",
    rule: str = "secrets",
    path: str = "tests/fixtures/example.env",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=finding_id,
        rule=rule,
        title="Test finding",
        description="Test.",
        severity=severity,
        path=path,
        recommendation="Fix it.",
    )


class TestSuppressionModel:
    def test_valid_suppression(self):
        s = Suppression(
            finding_id="SEC-ENV",
            path_pattern="tests/**",
            reason="Test fixture",
        )
        assert s.finding_id == "SEC-ENV"

    def test_missing_reason_fails(self):
        with pytest.raises(ValidationError):
            Suppression(finding_id="SEC-ENV", path_pattern="**", reason="")

    def test_missing_both_ids_fails(self):
        with pytest.raises(ValidationError):
            Suppression(path_pattern="**", reason="Some reason")

    def test_rule_id_only(self):
        s = Suppression(rule_id="secrets", reason="Legacy code")
        assert s.rule_id == "secrets"

    def test_with_expiry(self):
        s = Suppression(finding_id="SEC-ENV", reason="Temp", expires="2030-12-31")
        assert s.expires == "2030-12-31"


class TestApplyPolicySuppressions:
    def test_suppress_by_finding_id_and_path(self):
        findings = [_make_finding()]
        suppressions = [
            Suppression(
                finding_id="SEC-ENV",
                path_pattern="tests/fixtures/**",
                reason="Test fixture",
            )
        ]
        active, warnings = apply_policy_suppressions(findings, suppressions)
        assert len(active) == 0
        assert len(warnings) == 0

    def test_suppress_by_rule_id(self):
        findings = [_make_finding()]
        suppressions = [Suppression(rule_id="secrets", path_pattern="**", reason="All secrets OK")]
        active, warnings = apply_policy_suppressions(findings, suppressions)
        assert len(active) == 0

    def test_path_mismatch_not_suppressed(self):
        findings = [_make_finding(path="src/production.py")]
        suppressions = [
            Suppression(
                finding_id="SEC-ENV",
                path_pattern="tests/**",
                reason="Test only",
            )
        ]
        active, warnings = apply_policy_suppressions(findings, suppressions)
        assert len(active) == 1

    def test_expired_suppression_emits_warning(self):
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        findings = [_make_finding()]
        suppressions = [
            Suppression(
                finding_id="SEC-ENV",
                path_pattern="**",
                reason="Was temporary",
                expires=yesterday,
            )
        ]
        active, warnings = apply_policy_suppressions(findings, suppressions)
        # Finding NOT suppressed (suppression expired)
        assert len(active) == 1
        # Warning emitted
        assert len(warnings) == 1
        assert warnings[0].id == "SUPPRESSION-EXPIRED"

    def test_future_expiry_suppresses(self):
        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        findings = [_make_finding()]
        suppressions = [
            Suppression(
                finding_id="SEC-ENV",
                path_pattern="**",
                reason="Still valid",
                expires=tomorrow,
            )
        ]
        active, warnings = apply_policy_suppressions(findings, suppressions)
        assert len(active) == 0
        assert len(warnings) == 0

    def test_empty_suppressions(self):
        findings = [_make_finding()]
        active, warnings = apply_policy_suppressions(findings, [])
        assert active == findings
        assert len(warnings) == 0


class TestSuppressionConfig:
    def test_config_with_suppressions(self, tmp_path: Path):
        yaml_content = textwrap.dedent("""
            policy: balanced
            suppressions:
              - finding_id: "SEC-ENV"
                path_pattern: "tests/**"
                reason: "Test fixture"
                expires: "2030-12-31"
              - rule_id: "ai_footprints"
                path_pattern: "examples/**"
                reason: "Examples intentionally show AI footprints"
        """)
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text(yaml_content)

        cfg = VibeGuardConfig.load(cfg_file)
        assert len(cfg.suppressions) == 2
        assert cfg.suppressions[0].finding_id == "SEC-ENV"
        assert cfg.suppressions[0].reason == "Test fixture"
        assert cfg.suppressions[1].rule_id == "ai_footprints"

    def test_suppression_without_reason_fails(self, tmp_path: Path):
        yaml_content = textwrap.dedent("""
            policy: balanced
            suppressions:
              - finding_id: "SEC-ENV"
                path_pattern: "**"
                reason: ""
        """)
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text(yaml_content)

        with pytest.raises(ValidationError):
            VibeGuardConfig.load(cfg_file)
