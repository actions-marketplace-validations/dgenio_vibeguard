"""Tests for the public ``vibeguard.api`` surface."""

from __future__ import annotations

from pathlib import Path

import pytest

from vibeguard import api
from vibeguard.api import (
    PLUGIN_API_VERSION,
    RULE_REGISTRY,
    BaseRule,
    Confidence,
    Finding,
    GitMetadata,
    Rule,
    RuleMetadata,
    ScanContext,
    ScanResult,
    Severity,
    register_rule,
)
from vibeguard.config import VibeGuardConfig


class TestApiExports:
    def test_plugin_api_version_is_nonempty_string(self):
        assert isinstance(PLUGIN_API_VERSION, str)
        assert PLUGIN_API_VERSION.count(".") >= 1  # MAJOR.MINOR shape
        assert all(part.isdigit() for part in PLUGIN_API_VERSION.split("."))

    def test_base_rule_is_alias_of_rule(self):
        assert BaseRule is Rule

    def test_all_exports_resolve(self):
        # Every symbol listed in __all__ must be importable from vibeguard.api
        for name in api.__all__:
            assert hasattr(api, name), f"vibeguard.api is missing exported symbol {name!r}"

    def test_registry_is_the_real_registry(self):
        # vibeguard.api.RULE_REGISTRY must be the same object the package mutates
        from vibeguard.rules.registry import RULE_REGISTRY as core_registry

        assert RULE_REGISTRY is core_registry


class TestInlinePluginRule:
    def test_minimal_rule_runs_via_public_api(self, tmp_path: Path):
        """An inline rule defined using only ``vibeguard.api`` runs end-to-end."""
        (tmp_path / "sample.txt").write_text("TODO: ship it\nfine line\n")

        class TodoRule(BaseRule):
            id = "test-inline-todo"
            name = "Inline TODO rule"
            description = "Flags TODO comments."

            def scan(self, context: ScanContext) -> list[Finding]:
                findings: list[Finding] = []
                for path in context.files:
                    text = path.read_text(encoding="utf-8")
                    for lineno, line in enumerate(text.splitlines(), start=1):
                        if "TODO" in line:
                            findings.append(
                                Finding(
                                    id="TEST-TODO",
                                    rule=self.id,
                                    title="TODO found",
                                    description="A TODO comment was detected.",
                                    severity=Severity.LOW,
                                    path=self._rel(context, path),
                                    line=lineno,
                                    recommendation="Resolve it.",
                                    tags=["test"],
                                    confidence=Confidence.HIGH,
                                )
                            )
                return findings

        cfg = VibeGuardConfig()
        ctx = ScanContext(
            root=tmp_path,
            config=cfg,
            files=[tmp_path / "sample.txt"],
        )
        findings = TodoRule().scan(ctx)
        assert [f.id for f in findings] == ["TEST-TODO"]
        assert findings[0].line == 1
        assert findings[0].path == "sample.txt"

    def test_is_applicable_defaults_to_true(self):
        class AnyRule(BaseRule):
            id = "test-any"
            name = "Any"
            description = "Default applicability."

            def scan(self, context: ScanContext) -> list[Finding]:
                return []

        assert AnyRule().is_applicable(Path("whatever.xyz")) is True


class TestMetadataRegistration:
    def test_register_then_lookup(self):
        rule_id = "test-register-lookup"
        # Clean up if a previous flaky run left it behind
        RULE_REGISTRY.pop(rule_id, None)
        register_rule(
            RuleMetadata(
                rule_id=rule_id,
                title="Test",
                description="Registration round-trip.",
                finding_ids=["TEST-A"],
                default_severity="low",
                confidence="high",
                tags=["test"],
                applies_to=["*"],
            )
        )
        try:
            assert RULE_REGISTRY[rule_id].title == "Test"
            assert RULE_REGISTRY[rule_id].finding_ids == ("TEST-A",)
        finally:
            RULE_REGISTRY.pop(rule_id, None)

    def test_duplicate_registration_raises(self):
        rule_id = "test-duplicate"
        RULE_REGISTRY.pop(rule_id, None)
        register_rule(
            RuleMetadata(
                rule_id=rule_id,
                title="Once",
                description=".",
                finding_ids=["TEST-DUP"],
                tags=["test"],
            )
        )
        try:
            with pytest.raises(ValueError, match="Duplicate"):
                register_rule(
                    RuleMetadata(
                        rule_id=rule_id,
                        title="Twice",
                        description=".",
                        finding_ids=["TEST-DUP"],
                        tags=["test"],
                    )
                )
        finally:
            RULE_REGISTRY.pop(rule_id, None)


class TestModelsExports:
    def test_finding_severity_confidence_usable(self):
        f = Finding(
            id="X",
            rule="x",
            title="t",
            description="d",
            severity=Severity.MEDIUM,
            path="x.py",
            recommendation="r",
            confidence=Confidence.LOW,
        )
        assert f.severity is Severity.MEDIUM
        assert f.confidence is Confidence.LOW

    def test_scan_result_and_git_metadata_importable(self):
        # Smoke test: instantiating with defaults must work.
        assert ScanResult().findings == []
        assert GitMetadata().is_available is False
