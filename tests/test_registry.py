"""Tests for rule metadata registry."""

from __future__ import annotations

from vibeguard.rules.registry import RULE_REGISTRY, RuleMetadata


class TestRuleRegistry:
    def test_registry_has_all_existing_rules(self):
        # Import all rule modules to trigger registration
        import vibeguard.rules.agent_memory  # noqa: F401
        import vibeguard.rules.ai_footprints  # noqa: F401
        import vibeguard.rules.auth  # noqa: F401
        import vibeguard.rules.ci_docker  # noqa: F401
        import vibeguard.rules.dependencies  # noqa: F401
        import vibeguard.rules.go_rules  # noqa: F401
        import vibeguard.rules.iac  # noqa: F401
        import vibeguard.rules.packaging  # noqa: F401
        import vibeguard.rules.risky_diff  # noqa: F401
        import vibeguard.rules.secrets  # noqa: F401
        import vibeguard.rules.sourcemaps  # noqa: F401
        import vibeguard.rules.sql  # noqa: F401
        import vibeguard.rules.tests  # noqa: F401

        expected_rules = {
            "secrets",
            "sourcemaps",
            "packaging",
            "dependencies",
            "risky_diff",
            "tests",
            "ai_footprints",
            "go_rules",
            "ci_docker",
            "iac",
            "auth",
            "sql",
            "agent_memory",
        }
        assert expected_rules.issubset(set(RULE_REGISTRY.keys()))

    def test_each_rule_has_nonempty_finding_ids(self):
        for rule_id, meta in RULE_REGISTRY.items():
            assert meta.finding_ids, f"Rule {rule_id} has empty finding_ids"

    def test_metadata_is_dataclass(self):
        for meta in RULE_REGISTRY.values():
            assert isinstance(meta, RuleMetadata)

    def test_registry_entry_has_required_fields(self):
        for rule_id, meta in RULE_REGISTRY.items():
            assert meta.rule_id == rule_id
            assert meta.title
            assert meta.description
            assert meta.tags
