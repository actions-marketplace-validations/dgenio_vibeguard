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

    def test_every_rule_declares_a_config_key(self):
        """``register_rule`` defaults ``config_key`` to ``rule_id`` so this
        invariant must hold for every entry. Tested explicitly so a future
        registry refactor that drops the default is caught (#89)."""
        for rule_id, meta in RULE_REGISTRY.items():
            assert meta.config_key, f"Rule {rule_id} missing config_key"

    def test_known_config_key_mismatches(self):
        """The one historical mismatch — ``rule_id='risky_diff'`` is configured
        via the ``risky_patterns`` YAML section — must remain surfaced (#89)."""
        assert RULE_REGISTRY["risky_diff"].config_key == "risky_patterns"

    def test_every_finding_id_has_a_remediation(self):
        """``vibeguard explain <ID>`` must render a remediation for every
        registered finding ID. The static adapter's curated dict covers the
        canonical "rich text" cases; everything else must have a one-line
        remediation in the rule's metadata (#88)."""
        from vibeguard.explain.static import StaticExplainAdapter

        for rule_id, meta in RULE_REGISTRY.items():
            for fid in meta.finding_ids:
                fid_upper = fid.upper()
                has_curated = StaticExplainAdapter.explain_by_id(fid_upper) is not None
                has_remediation = fid_upper in meta.remediations
                assert has_curated or has_remediation, (
                    f"Finding {fid} (rule {rule_id}) has neither a curated "
                    f"explanation nor a remediation. Add one in either "
                    f"vibeguard/explain/static.py or the rule's "
                    f"RuleMetadata(remediations=...)."
                )
