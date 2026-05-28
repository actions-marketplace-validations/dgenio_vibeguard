"""Tests for the ``vibeguard rules`` CLI command group."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from vibeguard.cli import app

runner = CliRunner()


class TestRulesList:
    def test_table_output_contains_known_rules(self):
        result = runner.invoke(app, ["rules", "list"])
        assert result.exit_code == 0, result.stdout
        # The Rich table flattens to plain text in CliRunner; rule IDs appear
        # at the start of their row.
        for rule_id in ("secrets", "packaging", "sourcemaps", "auth", "tests"):
            assert rule_id in result.stdout

    def test_json_output_is_valid_and_complete(self):
        result = runner.invoke(app, ["rules", "list", "--json"])
        assert result.exit_code == 0, result.stdout
        payload = json.loads(result.stdout)
        assert "version" in payload
        assert isinstance(payload["rules"], list)
        rule_ids = {row["rule_id"] for row in payload["rules"]}
        # Spot-check a handful — exhaustive coverage lives in test_registry.py
        assert {"secrets", "auth", "packaging"}.issubset(rule_ids)
        # Each row carries the documented fields
        sample = next(row for row in payload["rules"] if row["rule_id"] == "secrets")
        assert isinstance(sample["finding_ids"], list)
        assert sample["default_severity"] in {"info", "low", "medium", "high", "critical"}

    def test_tag_filter_narrows_results(self):
        result = runner.invoke(app, ["rules", "list", "--json", "--tag", "secrets"])
        assert result.exit_code == 0, result.stdout
        rule_ids = {row["rule_id"] for row in json.loads(result.stdout)["rules"]}
        # The `secrets` rule has the literal `secrets` tag.
        assert "secrets" in rule_ids
        # And the `auth` rule does not — confirms the filter actually filters.
        assert "auth" not in rule_ids

    def test_tag_filter_is_case_insensitive(self):
        result = runner.invoke(app, ["rules", "list", "--json", "--tag", "SECRETS"])
        assert result.exit_code == 0, result.stdout
        rule_ids = {row["rule_id"] for row in json.loads(result.stdout)["rules"]}
        assert "secrets" in rule_ids

    def test_list_plugins_includes_plugins_block(self):
        result = runner.invoke(app, ["rules", "list", "--json", "--list-plugins"])
        assert result.exit_code == 0, result.stdout
        payload = json.loads(result.stdout)
        assert "plugins" in payload
        assert isinstance(payload["plugins"]["loaded"], list)
        assert isinstance(payload["plugins"]["failed"], list)


class TestRulesExplain:
    def test_explain_by_rule_id(self):
        result = runner.invoke(app, ["rules", "explain", "secrets"])
        assert result.exit_code == 0, result.stdout
        # Rule title and a known finding ID for the secrets rule
        assert "Secrets Detection" in result.stdout
        assert "SEC-ENV" in result.stdout

    def test_explain_by_finding_id_resolves_to_rule(self):
        result = runner.invoke(app, ["rules", "explain", "SEC-ENV"])
        assert result.exit_code == 0, result.stdout
        # Header line points at the parent rule, body shows the title.
        assert "SEC-ENV" in result.stdout
        assert "Secrets Detection" in result.stdout

    def test_explain_unknown_id_exits_two(self):
        result = runner.invoke(app, ["rules", "explain", "DOES-NOT-EXIST"])
        assert result.exit_code == 2
        assert "Unknown rule or finding ID" in result.stdout + result.stderr

    def test_explain_finding_id_is_case_insensitive(self):
        result = runner.invoke(app, ["rules", "explain", "sec-env"])
        assert result.exit_code == 0, result.stdout
        assert "Secrets Detection" in result.stdout

    def test_explain_surfaces_config_key_for_mismatched_rules(self):
        """`rules explain risky_diff` must point at the `risky_patterns:` YAML
        section so users can find the right key without grepping (#89)."""
        result = runner.invoke(app, ["rules", "explain", "risky_diff"])
        assert result.exit_code == 0, result.stdout
        assert "Config section" in result.stdout
        assert "risky_patterns" in result.stdout

    def test_explain_surfaces_config_key_when_it_matches_rule_id(self):
        """Even rules where config_key matches rule_id must surface the
        section name so users always know which YAML block to edit (#89)."""
        result = runner.invoke(app, ["rules", "explain", "secrets"])
        assert result.exit_code == 0, result.stdout
        assert "Config section" in result.stdout
        assert "secrets" in result.stdout

    def test_rules_list_json_includes_config_key(self):
        """`rules list --json` must expose `config_key` so integrators can
        build "go from rule id to YAML block" lookups (#89)."""
        result = runner.invoke(app, ["rules", "list", "--json"])
        assert result.exit_code == 0, result.stdout
        payload = json.loads(result.stdout)
        rows = {row["rule_id"]: row for row in payload["rules"]}
        assert rows["risky_diff"]["config_key"] == "risky_patterns"
        # The common case — rule_id and config_key match — is still emitted.
        assert rows["secrets"]["config_key"] == "secrets"
        # Every rule must declare a config_key (defaulted from rule_id at
        # registration time).
        for rule_id, row in rows.items():
            assert row["config_key"], f"{rule_id} missing config_key in JSON output"
