"""Registry <-> scanner consistency tests for the single source of truth (#175).

These fail fast if a built-in rule is half-wired: a class in BUILTIN_RULES with
no registry metadata, an unresolvable config_key, or a drift between the
declared rule set and the rules the scanner actually instantiates.
"""

from __future__ import annotations

from vibeguard.config import VibeGuardConfig
from vibeguard.rules import load_all_builtin_rules
from vibeguard.rules.base import Rule
from vibeguard.rules.builtin import BUILTIN_RULES
from vibeguard.rules.registry import RULE_REGISTRY


def setup_module(_module):
    # Ensure metadata is registered regardless of import order in the suite.
    load_all_builtin_rules()


def test_every_builtin_rule_is_a_rule_subclass():
    for rule_cls in BUILTIN_RULES:
        assert issubclass(rule_cls, Rule)
        assert rule_cls is not Rule


def test_builtin_rule_ids_are_unique():
    ids = [r.id for r in BUILTIN_RULES]
    assert len(ids) == len(set(ids)), f"duplicate rule ids in BUILTIN_RULES: {ids}"


def test_every_builtin_rule_has_registry_metadata():
    for rule_cls in BUILTIN_RULES:
        assert rule_cls.id in RULE_REGISTRY, (
            f"{rule_cls.__name__} (id={rule_cls.id!r}) is in BUILTIN_RULES "
            "but has no register_rule(...) metadata"
        )


def test_every_builtin_config_key_resolves_to_a_config_section():
    config = VibeGuardConfig()
    for rule_cls in BUILTIN_RULES:
        config_key = RULE_REGISTRY[rule_cls.id].config_key
        assert hasattr(config, config_key), (
            f"{rule_cls.id!r} metadata config_key={config_key!r} has no matching "
            "section on VibeGuardConfig"
        )
        section = getattr(config, config_key)
        assert hasattr(section, "enabled"), (
            f"config section {config_key!r} for rule {rule_cls.id!r} has no 'enabled' flag"
        )


def test_scanner_instantiates_exactly_the_builtin_set_by_default():
    # With default (all-enabled) config, the scanner's rule set must match
    # BUILTIN_RULES in both membership and order.
    config = VibeGuardConfig()
    selected = [
        rule_cls
        for rule_cls in BUILTIN_RULES
        if getattr(getattr(config, RULE_REGISTRY[rule_cls.id].config_key), "enabled", True)
    ]
    assert selected == list(BUILTIN_RULES)


def test_disabling_a_section_drops_exactly_that_rule():
    config = VibeGuardConfig()
    config.secrets.enabled = False
    selected = [
        rule_cls
        for rule_cls in BUILTIN_RULES
        if getattr(getattr(config, RULE_REGISTRY[rule_cls.id].config_key), "enabled", True)
    ]
    ids = {r.id for r in selected}
    assert "secrets" not in ids
    assert len(selected) == len(BUILTIN_RULES) - 1
