"""Canonical, ordered registry of built-in rule classes (#175).

This tuple is the single source of truth for *which* rules ship with VibeGuard
and *in what order* they run. The scanner iterates it instead of a hand-written
if-chain, and ``load_all_builtin_rules`` imports it to populate the metadata
registry — so adding a built-in rule is a one-line edit here, and the scanner,
``vibeguard rules list``, and the generated rule reference can never disagree
about the rule set.

Importing this module imports every built-in rule module, which runs each
rule's ``register_rule`` call as a side effect, so ``RULE_REGISTRY`` is fully
populated afterwards.

Ordering note (#175 risk): the order below is the scan + report order. Finding
order in reports follows it, so do not reorder casually — golden reporter tests
are the safety net.
"""

from __future__ import annotations

from vibeguard.rules.agent_memory import AgentMemoryRule
from vibeguard.rules.ai_footprints import AIFootprintsRule
from vibeguard.rules.auth import AuthRule
from vibeguard.rules.base import Rule
from vibeguard.rules.ci_docker import CiDockerRule
from vibeguard.rules.dependencies import DependenciesRule
from vibeguard.rules.go_rules import GoRulesRule
from vibeguard.rules.iac import IaCRule
from vibeguard.rules.packaging import PackagingRule
from vibeguard.rules.prompt_injection import PromptInjectionRule
from vibeguard.rules.risky_diff import RiskyDiffRule
from vibeguard.rules.secrets import SecretsRule
from vibeguard.rules.slopsquat import SlopsquatRule
from vibeguard.rules.sourcemaps import SourceMapsRule
from vibeguard.rules.sql import SqlRule
from vibeguard.rules.tests import MissingTestsRule

#: Built-in rule classes in scan/report order. Each class's ``id`` resolves to a
#: ``RuleMetadata`` entry, and that metadata's ``config_key`` names the
#: ``vibeguard.yaml`` section whose ``enabled`` flag gates the rule.
BUILTIN_RULES: tuple[type[Rule], ...] = (
    SecretsRule,
    SourceMapsRule,
    PackagingRule,
    DependenciesRule,
    RiskyDiffRule,
    MissingTestsRule,
    AIFootprintsRule,
    GoRulesRule,
    CiDockerRule,
    IaCRule,
    AuthRule,
    SqlRule,
    AgentMemoryRule,
    SlopsquatRule,
    PromptInjectionRule,
)
