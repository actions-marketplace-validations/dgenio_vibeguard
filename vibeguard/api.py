"""Public, stable plugin API for VibeGuard.

This module is the **only** import path that third-party rule packages should
depend on. Symbols re-exported here are part of the stable public API:
backwards-incompatible changes to anything listed in ``__all__`` will bump
the major component of :data:`vibeguard.PLUGIN_API_VERSION`.

See ``docs/plugin-api.md`` for the full contract.

Minimal example
---------------

.. code-block:: python

    from pathlib import Path
    from vibeguard.api import (
        BaseRule,
        Confidence,
        Finding,
        RuleMetadata,
        ScanContext,
        Severity,
        register_rule,
    )


    class HelloRule(BaseRule):
        id = "hello"
        name = "Hello"
        description = "Demo plugin rule that flags TODO comments."

        def scan(self, context: ScanContext) -> list[Finding]:
            findings: list[Finding] = []
            for path in context.files:
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for lineno, line in enumerate(text.splitlines(), start=1):
                    if "TODO" in line:
                        findings.append(
                            Finding(
                                id="HELLO-TODO",
                                rule=self.id,
                                title="TODO comment found",
                                description="A TODO comment was detected.",
                                severity=Severity.LOW,
                                path=self._rel(context, path),
                                line=lineno,
                                recommendation="Resolve or remove the TODO.",
                                tags=["hello"],
                                confidence=Confidence.HIGH,
                            )
                        )
            return findings


    register_rule(
        RuleMetadata(
            rule_id="hello",
            title="Hello",
            description="Demo plugin rule that flags TODO comments.",
            finding_ids=["HELLO-TODO"],
            default_severity="low",
            confidence="high",
            tags=["demo"],
            applies_to=["*"],
        )
    )
"""

from __future__ import annotations

from vibeguard import PLUGIN_API_VERSION
from vibeguard.explain.base import ExplainAdapter
from vibeguard.explain.registry import register_explain_adapter
from vibeguard.models import (
    Confidence,
    Finding,
    GitMetadata,
    ScanContext,
    ScanResult,
    Severity,
)
from vibeguard.rules.base import BaseRule, Rule
from vibeguard.rules.registry import RULE_REGISTRY, RuleMetadata, register_rule

__all__ = [
    # API version metadata
    "PLUGIN_API_VERSION",
    # Rule authoring surface
    "BaseRule",
    "Rule",
    "Finding",
    "Severity",
    "Confidence",
    "ScanContext",
    "ScanResult",
    "GitMetadata",
    # Metadata registration
    "RuleMetadata",
    "register_rule",
    "RULE_REGISTRY",
    # Explanation-adapter authoring surface
    "ExplainAdapter",
    "register_explain_adapter",
]
