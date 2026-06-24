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

from pathlib import Path

from vibeguard import PLUGIN_API_VERSION
from vibeguard.config import VibeGuardConfig
from vibeguard.explain.base import ExplainAdapter
from vibeguard.explain.registry import register_explain_adapter
from vibeguard.explain.static import StaticExplainAdapter
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
from vibeguard.scanner import run_scan

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
    # Programmatic scanning surface
    "scan_patch",
    # Explanation-adapter authoring surface
    "ExplainAdapter",
    "StaticExplainAdapter",
    "register_explain_adapter",
]


def scan_patch(patch_text: str, base_path: Path | str | None = None) -> ScanResult:
    """Scan a unified diff standalone, before it is applied (#153).

    This is the programmatic entry point behind ``vibeguard scan --patch``: an
    orchestrator, review bot, or MCP tool can ask "is this patch safe?" as a
    pure function — no checkout, no git state, no side effects. The new side of
    every file in ``patch_text`` is reconstructed into a throwaway temporary
    tree and scanned with findings restricted to the added lines (context lines
    give structure for multi-line rules but are never themselves reported);
    :attr:`ScanResult.scan_path` is the stable placeholder ``"<patch>"``.

    Parameters
    ----------
    patch_text:
        A unified diff (``git diff`` output). Multiple files per diff are
        supported; pure-deletion targets are skipped.
    base_path:
        Optional directory used only to auto-discover a ``vibeguard.yaml``
        (so the caller's rule configuration and suppressions apply). When
        ``None`` or no config is found, built-in defaults are used. The patch
        content itself is never read from this path.

    Returns
    -------
    ScanResult
        The standard scan result — identical in shape to ``scan``/``gate``.
    """
    config = _discover_config(base_path)
    root = Path(base_path) if base_path is not None else Path(".")
    return run_scan(root, config, patch_text=patch_text)


def _discover_config(base_path: Path | str | None) -> VibeGuardConfig:
    """Load ``vibeguard.yaml`` from ``base_path`` if present, else defaults.

    Unlike the CLI loader this never exits the process: an unreadable or invalid
    config falls back to defaults so a library caller always gets a result.
    """
    if base_path is None:
        return VibeGuardConfig()
    root = Path(base_path)
    candidate = (root if root.is_dir() else root.parent) / "vibeguard.yaml"
    if not candidate.exists():
        return VibeGuardConfig()
    try:
        return VibeGuardConfig.load(candidate)
    except Exception:  # noqa: BLE001 — a library caller must still get a result
        return VibeGuardConfig()
