"""Shared severity-presentation table for all reporters (#194).

Every reporter renders the same :class:`~vibeguard.models.Severity` enum, but
historically each one carried its own private mapping — console colours/icons,
markdown emoji, the GitHub Actions annotation command, the SARIF level, and the
VS Code ``DiagnosticSeverity`` code. Those tables agreed only by coincidence of
maintenance: a new severity or an icon tweak had to be replicated across five
files, and a missed one shipped an inconsistent UI.

This module is the single source of truth. Reporters look a severity up here
instead of keeping a local copy, and the completeness test in
``tests/test_severity_format.py`` fails fast if a ``Severity`` member is ever
added without a presentation entry.
"""

from __future__ import annotations

from dataclasses import dataclass

from vibeguard.models import Severity


@dataclass(frozen=True)
class SeverityPresentation:
    """How one severity renders across every output format.

    Each field is owned by one reporter family:

    * ``color`` / ``icon`` — Rich console reporter.
    * ``emoji`` — Markdown / PR-comment reporter.
    * ``sarif_level`` — SARIF 2.1.0 ``result.level`` (GitHub Code Scanning).
    * ``diagnostic_code`` — VS Code ``DiagnosticSeverity`` integer (LSP).
    * ``annotation_command`` — GitHub Actions workflow-command verb.
    """

    color: str
    icon: str
    emoji: str
    sarif_level: str
    diagnostic_code: int
    annotation_command: str


# One table, keyed by every Severity member. Values are copied verbatim from the
# per-reporter tables they replace so rendered output is byte-identical.
SEVERITY_PRESENTATION: dict[Severity, SeverityPresentation] = {
    Severity.INFO: SeverityPresentation(
        color="dim white",
        icon="ℹ",
        emoji="ℹ️",
        sarif_level="note",
        diagnostic_code=3,  # Hint
        annotation_command="notice",
    ),
    Severity.LOW: SeverityPresentation(
        color="cyan",
        icon="↓",
        emoji="🔵",
        sarif_level="note",
        diagnostic_code=2,  # Information
        annotation_command="notice",
    ),
    Severity.MEDIUM: SeverityPresentation(
        color="yellow",
        icon="⚠",
        emoji="🟡",
        sarif_level="warning",
        diagnostic_code=1,  # Warning
        annotation_command="warning",
    ),
    Severity.HIGH: SeverityPresentation(
        color="red",
        icon="✗",
        emoji="🔴",
        sarif_level="error",
        diagnostic_code=0,  # Error
        annotation_command="error",
    ),
    Severity.CRITICAL: SeverityPresentation(
        color="bold red",
        icon="☠",
        emoji="💀",
        sarif_level="error",
        diagnostic_code=0,  # Error
        annotation_command="error",
    ),
}


def presentation_for(severity: Severity) -> SeverityPresentation:
    """Return the presentation entry for ``severity``.

    Raises ``KeyError`` if a severity has no entry — which the completeness test
    guarantees cannot happen for a real ``Severity`` member, so callers never
    need a fallback.
    """
    return SEVERITY_PRESENTATION[severity]
