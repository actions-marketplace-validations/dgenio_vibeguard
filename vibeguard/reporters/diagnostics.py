"""Machine-readable diagnostics reporter for editor / IDE integrations.

Emits a stable, documented JSON array shaped like the VS Code
``DiagnosticSeverity`` model so editor extensions and AI coding agents can
consume VibeGuard findings without reverse-engineering the rest of the JSON
report. The schema is versioned via ``data.schema`` on every record and is
documented in ``docs/output-schemas.md``.
"""

from __future__ import annotations

import json
from typing import Any

from vibeguard.models import Finding, ScanResult, Severity
from vibeguard.reporters._format import SEVERITY_PRESENTATION

DIAGNOSTICS_SCHEMA = "vibeguard/diagnostics/v1"

# VS Code DiagnosticSeverity numeric codes. Documented so IDE plugins can rely
# on them without consulting the ``Severity`` enum. Derived from the shared
# presentation table (#194) so the codes can never drift from the other
# reporters; kept as a module-level name because it is part of this reporter's
# documented surface (see docs/output-schemas.md).
SEVERITY_TO_CODE: dict[Severity, int] = {
    sev: pres.diagnostic_code for sev, pres in SEVERITY_PRESENTATION.items()
}

_SOURCE = "vibeguard"


def _build_record(finding: Finding) -> dict[str, Any]:
    line = finding.line if finding.line and finding.line > 0 else 1
    # IDE diagnostics use 0-based line/character offsets (LSP). Findings carry
    # 1-based line numbers; convert here once, in the reporter, so the rest
    # of the codebase keeps the 1-based convention used elsewhere.
    line_zero = line - 1
    record: dict[str, Any] = {
        "severity": SEVERITY_TO_CODE[finding.severity],
        "code": finding.id,
        "source": _SOURCE,
        "message": finding.title,
        "file": finding.path.replace("\\", "/"),
        "range": {
            "start": {"line": line_zero, "character": 0},
            "end": {"line": line_zero, "character": 0},
        },
        # Top-level ``tags`` follows LSP semantics: a list of DiagnosticTag
        # integers (1=Unnecessary, 2=Deprecated). VibeGuard's category tags
        # (rule families like "secrets", "supply-chain") don't map onto that
        # enum, so they're emitted under ``data.tags`` and the top-level
        # field stays empty for strict consumers.
        "tags": [],
        "data": {
            "schema": DIAGNOSTICS_SCHEMA,
            "fingerprint": finding.fingerprint,
            "rule": finding.rule,
            "tags": list(finding.tags),
            "confidence": finding.confidence.value,
            "severity_label": finding.severity.value,
            "description": finding.description,
            "recommendation": finding.recommendation,
        },
    }
    if finding.evidence:
        record["data"]["evidence"] = finding.evidence
    return record


def render_diagnostics(result: ScanResult) -> str:
    """Return a JSON string with the diagnostics array."""
    records = [_build_record(f) for f in result.findings]
    return json.dumps(records, indent=2, default=str)


def print_diagnostics(result: ScanResult) -> None:
    """Print diagnostics JSON to stdout."""
    print(render_diagnostics(result))
