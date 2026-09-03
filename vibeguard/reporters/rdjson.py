"""reviewdog Diagnostic Format (rdjson) reporter (#237).

Emits reviewdog's ``DiagnosticResult`` JSON so VibeGuard plugs into reviewdog's
matrix of review backends (GitHub PR reviews, GitLab MRs, Gerrit, Bitbucket,
local ``-diff`` filtering) without VibeGuard maintaining any of them itself.
The format is documented upstream at
https://github.com/reviewdog/reviewdog/blob/master/proto/rdf/README.md and
consumed via ``reviewdog -f=rdjson``.

This is a thin, deterministic serializer: one ``Finding`` becomes one rdjson
``Diagnostic``. Output is stable (insertion order preserved, ``sort_keys`` off
to match the other reporters) so it is golden-testable.
"""

from __future__ import annotations

import json
from typing import Any

from vibeguard.models import Finding, ScanResult, Severity

_SOURCE = {
    "name": "vibeguard",
    "url": "https://github.com/dgenio/vibeguard",
}

# rdjson severity enum: UNKNOWN_SEVERITY | ERROR | WARNING | INFO.
# Mapping mirrors the issue spec: INFO/LOW -> INFO, MEDIUM -> WARNING,
# HIGH/CRITICAL -> ERROR.
_RDJSON_SEVERITY: dict[Severity, str] = {
    Severity.INFO: "INFO",
    Severity.LOW: "INFO",
    Severity.MEDIUM: "WARNING",
    Severity.HIGH: "ERROR",
    Severity.CRITICAL: "ERROR",
}

# Anchor format matches the slugs generated in docs/rules.md (lower-cased rule
# id). The code.url gives reviewers a one-click jump to the rule reference.
_RULES_DOC = "https://github.com/dgenio/vibeguard/blob/main/docs/rules.md"


def _rule_url(finding: Finding) -> str:
    return f"{_RULES_DOC}#{finding.rule.lower().replace('_', '-')}"


def _build_diagnostic(finding: Finding) -> dict[str, Any]:
    # reviewdog locations are 1-based; column is optional but a value of 1 keeps
    # consumers that require it happy without implying a real column.
    line = finding.line if finding.line and finding.line > 0 else 1
    diagnostic: dict[str, Any] = {
        "message": f"{finding.title}: {finding.description}",
        "location": {
            "path": finding.path.replace("\\", "/"),
            "range": {"start": {"line": line, "column": 1}},
        },
        "severity": _RDJSON_SEVERITY[finding.severity],
        "code": {"value": finding.id, "url": _rule_url(finding)},
        "source": _SOURCE,
    }
    return diagnostic


def render_rdjson(result: ScanResult) -> str:
    """Return a reviewdog ``DiagnosticResult`` JSON string for the scan result."""
    payload: dict[str, Any] = {
        "source": _SOURCE,
        "severity": "WARNING",
        "diagnostics": [_build_diagnostic(f) for f in result.findings],
    }
    return json.dumps(payload, indent=2, default=str)


def print_rdjson(result: ScanResult) -> None:
    """Print rdjson output to stdout."""
    print(render_rdjson(result))
