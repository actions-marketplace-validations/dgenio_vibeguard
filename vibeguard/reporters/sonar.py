"""SonarQube Generic Issue Import reporter (#244).

Emits SonarQube's Generic Issue Import JSON so teams whose quality dashboard is
SonarQube / SonarCloud can ingest VibeGuard findings alongside their existing
analyzers via ``sonar.externalIssuesReportPaths``.

Format: this targets the stable ``engineId``/``ruleId``/``type``/``severity``
external-issue shape documented for SonarQube (supported from 7.x through the
current 10.x line; the newer ``impacts``/``cleanCodeAttribute`` model is
accepted by 10.x but the legacy fields remain valid and the most portable).
The severity/category mapping table is documented in ``docs/output-schemas.md``.

A thin, deterministic serializer: one ``Finding`` becomes one issue.
"""

from __future__ import annotations

import json
from typing import Any

from vibeguard.models import Finding, ScanResult, Severity

_ENGINE_ID = "vibeguard"

# Finding severity -> SonarQube issue severity.
_SONAR_SEVERITY: dict[Severity, str] = {
    Severity.INFO: "INFO",
    Severity.LOW: "MINOR",
    Severity.MEDIUM: "MAJOR",
    Severity.HIGH: "CRITICAL",
    Severity.CRITICAL: "BLOCKER",
}

# Rule-family tags that mark a finding as a security vulnerability rather than a
# maintainability smell. Anything carrying one of these tags is typed
# VULNERABILITY; everything else is CODE_SMELL (VibeGuard never asserts a
# confirmed runtime BUG).
_VULNERABILITY_TAGS = frozenset(
    {
        "security",
        "secrets",
        "injection",
        "sql",
        "supply-chain",
        "auth",
        "crypto",
        "deserialization",
        "prompt-injection",
        "packaging",
        "sourcemaps",
    }
)


def _issue_type(finding: Finding) -> str:
    if _VULNERABILITY_TAGS.intersection(t.lower() for t in finding.tags):
        return "VULNERABILITY"
    return "CODE_SMELL"


def _build_issue(finding: Finding) -> dict[str, Any]:
    primary_location: dict[str, Any] = {
        "message": f"{finding.title}: {finding.description}",
        "filePath": finding.path.replace("\\", "/"),
    }
    if finding.line and finding.line > 0:
        # textRange is optional; when omitted SonarQube attaches the issue to the
        # whole file. Provide an explicit single-line range when we know it.
        primary_location["textRange"] = {
            "startLine": finding.line,
            "endLine": finding.line,
        }

    return {
        "engineId": _ENGINE_ID,
        "ruleId": finding.id,
        "type": _issue_type(finding),
        "severity": _SONAR_SEVERITY[finding.severity],
        "primaryLocation": primary_location,
    }


def render_sonar(result: ScanResult) -> str:
    """Return a SonarQube Generic Issue Import JSON string for the scan result."""
    payload: dict[str, Any] = {"issues": [_build_issue(f) for f in result.findings]}
    return json.dumps(payload, indent=2, default=str)


def print_sonar(result: ScanResult) -> None:
    """Print SonarQube generic-issue JSON to stdout."""
    print(render_sonar(result))
