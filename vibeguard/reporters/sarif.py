"""SARIF 2.1.0 reporter for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from typing import Any

from vibeguard.models import Finding, ScanResult, Severity

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _build_result(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a SARIF result object."""
    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": _SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": f"{finding.title}: {finding.description}"},
    }

    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.path.replace("\\", "/")},
        }
    }

    if finding.line and finding.line > 0:
        location["physicalLocation"]["region"] = {"startLine": finding.line}

    result["locations"] = [location]
    return result


def _build_rule(finding: Finding) -> dict[str, Any]:
    """Build a SARIF rule descriptor from a Finding."""
    return {
        "id": finding.id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL[finding.severity]},
        "properties": {
            "tags": finding.tags,
        },
    }


def render_sarif(result: ScanResult) -> str:
    """Return a SARIF 2.1.0 JSON string of the scan result."""
    # Deduplicate rules by finding ID
    seen_rules: dict[str, dict[str, Any]] = {}
    for finding in result.findings:
        if finding.id not in seen_rules:
            seen_rules[finding.id] = _build_rule(finding)

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VibeGuard",
                        "informationUri": "https://github.com/dgenio/vibeguard",
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": [_build_result(f) for f in result.findings],
            }
        ],
    }

    return json.dumps(sarif, indent=2, default=str)


def print_sarif(result: ScanResult) -> None:
    """Print SARIF output to stdout."""
    print(render_sarif(result))
