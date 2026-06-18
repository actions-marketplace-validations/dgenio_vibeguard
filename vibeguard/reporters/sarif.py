"""SARIF 2.1.0 reporter for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from typing import Any

from vibeguard.baseline import compute_fingerprint
from vibeguard.models import Finding, Remediation, RemediationKind, ScanResult, Severity
from vibeguard.reporters._format import SEVERITY_PRESENTATION

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# GitHub Code Scanning rejects SARIF uploads beyond a documented number of
# results per run (5,000 at time of writing). Cap below that by default so a
# first scan of a large legacy repo degrades gracefully — keeping the most
# severe findings — instead of failing the whole upload (#227). Configurable
# via ``output.sarif_max_results``.
DEFAULT_SARIF_MAX_RESULTS = 5000


def _sarif_level(severity: Severity) -> str:
    return SEVERITY_PRESENTATION[severity].sarif_level


def _build_fixes(finding: Finding) -> list[dict[str, Any]] | None:
    """Map a finding's structured remediation to SARIF ``fixes`` (#238).

    Only the kinds that name a precise, single-file edit (``replace-span`` and
    ``add-line``) become SARIF fixes — GitHub renders these as one-click
    suggested changes. ``add-ignore-entry`` / ``delete-file`` / ``manual``
    can't be expressed as an in-file region edit, so they ride along in the
    JSON output only. Returns ``None`` when there is no SARIF-expressible fix,
    so the ``fixes`` property is simply omitted.
    """
    rem: Remediation | None = finding.remediation
    if rem is None:
        return None
    if rem.kind not in (RemediationKind.REPLACE_SPAN, RemediationKind.ADD_LINE):
        return None
    line = rem.line if rem.line and rem.line > 0 else finding.line
    if not line or line <= 0:
        return None

    target = (rem.target or finding.path).replace("\\", "/")
    replacement: dict[str, Any]
    if rem.kind == RemediationKind.ADD_LINE:
        # Insert before ``line``: a zero-width deleted region at column 1 plus
        # the inserted text (newline-terminated so it lands on its own line).
        replacement = {
            "deletedRegion": {"startLine": line, "startColumn": 1, "endColumn": 1},
            "insertedContent": {"text": (rem.content or "") + "\n"},
        }
    else:  # REPLACE_SPAN
        replacement = {"deletedRegion": {"startLine": line, "endLine": line}}
        if rem.content:
            replacement["insertedContent"] = {"text": rem.content}

    return [
        {
            "description": {"text": rem.description},
            "artifactChanges": [
                {
                    "artifactLocation": {"uri": target},
                    "replacements": [replacement],
                }
            ],
        }
    ]


def _build_result(finding: Finding) -> dict[str, Any]:
    """Convert a Finding to a SARIF result object."""
    result: dict[str, Any] = {
        "ruleId": finding.id,
        "level": _sarif_level(finding.severity),
        "message": {"text": f"{finding.title}: {finding.description}"},
    }

    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.path.replace("\\", "/")},
        }
    }

    if finding.line and finding.line > 0:
        # SARIF 2.1.0 §3.30: a region with only `startLine` is technically
        # valid but ambiguous; setting `endLine` to the same line makes the
        # single-line span explicit for downstream consumers.
        location["physicalLocation"]["region"] = {
            "startLine": finding.line,
            "endLine": finding.line,
        }

    result["locations"] = [location]
    # SARIF 2.1.0 §3.27.23 partialFingerprints — used by GitHub Code Scanning
    # (and other consumers) to deduplicate the same finding across runs even
    # when line numbers shift. Reuse the same fingerprint scheme as the
    # baseline module so a finding's identity is stable end-to-end.
    result["partialFingerprints"] = {"vibeguard/v1": compute_fingerprint(finding)}

    # SARIF 2.1.0 §3.55 fixes — machine-actionable suggested edits (#238).
    fixes = _build_fixes(finding)
    if fixes is not None:
        result["fixes"] = fixes
    return result


def _build_rule(finding: Finding) -> dict[str, Any]:
    """Build a SARIF rule descriptor from a Finding."""
    return {
        "id": finding.id,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description},
        "defaultConfiguration": {"level": _sarif_level(finding.severity)},
        "properties": {
            "tags": finding.tags,
        },
    }


def _overflow_invocation(total: int, cap: int) -> dict[str, Any]:
    """Build an invocation carrying an overflow notification (#227)."""
    text = (
        f"VibeGuard found {total} findings but this SARIF run is capped at {cap} "
        "results (GitHub Code Scanning ingestion limit). The most severe findings "
        "are included, ordered by severity. Run `vibeguard scan --json` (or use a "
        "baseline workflow) to obtain the full set."
    )
    return {
        "executionSuccessful": True,
        "toolExecutionNotifications": [
            {
                "level": "note",
                "message": {"text": text},
            }
        ],
    }


def render_sarif(result: ScanResult, *, max_results: int = DEFAULT_SARIF_MAX_RESULTS) -> str:
    """Return a SARIF 2.1.0 JSON string of the scan result.

    When the number of findings exceeds ``max_results``, the run is capped: the
    findings are ordered by severity (then path, then line for determinism), the
    top ``max_results`` are emitted, and an informational
    ``toolExecutionNotifications`` entry records the overflow (#227). For result
    sets at or below the cap the output is byte-identical to the historical
    reporter — findings keep their original order and no invocation is added.
    """
    findings = list(result.findings)
    truncated = len(findings) > max_results
    if truncated:
        # Severity-first so the gate-relevant findings survive the cap; path/line
        # as stable tie-breakers keep the output deterministic.
        findings.sort(
            key=lambda f: (f.severity, f.path, f.line or 0),
            reverse=True,
        )
        findings = findings[:max_results]

    # Deduplicate rules by finding ID (over the emitted set only).
    seen_rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if finding.id not in seen_rules:
            seen_rules[finding.id] = _build_rule(finding)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "VibeGuard",
                "informationUri": "https://github.com/dgenio/vibeguard",
                "rules": list(seen_rules.values()),
            }
        },
        "results": [_build_result(f) for f in findings],
    }
    if truncated:
        run["invocations"] = [_overflow_invocation(len(result.findings), max_results)]

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [run],
    }

    return json.dumps(sarif, indent=2, default=str)


def print_sarif(result: ScanResult, *, max_results: int = DEFAULT_SARIF_MAX_RESULTS) -> None:
    """Print SARIF output to stdout."""
    print(render_sarif(result, max_results=max_results))
