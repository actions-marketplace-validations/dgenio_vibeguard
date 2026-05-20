"""GitHub Actions annotation reporter."""

from __future__ import annotations

import os

from vibeguard.models import Finding, ScanResult, Severity

_SEVERITY_TO_COMMAND: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}


def is_github_actions() -> bool:
    """Return True if running inside GitHub Actions."""
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _format_annotation(finding: Finding) -> str:
    """Format a single finding as a GitHub Actions workflow command."""
    cmd = _SEVERITY_TO_COMMAND[finding.severity]
    parts = [f"file={finding.path.replace(chr(92), '/')}"]
    if finding.line and finding.line > 0:
        parts.append(f"line={finding.line}")
    parts.append(f"title={finding.id}: {finding.title}")
    params = ",".join(parts)
    message = f"{finding.id}: {finding.title}. Severity: {finding.severity.value}."
    if finding.recommendation:
        message += f" {finding.recommendation}"
    return f"::{cmd} {params}::{message}"


def render_annotations(result: ScanResult) -> str:
    """Return GitHub Actions workflow command annotations for all findings."""
    lines = [_format_annotation(f) for f in result.findings]
    return "\n".join(lines)


def emit_annotations(result: ScanResult) -> None:
    """Print annotations to stdout (for GitHub Actions to pick up)."""
    output = render_annotations(result)
    if output:
        print(output)
