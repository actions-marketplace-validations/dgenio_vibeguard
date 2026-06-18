"""GitHub Actions annotation reporter."""

from __future__ import annotations

import os

from vibeguard.models import Finding, ScanResult
from vibeguard.reporters._format import SEVERITY_PRESENTATION


def is_github_actions() -> bool:
    """Return True if running inside GitHub Actions."""
    return os.environ.get("GITHUB_ACTIONS") == "true"


def _escape_property(value: str) -> str:
    """Escape a workflow command property value (the ``key=value`` segment).

    Per the GitHub Actions workflow-command spec, property values must escape
    ``%``, ``\\r``, ``\\n``, ``:`` and ``,`` — the last two would otherwise
    terminate the property or be read as a delimiter.
    """
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace(":", "%3A")
        .replace(",", "%2C")
    )


def _escape_message(value: str) -> str:
    """Escape a workflow command message body.

    Messages must escape ``%``, ``\\r`` and ``\\n``; ``:`` and ``,`` are
    allowed in the body since the body is everything after the ``::``.
    """
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _format_annotation(finding: Finding) -> str:
    """Format a single finding as a GitHub Actions workflow command."""
    cmd = SEVERITY_PRESENTATION[finding.severity].annotation_command
    parts = [f"file={_escape_property(finding.path.replace(chr(92), '/'))}"]
    if finding.line and finding.line > 0:
        parts.append(f"line={finding.line}")
    parts.append(f"title={_escape_property(f'{finding.id}: {finding.title}')}")
    params = ",".join(parts)
    message = f"{finding.id}: {finding.title}. Severity: {finding.severity.value}."
    if finding.recommendation:
        message += f" {finding.recommendation}"
    return f"::{cmd} {params}::{_escape_message(message)}"


def render_annotations(result: ScanResult) -> str:
    """Return GitHub Actions workflow command annotations for all findings."""
    lines = [_format_annotation(f) for f in result.findings]
    return "\n".join(lines)


def emit_annotations(result: ScanResult) -> None:
    """Print annotations to stdout (for GitHub Actions to pick up)."""
    output = render_annotations(result)
    if output:
        print(output)
