"""Inline suppression parser for VibeGuard."""

from __future__ import annotations

import re

# Matches: # vibeguard: ignore ID1,ID2 reason="some reason"
# Or:      // vibeguard: ignore ID1 reason="reason"
_SUPPRESSION_RE = re.compile(
    r"(?:#|//|/\*)\s*vibeguard:\s*ignore\s+"
    r"(?P<ids>[A-Z][A-Z0-9\-,]+)"
    r'(?:\s+reason\s*=\s*"(?P<reason>[^"]*)")?'
)


def parse_inline_suppressions(content: str) -> dict[int, list[str]]:
    """Parse inline suppression comments from file content.

    Returns a mapping of line_number -> list of suppressed finding IDs.
    Line numbers are 1-based.
    """
    suppressions: dict[int, list[str]] = {}
    for lineno, line in enumerate(content.splitlines(), start=1):
        match = _SUPPRESSION_RE.search(line)
        if match:
            ids = [fid.strip() for fid in match.group("ids").split(",") if fid.strip()]
            suppressions[lineno] = ids
    return suppressions


def find_missing_reasons(content: str) -> list[tuple[int, list[str]]]:
    """Find inline suppressions that are missing a reason= argument.

    Returns list of (line_number, finding_ids) for suppressions without reasons.
    """
    missing: list[tuple[int, list[str]]] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        match = _SUPPRESSION_RE.search(line)
        if match:
            reason = match.group("reason")
            if reason is None or reason.strip() == "":
                ids = [fid.strip() for fid in match.group("ids").split(",") if fid.strip()]
                missing.append((lineno, ids))
    return missing
