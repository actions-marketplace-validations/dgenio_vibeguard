"""Git utilities for VibeGuard."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from vibeguard.models import GitMetadata

# Matches unified diff hunk headers: @@ -old_start,old_count +new_start,new_count @@
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def get_git_metadata(root: Path, base_branch: str | None = None) -> GitMetadata:
    """Collect git metadata and changed file list."""
    try:
        # Verify we are in a git repo
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return GitMetadata(is_available=False, error="Not a git repository")

        branch = _run_git(root, ["git", "rev-parse", "--abbrev-ref", "HEAD"])
        commit = _run_git(root, ["git", "rev-parse", "--short", "HEAD"])

        resolved_base = base_branch or _detect_base_branch(root)
        changed_files: list[str] = []

        if resolved_base:
            raw = _run_git(
                root,
                ["git", "diff", "--name-only", f"{resolved_base}...HEAD"],
            )
            if raw:
                changed_files = [f for f in raw.splitlines() if f.strip()]

        if not changed_files:
            # Fall back to uncommitted + staged changes
            raw = _run_git(root, ["git", "diff", "--name-only", "HEAD"])
            if raw:
                changed_files = [f for f in raw.splitlines() if f.strip()]

        return GitMetadata(
            branch=branch or None,
            base_branch=resolved_base,
            commit=commit or None,
            changed_files=changed_files,
            is_available=True,
        )

    except Exception as exc:  # noqa: BLE001
        return GitMetadata(is_available=False, error=str(exc))


def _run_git(root: Path, cmd: list[str]) -> str:
    try:
        result = subprocess.run(
            cmd,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def _detect_base_branch(root: Path) -> str | None:
    """Try to detect the default base branch (main or master)."""
    for candidate in ("origin/main", "origin/master", "main", "master"):
        raw = _run_git(root, ["git", "rev-parse", "--verify", candidate])
        if raw:
            return candidate
    return None


def get_diff_text(root: Path, base_branch: str | None = None) -> str:
    """Get the unified diff text for changed files."""
    resolved_base = base_branch or _detect_base_branch(root)
    if resolved_base:
        return _run_git(root, ["git", "diff", f"{resolved_base}...HEAD"])
    # Fallback to uncommitted changes
    return _run_git(root, ["git", "diff", "HEAD"])


def parse_changed_lines(diff_text: str) -> dict[str, list[tuple[int, int]]]:
    """Parse unified diff to extract per-file added/modified line ranges.

    Returns a dict mapping relative file paths to lists of (start_line, end_line)
    tuples covering the added (``+``) lines in the new file. Context lines and
    deletions are excluded so that ``--diff`` mode filters findings down to the
    lines this change actually introduced.
    """
    added: dict[str, list[int]] = {}
    current_file: str | None = None
    new_line: int | None = None

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            added.setdefault(current_file, [])
            new_line = None
            continue

        if line.startswith("@@") and current_file is not None:
            match = _HUNK_RE.match(line)
            new_line = int(match.group(1)) if match else None
            continue

        if current_file is None or new_line is None:
            continue

        # Skip stray file headers inside multi-file diffs
        if line.startswith("+++") or line.startswith("---"):
            continue

        if line.startswith("+"):
            added[current_file].append(new_line)
            new_line += 1
        elif line.startswith("-"):
            # Removed line — does not advance the new-file counter.
            pass
        elif line.startswith("\\"):
            # "\ No newline at end of file" — metadata, skip.
            pass
        else:
            # Context line — advances the new-file counter but is not "changed".
            new_line += 1

    return {path: _coalesce_lines(lines) for path, lines in added.items()}


def _coalesce_lines(lines: list[int]) -> list[tuple[int, int]]:
    """Collapse a list of line numbers into contiguous (start, end) ranges."""
    if not lines:
        return []
    ordered = sorted(set(lines))
    ranges: list[tuple[int, int]] = []
    start = end = ordered[0]
    for n in ordered[1:]:
        if n == end + 1:
            end = n
        else:
            ranges.append((start, end))
            start = end = n
    ranges.append((start, end))
    return ranges
