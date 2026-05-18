"""Git utilities for VibeGuard."""

from __future__ import annotations

import subprocess
from pathlib import Path

from vibeguard.models import GitMetadata


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
