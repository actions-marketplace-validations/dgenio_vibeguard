#!/usr/bin/env python3
"""Guard against version/release drift across docs (issues #86, #87, #94).

This is the mechanical backstop for ``docs/release-checklist.md``. It checks
the surfaces that have silently drifted before, **without** touching the
network or asserting which tags exist on GitHub/PyPI:

1. Every ``dgenio/vibeguard@vX.Y.Z`` reference across the README, ``docs/``,
   and ``action.yml`` pins the *same* tag — duplicated PR-gate snippets must
   not drift apart.
2. Plugin pin examples (``vibeguard-gate>=…``) use an open-ended,
   API-tracking lower bound, not an exclusive upper bound that would exclude
   the current release (the #86 failure mode, e.g. ``>=0.6,<0.7``).
3. The README documents the canonical PyPI install (``pip install
   vibeguard-gate``).

Usage::

    python scripts/check_doc_versions.py        # exit 1 on drift
    python scripts/check_doc_versions.py --root /path/to/repo
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ``dgenio/vibeguard@v0.8.0`` — capture the tag. The version must start with a
# digit so documentation placeholders (``@vX.Y.Z``, ``@v<version>``) are not
# mistaken for real pins. Real pins are what must stay consistent.
_ACTION_REF = re.compile(r"dgenio/vibeguard@(v\d[\w.]*)")

# An exclusive upper bound on the plugin pin, e.g. ``vibeguard-gate>=0.6,<0.7``.
# The plugin contract tracks PLUGIN_API_VERSION, so the published guidance is
# an open-ended lower bound; an upper bound silently excludes new releases.
_PLUGIN_PIN_WITH_UPPER = re.compile(r"vibeguard-gate\s*>=\s*[\d.]+\s*,\s*<\s*[\d.]+")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _doc_paths(root: Path) -> list[Path]:
    """README, every ``docs/*.md``, and the action manifest."""
    paths: list[Path] = [root / "README.md", root / "action.yml"]
    paths.extend(sorted((root / "docs").rglob("*.md")))
    return [p for p in paths if p.exists()]


def check(root: Path = REPO_ROOT) -> list[str]:
    """Return a list of human-readable drift errors (empty == clean)."""
    errors: list[str] = []
    paths = _doc_paths(root)

    # 1. Action-ref consistency.
    refs: dict[str, list[str]] = {}
    for path in paths:
        for ref in _ACTION_REF.findall(_read(path)):
            refs.setdefault(ref, []).append(str(path.relative_to(root)))
    if len(refs) > 1:
        detail = "; ".join(f"{tag} in {sorted(set(files))}" for tag, files in sorted(refs.items()))
        errors.append(
            "dgenio/vibeguard@<tag> references disagree across docs — they "
            f"must all pin the same tag: {detail}. See docs/release-checklist.md."
        )

    # 2. Plugin pin must not carry an excluding upper bound.
    for path in paths:
        for match in _PLUGIN_PIN_WITH_UPPER.findall(_read(path)):
            errors.append(
                f"{path.relative_to(root)} pins a plugin range with an upper "
                f"bound ({match!r}); use an open-ended `vibeguard-gate>=X.Y` "
                "that tracks PLUGIN_API_VERSION. See #86 / docs/plugin-api.md."
            )

    # 3. README must document the PyPI install path.
    readme = root / "README.md"
    if readme.exists() and "pip install vibeguard-gate" not in _read(readme):
        errors.append(
            "README.md no longer documents `pip install vibeguard-gate` — the "
            "canonical PyPI adoption path. See docs/release-checklist.md."
        )

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root to check (default: the repo this script lives in)",
    )
    args = parser.parse_args(argv)

    errors = check(args.root)
    if errors:
        print("[check_doc_versions] version/doc drift detected:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print("[check_doc_versions] no version/doc drift detected")
    return 0


if __name__ == "__main__":  # pragma: no cover — CLI entry point
    sys.exit(main())
