#!/usr/bin/env python3
"""Turn repeated VibeGuard findings into candidate lessonweaver LessonCards.

A runnable, dependency-free demonstration of the interop loop described in
``docs/interop-lessons.md``:

1. Scan each ``examples/pr-scenarios/`` directory, treating each one as a
   separate PR (a distinct "context").
2. Emit a weaver-spec ``ArtifactSafetyReport`` per scenario (VibeGuard's
   ``--weaver`` export).
3. Aggregate findings by **rule category** across contexts.
4. A category seen in one context is a one-off (no lesson); a category seen
   across two or more contexts is a repeated pattern → a candidate weaver-spec
   ``LessonCard`` (``lifecycle_state: in_review`` — a human reviews it before
   it ever goes active).

VibeGuard is the detection layer; lessonweaver (optional) is the learning loop.
This script imports **only** VibeGuard — the seam is serialized output, not a
runtime dependency.

Run it::

    python examples/interop/findings_to_lessons.py

"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanResult, Severity
from vibeguard.reporters.weaver import build_report
from vibeguard.scanner import run_scan

# examples/interop/findings_to_lessons.py -> repo root is two parents up.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCENARIOS_DIR = REPO_ROOT / "examples" / "pr-scenarios"

# Number of distinct PR contexts a category must appear in to be treated as a
# repeated pattern (a habit) rather than a one-off.
REPEAT_THRESHOLD = 2


def scan_scenarios(scenarios_dir: Path = SCENARIOS_DIR) -> dict[str, ScanResult]:
    """Scan every scenario directory; return ``{scenario_name: ScanResult}``."""
    results: dict[str, ScanResult] = {}
    for scenario in sorted(p for p in scenarios_dir.iterdir() if p.is_dir()):
        results[scenario.name] = run_scan(scenario, VibeGuardConfig())
    return results


def build_reports(results: dict[str, ScanResult], *, created_at: str) -> dict[str, dict]:
    """Build one advisory ArtifactSafetyReport per scenario."""
    return {
        name: build_report(
            result,
            threshold=Severity.HIGH,
            blocking=False,
            created_at=created_at,
            target_ref=f"pr-scenario:{name}",
        )
        for name, result in results.items()
    }


def build_lesson_cards(
    results: dict[str, ScanResult],
    *,
    created_at: str,
    repeat_threshold: int = REPEAT_THRESHOLD,
) -> list[dict]:
    """Aggregate findings by rule category and mint candidate LessonCards.

    A category appearing in ``repeat_threshold`` or more distinct scenario
    contexts is treated as a repeated pattern and gets a candidate
    ``LessonCard`` in the ``in_review`` lifecycle state.
    """
    # rule category -> {"contexts": {scenario, ...}, "finding_ids": {...},
    #                   "fingerprints": {...}}
    by_category: dict[str, dict] = {}
    for scenario, result in results.items():
        for finding in result.findings:
            agg = by_category.setdefault(
                finding.rule,
                {"contexts": set(), "finding_ids": set(), "fingerprints": set()},
            )
            agg["contexts"].add(scenario)
            agg["finding_ids"].add(finding.id)
            agg["fingerprints"].add(f"vibeguard:fingerprint:{finding.fingerprint}")

    lessons: list[dict] = []
    for rule in sorted(by_category):
        agg = by_category[rule]
        if len(agg["contexts"]) < repeat_threshold:
            continue  # one-off — a fix, not a lesson
        contexts = sorted(agg["contexts"])
        finding_ids = sorted(agg["finding_ids"])
        lessons.append(
            {
                "lesson_id": f"vibeguard-lesson-{rule}",
                "title": f"Review {rule} findings before merging ({rule})",
                "body": (
                    f"VibeGuard flagged the {rule} category across "
                    f"{len(contexts)} separate changes "
                    f"({', '.join(finding_ids)}). A recurring pattern across "
                    "PRs is a habit, not a one-off — review and address it at "
                    "the source rather than per-PR."
                ),
                "created_at": created_at,
                "lifecycle_state": "in_review",
                "scope": "repo",
                "applicability": [rule, *finding_ids],
                "source_refs": sorted(agg["fingerprints"]),
                "provenance": {
                    "tool": "VibeGuard",
                    "derived_from": "repeated ArtifactSafetyReport findings",
                },
            }
        )
    return lessons


def main() -> int:
    if not SCENARIOS_DIR.is_dir():
        print(f"scenario dir not found: {SCENARIOS_DIR}", file=sys.stderr)
        return 1

    # A fixed timestamp keeps this demo's output reproducible; real runs would
    # let build_report() stamp the current time.
    created_at = "2026-06-04T00:00:00+00:00"

    results = scan_scenarios()
    reports = build_reports(results, created_at=created_at)
    lessons = build_lesson_cards(results, created_at=created_at)

    repeated = {lesson["applicability"][0] for lesson in lessons}
    one_off = sorted({f.rule for r in results.values() for f in r.findings} - repeated)

    print("=== ArtifactSafetyReports (one advisory report per PR scenario) ===")
    for name in sorted(reports):
        report = reports[name]
        print(f"  {name}: decision={report['decision']} findings={len(report['findings'])}")

    print(f"\n=== Repeated categories (>= {REPEAT_THRESHOLD} PRs) -> candidate lessons ===")
    print(json.dumps(lessons, indent=2))

    print("\n=== One-off categories (seen in a single PR; no lesson minted) ===")
    print(f"  {', '.join(one_off) if one_off else '(none)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
