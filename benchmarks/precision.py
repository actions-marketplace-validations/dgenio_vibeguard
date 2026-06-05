"""Precision / recall / F1 on the labeled AI-PR corpus (#115).

Where :mod:`benchmarks.scenarios` reports *what* VibeGuard detects on a
handful of realistic fixtures, this harness measures *how trustworthy the
blocking gate is* on the labeled true-positive / false-positive corpus under
``tests/fixtures/corpus/``.

Each case directory is named ``tp_*`` (a real risk the gate should block)
or ``fp_*`` (a benign change the gate must not block). For every rule family
we treat "the gate flags this case" as "it produced a finding at or above the
*actionable* severity tier (HIGH/CRITICAL)" — the same decision
``vibeguard gate --fail-on high`` makes — and derive:

* **precision** = TP / (TP + FP) — of the cases the gate blocked, how many
  were genuine risks (the metric that decides whether teams trust
  ``--fail-on``);
* **recall** = TP / (TP + FN) — of the genuine risks, how many the gate
  caught;
* **F1** = the harmonic mean.

We also report a severity-agnostic **detection recall** so advisory-tier
rules (``risky_diff`` is MEDIUM, ``ai_footprints`` can be INFO) aren't
misread as "missing" just because they intentionally don't block.

The harness is deterministic and offline — findings don't vary between runs,
so the output is safe to diff or snapshot.

Run it::

    python -m benchmarks.precision             # human-readable table
    python -m benchmarks.precision --json       # machine-readable
    python -m benchmarks.precision --markdown    # regenerate docs/precision-report.md

The committed report lives at ``docs/precision-report.md``; the live CI
regression guard is ``tests/test_corpus_precision.py`` (every ``tp_`` case
must fire, every ``fp_`` case must stay below the actionable tier).
"""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vibeguard.config import VibeGuardConfig
from vibeguard.models import Severity
from vibeguard.scanner import run_scan

CORPUS_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "corpus"

# Directory name -> rule.id values that count as a "hit" for that family.
# Mirrors ``_RULE_FAMILIES`` in tests/test_corpus_precision.py (the live CI
# guard); test_corpus_categories_are_known there fails if the two drift.
_RULE_FAMILIES: dict[str, set[str]] = {
    "secrets": {"secrets"},
    "risky_diff": {"risky_diff"},
    "auth": {"auth", "ai_footprints"},
    "sourcemaps": {"sourcemaps"},
    "dependencies": {"dependencies"},
    "packaging": {"packaging"},
    "ai_footprints": {"ai_footprints", "auth", "risky_diff"},
}

_ACTIONABLE = Severity.HIGH  # gate blocks at HIGH/CRITICAL by default


@dataclass
class FamilyStats:
    """Confusion-matrix counts for one rule family at the actionable tier."""

    tp: int = 0  # tp_ case blocked (correct)
    fn: int = 0  # tp_ case not blocked (miss)
    fp: int = 0  # fp_ case blocked (false alarm)
    tn: int = 0  # fp_ case not blocked (correct)
    detected_any: int = 0  # tp_ case that fired any family finding
    tp_total: int = 0  # number of tp_ cases

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def detection_recall(self) -> float:
        return self.detected_any / self.tp_total if self.tp_total else 1.0


def _stage_case(case_path: Path, root: Path) -> None:
    """Recreate a corpus case's file layout under ``root`` for scanning."""
    if case_path.is_dir():
        for child in case_path.rglob("*"):
            if child.is_file():
                out = root / child.relative_to(case_path)
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(child, out)
    else:
        out = root / case_path.name
        shutil.copy(case_path, out)


def _scan_case(case_path: Path) -> list:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "repo"
        repo.mkdir()
        _stage_case(case_path, repo)
        # ``strict`` surfaces the broadest set of findings, matching the
        # corpus test, so precision is measured against the noisiest policy.
        result = run_scan(repo, VibeGuardConfig(policy="strict"))
        return list(result.findings)


def evaluate() -> dict[str, FamilyStats]:
    """Build per-family confusion-matrix stats across the whole corpus."""
    stats: dict[str, FamilyStats] = defaultdict(FamilyStats)
    for category_dir in sorted(CORPUS_DIR.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("__"):
            continue
        family = _RULE_FAMILIES.get(category_dir.name)
        if family is None:
            continue
        st = stats[category_dir.name]
        for case in sorted(category_dir.iterdir()):
            if not (case.name.startswith("tp_") or case.name.startswith("fp_")):
                continue
            findings = [f for f in _scan_case(case) if f.rule in family]
            blocked = any(f.severity >= _ACTIONABLE for f in findings)
            if case.name.startswith("tp_"):
                st.tp_total += 1
                if findings:
                    st.detected_any += 1
                if blocked:
                    st.tp += 1
                else:
                    st.fn += 1
            else:  # fp_
                if blocked:
                    st.fp += 1
                else:
                    st.tn += 1
    return dict(stats)


def _aggregate(stats: dict[str, FamilyStats]) -> FamilyStats:
    total = FamilyStats()
    for st in stats.values():
        total.tp += st.tp
        total.fn += st.fn
        total.fp += st.fp
        total.tn += st.tn
        total.detected_any += st.detected_any
        total.tp_total += st.tp_total
    return total


def _to_json(stats: dict[str, FamilyStats]) -> dict[str, Any]:
    def row(st: FamilyStats) -> dict[str, Any]:
        return {
            "tp": st.tp,
            "fn": st.fn,
            "fp": st.fp,
            "tn": st.tn,
            "precision": round(st.precision, 4),
            "recall": round(st.recall, 4),
            "f1": round(st.f1, 4),
            "detection_recall": round(st.detection_recall, 4),
        }

    return {
        "tier": "actionable (HIGH/CRITICAL)",
        "families": {name: row(st) for name, st in sorted(stats.items())},
        "overall": row(_aggregate(stats)),
    }


def _format_text(stats: dict[str, FamilyStats]) -> str:
    lines = [
        "VibeGuard precision / recall on the labeled AI-PR corpus",
        "(blocking tier = HIGH/CRITICAL; the decision `gate --fail-on high` makes)",
        "",
        f"  {'family':<14} {'P':>6} {'R':>6} {'F1':>6}  "
        f"{'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  {'det.R':>6}",
        f"  {'-' * 14} {'-' * 6} {'-' * 6} {'-' * 6}  "
        f"{'-' * 3} {'-' * 3} {'-' * 3} {'-' * 3}  {'-' * 6}",
    ]
    for name, st in sorted(stats.items()):
        lines.append(
            f"  {name:<14} {st.precision:>6.2f} {st.recall:>6.2f} {st.f1:>6.2f}  "
            f"{st.tp:>3} {st.fp:>3} {st.fn:>3} {st.tn:>3}  {st.detection_recall:>6.2f}"
        )
    agg = _aggregate(stats)
    lines += [
        f"  {'-' * 14}",
        f"  {'OVERALL':<14} {agg.precision:>6.2f} {agg.recall:>6.2f} {agg.f1:>6.2f}  "
        f"{agg.tp:>3} {agg.fp:>3} {agg.fn:>3} {agg.tn:>3}  {agg.detection_recall:>6.2f}",
    ]
    return "\n".join(lines)


def _format_markdown(stats: dict[str, FamilyStats]) -> str:
    agg = _aggregate(stats)
    lines = [
        "# VibeGuard precision report",
        "",
        "<!-- Generated by `make bench-precision` / "
        "`python -m benchmarks.precision --markdown`. Do not edit by hand. -->",
        "",
        "Precision, recall and F1 on the labeled AI-PR corpus under",
        "`tests/fixtures/corpus/`, measured at the **actionable tier** (HIGH/CRITICAL) —",
        "the decision `vibeguard gate --fail-on high` makes. A case is *blocked* when",
        "it produces a finding at or above HIGH in the relevant rule family.",
        "",
        "* **Precision** — of the cases the gate blocked, the fraction that were genuine risks.",
        "* **Recall** — of the genuine risks, the fraction the gate caught.",
        "* **Detection recall** — the fraction of true-positive cases that "
        "produced *any* finding, regardless of severity (advisory-tier rules "
        "like `risky_diff`/`ai_footprints` detect but don't block).",
        "",
        "| Rule family | Precision | Recall | F1 | TP | FP | FN | TN | Detection recall |",
        "| --- | --: | --: | --: | --: | --: | --: | --: | --: |",
    ]
    for name, st in sorted(stats.items()):
        lines.append(
            f"| `{name}` | {st.precision:.2f} | {st.recall:.2f} | {st.f1:.2f} "
            f"| {st.tp} | {st.fp} | {st.fn} | {st.tn} | {st.detection_recall:.2f} |"
        )
    lines.append(
        f"| **Overall** | **{agg.precision:.2f}** | **{agg.recall:.2f}** | "
        f"**{agg.f1:.2f}** | {agg.tp} | {agg.fp} | {agg.fn} | {agg.tn} | "
        f"{agg.detection_recall:.2f} |"
    )
    lines += [
        "",
        "The live regression guard is `tests/test_corpus_precision.py`, which "
        "fails CI if any `tp_` case stops firing or any `fp_` case starts "
        "producing an actionable (HIGH/CRITICAL) finding. Regenerate this "
        "report with `make bench-precision` after adding corpus cases.",
        "",
    ]
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure VibeGuard precision/recall/F1 on the labeled corpus."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    group.add_argument(
        "--markdown",
        action="store_true",
        help="Write the Markdown report to docs/precision-report.md",
    )
    args = parser.parse_args(argv)

    stats = evaluate()
    if args.json:
        print(json.dumps(_to_json(stats), indent=2))
    elif args.markdown:
        report = _format_markdown(stats)
        out = Path(__file__).resolve().parent.parent / "docs" / "precision-report.md"
        out.write_text(report, encoding="utf-8")
        print(f"Wrote {out}")
    else:
        print(_format_text(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
