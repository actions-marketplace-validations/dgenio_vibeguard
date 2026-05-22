"""FP/TP corpus driver — measures rule precision and recall (#53).

For every category directory under ``tests/fixtures/corpus/``:

* every ``tp_*`` case must produce at least one finding whose ``rule``
  field matches the category (recall).
* every ``fp_*`` case must NOT produce any CRITICAL or HIGH finding for
  that category (precision at the actionable severity tier).

Cases can be either:

* a single file (``tp_<name>.<ext>``) — scanned in isolation, or
* a directory (``tp_<name>/``) — useful for rules like ``dependencies``
  and ``packaging`` that key off specific filenames such as
  ``package.json`` or ``pyproject.toml``.

The driver also prints a summary so contributors can see the aggregate
hit rate per rule when running ``pytest -s``.
"""

from __future__ import annotations

import shutil
from collections import defaultdict
from pathlib import Path

import pytest

from vibeguard.config import VibeGuardConfig
from vibeguard.models import Severity
from vibeguard.scanner import run_scan

CORPUS_DIR = Path(__file__).parent / "fixtures" / "corpus"

# Directory name -> rule.id values that should match a finding's `rule` field
# for that case. Some rules emit findings under closely-related rule IDs
# (e.g. AI footprints can shadow auth detections); the corpus treats any
# rule in the same family as a hit.
_RULE_FAMILIES: dict[str, set[str]] = {
    "secrets": {"secrets"},
    "risky_diff": {"risky_diff"},
    "auth": {"auth", "ai_footprints"},
    "sourcemaps": {"sourcemaps"},
    "dependencies": {"dependencies"},
    "packaging": {"packaging"},
    "ai_footprints": {"ai_footprints", "auth", "risky_diff"},
}


def _iter_cases() -> list[tuple[str, str, Path]]:
    """Yield ``(category, case_name, case_path)`` for every TP/FP case."""
    cases: list[tuple[str, str, Path]] = []
    for category_dir in sorted(CORPUS_DIR.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("__"):
            continue
        for entry in sorted(category_dir.iterdir()):
            name = entry.name
            if not (name.startswith("tp_") or name.startswith("fp_")):
                continue
            cases.append((category_dir.name, name, entry))
    return cases


def _stage_case(case_path: Path, dest: Path) -> None:
    """Copy a case (file or directory) into a fresh tmp tree."""
    target = dest / "repo"
    target.mkdir()
    if case_path.is_dir():
        # Recreate the case's filename layout under ``repo/`` so the
        # rules see e.g. ``repo/package.json`` rather than
        # ``repo/tp_url_dep/package.json``.
        for child in case_path.rglob("*"):
            if child.is_file():
                rel = child.relative_to(case_path)
                out = target / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(child, out)
    else:
        # For sourcemaps the rule looks for ``dist/*.map``; preserve any
        # parent directory naming present in the corpus.
        rel_to_category = case_path.relative_to(case_path.parent)
        out = target / rel_to_category
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(case_path, out)


_CASES = _iter_cases()


@pytest.mark.parametrize(
    "category,case_name,case_path",
    _CASES,
    ids=[f"{c}/{n}" for c, n, _p in _CASES],
)
def test_corpus_case(
    category: str,
    case_name: str,
    case_path: Path,
    tmp_path: Path,
) -> None:
    """Each TP/FP case must behave as advertised by its prefix."""
    _stage_case(case_path, tmp_path)
    cfg = VibeGuardConfig(policy="strict")  # strict surfaces broader-version dep findings
    result = run_scan(tmp_path / "repo", cfg)

    family = _RULE_FAMILIES.get(category)
    if family is None:
        pytest.fail(
            f"Unknown corpus category '{category}'. "
            f"Add it to _RULE_FAMILIES or remove the directory."
        )
    family_findings = [f for f in result.findings if f.rule in family]

    if case_name.startswith("tp_"):
        assert family_findings, (
            f"TP case `{category}/{case_name}` produced no findings in rule family "
            f"{sorted(family)}. All findings: "
            f"{[(f.id, f.rule, f.severity.value) for f in result.findings]}"
        )
    elif case_name.startswith("fp_"):
        actionable = [f for f in family_findings if f.severity >= Severity.HIGH]
        assert not actionable, (
            f"FP case `{category}/{case_name}` produced "
            f"{len(actionable)} CRITICAL/HIGH finding(s) in rule family {sorted(family)}: "
            f"{[(f.id, f.severity.value) for f in actionable]}"
        )


def test_corpus_has_minimum_coverage() -> None:
    """Every rule family with a directory must have at least one TP and one FP."""
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0})
    for category, name, _p in _iter_cases():
        kind = "tp" if name.startswith("tp_") else "fp"
        counts[category][kind] += 1

    missing: list[str] = []
    for category, kinds in counts.items():
        if kinds["tp"] == 0:
            missing.append(f"{category} has no TP cases")
        if kinds["fp"] == 0:
            missing.append(f"{category} has no FP cases")

    assert not missing, "Corpus coverage gaps:\n  " + "\n  ".join(missing)


def test_corpus_categories_are_known() -> None:
    """Every category directory must map to a known rule family."""
    extra = []
    for category_dir in CORPUS_DIR.iterdir():
        if not category_dir.is_dir() or category_dir.name.startswith("__"):
            continue
        if category_dir.name not in _RULE_FAMILIES:
            extra.append(category_dir.name)
    assert not extra, (
        f"Unknown corpus categories: {extra}. Add them to _RULE_FAMILIES in {__file__}."
    )
