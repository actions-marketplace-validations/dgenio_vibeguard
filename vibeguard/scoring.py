"""Repository health-score computation.

The score is a deterministic roll-up of the findings already produced by the
scanner — no ML, no network, no opinion baked into the rules. The numbers
below are the entire formula:

* Start at ``100``.
* Subtract ``SEVERITY_WEIGHTS[severity]`` for every finding.
* Floor at ``0``.

Grade thresholds (``total`` → ``grade``):

* ``>= 90`` → ``A``
* ``75–89`` → ``B``
* ``50–74`` → ``C``
* ``25–49`` → ``D``
* ``< 25``  → ``F``

The score is informational only; ``gate`` continues to use the
severity-threshold semantics it always has, not the score.
"""

from __future__ import annotations

from typing import Literal

from vibeguard.models import Finding, HealthScore, Severity

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_GRADE_THRESHOLDS: list[tuple[int, Literal["A", "B", "C", "D", "F"]]] = [
    (90, "A"),
    (75, "B"),
    (50, "C"),
    (25, "D"),
    (0, "F"),
]


def _grade_for(total: int) -> Literal["A", "B", "C", "D", "F"]:
    for cutoff, grade in _GRADE_THRESHOLDS:
        if total >= cutoff:
            return grade
    return "F"


def compute_health_score(findings: list[Finding]) -> HealthScore:
    """Return a ``HealthScore`` derived from ``findings``.

    The result is fully deterministic: identical findings (in any order) yield
    identical scores. Category counts use ``Finding.rule`` so plugin rules
    surface in the breakdown automatically.
    """
    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    by_category: dict[str, int] = {}
    penalty = 0

    for f in findings:
        by_severity[f.severity.value] += 1
        by_category[f.rule] = by_category.get(f.rule, 0) + 1
        penalty += SEVERITY_WEIGHTS[f.severity]

    total = max(0, 100 - penalty)
    return HealthScore(
        total=total,
        grade=_grade_for(total),
        penalty=penalty,
        by_severity=by_severity,
        by_category=dict(sorted(by_category.items())),
        weights={k.value: v for k, v in SEVERITY_WEIGHTS.items()},
    )
