"""Tests for the repo health score (issue #64)."""

from __future__ import annotations

import json

from vibeguard.models import Confidence, Finding, ScanResult, Severity
from vibeguard.scoring import SEVERITY_WEIGHTS, compute_health_score


def _finding(severity: Severity, rule: str = "secrets", path: str = "a.py") -> Finding:
    return Finding(
        id=f"X-{severity.value.upper()}",
        rule=rule,
        title="t",
        description="d",
        severity=severity,
        path=path,
        line=1,
        evidence=None,
        recommendation="r",
        tags=[],
        confidence=Confidence.HIGH,
    )


class TestScoreComputation:
    def test_no_findings_is_perfect(self):
        score = compute_health_score([])
        assert score.total == 100
        assert score.grade == "A"
        assert score.penalty == 0
        assert score.by_severity == {
            "info": 0,
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }
        assert score.by_category == {}

    def test_weights_match_documented_values(self):
        assert SEVERITY_WEIGHTS[Severity.CRITICAL] == 25
        assert SEVERITY_WEIGHTS[Severity.HIGH] == 10
        assert SEVERITY_WEIGHTS[Severity.MEDIUM] == 3
        assert SEVERITY_WEIGHTS[Severity.LOW] == 1
        assert SEVERITY_WEIGHTS[Severity.INFO] == 0

    def test_penalty_sums_per_severity(self):
        findings = [
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
            _finding(Severity.INFO),
        ]
        score = compute_health_score(findings)
        # 25 + 10 + 3 + 1 + 0 = 39
        assert score.penalty == 39
        assert score.total == 100 - 39

    def test_score_floor_at_zero(self):
        # 5 criticals = 125 penalty, must floor at 0
        findings = [_finding(Severity.CRITICAL) for _ in range(5)]
        score = compute_health_score(findings)
        assert score.total == 0
        assert score.grade == "F"
        assert score.penalty == 125

    def test_grade_thresholds(self):
        # Build cases that exactly land on each threshold boundary
        cases = [
            ([], "A"),  # 100 → A
            ([_finding(Severity.HIGH)], "A"),  # 90 → A
            ([_finding(Severity.HIGH)] * 2 + [_finding(Severity.LOW)] * 5, "B"),  # 75 → B
            ([_finding(Severity.HIGH)] * 5, "C"),  # 50 → C
            ([_finding(Severity.CRITICAL)] * 3, "D"),  # 25 → D
            ([_finding(Severity.CRITICAL)] * 4, "F"),  # 0 → F
        ]
        for findings, expected_grade in cases:
            score = compute_health_score(findings)
            assert score.grade == expected_grade, (
                f"For {len(findings)} findings → total={score.total} got {score.grade}, "
                f"expected {expected_grade}"
            )

    def test_deterministic_order_independent(self):
        a = [_finding(Severity.CRITICAL), _finding(Severity.LOW, rule="x")]
        b = [_finding(Severity.LOW, rule="x"), _finding(Severity.CRITICAL)]
        assert compute_health_score(a) == compute_health_score(b)

    def test_by_category_counts_per_rule(self):
        findings = [
            _finding(Severity.HIGH, rule="secrets"),
            _finding(Severity.HIGH, rule="secrets"),
            _finding(Severity.MEDIUM, rule="risky_diff"),
        ]
        score = compute_health_score(findings)
        assert score.by_category == {"secrets": 2, "risky_diff": 1}

    def test_by_severity_counts_match_total(self):
        findings = [
            _finding(Severity.HIGH),
            _finding(Severity.HIGH),
            _finding(Severity.LOW),
        ]
        score = compute_health_score(findings)
        total_from_breakdown = sum(score.by_severity.values())
        assert total_from_breakdown == len(findings)
        assert score.by_severity["high"] == 2
        assert score.by_severity["low"] == 1

    def test_weights_present_in_output(self):
        score = compute_health_score([])
        assert score.weights == {
            "info": 0,
            "low": 1,
            "medium": 3,
            "high": 10,
            "critical": 25,
        }


class TestScoreOnScanResult:
    def test_scan_result_exposes_health_score(self):
        result = ScanResult(findings=[_finding(Severity.HIGH)], scanned_files=1)
        score = result.health_score
        assert score.total == 90
        assert score.grade == "A"

    def test_health_score_in_json_dump(self):
        result = ScanResult(findings=[_finding(Severity.CRITICAL)], scanned_files=1)
        dumped = json.loads(result.model_dump_json())
        assert "health_score" in dumped
        assert dumped["health_score"]["total"] == 75
        assert dumped["health_score"]["grade"] == "B"
        assert dumped["health_score"]["weights"]["critical"] == 25

    def test_health_score_recomputes_after_model_copy(self):
        result = ScanResult(findings=[_finding(Severity.HIGH)], scanned_files=1)
        # CLI helpers use model_copy(update={"findings": ...}) — the score must
        # reflect the new findings, not the old ones.
        updated = result.model_copy(update={"findings": []})
        assert updated.health_score.total == 100
        assert updated.health_score.grade == "A"
