"""Regression guard for the benchmark scenario fixtures (#97).

Makes the published benchmark claims CI-enforced:

* every *vulnerable* fixture still surfaces the headline finding IDs the
  report documents, and
* every *clean* fixture produces zero blocking (high/critical) findings under
  its policy — i.e. the false-positive baseline stays at zero.
"""

from __future__ import annotations

import pytest

from benchmarks.scenarios import SCENARIOS, Scenario, evaluate

_VULNERABLE = [s for s in SCENARIOS if s.kind == "vulnerable"]
_CLEAN = [s for s in SCENARIOS if s.kind == "clean"]


@pytest.mark.parametrize("scenario", _VULNERABLE, ids=lambda s: s.name)
def test_vulnerable_scenario_surfaces_expected_findings(scenario: Scenario) -> None:
    report = evaluate(scenario)
    assert not report["missing_expected"], (
        f"{scenario.name}: expected findings not surfaced: {report['missing_expected']}"
    )
    assert report["blocking"], f"{scenario.name}: expected at least one blocking finding"


@pytest.mark.parametrize("scenario", _CLEAN, ids=lambda s: s.name)
def test_clean_scenario_has_zero_blocking_findings(scenario: Scenario) -> None:
    report = evaluate(scenario)
    assert report["blocking"] == [], (
        f"{scenario.name}: clean fixture produced blocking findings: {report['blocking']}"
    )


def test_false_positive_baseline_is_zero() -> None:
    total_fp = sum(len(evaluate(s)["blocking"]) for s in _CLEAN)
    assert total_fp == 0
