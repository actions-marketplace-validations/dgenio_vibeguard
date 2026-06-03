"""Pin the expected findings for the realistic PR scenarios under
``examples/pr-scenarios/`` (#98).

Each scenario is a small final-state tree representing a mistake an AI coding
agent commonly ships. Scanning a scenario with its own directory as the root
must surface the headline finding IDs documented in that scenario's README.
These assertions are the regression guard: if a rule or fixture drifts so a
scenario stops firing, this fails.

Static fixtures cannot exercise diff-only rules (e.g. ``TEST-MISSING``), so
those are documented in the scenario README rather than asserted here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vibeguard.config import VibeGuardConfig
from vibeguard.scanner import run_scan

SCENARIOS = Path(__file__).resolve().parent.parent / "examples" / "pr-scenarios"

# scenario directory -> finding IDs that MUST be present when the scenario is
# scanned with its own directory as the scan root.
_EXPECTED: dict[str, set[str]] = {
    "01-tls-verify-disabled": {"AUTH-VERIFY-FALSE", "AI-TRUSTALLCERTS"},
    "02-auth-bypass-left-in": {"AUTH-BYPASS-COMMENT", "AI-TEMPBYPASS"},
    "03-package-leaks-env-and-sourcemaps": {"SEC-ENV", "MAP-PKG", "PKG-NPMLEAK"},
    "04-agent-memory-committed": {
        "AGENT-MEMORY-LOG",
        "AGENT-MEMORY-DIR",
        "AGENT-TOOL-TRACE",
    },
    "05-dependency-via-git-url": {"DEP-URLNODE"},
    "06-risky-db-write-no-tests": {"SQL-PY-FSTRING", "SQL-PY-CONCAT"},
    "07-slopsquatted-dependency": {"SLOP-HALLUCINATION-SHAPE"},
    "08-prompt-injection-in-comments": {"PI-OVERRIDE", "PI-EXFIL"},
}


def _finding_ids(scenario: str) -> set[str]:
    result = run_scan(SCENARIOS / scenario, VibeGuardConfig())
    return {f.id for f in result.findings}


def test_every_scenario_dir_is_covered() -> None:
    """Guard against adding a scenario folder without a pinned expectation."""
    on_disk = {p.name for p in SCENARIOS.iterdir() if p.is_dir()}
    assert on_disk == set(_EXPECTED), (
        "Scenario directories and pinned expectations are out of sync: "
        f"on disk={sorted(on_disk)} pinned={sorted(_EXPECTED)}"
    )


@pytest.mark.parametrize("scenario", sorted(_EXPECTED))
def test_scenario_surfaces_expected_findings(scenario: str) -> None:
    ids = _finding_ids(scenario)
    missing = _EXPECTED[scenario] - ids
    assert not missing, f"{scenario}: expected findings not surfaced: {sorted(missing)}"


@pytest.mark.parametrize("scenario", sorted(_EXPECTED))
def test_every_scenario_has_a_high_or_critical_finding(scenario: str) -> None:
    """Each scenario is a should-block case: it must block at --fail-on high."""
    result = run_scan(SCENARIOS / scenario, VibeGuardConfig())
    severities = {f.severity.value for f in result.findings}
    assert {"high", "critical"} & severities, (
        f"{scenario}: expected at least one high/critical finding, got {sorted(severities)}"
    )
