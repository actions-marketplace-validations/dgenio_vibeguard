"""End-to-end checks that the bundled demo fixtures exercise the rules they
advertise (#105).

The unit behaviour of each packaging finding lives in ``test_packaging.py``.
These tests instead scan the real ``examples/`` trees the way ``make demo``
does, so the demo output keeps surfacing the packaging-leak finding IDs that
#34 / #80 added. If a future fixture edit drops one of them, this fails.
"""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.scanner import run_scan

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def _finding_ids(rel: str) -> set[str]:
    result = run_scan(EXAMPLES / rel, VibeGuardConfig())
    return {f.id for f in result.findings}


def test_node_example_total_matches_readme_example_output() -> None:
    """The README "Example Output" block pins this count (16 findings). Keep
    the curated table and the live scan in lockstep — if this fails, the rule
    set changed the demo output and the README block needs regenerating."""
    result = run_scan(EXAMPLES / "vulnerable-node-package", VibeGuardConfig())
    assert len(result.findings) == 16


def test_node_example_surfaces_prepare_and_broad_npmignore() -> None:
    ids = _finding_ids("vulnerable-node-package")
    assert "PKG-PREPARE-SCRIPT" in ids
    assert "PKG-NPMIGNORE-BROAD" in ids


def test_python_example_surfaces_coverage_and_ci_leaks() -> None:
    ids = _finding_ids("vulnerable-python-package")
    assert "PKG-COVERAGE-LEAK" in ids
    assert "PKG-CI-LEAK" in ids


def test_demo_fixtures_cover_all_four_packaging_leak_ids() -> None:
    """The four #34/#80 finding IDs are exercised across the demo set."""
    ids = _finding_ids("vulnerable-node-package") | _finding_ids("vulnerable-python-package")
    assert {
        "PKG-PREPARE-SCRIPT",
        "PKG-NPMIGNORE-BROAD",
        "PKG-COVERAGE-LEAK",
        "PKG-CI-LEAK",
    } <= ids
