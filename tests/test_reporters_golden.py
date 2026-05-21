"""Golden snapshot tests for the JSON, Markdown, and SARIF reporters (#54).

The canonical ``ScanResult`` lives in
``tests/fixtures/canonical_scan_result.py`` and is deterministic — no
timestamps, no per-run state. Each reporter renders the canonical result
and the output is compared byte-for-byte against the committed golden
file.

To regenerate after an intentional reporter change::

    PYTEST_UPDATE_GOLDENS=1 pytest tests/test_reporters_golden.py
    # or
    make update-goldens

A drift caught here means a reporter's public output changed — likely
breaking downstream JSON/SARIF/PR-comment consumers. Either update the
golden (and call it out in the PR description) or revert the reporter
change.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.fixtures.canonical_scan_result import build_canonical_result
from vibeguard.reporters.json_reporter import render_json
from vibeguard.reporters.markdown import render_markdown
from vibeguard.reporters.sarif import render_sarif

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "golden"
UPDATE_ENV_VAR = "PYTEST_UPDATE_GOLDENS"


def _check_golden(name: str, actual: str) -> None:
    """Compare ``actual`` to ``GOLDEN_DIR/name`` or rewrite it if requested."""
    path = GOLDEN_DIR / name
    # Normalize to a trailing newline so reporters that don't emit one
    # still produce a stable file.
    normalized = actual if actual.endswith("\n") else actual + "\n"

    if os.environ.get(UPDATE_ENV_VAR) == "1":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(normalized, encoding="utf-8")
        return

    if not path.exists():
        pytest.fail(
            f"Golden file missing: {path}. "
            f"Run `{UPDATE_ENV_VAR}=1 pytest tests/test_reporters_golden.py` "
            "to create it."
        )

    expected = path.read_text(encoding="utf-8")
    assert normalized == expected, (
        f"Golden mismatch for {name}. If the change is intentional, run "
        f"`make update-goldens` and review the diff."
    )


class TestGoldenReporters:
    def test_json_reporter_matches_golden(self) -> None:
        result = build_canonical_result()
        rendered = render_json(result)
        _check_golden("scan_result.json", rendered)

    def test_markdown_reporter_matches_golden(self) -> None:
        result = build_canonical_result()
        rendered = render_markdown(result)
        _check_golden("scan_result.md", rendered)

    def test_sarif_reporter_matches_golden(self) -> None:
        result = build_canonical_result()
        rendered = render_sarif(result)
        _check_golden("scan_result.sarif", rendered)

    def test_json_golden_is_valid_json(self) -> None:
        """Defence-in-depth: the JSON golden must parse and round-trip."""
        path = GOLDEN_DIR / "scan_result.json"
        if not path.exists():
            pytest.skip("Run with PYTEST_UPDATE_GOLDENS=1 first to materialize the golden.")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert data["scanned_files"] == 12

    def test_sarif_golden_is_valid_sarif(self) -> None:
        """Defence-in-depth: the SARIF golden must parse and look like SARIF."""
        path = GOLDEN_DIR / "scan_result.sarif"
        if not path.exists():
            pytest.skip("Run with PYTEST_UPDATE_GOLDENS=1 first to materialize the golden.")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "VibeGuard"
        # Every result must carry partialFingerprints (regression guard for the
        # SARIF dedup contract documented in tests/test_sarif.py).
        for r in data["runs"][0]["results"]:
            assert "partialFingerprints" in r
            assert "vibeguard/v1" in r["partialFingerprints"]

    def test_markdown_golden_has_expected_structure(self) -> None:
        """Defence-in-depth: the Markdown golden must contain expected sections."""
        path = GOLDEN_DIR / "scan_result.md"
        if not path.exists():
            pytest.skip("Run with PYTEST_UPDATE_GOLDENS=1 first to materialize the golden.")
        content = path.read_text(encoding="utf-8")
        # The canonical result has 5 findings — verify the Markdown reflects this
        lines = content.splitlines()
        assert any("finding" in line.lower() or "##" in line for line in lines), (
            "Markdown golden lacks expected heading structure"
        )
        # Count table rows or finding entries (pipe-delimited rows excluding header)
        finding_indicators = [l for l in lines if "|" in l and "severity" not in l.lower() and "---" not in l]
        assert len(finding_indicators) >= 5, (
            f"Expected at least 5 finding rows in Markdown golden, got {len(finding_indicators)}"
        )
