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
from rich.console import Console

from tests.fixtures.canonical_scan_result import build_canonical_result
from vibeguard.reporters.console import build_findings_table
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

    def _render_table(self, width: int) -> str:
        """Render the console findings table at a fixed terminal width."""
        console = Console(width=width, force_terminal=False, no_color=True)
        with console.capture() as capture:
            console.print(build_findings_table(build_canonical_result()))
        return capture.get()

    def test_console_table_survives_80_columns(self) -> None:
        """At 80 cols the severity column and rule names must not collapse (#85).

        The bug: Rich shrank every column proportionally on narrow
        terminals, dropping the severity icon/label and truncating rule
        names to 3 chars (``sec…``). The fix pins ``no_wrap`` + ``min_width``
        on the Sev and Rule columns.
        """
        rendered = self._render_table(80)

        # Severity labels render in full, with their icons, not collapsed away.
        assert "☠ CRITICAL" in rendered
        assert "✗ HIGH" in rendered
        assert "⚠ MEDIUM" in rendered

        # Rule names render in full — including the longest builtin rule id
        # (``ai_footprints``, 13 chars) — rather than being truncated to 3.
        assert "secrets" in rendered
        assert "ai_footprints" in rendered
        assert "sec…" not in rendered

        # The Path column is the one that absorbs the squeeze, so the table
        # body still fits within the 80-column budget.
        for line in rendered.splitlines():
            assert len(line) <= 80, f"Line exceeds 80 cols: {line!r}"

    def test_console_table_wide_terminal_unchanged(self) -> None:
        """Wide terminals keep showing full severity + rule + title (#85)."""
        rendered = self._render_table(200)
        assert "☠ CRITICAL" in rendered
        assert "ai_footprints" in rendered
        assert "AWS Access Key ID detected" in rendered

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
        finding_indicators = [
            line
            for line in lines
            if "|" in line and "severity" not in line.lower() and "---" not in line
        ]
        assert len(finding_indicators) >= 5, (
            f"Expected at least 5 finding rows in Markdown golden, got {len(finding_indicators)}"
        )
