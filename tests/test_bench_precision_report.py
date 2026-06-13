"""Freshness guard for the committed precision report (#115).

``benchmarks.precision`` regenerates ``docs/precision-report.md``. The corpus
behaviour itself is guarded by ``tests/test_corpus_precision.py``, but that
guard still passes when corpus cases are added or removed — which silently
changes the report's counts. These tests mirror ``test_generate_rule_docs``:
they assert ``--check`` flags a stale or missing committed report, so the
artifact can't drift unnoticed.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT = REPO_ROOT / "docs" / "precision-report.md"


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "benchmarks.precision", *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


class TestPrecisionReportFreshness:
    def test_output_is_deterministic(self, tmp_path: Path):
        first = tmp_path / "first.md"
        second = tmp_path / "second.md"
        assert _run(["--markdown", "-o", str(first)]).returncode == 0
        assert _run(["--markdown", "-o", str(second)]).returncode == 0
        assert first.read_bytes() == second.read_bytes()

    def test_check_mode_passes_when_committed_is_current(self):
        # Regenerate into the canonical location so any in-tree drift is ironed
        # out for the duration of this test, then assert --check is happy.
        backup = REPORT.read_text(encoding="utf-8") if REPORT.exists() else None
        try:
            assert _run(["--markdown"]).returncode == 0  # regenerate in place
            assert _run(["--check"]).returncode == 0
        finally:
            if backup is not None:
                REPORT.write_text(backup, encoding="utf-8")

    def test_check_mode_fails_on_drift(self, tmp_path: Path):
        drift = tmp_path / "drift.md"
        drift.write_text("intentionally wrong\n", encoding="utf-8")
        result = _run(["--check", "-o", str(drift)])
        assert result.returncode == 1
        assert "out of date" in result.stderr.lower()

    def test_check_mode_fails_when_output_missing(self, tmp_path: Path):
        missing = tmp_path / "missing.md"
        result = _run(["--check", "-o", str(missing)])
        assert result.returncode == 1
        assert "missing" in result.stderr.lower()

    def test_committed_report_is_up_to_date(self):
        """The report checked into the repo must match a fresh regeneration."""
        result = _run(["--check"])
        assert result.returncode == 0, (
            f"docs/precision-report.md is stale — run `make bench-precision`.\n{result.stderr}"
        )

    def test_make_bench_precision_check_target_runs(self):
        if shutil.which("make") is None:
            pytest.skip("`make` not available in this environment")
        result = subprocess.run(
            ["make", "bench-precision-check"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
