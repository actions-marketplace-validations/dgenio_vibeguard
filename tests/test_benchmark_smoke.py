"""Smoke test for the benchmark harness (#52).

Asserts the benchmark runs end-to-end at the smallest size and produces
the expected report shape. Does **not** assert on absolute speed — CI
timing is too noisy for that. Real performance trending is left to
manual runs of ``make bench`` per ``benchmarks/README.md``.
"""

from __future__ import annotations

import json
import subprocess
import sys

from benchmarks.generate_fixtures import GenConfig, generate
from benchmarks.run import benchmark


def test_benchmark_runs_at_small_size() -> None:
    report = benchmark("small", iterations=1, seed=0)
    assert report["size"] == "small"
    assert report["files"] == 50
    assert report["iterations"] == 1
    assert len(report["timings_seconds"]) == 1
    assert report["median_seconds"] >= 0.0
    assert report["files_per_second"] >= 0.0
    # The synthetic repo plants findings in ~15% of files, so the
    # smallest size must surface at least one finding. This is a
    # tight assertion that catches a benchmark-generator regression
    # (e.g. bait planting silently disabled) far better than a >=0 check.
    assert report["findings_total"] >= 1
    assert isinstance(report["findings_per_rule"], dict)


def test_generator_is_deterministic(tmp_path) -> None:
    """Same seed must produce identical byte-for-byte output."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    generate(a, GenConfig(n_files=10, seed=42))
    generate(b, GenConfig(n_files=10, seed=42))

    a_files = sorted(p.relative_to(a) for p in a.rglob("*") if p.is_file())
    b_files = sorted(p.relative_to(b) for p in b.rglob("*") if p.is_file())
    assert a_files == b_files
    for rel in a_files:
        assert (a / rel).read_bytes() == (b / rel).read_bytes(), (
            f"Generator non-deterministic at {rel}"
        )


def test_generator_seed_changes_content(tmp_path) -> None:
    """Different seeds must produce different byte content somewhere."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    generate(a, GenConfig(n_files=10, seed=1))
    generate(b, GenConfig(n_files=10, seed=2))
    a_blob = b"".join(sorted(p.read_bytes() for p in a.rglob("*") if p.is_file()))
    b_blob = b"".join(sorted(p.read_bytes() for p in b.rglob("*") if p.is_file()))
    assert a_blob != b_blob


def test_benchmark_cli_json_output() -> None:
    """The CLI must produce valid JSON when ``--json`` is passed."""
    result = subprocess.run(
        [sys.executable, "-m", "benchmarks.run", "--size", "small", "--iter", "1", "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(result.stdout)
    assert data["size"] == "small"
    assert data["files"] == 50
    assert "median_seconds" in data
