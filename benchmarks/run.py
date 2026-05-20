"""Benchmark runner: scan a generated synthetic repo and report timings (#52).

Deterministic, offline, pure stdlib (plus VibeGuard itself). Runs the
scanner ``--iter`` times (default 3), reports median wall-clock time,
files/second, findings/second, and counts of findings by rule.

This is informational only — there is no pass/fail gate. Pipe ``--json``
into your own scripts for trending.
"""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

from benchmarks.generate_fixtures import SIZES, GenConfig, generate
from vibeguard.config import VibeGuardConfig
from vibeguard.scanner import run_scan


def _run_once(repo: Path, cfg: VibeGuardConfig) -> tuple[float, int, dict[str, int]]:
    """Return (seconds, n_findings, per_rule_counts) for one scan."""
    start = time.perf_counter()
    result = run_scan(repo, cfg)
    elapsed = time.perf_counter() - start
    counts = Counter(f.rule for f in result.findings)
    return elapsed, len(result.findings), dict(counts)


def benchmark(
    size: str,
    iterations: int = 3,
    seed: int = 0,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    """Run the benchmark and return a structured report."""
    n_files = SIZES[size]
    cfg = VibeGuardConfig()

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(out_dir) if out_dir else Path(tmp) / f"bench-{size}"
        generate(repo, GenConfig(n_files=n_files, seed=seed))

        timings: list[float] = []
        last_count = 0
        last_per_rule: dict[str, int] = {}
        for _ in range(iterations):
            elapsed, count, per_rule = _run_once(repo, cfg)
            timings.append(elapsed)
            last_count = count
            last_per_rule = per_rule

        median = statistics.median(timings)
        return {
            "size": size,
            "files": n_files,
            "iterations": iterations,
            "seed": seed,
            "timings_seconds": timings,
            "median_seconds": median,
            "min_seconds": min(timings),
            "max_seconds": max(timings),
            "files_per_second": n_files / median if median > 0 else 0.0,
            "findings_total": last_count,
            "findings_per_second": last_count / median if median > 0 else 0.0,
            "findings_per_rule": last_per_rule,
        }


def _format_text(report: dict[str, Any]) -> str:
    lines = [
        f"VibeGuard benchmark — size={report['size']} files={report['files']} "
        f"iterations={report['iterations']} seed={report['seed']}",
        "",
        f"  median:  {report['median_seconds']:.3f}s",
        f"  min:     {report['min_seconds']:.3f}s",
        f"  max:     {report['max_seconds']:.3f}s",
        f"  files/s: {report['files_per_second']:.1f}",
        f"  findings: {report['findings_total']} ({report['findings_per_second']:.1f} findings/s)",
        "",
        "  per-rule findings:",
    ]
    for rule, n in sorted(report["findings_per_rule"].items(), key=lambda kv: -kv[1]):
        lines.append(f"    {rule:<16} {n}")
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the VibeGuard scanner benchmark.")
    parser.add_argument("--size", choices=list(SIZES), default="small")
    parser.add_argument("--iter", dest="iterations", type=int, default=3)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", type=Path, help="Optional persistent output directory")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    report = benchmark(args.size, args.iterations, args.seed, args.out)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(_format_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
