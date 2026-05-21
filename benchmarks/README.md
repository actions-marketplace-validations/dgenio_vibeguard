# Benchmarks

Deterministic, offline benchmark suite for the VibeGuard scanner. Used to
measure scan speed and detect performance regressions during local
development.

## Running

```
make bench           # default: small
make bench-medium
make bench-large
```

Or, directly:

```
python -m benchmarks.run --size small               # default 3 iterations
python -m benchmarks.run --size medium --iter 5
python -m benchmarks.run --size large --json        # machine-readable
python -m benchmarks.run --size small --seed 42     # reproducible RNG
```

The runner generates a synthetic repository on every invocation (or reuses a
cached one if `--out` is given), runs `vibeguard.scanner.run_scan` against
it, and prints median wall-clock time, files/second, findings/second, and a
per-rule breakdown.

## Sizes

| Size   | Files | Avg file size | Total |
|--------|------:|--------------:|------:|
| small  |   50  |        10 KB  | ~500 KB |
| medium |  500  |        10 KB  |  ~5 MB |
| large  | 2000  |        10 KB  | ~20 MB |

A configurable percentage of generated files contain seeded "finding bait"
(fake AWS keys, eval calls, etc.) so the rules have realistic work to do.

## Why this is not in CI

CI runners share hardware and have unpredictable timing variance. A hard
regression threshold here would produce false alarms; running the benchmark
locally before and after a perf-sensitive change is the recommended workflow.
