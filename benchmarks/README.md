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

## Collection-phase directory pruning (#219)

`scanner._collect_files` walks with `os.walk` and prunes ignored directories
(`node_modules/`, `.venv/`, …) in place, so their contents are never
enumerated or stat'd — instead of `rglob`-ing every entry and filtering each
path afterwards. The file set and sort order are unchanged
(`tests/test_file_collection.py`); only ignored trees are skipped earlier.

On a synthetic tree with ~4,450 entries dominated by a populated
`node_modules/` (50 real source files), collection drops from ~73 ms to
~1.7 ms — roughly a **40×** reduction on the collection phase, the cost that
dominates scans of real JS/Python repos. Re-measure with the same fixture
before/after any change to the walk.
