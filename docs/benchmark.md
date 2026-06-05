# VibeGuard benchmark & evaluation

This report covers two questions a team asks before adopting a PR gate:

1. **Is it fast enough for a PR workflow?** → the *performance* benchmark.
2. **Does it catch real AI-diff mistakes without drowning me in noise?** → the
   *scenario* evaluation, including a false-positive baseline on clean code.

Everything here is **deterministic and offline**. The scenario findings are
byte-stable across runs (and CI-enforced — see
[`tests/test_benchmark_scenarios.py`](../tests/test_benchmark_scenarios.py)).
Only the performance *timings* vary by hardware.

> Scope note: VibeGuard is a deterministic gate for common AI-generated diff
> mistakes — not a SAST suite, CVE scanner, or LLM-based reviewer. The
> benchmark measures exactly that scope and nothing broader.

---

## 1. Performance

A synthetic repo (deterministic given `--seed`) is generated and scanned
`--iter` times; the median wall-clock time is reported. See
[`benchmarks/run.py`](../benchmarks/run.py) and
[`benchmarks/generate_fixtures.py`](../benchmarks/generate_fixtures.py).

### Reproduce

```bash
make bench            # small (50 files)
make bench-medium     # 500 files
make bench-large      # 2000 files
# or, machine-readable:
python -m benchmarks.run --size medium --iter 5 --json
```

### Reference results

Throughput is roughly linear in file count. **These numbers are from one
developer machine and are illustrative only — run the command above on your
own hardware/CI for a figure you can trust.**

| Size   | Files | Median time | Throughput |
|--------|------:|------------:|-----------:|
| small  |    50 |      ~0.5 s |  ~100 files/s |
| medium |   500 |      ~4.7 s |  ~100 files/s |

For PR usage prefer `--diff`, which scans only changed files and keeps gate
time roughly constant regardless of repo size.

---

## 2. Scenario detection & false-positive baseline

The fixtures under [`benchmarks/scenarios/`](../benchmarks/scenarios) are
small, hand-written trees that mirror real AI-assisted mistakes (vulnerable)
or ordinary well-behaved code (clean). The harness scans each and reports
findings by severity, plus the count of **blocking** (high/critical) findings.

### Reproduce

```bash
make bench-scenarios
# or, machine-readable:
python -m benchmarks.scenarios --json
```

### Results

| Scenario | Kind | Findings | Blocking | Headline detections |
|---|---|---:|---:|---|
| `node-web-app` | vulnerable | 9 | 5 | `SEC-ENV`, `MAP-PKG`, `PKG-NPMLEAK`, `DEP-URLNODE`, `RISK-CORSCONFIG` |
| `python-api` | vulnerable | 11 | 5 | `AUTH-VERIFY-FALSE`, `RISK-SUBPROCESSSHELL`, `SQL-PY-FSTRING`, `SEC-HARDCODEDPASSWORD` |
| `go-service` | vulnerable | 4 | 2 | `GO-INSECURE-TLS`, `GO-EXEC-SHELL`, `GO-CORS-WILDCARD` |
| `iac-config` | vulnerable | 3 | 3 | `TF-IAM-WILDCARD`, `TF-SG-OPEN`, `TF-S3-PUBLIC` |
| `clean-library` | clean (`oss-library`) | 1 | **0** | — |
| `monorepo` | clean (`oss-library`) | 0 | **0** | — |

**False-positive baseline: 0 blocking findings across the clean fixtures.**

Notes on the clean fixtures:

- `clean-library` surfaces a single **medium** `RISK-DBWRITE` "area to review"
  note on a parameterised `conn.execute(...)`. It is informational and
  **non-blocking** — the `sql` rule correctly does *not* fire on the `?`-bound
  query. This is the intended behaviour: `risky_diff` flags *areas*, severity
  tiers decide what blocks.
- `monorepo` (two packages, each with `src/` + `tests/`) produces no findings.

The clean fixtures are evaluated under the **`oss-library`** policy pack, the
recommended profile for library authors. "Blocking" means a finding at or
above the default `--fail-on high` threshold.

---

## 3. Precision & recall on the labeled corpus

Where the scenario baseline above shows headline detections, the labeled
corpus under [`tests/fixtures/corpus/`](../tests/fixtures/corpus) answers the
question that decides whether a team can trust `--fail-on` in CI: **when the
gate blocks, is it right, and does it catch the real risks?** Every case is
labeled `tp_*` (a genuine risk the gate should block) or `fp_*` (a benign
change the gate must not block), and the harness derives precision, recall,
and F1 per rule family **at the actionable tier** (HIGH/CRITICAL) — the exact
decision `vibeguard gate --fail-on high` makes.

### Reproduce

```bash
make bench-precision
# or, machine-readable:
python -m benchmarks.precision --json
```

### Results

The committed, regenerable report lives at
[`docs/precision-report.md`](precision-report.md). The headline today:
**precision 1.00** (no blocking false positives across the corpus) with an
overall **detection recall of 1.00** (every true-positive case fires at least
one finding). Blocking *recall* is intentionally below 1.0 because advisory
rules such as `risky_diff` (MEDIUM) and the informational `ai_footprints`
tier detect but do not block — the report's `Detection recall` column
separates the two so an advisory rule isn't misread as a miss.

### CI regression guard

[`tests/test_corpus_precision.py`](../tests/test_corpus_precision.py) runs the
corpus on every PR and fails if any `tp_` case stops firing or any `fp_` case
starts producing an actionable (HIGH/CRITICAL) finding — so rule changes
cannot silently degrade precision. Add new corpus cases there (one `tp_` and
one `fp_` per family minimum) and rerun `make bench-precision` to refresh the
report.

---

## What is measured vs. not measured

**Measured**

- Scan throughput on synthetic repos of increasing size.
- Detection of the documented finding IDs on realistic vulnerable fixtures
  across Node, Python, Go, and Terraform.
- Zero blocking findings on clean fixtures (false-positive baseline).
- Precision / recall / F1 per rule family on the labeled `tp_`/`fp_` corpus,
  at the actionable (HIGH/CRITICAL) blocking tier.

**Not measured**

- Recall against an external/standard vulnerability corpus (out of scope —
  VibeGuard targets AI-diff mistakes, not full SAST coverage).
- CVE/dependency-advisory detection or any network-dependent check.
- Real-world noise on large proprietary codebases (run `--diff` on your own
  repo to gauge this).
- Absolute timings as a cross-machine guarantee — only relative scaling.

---

## Limitations

- Performance timings are hardware-sensitive; treat the reference table as
  ballpark, not a contract. CI runners add variance, which is why the perf
  benchmark is **not** a CI gate (see `benchmarks/README.md`).
- The scenario set is intentionally small and curated; it demonstrates
  detection on representative mistakes, not statistical coverage.
- Diff-only rules (e.g. `TEST-MISSING`) require a git diff and are exercised
  in the PR-scenario docs ([`examples/pr-scenarios/`](../examples/pr-scenarios)),
  not in this static evaluation.

---

## Updating this report

1. Add or edit fixtures under `benchmarks/scenarios/<name>/`.
2. Register the scenario in `benchmarks/scenarios.py` (`SCENARIOS`), with
   `expected_ids` for vulnerable cases.
3. Run `make bench-scenarios` and update the **Results** table above.
4. Run `pytest tests/test_benchmark_scenarios.py` — it enforces the headline
   detections and the zero-false-positive baseline.
5. For performance, re-run `make bench`/`bench-medium` and refresh the
   reference table (label it clearly as machine-specific).
