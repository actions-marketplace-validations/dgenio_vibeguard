# VibeGuard Stability Contract (v1)

VibeGuard is built to run as a **pre-merge gate in CI**. A gate is only
worth enforcing if its behaviour is predictable across releases. This page
is the contract: it states which surfaces are stable, how compatibility is
handled, and what counts as a breaking change.

Anything documented as **stable** here will not change in a backwards-
incompatible way without a major version bump and a migration note in the
release notes. Anything marked **experimental** may change in a minor
release.

> Scope: this contract covers the user-facing product surface (CLI,
> outputs, finding IDs, config). The *plugin* API has its own contract in
> [`plugin-api.md`](plugin-api.md), governed by `PLUGIN_API_VERSION`.

---

## TL;DR

| Surface | Stability | Notes |
|---|---|---|
| `scan`, `gate`, `init`, `explain`, `rules`, `publish-check`, `baseline`, `version` commands | **Stable** | Names, exit-code meanings, and core flags |
| Exit codes (`0` / `1` / `2`) | **Stable** | See [Exit codes](#exit-codes) |
| Finding IDs (`SEC-ENV`, `MAP-DIST`, …) | **Stable** | Renames are breaking; deprecations are documented |
| Rule IDs / config section keys | **Stable** | The `rule id` ↔ `config_key` mapping is published in `rules.md` |
| JSON / SARIF / diagnostics output schemas | **Stable** | Documented in [`output-schemas.md`](output-schemas.md) |
| Console (Rich) table layout | **Experimental** | Human-facing; may be re-laid-out without a major bump |
| Markdown / PR-comment wording | **Experimental** | Structure is stable; exact prose is not |
| `vibeguard.yaml` schema | **Stable, additive** | New keys are additive; removing/repurposing a key is breaking |
| `dev`-namespaced / undocumented commands | **Experimental** | Not part of v1 |

---

## CLI command stability

These commands and their documented behaviour are stable for v1:

- `vibeguard init` — create a `vibeguard.yaml`. Never overwrites an existing
  config; exits `0` with a notice if one is present.
- `vibeguard scan` — **informational**. It prints findings and
  **always exits `0`**, even with `--fail-on`. `--fail-on` on `scan` only
  sets the severity used to mark findings as "blocking" in the output; it
  does not change the exit code.
- `vibeguard gate` — runs the same analysis as `scan` but **exits `1`** when
  findings meet or exceed the `--fail-on` threshold.
- `vibeguard explain <ID>` — remediation for a finding ID.
- `vibeguard rules list` / `vibeguard rules explain <rule-id>` — rule
  discovery.
- `vibeguard publish-check` — gate on the *published* file set for npm /
  python sdist.
- `vibeguard baseline create|update` — manage accepted-findings baselines.
- `vibeguard version` — version / Python / platform / install path.

The `scan` vs `gate` distinction is the most important contract in this
file: **`scan` never fails your build; `gate` is the thing you put in CI.**
This split is guaranteed by tests (`tests/test_cli.py`,
`tests/test_cli_e2e.py::TestScanFailOnHelp`).

## Exit codes

| Code | Meaning | Applies to |
|---|---|---|
| `0` | Success — no blocking findings (or `scan`, always) | all commands |
| `1` | Blocking findings at or above `--fail-on` | `gate`, `publish-check` |
| `2` | Operational/usage error (bad path, malformed config, unknown ID) | all commands |

Exit `2` is reserved for "the tool could not run as asked". It is distinct
from `1` ("the tool ran and the gate failed") so CI can tell a real failure
from a misconfiguration.

## Config file compatibility

- The `vibeguard.yaml` schema is **stable and additive**: new optional keys
  may appear in minor releases with safe defaults.
- Removing a key, renaming a key, or changing a default in a way that makes
  a previously-clean repo fail is a **breaking change** and requires a major
  bump.
- The `rule id` ↔ `config_key` mapping is not always 1:1 (for example, the
  `risky_diff` rule is configured under `risky_patterns:`). The authoritative
  mapping is published per-rule in [`rules.md`](rules.md) and via
  `vibeguard rules explain <rule-id>`.
- A missing config file is **not** an error — VibeGuard loads built-in
  defaults (`tests/test_config.py::test_load_nonexistent_returns_defaults`).
- A malformed or invalid config (bad `fail_on`, unknown `policy`, etc.)
  **fails closed** with exit `2` rather than silently falling back
  (`tests/test_config.py`).

## Finding ID and rule metadata stability

- **Finding IDs are stable identifiers.** Once a finding ID ships in a
  release it will not be renamed or repurposed without a major bump. If a
  finding is retired, its ID is documented as deprecated rather than reused.
- This is what makes `ignore.findings`, `severity_overrides`, and SARIF
  `ruleId` correlation safe to pin in your own config.
- **Default severities are stable**, but are user-overridable via
  `severity_overrides` and policy packs. Raising a default severity (which
  can newly-block a previously-passing gate) is treated as a breaking change
  for the affected finding and called out in release notes.
- Rule metadata (`rule_id`, `config_key`, `default_severity`, `confidence`,
  `finding_ids`) is published in [`rules.md`](rules.md), regenerated from the
  registry by `make docs`.

## Output schema stability

The machine-readable reporters are integration surfaces and are stable:

- **JSON** (`--json`), **SARIF** (`--sarif`), and **IDE diagnostics** field
  shapes are documented in [`output-schemas.md`](output-schemas.md) and
  guarded by golden snapshot tests (`tests/test_reporters_golden.py`,
  `tests/test_sarif.py`). New fields may be added; existing fields are not
  removed or retyped without a major bump.
- The **console (Rich) table** and **Markdown / PR-comment** renderers are
  human-facing. Their *structure* (a severity-sorted table; a PASS/FAIL
  headline that reflects blocking findings) is stable, but exact column
  widths and prose are **experimental** and may change in a minor release.
  Do not parse the console output — use `--json`/`--sarif`.

## Plugin API stability

The plugin API is versioned independently via `PLUGIN_API_VERSION`
(currently `1.0`) and documented in [`plugin-api.md`](plugin-api.md).
Plugins import only from `vibeguard.api`; everything else under
`vibeguard.*` is internal and may change without notice.

## Versioning policy

VibeGuard follows semantic versioning for the surfaces above:

- **MAJOR** — a backwards-incompatible change to any *stable* surface
  (removed/renamed command, removed finding ID, removed/retyped output
  field, removed/renamed config key, raised default severity that can
  newly-block).
- **MINOR** — additive, backwards-compatible changes (new rule, new finding
  ID, new optional config key, new output field, new command).
- **PATCH** — bug fixes and detection-accuracy improvements that do not
  change the stable contract.

Detection improvements are a deliberate grey area: fixing a false negative
can newly-block a repo even in a patch release. We bias toward shipping these
in **minor** releases and calling them out in the release notes when they can
realistically change a gate result. The [release checklist](release-checklist.md)
codifies this.

## Operational behaviour ("fails closed")

A safety gate must never report success when it could not actually do its
job. The following operational cases are guaranteed and test-backed:

| Case | Behaviour | Guaranteed by |
|---|---|---|
| `--path` does not exist | exit `2`, error message, **never** "Gate passed" | `tests/test_cli_e2e.py::TestPathValidation` (#81) |
| `--path` is a file, not a directory | exit `2`, "must be a directory" | `tests/test_cli_e2e.py::TestPathValidation` (#83) |
| Malformed / invalid config | exit `2`, fail closed | `tests/test_config.py` |
| Zero files scanned due to user error | surfaced, not silently "clean" | `tests/test_cli_e2e.py` (#83) |
| `scan --pr-comment` with blocking findings | headline is **FAIL**, not PASS | `tests/test_pr_comment.py` (#82) |
| `explain` / `rules explain` unknown ID | exit `2`, consistent message | `tests/test_cli.py`, `tests/test_cli_e2e.py` (#90) |
| Plugin fails to load | scan continues; failure is reported, not swallowed | `tests/test_plugin_discovery.py` |
| `git` unavailable in `--diff` mode | reported; does not crash the gate | diff-scope handling |

## What is *not* covered by this contract

- Exact console colours, icons, and table column widths.
- Exact wording of human-facing messages and Markdown prose.
- Internal module layout under `vibeguard.*` (use `vibeguard.api` for
  plugins).
- Benchmark numbers (informational; see [`benchmark.md`](benchmark.md)).
- Anything explicitly marked experimental above.

## Reporting a contract break

If a release changes any **stable** surface above without a major bump and a
migration note, that is a bug — please
[open an issue](https://github.com/dgenio/vibeguard/issues/new/choose) and
reference this contract.
