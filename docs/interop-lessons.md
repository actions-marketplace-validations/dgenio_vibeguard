# Interop: turning repeated findings into reviewed lessons

VibeGuard is a **detection layer**. It finds risky patterns in AI-generated
diffs and reports them; it does not learn, store history, or change agent
behaviour. That is by design — the gate stays deterministic, standalone, and
has no runtime dependency on any other tool.

But a *repeated* finding is a signal in its own right. If the same class of
risky pattern keeps appearing across PRs — say, an agent that habitually
disables TLS verification — that recurrence is exactly the kind of evidence a
learning loop can turn into a **reviewed lesson** that steers future agent
work away from the pattern.

[lessonweaver](https://github.com/dgenio/lessonweaver) is one such loop: it
consumes trace-like evidence and produces reviewed `LessonCard`s. This note
shows how VibeGuard findings can feed that loop **through serialized output
only** — VibeGuard never imports or calls lessonweaver, and lessonweaver
remains entirely optional.

- **VibeGuard** = detection. Deterministic, standalone, no learning.
- **lessonweaver** = the optional learning loop. Reviewed lessons, lifecycle.
- The seam between them is a **file**, not a dependency.

---

## The export: `vibeguard scan --weaver`

The `--weaver` flag (on both `scan` and `gate`) emits a weaver-spec
[`ArtifactSafetyReport`](weaver/artifact_safety_report.schema.json) — the
canonical contract for *"the output of an artifact safety gate run."* VibeGuard
**is** a dev-time artifact safety gate, so the fit is direct.

> The native `--json`, `--sarif`, and `--diagnostics` outputs are unchanged.
> `--weaver` is purely additive.

```bash
vibeguard scan --path . --weaver > report.json
```

### Field mapping (Finding → ArtifactSafetyReport)

The report is a 1:1 mapping of the scan result. Top-level:

| ArtifactSafetyReport | Source | Notes |
|----------------------|--------|-------|
| `report_id`          | `sha256(sorted finding fingerprints + scan_path)` | Stable for an unchanged finding set. |
| `gate_id`            | `"vibeguard"` | Constant. |
| `decision`           | `fail` if any finding ≥ `fail_on`, else `pass` | Mirrors the gate verdict. |
| `created_at`         | UTC timestamp at render time | Required by the contract — see *Determinism* below. |
| `mode`               | `gate` → `blocking`, `scan` → `advisory` | |
| `summary`            | finding count + blocking count | |
| `findings[]`         | one entry per `Finding` | see below |
| `provenance`         | `{tool, version, information_uri, ruleset}` | |

Per finding:

| ArtifactSafetyReport finding | VibeGuard `Finding` | Notes |
|------------------------------|---------------------|-------|
| `finding_id`  | `id` | The rule's finding ID, e.g. `AI-TRUSTALLCERTS`. |
| `severity`    | `severity` | Same enum: `info`/`low`/`medium`/`high`/`critical`. |
| `message`     | `f"{title}: {description}"` | |
| `fingerprint` | `fingerprint` | Stable identity across line moves — the dedup key. |
| `remediation` | `recommendation` | |
| `rule`, `path`, `line`, `tags`, `confidence`, `evidence` | same | VibeGuard extras under the contract's `additionalProperties`. |

### Determinism

Every other VibeGuard reporter is byte-reproducible. `--weaver` is the one
exception: `ArtifactSafetyReport.created_at` is a **required** `date-time`
field, so each report is timestamped at render time. The `report_id` and every
`fingerprint`, by contrast, are derived from finding content and stay stable
across runs, so downstream dedup does not depend on the timestamp.

---

## One-off vs. repeated: what becomes a lesson

A single finding in a single PR is **not** a lesson — it is a fix. A lesson is
warranted only when a *category* of pattern **recurs across PRs** — that is the
signal of a team- or agent-level habit, rather than a one-time slip. The
aggregation rule is deliberately simple and lives in the consumer, not in
VibeGuard:

- Group findings by **rule category** (`finding.rule`, e.g. `ai_footprints`),
  keyed by `fingerprint` so the same physical issue is never double-counted.
- A category seen in **one** PR context → one-off. Report it; do not mint a
  lesson.
- A category seen across **two or more distinct PR contexts** → repeated
  pattern (a habit) → candidate `LessonCard`. The lesson names the specific
  finding IDs (`AI-TRUSTALLCERTS`, …) it generalises from.

The runnable example in [`../examples/interop/`](../examples/interop/) does
exactly this over the bundled `examples/pr-scenarios/` fixtures — treating each
scenario directory as a separate PR — and prints both the
`ArtifactSafetyReport`s and the candidate lessons.

---

## Worked example: the `ai_footprints` category

Pick one category: `ai_footprints` — the rule family that flags telltale
AI-generated risk markers. Across the fixtures it recurs in two distinct PR
contexts: `AI-TRUSTALLCERTS` ("trust-all certificates") in
`01-tls-verify-disabled`, and `AI-TEMPBYPASS` ("temporary security bypass") in
`02-auth-bypass-left-in`. Two distinct contexts → a habit, not a slip → the
consumer mints a **candidate** lesson as a weaver-spec
[`LessonCard`](weaver/lesson_card.schema.json):

```json
{
  "lesson_id": "vibeguard-lesson-ai_footprints",
  "title": "Review AI footprints before merging (ai_footprints)",
  "body": "VibeGuard flagged the ai_footprints category across 2 separate changes (AI-TRUSTALLCERTS, AI-TEMPBYPASS). Generated code repeatedly ships AI risk markers — disabled TLS verification and left-in temporary security bypasses. Do not merge trust-all TLS clients or temporary auth bypasses; keep verification on and remove scaffolding bypasses before review.",
  "created_at": "2026-06-04T00:00:00+00:00",
  "lifecycle_state": "in_review",
  "scope": "repo",
  "applicability": ["ai_footprints", "AI-TRUSTALLCERTS", "AI-TEMPBYPASS"],
  "source_refs": [
    "vibeguard:fingerprint:<fp-from-01-tls-verify-disabled>",
    "vibeguard:fingerprint:<fp-from-02-auth-bypass-left-in>"
  ],
  "provenance": { "tool": "VibeGuard", "derived_from": "repeated ArtifactSafetyReport findings" }
}
```

Two things make this a *useful* lesson rather than a vague rule:

1. **It is specific** — it names the exact patterns (`AI-TRUSTALLCERTS`,
   `AI-TEMPBYPASS`) and the corrective behaviour, not "write secure code."
2. **It is gated** — `lifecycle_state` is `in_review`, never `active`. A human
   reviews the candidate before it influences any agent. VibeGuard proposes;
   the review loop disposes.

---

## Acceptance-criteria mapping

This note plus the `--weaver` export and the `examples/interop/` script cover:

- **#103** — minimal export shape documented; one realistic finding category
  (`AI-TRUSTALLCERTS`); a runnable example over synthetic PR scenarios;
  one-off vs. repeated distinguished; expected lesson outcome shown; no runtime
  dependency on lessonweaver.
- **#120** — additive `ArtifactSafetyReport` export (native JSON/SARIF
  unchanged); field mapping documented and validated against the vendored
  weaver-spec schema (`tests/test_reporters_weaver.py`); runnable example feeds
  findings toward lessonweaver-shaped `LessonCard`s; no hard runtime
  dependency on any sibling.
