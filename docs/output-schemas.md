# VibeGuard Output Schemas

This page documents three stable outputs that downstream tools — CI dashboards,
IDE extensions, AI coding agents — depend on:

1. **Finding fingerprints** (`Finding.fingerprint`)
2. **Repo health score** (`ScanResult.health_score`)
3. **Machine-readable diagnostics** (`vibeguard scan --diagnostics`)

Anything in this document is part of VibeGuard's public contract. Breaking
changes require a major version bump.

---

## 1. Finding fingerprints

Every `Finding` carries a deterministic `fingerprint` field. It is the same
fingerprint used by the baseline file and the SARIF `partialFingerprints` map,
so a finding's identity is the same end-to-end.

### Algorithm

```
fingerprint = sha256(
    finding_id + ":" +
    normalized_path + ":" +
    sha256(stored_evidence)[:16]
)
```

* `finding_id` is the finding's stable identifier (e.g. `SEC-AWSACCESSKEY`).
* `normalized_path` is the relative file path with `\\` replaced by `/`.
* `stored_evidence` is the **stored** (post-truncation) evidence string. VibeGuard
  truncates evidence to the first 200 characters (plus a `…` marker) to avoid
  inadvertently keeping long secrets in memory. Two findings whose evidence
  shares the same first 200 characters **and** matches on `finding_id` and
  `normalized_path` will produce the same fingerprint; in practice the
  discriminator strength of `id` + `path` keeps this collision boundary
  narrow. If evidence is `null`, the inner segment is the empty string.
* **Line numbers are deliberately excluded.** A finding stays identifiable
  when surrounding code shifts.

### Where it appears

| Output                          | Field                                |
|---------------------------------|--------------------------------------|
| JSON (`--json`)                 | `findings[].fingerprint`             |
| Markdown (`--markdown`)         | "Fingerprint: `<first 12 hex>`"      |
| SARIF (`--sarif`)               | `partialFingerprints["vibeguard/v1"]` |
| Diagnostics (`--diagnostics`)   | `[].data.fingerprint`                |
| Baseline file                   | top-level entry key                  |

---

## 2. Repo health score

`ScanResult.health_score` is a deterministic roll-up of the findings produced
by the scan, after suppressions and baseline filtering have been applied. It
is informational only — **`vibeguard gate` keeps its severity-threshold
semantics** and does not consult the score.

### Formula

```
penalty = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
total   = max(0, 100 - penalty)
```

Weights (locked constants in `vibeguard/scoring.py`):

| Severity   | Weight |
|------------|--------|
| `critical` | 25     |
| `high`     | 10     |
| `medium`   | 3      |
| `low`      | 1      |
| `info`     | 0      |

### Grade

| `total` range | Grade |
|---------------|-------|
| 90 – 100      | A     |
| 75 – 89       | B     |
| 50 – 74       | C     |
| 25 – 49       | D     |
| 0 – 24        | F     |

### Shape

```jsonc
{
  "total": 88,
  "grade": "B",
  "penalty": 12,
  "by_severity": {
    "info": 0, "low": 2, "medium": 3, "high": 0, "critical": 0
  },
  "by_category": {
    "secrets": 2, "risky_diff": 3
  },
  "weights": {
    "info": 0, "low": 1, "medium": 3, "high": 10, "critical": 25
  }
}
```

`weights` is included in the output so a consumer can re-derive the score
without consulting this document.

---

## 3. Diagnostics output (`--diagnostics`)

`vibeguard scan --diagnostics` (and the equivalent flag on `gate`) emits a
JSON array shaped like VS Code's `Diagnostic` type. The schema is versioned
via `data.schema` on every record so editor plugins can refuse to consume
unknown versions.

### Schema (v1 — `vibeguard/diagnostics/v1`)

```jsonc
[
  {
    "severity": 0,                   // 0=Error, 1=Warning, 2=Information, 3=Hint
    "code": "SEC-AWSACCESSKEY",      // finding id
    "source": "vibeguard",
    "message": "AWS Access Key detected",
    "file": "src/config.py",
    "range": {
      "start": { "line": 9, "character": 0 },   // 0-based, LSP convention
      "end":   { "line": 9, "character": 0 }
    },
    "tags": [],                              // LSP DiagnosticTag[] (1=Unnecessary, 2=Deprecated); see note
    "data": {
      "schema": "vibeguard/diagnostics/v1",
      "fingerprint": "<sha256 hex>",
      "rule": "secrets",
      "tags": ["secrets"],                   // VibeGuard category tags
      "confidence": "high",
      "severity_label": "critical",
      "description": "An AWS access key was found in source code.",
      "recommendation": "Remove and rotate the key.",
      "evidence": "AKIA...EXAMPLE"        // optional
    }
  }
]
```

### Severity mapping

| VibeGuard severity | DiagnosticSeverity | Numeric |
|--------------------|--------------------|---------|
| `critical`         | Error              | `0`     |
| `high`             | Error              | `0`     |
| `medium`           | Warning            | `1`     |
| `low`              | Information        | `2`     |
| `info`             | Hint               | `3`     |

### Tags and rule family

* **Top-level `tags`** follows LSP semantics — a list of `DiagnosticTag`
  integers (1 = `Unnecessary`, 2 = `Deprecated`). VibeGuard's rule families
  don't currently map onto that enum, so the top-level field is emitted as an
  empty array. Strict consumers that type the JSON against the LSP
  `Diagnostic` shape see a spec-compliant value.
* **`data.rule`** carries the singular rule family that produced the finding
  (`"secrets"`, `"risky_diff"`, `"sourcemaps"`, …). One value per finding.
* **`data.tags`** carries VibeGuard's per-finding category tag list. It can
  include the same string as `data.rule` plus cross-cutting tags like
  `"supply-chain"` that aren't the rule family itself. Consumers that want to
  group by rule family should read `data.rule`; consumers that want to filter
  by any tag (rule family or cross-cutting) should read `data.tags`.

### Field naming vs. issue #51

The shape above renames two fields from the original issue's example: what
issue #51 called `data.rule_id` is shipped as `data.rule`, and what it called
`data.vibeguard_severity` is shipped as `data.severity_label`. Same semantics,
shorter and more consistent with the rest of the `Finding` model.

### Schema file

A machine-readable JSON Schema (Draft 7) for the per-record shape lives at
[`docs/diagnostics-schema.json`](diagnostics-schema.json). Editor extension
authors should validate diagnostics output against that file rather than
hand-parsing this document.

### Stability

* Required keys (`severity`, `code`, `source`, `message`, `file`, `range`,
  `tags`, `data`) and the structure of `range` will not change within v1.
* New optional keys may be added under `data` without bumping the schema
  version. Consumers should ignore unknown keys.
* Removing or renaming a required key, or changing `severity` semantics, is a
  breaking change and bumps the schema version.
