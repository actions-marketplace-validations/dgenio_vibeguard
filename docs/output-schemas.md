# VibeGuard Output Schemas

This page documents the stable outputs that downstream tools — CI dashboards,
IDE extensions, AI coding agents — depend on:

1. **Finding fingerprints** (`Finding.fingerprint`)
2. **Repo health score** (`ScanResult.health_score`)
2a. **Scan diagnostics** (`ScanResult.diagnostics` / `errors`)
3. **Machine-readable diagnostics** (`vibeguard scan --diagnostics`)
4. **Structured remediation metadata** (`Finding.remediation`, SARIF `fixes`)
5. **SARIF ingestion safeguards** (result cap for code scanning)
6. **reviewdog rdjson** (`vibeguard scan --rdjson`)
7. **SonarQube generic issue import** (`vibeguard scan --sonar`)

Writing any format to a file (instead of stdout) and emitting several at once
is covered under [Writing reports to files](#8-writing-reports-to-files).

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

## 2a. Scan diagnostics (`ScanResult.diagnostics`)

Separate from the editor-facing `--diagnostics` reporter below, every scan
result carries a list of **scan diagnostics** — the non-finding events that
happened while scanning. They appear in `--json` output as
`diagnostics` (structured) alongside the legacy `errors` array (#195).

```json
"diagnostics": [
  {
    "category": "rule_error",
    "severity": "error",
    "message": "Rule secrets failed: ...",
    "path": null,
    "rule": "secrets",
    "detail": "..."
  }
],
"errors": ["Rule secrets failed: ..."]
```

* **`category`** — one of a small, stable taxonomy. New categories may be
  **added** in a minor release; existing ones are never renamed:

  | Category | Meaning |
  |---|---|
  | `skipped_file` | A file was not scanned (binary, oversize, gitignored, or unreadable). |
  | `plugin_load` | A third-party rule plugin failed to load (scan continued). |
  | `git_context` | Degraded git context in `--diff` mode (e.g. no base branch; HEAD-only diff). |
  | `rule_error` | A rule raised an exception and was skipped (scan continued). |
  | `network` | An opt-in networked check (slopsquat registry lookup) could not complete (#191). |

* **`severity`** — `info` (routine, e.g. a binary skip), `warning`, or `error`.
  This separates expected noise from a genuinely degraded scan.
* **`message`** — a single human-readable line. The `errors` array is exactly
  `[d.message for d in diagnostics]`, kept as a backward-compatible flat view;
  prefer `diagnostics` for anything that needs to react per category.
* **`path` / `rule` / `detail`** — optional context when available.

`gate --strict-errors` (and `gate.strict_errors: true`) consumes this model: it
fails the gate when any **degraded** diagnostic is present — every category
except a routine (`info`) `skipped_file` — so a partially-broken scan cannot
show a green check (#218). See the [Exit codes](stability-contract.md#exit-codes)
contract.

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

---

## 4. Structured remediation metadata (`Finding.remediation`)

For the mechanically-fixable subset of findings, VibeGuard attaches a structured
`remediation` object so coding agents and review bots can apply or propose a fix
without re-parsing the prose `recommendation` (#238). The field is **optional**
and `null` when no machine-actionable fix is known — old consumers that ignore
unknown/null fields are unaffected.

### Shape

```jsonc
{
  "id": "MAP-URL",
  "rule": "sourcemaps",
  // …the usual Finding fields…
  "remediation": {
    "kind": "replace-span",        // delete-file | add-line | replace-span | add-ignore-entry | manual
    "target": "dist/app.js",       // path the fix edits (defaults to the finding path)
    "line": 42,                     // 1-based line, when known
    "content": "",                  // text to insert / the replacement span ("" = delete)
    "description": "Delete the //# sourceMappingURL= comment.",
    "confidence": "high"            // how safe the fix is to apply automatically
  }
}
```

### Kinds

| Kind | Meaning | SARIF `fix`? |
|------|---------|--------------|
| `replace-span` | Replace (or delete, when `content` is empty) a known line | yes |
| `add-line` | Insert `content` before `line` | yes |
| `add-ignore-entry` | Append `content` to an ignore file (`.gitignore`/`.npmignore`) | no — JSON only |
| `delete-file` | Remove the file at `target` | no — JSON only |
| `manual` | Needs human judgement; carries guidance only | no |

VibeGuard only emits a remediation when the edit is mechanically safe; a wrong
auto-fix is worse than none. Applying fixes is out of scope here (it belongs to
the separate `vibeguard fix` work) — this is the shared data model.

### SARIF `fixes`

Findings whose remediation is `replace-span` or `add-line` also emit a SARIF
2.1.0 [`fix`](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
object (`result.fixes[]`), which GitHub Code Scanning renders as a one-click
suggested change. `add-ignore-entry`/`delete-file`/`manual` can't be expressed
as an in-file region edit, so they appear in JSON output only.

---

## 5. SARIF ingestion safeguards

GitHub Code Scanning rejects SARIF uploads beyond a documented number of results
per run (5,000 at time of writing). To keep a first scan of a large legacy repo
from failing the whole upload, the SARIF reporter caps results (#227):

* The cap defaults to **5,000** and is configurable via
  `output.sarif_max_results` in `vibeguard.yaml`.
* When the finding count exceeds the cap, findings are ordered **by severity**
  (then path, then line for determinism) and the top *N* are emitted, so the
  gate-relevant findings survive.
* An informational `runs[].invocations[].toolExecutionNotifications[]` entry
  records the total count and points at `--json` (or a baseline workflow) for
  the full set.
* Result sets **at or below** the cap are byte-identical to previous releases —
  no reordering, no notification.

For large repositories, baseline the existing findings first, then gate only new
ones (see `docs/github-actions.md`).

---

## 6. reviewdog rdjson (`--rdjson`)

`vibeguard scan --rdjson` (and `gate --rdjson`) emits reviewdog's
[Diagnostic Format](https://github.com/reviewdog/reviewdog/blob/master/proto/rdf/README.md),
so VibeGuard plugs into reviewdog's review backends (GitHub, GitLab, Gerrit,
Bitbucket) without first-party support for each.

```jsonc
{
  "source": { "name": "vibeguard", "url": "https://github.com/dgenio/vibeguard" },
  "severity": "WARNING",
  "diagnostics": [
    {
      "message": "Trust-all certificates: TLS verification disabled.",
      "location": { "path": "src/client.py", "range": { "start": { "line": 42, "column": 1 } } },
      "severity": "ERROR",                       // INFO/LOW→INFO, MEDIUM→WARNING, HIGH/CRITICAL→ERROR
      "code": { "value": "AI-TRUSTALLCERTS", "url": ".../docs/rules.md#auth" },
      "source": { "name": "vibeguard", "url": "https://github.com/dgenio/vibeguard" }
    }
  ]
}
```

Consume it with `reviewdog -f=rdjson`:

```yaml
- run: vibeguard scan --diff --base "origin/${{ github.base_ref }}" --rdjson --output vg.rdjson
- run: reviewdog -f=rdjson -name=vibeguard -reporter=github-pr-review < vg.rdjson
```

---

## 7. SonarQube generic issue import (`--sonar`)

`vibeguard scan --sonar` emits SonarQube's
[Generic Issue Import](https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/importing-external-issues/external-analyzer-reports/)
JSON for `sonar.externalIssuesReportPaths`.

```jsonc
{
  "issues": [
    {
      "engineId": "vibeguard",
      "ruleId": "SEC-ENV",
      "type": "VULNERABILITY",        // VULNERABILITY for security-tagged rules, else CODE_SMELL
      "severity": "CRITICAL",         // see mapping below
      "primaryLocation": {
        "message": "Sensitive file committed: .env",
        "filePath": "src/.env",
        "textRange": { "startLine": 9, "endLine": 9 }   // omitted for file-level findings
      }
    }
  ]
}
```

### Severity mapping

| VibeGuard | SonarQube |
|-----------|-----------|
| `critical` | `BLOCKER` |
| `high` | `CRITICAL` |
| `medium` | `MAJOR` |
| `low` | `MINOR` |
| `info` | `INFO` |

**Version compatibility:** this targets the stable
`engineId`/`ruleId`/`type`/`severity` external-issue shape supported from
SonarQube 7.x through the current 10.x line. (10.x also accepts the newer
`impacts`/`cleanCodeAttribute` model, but the legacy fields remain valid and are
the most portable.)

`sonar-project.properties`:

```properties
sonar.externalIssuesReportPaths=vibeguard-sonar.json
```

```yaml
- run: vibeguard scan --sonar --output vibeguard-sonar.json
```

---

## 8. Writing reports to files

Every machine format can be written to a file instead of stdout, and several can
be produced from one scan (#233):

* `--output PATH` (`-o`) writes the single selected format to `PATH`
  (`-` means stdout). It requires a format flag; `--output` alone is an error
  (exit 2), as is an unwritable destination.
* `--report FORMAT=PATH` is repeatable and emits several formats from **one**
  scan — no shell redirection, no double scan:

  ```bash
  vibeguard gate --diff --base "origin/${{ github.base_ref }}" \
    --report sarif=vibeguard.sarif \
    --report pr-comment=comment.md
  ```

  `--report` cannot be combined with `--output` or a bare format flag (exit 2).
  Valid formats: `json`, `sarif`, `markdown`, `pr-comment`, `diagnostics`,
  `weaver`, `rdjson`, `sonar`.

The human pass/fail summary still prints to stderr, and exit codes are
unchanged. Existing stdout invocations (no `--output`/`--report`) are
byte-identical to previous releases.
