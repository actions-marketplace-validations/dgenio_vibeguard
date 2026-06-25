# Suppressing findings

VibeGuard gives you three layers for silencing a finding, from the most local
to the most global:

1. **Inline suppressions** — a comment on (or above) the offending line.
2. **Policy suppressions** — reviewable `vibeguard.yaml` entries, optionally
   with an expiry date.
3. **Baselines** — accept the entire current set of findings and only gate on
   *new* ones.

This page documents the inline syntax end-to-end, then explains how the three
layers interact.

---

## Inline suppressions

### Grammar

```text
<comment-leader> vibeguard: ignore <ID>[,<ID>...] reason="<why>"
```

- **`<comment-leader>`** — one of the recognised single-line comment styles
  (see [Supported comment styles](#supported-comment-styles)).
- **`vibeguard: ignore`** — the literal marker. Whitespace around the colon is
  flexible (`vibeguard:ignore` and `vibeguard:  ignore` both parse).
- **`<ID>[,<ID>...]`** — one or more finding IDs (e.g. `SEC-AWSACCESSKEY`),
  comma-separated, no spaces. Finding IDs are uppercase; look one up with
  `vibeguard explain <ID>` or list them all with `vibeguard rules list`.
- **`reason="..."`** — a short justification. It is **strongly recommended**:
  omitting it does not stop the suppression from working, but VibeGuard emits a
  `SUPPRESSION-NO-REASON` finding (see [below](#the-suppression-no-reason-warning))
  so unexplained suppressions stay visible in review.

### Placement: same line or the line above

A suppression comment applies to its **own line and the line immediately
below it**. That means both of these suppress the `api_key` finding:

```python
api_key = "AKIAIOSFODNN7EXAMPLE"  # vibeguard: ignore SEC-AWSACCESSKEY reason="test fixture"
```

```python
# vibeguard: ignore SEC-AWSACCESSKEY reason="test fixture"
api_key = "AKIAIOSFODNN7EXAMPLE"
```

The previous-line form is useful when the line is already long or when the
comment leader differs from the language (for example, suppressing an HTML
finding from a Markdown comment on the line above).

### Multiple IDs on one line

If a single line trips more than one rule, list every ID you want to silence,
comma-separated:

```python
x = make_request(verify=False)  # vibeguard: ignore RISK-TRUSTCERTS,AI-TRUSTALLCERTS reason="internal CA, pinned"
```

Only the listed IDs are suppressed; any *other* finding on that line still
fires.

### Supported comment styles

| Leader | File types |
|--------|------------|
| `#`    | Python, shell, YAML, TOML, Dockerfile, HCL/Terraform |
| `//`   | JavaScript/TypeScript, Go, HCL/Terraform |
| `--`   | SQL |
| `<!--` | HTML, Markdown — e.g. `<!-- vibeguard: ignore PI-HIDDENUNICODE reason="example" -->` |

Inline suppressions are parsed in these file types:

```text
.py .js .ts .jsx .tsx .go .rb .java .cs
.yaml .yml .toml .tf .hcl .sql
.md .markdown .html .htm .sh .bash .dockerfile
Dockerfile (and Dockerfile.* variants)
```

The suppression *directive* must sit on a single line, so multi-line block
comments (`/* ... */`) are not recognised — put it on a single comment line.
(This is separate from *placement*, which is "same line or the line above" as
described above.)

### The `SUPPRESSION-NO-REASON` warning

An inline suppression without a `reason="..."` argument still suppresses its
target, but VibeGuard reports a low-severity `SUPPRESSION-NO-REASON` finding
pointing at the suppression. This keeps "silent" suppressions auditable: a
reviewer can see *that* something was suppressed even when they can't see
*why*. Add a reason to clear the warning.

---

## Policy suppressions (`vibeguard.yaml`)

For suppressions that should live in policy rather than next to the code — or
that you want to expire automatically — use the `suppressions:` list:

```yaml
suppressions:
  - finding_id: SEC-AWSACCESSKEY
    path_pattern: "tests/fixtures/**"
    reason: "Known test fixtures, not live credentials"
    expires: "2026-12-31"   # optional ISO date (YYYY-MM-DD)
```

An expired policy suppression no longer suppresses — instead VibeGuard emits a
`SUPPRESSION-EXPIRED` warning so stale exceptions resurface for review.

To suppress a finding ID everywhere with no path scoping or expiry, the
coarser `ignore.findings` list also works:

```yaml
ignore:
  findings:
    - SEC-AWSACCESSKEY
```

---

## Baselines

When adopting VibeGuard on an existing repository, a baseline lets you accept
the current findings and gate only on *new* ones:

```yaml
baseline: .vibeguard-baseline.json
```

Inline and policy suppressions are still applied on top of a baseline — use
them for findings you want to silence permanently, and the baseline for the
backlog you intend to burn down.

---

## Which layer should I use?

- **Inline** — a specific, intentional false positive or accepted risk on a
  known line, reviewed in the same diff as the code. The reason lives next to
  the code it explains.
- **Policy** — the same exception across many files, or one you want to expire
  and revisit. Reviewed centrally in `vibeguard.yaml`.
- **Baseline** — bulk-accept pre-existing findings during onboarding so the
  gate only blocks on newly introduced ones.
