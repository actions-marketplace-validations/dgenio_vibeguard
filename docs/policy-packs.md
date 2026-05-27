# Policy packs

A **policy pack** is a bundled set of VibeGuard defaults that match a
common security profile. Apply a pack instead of hand-rolling every option
in `vibeguard.yaml` — then override only the keys that need to differ.

Pack settings are merged in as **defaults**: any key you set in your own
`vibeguard.yaml` always wins over the pack.

## Built-in packs

| Name | Use case | `fail_on` | Highlights |
|---|---|---|---|
| `oss-library` | Open-source library authors | `high` | `tests` rule disabled, `examples/` and `docs/` ignored |
| `web-app` | Full-stack web apps | `medium` | All rules on; `auth`, `sql`, `risky_diff` promoted to `high` |
| `strict-ci` | CI enforcement | `low` | `policy: strict`, every rule family promoted to `critical` |

The full YAML for each pack is in [`vibeguard/policies/`](../vibeguard/policies/).
Inspecting that directory is the most reliable way to see exactly what a
pack will apply.

## Applying a pack

### From the CLI

```bash
vibeguard scan --path . --policy-pack web-app
vibeguard gate --path . --policy-pack strict-ci
```

`--policy-pack` on the CLI takes precedence over any `policy_pack:` key
in `vibeguard.yaml`.

### From `vibeguard.yaml`

```yaml
policy_pack: oss-library

# Optional: override anything from the pack.
# The pack sets fail_on: high; bump it for this repo only.
fail_on: critical
```

### Generate a config from a pack

```bash
vibeguard init --policy-pack web-app
```

…creates a `vibeguard.yaml` that references the pack and is ready to edit.

## Merge semantics

Packs are layered under the user's config with these rules:

* **Scalars** (e.g. `fail_on`, `policy`): user value wins when set.
* **Sub-config sections** (e.g. `tests:`, `secrets:`): merged key by key.
  User-supplied keys win; pack keys fill in the rest.
* **Lists** (e.g. `ignore.paths`, `severity_overrides`, `suppressions`):
  user value **replaces** pack value entirely when present. Lists never
  extend — this matches every other config-merge tool we surveyed and
  avoids surprise duplicate entries.

An unknown pack name fails fast at config-load with a Pydantic
`ValidationError` listing the valid options.

## Source-test mapping for monorepos

VibeGuard's built-in missing-tests heuristic assumes a top-level
`src/` ⇄ `tests/` layout. Monorepos with per-package tests directories
hit false positives — `packages/api/src/handler.py` changes get flagged
even though `packages/api/tests/test_handler.py` is up to date.

Configure source-test mappings to teach the rule about your layout:

```yaml
tests:
  enabled: true
  mapping:
    - source: "packages/api/src/**"
      tests:
        - "packages/api/tests/**"
    - source: "packages/web/src/**"
      tests:
        - "packages/web/tests/**"
        - "packages/web/spec/**"   # multiple test globs are allowed
```

### Semantics

* Both `source` and `tests` use **gitignore-style globs** (the same syntax
  `.vibeguardignore` uses).
* A changed source file matching one or more mapping's `source` glob is
  considered **covered** if at least one of those mappings has a `tests`
  glob that also matches a changed file in the same change set.
* Files that match **no** mapping fall back to the legacy heuristic, so
  partial monorepo configs don't silently disable the rule everywhere.
* With no `mapping:` configured (the default), behavior is identical to
  every prior VibeGuard release — there is no startup or per-scan cost.

### Validation

The following configs fail loudly at load time:

* Empty `source` pattern — raises `'source' must be a non-empty glob pattern`.
* Empty list under `tests:` — fails Pydantic `min_length=1` validation.
* Empty-string entry inside `tests:` — raises `'tests' patterns must not be empty strings`.
* Any extra key inside a mapping item — fails Pydantic `extra="forbid"` validation.

### Simple-repo example

For a non-monorepo project, leave `tests.mapping` empty — the defaults
still work:

```yaml
tests:
  enabled: true
  # no mapping needed; heuristic handles src/ ⇄ tests/ layouts
```
