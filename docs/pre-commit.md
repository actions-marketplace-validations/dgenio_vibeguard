# Using VibeGuard with pre-commit

VibeGuard ships a [`.pre-commit-hooks.yaml`](../.pre-commit-hooks.yaml) so any
project using [pre-commit](https://pre-commit.com) can drop the gate into its
local hook chain in two lines — no `local`-hook boilerplate, no custom shell
wrapper, no second tool to keep version-pinned.

## Install pre-commit

```bash
pip install pre-commit
pre-commit install
```

## Add VibeGuard to `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/dgenio/vibeguard
    rev: v0.6.0   # pin to a released tag — never `main`
    hooks:
      - id: vibeguard-gate
```

`vibeguard-gate` runs `vibeguard gate --fail-on high` by default. It blocks
the commit if any finding at or above `high` severity is reported. Override
the threshold via `args`:

```yaml
      - id: vibeguard-gate
        args: [--fail-on, critical]
```

## Available hooks

| Hook ID                     | Command              | Exit behaviour                                        | Typical use                                          |
| --------------------------- | -------------------- | ----------------------------------------------------- | ---------------------------------------------------- |
| `vibeguard-gate`            | `vibeguard gate`     | Non-zero on findings at or above `--fail-on` (default `high`). | Block risky commits in pre-commit / pre-push.        |
| `vibeguard-gate-staged`     | `vibeguard gate --staged` | Non-zero on findings in the **staged** changes only. | Fast pre-commit gate — scan just what you're committing. |
| `vibeguard-scan`            | `vibeguard scan`     | Always 0 — informational only.                        | Print findings without blocking commits.             |
| `vibeguard-validate-config` | `vibeguard validate` | Non-zero if `vibeguard.yaml` fails schema validation. | Catch config typos before they break CI.             |

Each hook declares `pass_filenames: false` because VibeGuard scans the
working tree as a whole; passing individual staged paths would drop the
cross-file context the rules rely on (e.g. package leak detection, missing-
tests checks).

`vibeguard-gate-staged` scopes the scan to the git index (`git diff --cached`)
for a faster gate on large repositories: it inspects only the changes you are
about to commit rather than the whole tree. See
[scan-scope.md](scan-scope.md) for the full scope-mode reference.

`vibeguard-validate-config` is the one exception — it runs only when
`vibeguard.yaml` itself changes (`files: ^vibeguard\.yaml$`).

## Common configurations

**Gate on critical only — surface everything else without blocking**

```yaml
repos:
  - repo: https://github.com/dgenio/vibeguard
    rev: v0.6.0
    hooks:
      - id: vibeguard-gate
        args: [--fail-on, critical]
      - id: vibeguard-scan
```

**Run on pre-push instead of pre-commit**

```yaml
repos:
  - repo: https://github.com/dgenio/vibeguard
    rev: v0.6.0
    hooks:
      - id: vibeguard-gate
        stages: [pre-push]
```

**Scope to a sub-directory** (monorepos)

```yaml
      - id: vibeguard-gate
        args: [--fail-on, high, --path, packages/api]
```

**Use a custom config file**

```yaml
      - id: vibeguard-gate
        args: [--fail-on, high, --config, .vibeguard/strict.yaml]
```

## Skipping the hook ad-hoc

Use the standard pre-commit escape hatch:

```bash
SKIP=vibeguard-gate git commit -m "wip"
```

## CI: `pre-commit.ci` autoupdate

[`pre-commit.ci`](https://pre-commit.ci) picks the repo up automatically.
Add this to `.pre-commit-config.yaml` to opt-in to weekly `rev:` bumps:

```yaml
ci:
  autoupdate_schedule: weekly
```

## Troubleshooting

- **`command not found: vibeguard`** — pre-commit installs the hook in its
  own isolated virtualenv, so the host shell does not need `vibeguard` on
  `$PATH`. If you see this error, check that `language: python` is set in
  `.pre-commit-hooks.yaml` (it ships that way by default).
- **`Repository not in expected format`** — pin `rev:` to a released tag,
  not a branch name. `main` is rejected by pre-commit.
- **Different findings between hook and CI** — both run the same `vibeguard`
  binary; the most common cause is a different `--fail-on` value or a
  missing `vibeguard.yaml` in the working tree.

## Related

- [`docker.md`](docker.md) — run the same gate as a container instead.
- [`github-actions.md`](github-actions.md) — first-party GitHub Action.
