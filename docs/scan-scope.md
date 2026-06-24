# Scan scope: what gets scanned, in what mode, and why

VibeGuard's `scan` and `gate` commands always do the same thing — run the
enabled rules and report findings — but *which* files and *which* lines they
look at depends on the **scope mode** you select. This page is the reference for
that behaviour: the available modes, how targets are resolved, the precedence
rules, and how findings are filtered in each mode.

`scan` is informational (always exits `0`); `gate` enforces (exits non-zero on
blocking findings). Scope selection is identical for both.

## The scan pipeline

Every scan flows through the same ordered stages. Each stage can *remove* a file
or a finding from what is ultimately reported, which is why "why wasn't X
flagged?" almost always resolves to "which stage dropped it":

```
targets ─▶ collect ─▶ run rules ─▶ scope filter ─▶ suppressions ─▶ policy ─▶ baseline ─▶ report
           │            │            │               │              │          │
   ignore/size/binary   findings  diff/staged/patch  inline       severity   known
   prune the file set   per file  keep only changed  # vibeguard:  overrides  findings
                                  lines/files        ignore        + fail-on  filtered out
```

- **collect** — resolve targets into a concrete file set (see *Targets* and the
  exclusion-mechanism table below).
- **run rules** — every enabled rule inspects the collected files / changed set.
- **scope filter** — in `--diff` / `--staged` / `--patch`, findings are reduced
  to the change set (see *Scope modes*); a full scan skips this stage.
- **suppressions** — inline `# vibeguard: ignore[...]` comments drop matching
  findings.
- **policy** — severity overrides and `--fail-on` decide what blocks.
- **baseline** — previously accepted findings are filtered out, if a baseline is
  configured.

## Targets: what to scan

By default VibeGuard scans the current directory. You can point it at one or
more **targets** — files or directories — in two equivalent ways:

```bash
vibeguard scan                     # current directory
vibeguard scan src/                # one directory
vibeguard scan src/ tests/         # several directories
vibeguard scan src/app.py util.py  # individual files
vibeguard scan --path src/         # --path is an alias for a single target
```

Rules:

- **Positional paths win over `--path`.** `--path/-p` remains supported as an
  alias for a single target; if you pass positional paths, `--path` is ignored.
- **Directories are walked**, honouring every ignore layer (see below).
- **A file named explicitly is an intentional request**, so it bypasses the
  ignore layers (config `ignore.paths`, `.vibeguardignore`, and `.gitignore`)
  and is excluded only by the universal size/binary checks. This lets you scan a
  single file even if it lives under an ignored directory.
- **Finding paths are reported relative to the targets' common ancestor**, so
  `vibeguard scan src/ tests/` reports `src/...` and `tests/...` rather than
  absolute paths. A single directory target keeps that directory as the root.
- A missing target fails closed with exit code `2` — a typo never silently
  scans nothing.

### Ignore layers (directory targets)

When walking a directory, files are excluded by, in order:

1. `ignore.paths` in `vibeguard.yaml` and `.vibeguardignore` (gitignore syntax,
   unified into one last-match-wins spec; a `!` negation can re-include a path).
2. `.gitignore`, when `scanner.respect_gitignore` is `true` (the default), with
   a **git-tracked carve-out**: a file git already tracks is still scanned even
   if a `.gitignore` rule would exclude it (so a committed `.env` still trips
   `SEC-ENV`).
3. The universal size limit (`scanner.max_file_size_kb`) and a binary-content
   check.

Ignored directories are pruned *during* the walk, so their contents are never
enumerated.

### Exclusion mechanisms (what drops a file or a finding)

The mechanisms below decide what survives to be reported. They apply at
different pipeline stages, and within the collection stage they apply in the
order listed (a later layer's `!` negation can re-include a path an earlier
layer excluded):

| Mechanism | Syntax | Semantics | Stage | Notes / precedence |
| --- | --- | --- | --- | --- |
| `ignore.paths` (config) | gitignore (pathspec) | Excludes matching paths | collect | Unified last-match-wins with `.vibeguardignore` |
| `.vibeguardignore` | gitignore (pathspec) | Excludes matching paths | collect | Same spec as above; a `!` negation can re-include |
| `.gitignore` | gitignore (pathspec) | Excludes matching paths when `scanner.respect_gitignore` (default on) | collect | Git-tracked carve-out: a tracked file is still scanned |
| Size limit | `scanner.max_file_size_kb` | Skips files over the cap | collect | Universal — applies to explicit file targets too |
| Binary sniff | null-byte in first 8 KB | Skips binary files | collect | Universal — applies to explicit file targets too |
| Explicit file target | positional path / `--path FILE` | **Bypasses** the three ignore layers above | collect | Size/binary still apply |
| Scope filter | `--diff` / `--staged` / `--patch` | Keeps only findings on the change set's added/changed lines (file-level findings on a changed file kept; aggregate findings always kept) | scope filter | Skipped entirely for a full scan |
| Inline suppression | `# vibeguard: ignore[ID]` | Drops the matching finding on that line | suppressions | Requires a `reason=` (warns otherwise) |
| Policy / `--fail-on` | config / CLI | Decides which surviving findings *block* | policy | Does not remove findings from the report |
| Baseline | baseline file | Filters out previously accepted findings | baseline | Optional; off unless configured |

## Scope modes

Exactly one scope mode may be active. `--diff`, `--staged`, and `--patch` are
mutually exclusive; selecting more than one is a usage error (exit `2`).

| Mode | Flag | What it scans | Change set comes from |
| --- | --- | --- | --- |
| Full | *(default)* | All files under the targets | — (every finding kept) |
| Diff | `--diff` | Working-tree files, findings restricted to the change set | `git diff <base>...HEAD` (or `git diff HEAD`) |
| Staged | `--staged` | Only the staged files (content from the working tree) | `git diff --cached` |
| Patch | `--patch FILE`/`-` | A unified diff, standalone | the diff itself |

### Full scan

Every file under the targets is scanned and every finding is reported. This is
the default and the right choice for a first audit or a scheduled full sweep.

### `--diff` (changed vs the base branch)

Restricts findings to the change set of `base...HEAD`. The base ref is resolved
as: `--base` → `git.base_branch` config → automatic detection (`origin/main` →
`origin/master` → `main` → `master`). When no base can be found, VibeGuard
degrades to `git diff HEAD` and emits a `git_context` diagnostic so you know the
diff may be incomplete (pass `--base`, set `git.base_branch`, or fetch the base
branch — and use `fetch-depth: 0` on shallow CI clones).

This is the canonical PR gate. Findings on files outside the diff are dropped as
pre-existing repository state; line-level findings survive only when they fall
on an added/changed line.

```bash
vibeguard gate --diff --base "origin/${{ github.base_ref }}" --fail-on high
```

### `--staged` (the fast pre-commit gate)

Scopes the scan to the git **index** (`git diff --cached`), independent of any
base branch. It reflects exactly what a commit would record, which makes it the
natural fast gate for a `pre-commit` hook:

```bash
vibeguard gate --staged --fail-on high
```

Unlike `--diff` (which walks the whole working tree and then filters findings),
`--staged` **collects only the staged files**, so the scan cost scales with the
size of the change rather than the size of the repository — the property that
keeps a per-commit hook fast on a large repo. VibeGuard ships a ready-made hook
for this — `vibeguard-gate-staged` — alongside the full-tree `vibeguard-gate`
hook (see [pre-commit.md](pre-commit.md)). An empty index simply means "nothing
staged" and passes cleanly.

> Note: staged mode reads file *content* from the working tree and uses the
> index only to choose which files (and lines) are in scope. If a staged file
> has further unstaged edits, the content scanned is the working-tree version.

> Cross-file trade-off: because only the staged files are collected, rules that
> reason across the whole tree (e.g. package-leak detection, or missing-test
> cross-references that look for a sibling test file) see only the staged set in
> staged mode and are correspondingly weaker than in a full or `--diff` scan.
> Rules that key on the changed-file set behave identically. For an exhaustive
> cross-file pass, run a full or `--diff` scan in CI.

### `--patch` (gate a diff before it is applied)

Scans a unified diff supplied from a file or stdin (`-`), without needing the
files on disk:

```bash
git diff origin/main...HEAD | vibeguard gate --patch - --fail-on high
vibeguard scan --patch changes.diff --json
```

VibeGuard reconstructs the **new side** of each file in the diff (added and
context lines, positioned by the hunk line numbers) into a temporary tree and
scans that, restricting findings to the **added** lines. Context lines provide
structure for multi-line rules but are never themselves reported. This lets you
gate a proposed change — for example, a patch produced by a coding agent —
before applying it to the working tree.

`--patch` reads its file list from the diff itself, so it cannot be combined
with positional path arguments.

> Limitation: only lines that appear in the diff are reconstructed. Gaps between
> hunks are blank, so a rule that needs whole-file context (rather than the
> changed region) may see less than it would in a full scan. For exhaustive
> coverage, apply the change and run a full or `--diff` scan.

## Precedence summary

1. **Mode exclusivity** — at most one of `--diff` / `--staged` / `--patch`;
   otherwise exit `2`.
2. **Targets** — positional paths override `--path`; `--patch` ignores both and
   takes its files from the diff.
3. **Git-backed modes** (`--diff`, `--staged`) operate on a single repository
   directory; passing multiple paths or a file is a usage error.
4. **Config discovery** — `vibeguard.yaml` is auto-discovered from the first
   target (or its parent for a file target); for `--patch`, from `--path`
   (current directory by default).
5. **Filtering** — full scan keeps every finding; diff/staged/patch keep only
   findings on the change set's added/changed lines (file-level findings on a
   changed file are kept).

See also: [stability-contract.md](stability-contract.md) for the exit-code
contract, and [output-schemas.md](output-schemas.md) for the report formats.
