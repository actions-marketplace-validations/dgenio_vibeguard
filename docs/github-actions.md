# GitHub Actions Adoption Guide

This guide shows how to integrate VibeGuard into your GitHub Actions PR workflow using SARIF code scanning, PR comments, baselines, and annotations.

## 0. One-Command Setup

The fastest path: let VibeGuard write the workflow for you.

```bash
pip install vibeguard-gate
vibeguard setup github-actions
```

This generates `.github/workflows/vibeguard.yml` — a single job that wires all
three PR surfaces at once:

1. **SARIF upload** → inline code-scanning annotations on the PR diff.
2. **PR comment** → one summary comment, updated in place on every push (no spam).
3. **Gate** → fails the PR on findings at/above `--fail-on` (default `high`).

Review the file, commit it, and open a PR. Options:

| Flag | Effect |
|---|---|
| `--policy-pack <name>` | Also write a `vibeguard.yaml` for the pack and derive the gate threshold from it (e.g. `web-app` → `medium`). |
| `--fail-on <severity>` | Override the gate threshold (`info`–`critical`). |
| `--with-config` | Also write a default `vibeguard.yaml`. |
| `--dry-run` | Print the generated file(s) to stdout without writing. |
| `--force` | Overwrite an existing workflow (refuses by default). |

The generated workflow installs VibeGuard from PyPI (`pip install
vibeguard-gate`) and posts the comment with
[`actions/github-script`](https://github.com/actions/github-script), so it adds
no networking to the VibeGuard CLI itself. The sections below document the same
surfaces individually if you prefer to assemble the workflow by hand.

## 1. Minimal PR Gate Workflow

The simplest setup: fail PRs that introduce high/critical findings.

```yaml
name: VibeGuard Gate
on:
  pull_request:

permissions:
  contents: read

jobs:
  vibeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # needed for --diff mode

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip

      - name: Install VibeGuard
        run: pip install vibeguard-gate

      - name: Run VibeGuard gate
        run: vibeguard gate --diff --fail-on high
```

Or using the first-party action:

```yaml
      - uses: dgenio/vibeguard@v0.8.0
        with:
          diff: 'true'
          fail-on: high
```

## 2. SARIF Upload (Code Scanning Annotations)

Upload SARIF to get inline annotations in PR diffs and findings in the Security tab.

```yaml
name: VibeGuard Code Scanning
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write  # required for SARIF upload

jobs:
  vibeguard-sarif:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip

      - name: Install VibeGuard
        run: pip install vibeguard-gate

      - name: Run VibeGuard scan (SARIF)
        run: vibeguard scan --sarif > vibeguard.sarif
        continue-on-error: true

      - name: Upload SARIF to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: vibeguard.sarif
          category: vibeguard
```

## 3. PR Comment Workflow

Post a single summary comment that **updates in place** on every push instead of
adding a new comment each time. VibeGuard's `--pr-comment` output leads with a
hidden marker (`<!-- vibeguard-report -->`); the step below finds the existing
comment by that marker and edits it, falling back to creating one on the first
run.

```yaml
name: VibeGuard PR Comment
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write  # required for posting comments

jobs:
  vibeguard-comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip

      - name: Install VibeGuard
        run: pip install vibeguard-gate

      - name: Generate PR comment
        run: vibeguard gate --diff --fail-on high --pr-comment > vibeguard-comment.md
        continue-on-error: true

      - name: Post / update comment
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require("fs");
            const body = fs.readFileSync("vibeguard-comment.md", "utf8");
            const marker = "<!-- vibeguard-report -->";
            // Page through every comment (listComments caps at 30/page) so the
            // marker comment is still found on long PRs, and only match our own
            // bot comment so a user echoing the marker can't be overwritten.
            const comments = await github.paginate(github.rest.issues.listComments, {
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              per_page: 100,
            });
            const existing = comments.find(
              (c) => c.user?.login === "github-actions[bot]" && c.body && c.body.includes(marker)
            );
            if (existing) {
              await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: existing.id,
                body,
              });
            } else {
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body,
              });
            }
```

> **Fork PRs:** on pull requests from forks, GitHub restricts `GITHUB_TOKEN` to
> read-only regardless of the `permissions:` block, so the comment step can't
> post. Use the SARIF upload (Section 2) for fork coverage, or gate forks without
> the comment surface.

> `vibeguard setup github-actions` (Section 0) generates a workflow that already
> includes this idempotent comment step alongside SARIF upload and the gate.

## 4. Baseline Workflow

Create a baseline on the default branch to suppress pre-existing findings, then use it in PRs.

### Create baseline on main branch merges:

```yaml
name: Update VibeGuard Baseline
on:
  push:
    branches: [main]

permissions:
  contents: write

jobs:
  update-baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip

      - name: Install VibeGuard
        run: pip install vibeguard-gate

      - name: Create baseline
        run: vibeguard baseline create --output .vibeguard-baseline.json

      - name: Commit baseline
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add .vibeguard-baseline.json
          git diff --cached --quiet || git commit -m "chore: update vibeguard baseline"
          git push
```

### Use baseline in PR gate:

```yaml
      - name: Run gate with baseline
        run: vibeguard gate --diff --fail-on high --baseline .vibeguard-baseline.json
```

## 5. Recommended Thresholds

| Risk Profile | `fail-on` | Use Case |
|---|---|---|
| **Strict** | `medium` | Regulated environments, security-critical code |
| **Balanced** | `high` | Default for most teams |
| **Audit-only** | `critical` | Initial adoption, observability mode |
| **Info** | — (don't gate) | Use `scan` instead of `gate` for monitoring |

## 6. Caching

Speed up runs by caching pip installs:

```yaml
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: pip
          cache-dependency-path: '**/pyproject.toml'
```

## Problem Matcher

VibeGuard ships a [problem matcher](../.github/problem-matchers/vibeguard.json) for console output.
Enable it to get annotations even without `--sarif`:

```yaml
      - name: Enable VibeGuard problem matcher
        run: echo "::add-matcher::.github/problem-matchers/vibeguard.json"
```

## Annotations Mode

VibeGuard auto-emits `::error`, `::warning`, and `::notice` annotations when running inside GitHub Actions. Disable with `--no-annotations`:

```yaml
      - name: Run without annotations
        run: vibeguard gate --diff --fail-on high --no-annotations
```
