# VibeGuard vs. other tools

VibeGuard is **not** a replacement for your existing security and quality
stack. It is a fast, deterministic pre-merge gate for the specific class of
mistakes that AI-assisted coding ("vibe coding") produces — the small,
obvious, review-before-merge problems that tend to fall *between* linting,
SAST, secret-history scanning, dependency auditing, and human review.

This guide explains when VibeGuard helps, when it doesn't, and how it fits
alongside the tools you already run.

---

## Use VibeGuard when…

- You accept large AI-generated diffs and want a fast gate **before** they
  reach review or merge.
- You want to catch "AI footprints" — `# TODO: implement real auth`,
  `verify=False` added to make a test pass, `cors({ origin: "*" })`,
  trust-all-certificate blocks, commented-out auth middleware.
- You want to stop packaging mistakes (a `package.json` `files` entry that
  publishes source maps, an `.npmignore` negation, a `MANIFEST.in` graft
  that ships `.env` or tests) before `npm publish` / `twine upload`.
- You want a deterministic, offline check with **no API key, no network
  calls, and no LLM in the loop** that runs in single-digit seconds in CI
  or a pre-commit hook.
- You want a gate that fails *closed* on a PR and produces machine-readable
  output (JSON, SARIF, IDE diagnostics) for the rest of your pipeline.

## Do not use VibeGuard as…

- **A full SAST replacement.** It does not do interprocedural dataflow or
  taint analysis. Use Semgrep, CodeQL, or Bandit for that.
- **A secret-history scanner.** It flags a `.env` or token that is about to
  be committed *now*; it does not scan your full git history for already-
  leaked credentials. Use gitleaks or truffleHog for history.
- **A dependency-vulnerability scanner.** It flags git/URL/path dependencies
  and typosquatting heuristics, not known CVEs. Use Dependabot, pip-audit,
  npm audit, or Snyk for CVE coverage.
- **A substitute for human code review**, or a guarantee that code is safe
  or production-ready.

---

## Comparison by tool category

Each row states what the other tool is genuinely better at, and what
VibeGuard tends to catch earlier or differently on an AI-generated diff.

| Tool category | What it's better at | What VibeGuard catches earlier / differently |
|---|---|---|
| **CodeQL / deep SAST** | Interprocedural dataflow and taint tracking; finding exploitable vulnerabilities across a whole program; mature, audited query packs. | "Intent" smells that aren't a classic vuln — `verify=False`, CORS wildcards, commented-out auth, `# TODO: real auth` — and packaging-manifest hygiene, on the diff, in seconds, with no build step. |
| **Semgrep / custom rule engines** | Rich, community-maintained rule registries; AST-aware custom rules; multi-language semantic patterns. | A curated, opinionated default set tuned for *AI-coding* failure modes, plus packaging/dependency-manifest and committed-agent-artifact checks that general rule packs rarely cover. VibeGuard is complementary — many teams run both. |
| **gitleaks / truffleHog** | Broad secret-pattern coverage; scanning the **full git history** for credentials that already leaked. | A secret in newly-staged code that hasn't been pushed yet, and a `.env` that is *about to be committed* — caught at the gate before it enters history. |
| **Dependabot / pip-audit / npm audit / Snyk** | Known-CVE coverage, including transitive dependencies; automated upgrade PRs. | git/URL/path dependencies, typosquatting heuristics, broad version ranges, and lockfile/registry drift introduced by an AI commit — none of which are CVEs. |
| **Linters (ruff, eslint)** | Style, formatting, and simple correctness across the whole tree. | Security-shaped problems a linter intentionally ignores: disabled SSL verification, auth bypasses, packaging leaks, risky-diff signals. |

The intent is to **complement** these tools, not replace them.

---

## Recommended layered pipeline

A typical pipeline runs VibeGuard as the fast pre-merge gate and keeps the
deeper, slower tools where they belong:

1. **Lint / typecheck** — ruff / eslint, mypy / tsc.
2. **VibeGuard PR gate** — deterministic, diff-scoped, fails the PR on
   blocking AI-coding mistakes (this guide).
3. **SAST** — Semgrep / CodeQL for dataflow and exploitable vulnerabilities.
4. **Secret-history scan** — gitleaks / truffleHog across the full history.
5. **Dependency vulnerabilities** — Dependabot / pip-audit / npm audit / Snyk.

A minimal GitHub Actions job for step 2:

```yaml
name: VibeGuard
on: [pull_request]
jobs:
  vibeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: dgenio/vibeguard@v0.8.0
        with:
          diff: "true"
          fail-on: high
```

VibeGuard runs first because it is fast and deterministic: it gives the
author feedback in seconds, and only the diffs it lets through reach the
heavier scanners.

---

## AI-diff examples that fall between other tools

These are the concrete situations VibeGuard is built for — each one is easy
to introduce with an AI agent and easy for the other tools in the stack to
miss on a fresh diff:

- **`# TODO: implement real auth`** left in a request handler that currently
  returns `True` / `200` for everyone.
- **Source maps published in a package** because the agent added `"**/*.map"`
  (or `dist/`) to `package.json`'s `files` array.
- **`verify=False` added to make a failing integration test pass**, silently
  disabling TLS certificate validation.
- **A URL / git dependency introduced to solve an install problem** instead
  of a pinned registry release.
- **A risk-sensitive change with no tests** — a migration or query-
  construction change shipped with zero corresponding test edits.

For the full list of rules and the finding IDs each emits, see
[`rules.md`](rules.md); run `vibeguard explain <finding-id>` for per-finding
remediation guidance.
