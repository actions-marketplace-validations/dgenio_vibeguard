# VibeGuard

**Guardrails for vibe-coded software.**

> "AI coding tools made it cheap to generate code. They did not make it cheap to trust code."

[![CI](https://github.com/dgenio/vibeguard/actions/workflows/ci.yml/badge.svg)](https://github.com/dgenio/vibeguard/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

---

## The Problem

AI coding tools let developers ship in hours what used to take days. That is genuinely great. But accepting large AI-generated diffs without scrutiny creates a new failure mode that traditional security tools were not designed to catch:

- **Accidentally committed secrets** — API keys, tokens, and database URLs sneak in through AI-generated config files
- **Package publish leaks** — source maps, .env files, and test fixtures end up in npm/PyPI packages
- **Dependency supply chain risks** — AI agents pull in git URLs, typosquatted packages, or broad version ranges
- **Security control bypasses** — AI comments out auth checks or disables SSL verification to "make things work"
- **Risky code changes without tests** — huge diffs touching auth, crypto, and database writes with zero test coverage
- **AI footprints** — placeholder credentials, `# TODO: implement real auth`, and `trust all certificates`

## Why VibeGuard Exists

VibeGuard is **not** another AI wrapper, SAST scanner, or dependency checker.

It is a **fast, deterministic pre-merge safety gate** specifically designed for the failure modes of AI-assisted coding ("vibe coding"). It runs in seconds, works offline, and requires no API key.

Think of it as the check between "AI generated this diff" and "this diff reaches production."

## What It Catches

| Category | Examples |
|---|---|
| 🔑 **Secrets** | AWS keys, GitHub tokens, OpenAI keys, database URLs, private keys, .env files |
| 🗺️ **Source maps** | .map files in dist/, sourceMappingURL in bundles, npm packages that publish maps |
| 📦 **Packaging leaks** | .env, tests/, .github/, source maps in npm/PyPI packages |
| 🔗 **Dependency risks** | git/URL deps, typosquatted packages, unpinned versions (strict mode) |
| ⚠️ **Risky code patterns** | eval/exec, shell=True, JWT verify=False, CORS wildcard, pickle.loads, SQL construction |
| 🧪 **Missing tests** | Source changes with no corresponding test changes |
| 🤖 **AI footprints** | Placeholder creds, disabled auth, trust-all-certs, TODO stubs, temporary bypasses |

---

## Quickstart

```bash
pip install vibeguard
```

Or from source:

```bash
git clone https://github.com/dgenio/vibeguard
cd vibeguard
pip install -e ".[dev]"
```

Initialize a config file:

```bash
vibeguard init
```

Scan a directory:

```bash
vibeguard scan --path .
```

Gate your CI (exits 1 if blocking findings found):

```bash
vibeguard gate --diff --fail-on high
```

---

## CLI Reference

### `vibeguard init`

Creates a `vibeguard.yaml` config file with sensible defaults.

```bash
vibeguard init
vibeguard init --path /path/to/repo
```

### `vibeguard scan`

Scans a repository and prints findings. **Always exits 0** (informational).

```bash
vibeguard scan
vibeguard scan --path .
vibeguard scan --diff                  # only changed files (requires git)
vibeguard scan --json                  # machine-readable output
vibeguard scan --markdown              # for PR comments
vibeguard scan --verbose               # detailed descriptions
vibeguard scan --fail-on medium        # set threshold (informational only)
```

### `vibeguard gate`

Same as `scan` but **exits 1** when findings meet or exceed the threshold.

```bash
vibeguard gate --path . --fail-on high
vibeguard gate --diff --fail-on medium
```

### `vibeguard publish-check`

Simulate `npm publish` or `python -m build` and gate on findings in the
published file set, before anything reaches the registry.

```bash
vibeguard publish-check --path .
vibeguard publish-check --ecosystem npm --manifest-out publish-manifest.json
vibeguard publish-check --ecosystem python-sdist --fail-on medium
```

See [docs/pre-publish.md](docs/pre-publish.md) for the full guide,
finding IDs, and a GitHub Actions release-gate template.

### `vibeguard explain <finding-id>`

Print a detailed explanation and remediation guide for a finding.

```bash
vibeguard explain SEC-ENV
vibeguard explain MAP-DIST
vibeguard explain TEST-MISSING
```

---

## Example Output

```
                         VibeGuard Findings
┌──────────┬──────────────┬─────────────────────────────┬──────────────────────────────────────┐
│ Sev      │ Rule         │ Path                        │ Title                                │
├──────────┼──────────────┼─────────────────────────────┼──────────────────────────────────────┤
│ ☠ CRIT   │ secrets      │ .env                        │ Sensitive file committed: .env       │
│ ☠ CRIT   │ secrets      │ src/server.js:9             │ GitHub Token detected                │
│ ✗ HIGH   │ sourcemaps   │ dist/app.js.map             │ Source map file in publish directory │
│ ✗ HIGH   │ dependencies │ package.json                │ URL/git/path dependency: axios       │
│ ✗ HIGH   │ packaging    │ package.json                │ npm package may publish .env files   │
│ ⚠ MEDIUM │ risky_diff   │ src/server.js:24            │ Risk-sensitive area: eval() usage    │
│ ⚠ MEDIUM │ ai_footprints│ src/server.js:14            │ AI footprint: security disabled      │
│ ↓ LOW    │ tests        │ src/server.js               │ Source changes without test changes  │
└──────────┴──────────────┴─────────────────────────────┴──────────────────────────────────────┘

  Scanned 6 file(s)  •  8 finding(s)  |  critical: 2  high: 3  medium: 2  low: 1  •  policy: balanced

✗ Gate failed: findings at or above high severity detected.
```

Try it yourself:

```bash
vibeguard scan --path examples/vulnerable-node-package
vibeguard gate --path examples/vulnerable-python-package --fail-on medium
```

---

## Policy Levels

| Policy | Description |
|---|---|
| `relaxed` | Only critical and high findings |
| `balanced` | High + medium findings (default) |
| `strict` | All findings; unpinned dependencies and missing tests are elevated |

Set in `vibeguard.yaml`:

```yaml
policy: strict
fail_on: medium
```

Or override on the command line:

```bash
vibeguard gate --fail-on medium
```

---

## Configuration

Run `vibeguard init` to create a `vibeguard.yaml`:

```yaml
policy: balanced
fail_on: high

ignore:
  paths:
    - .git/
    - node_modules/
    - .venv/
    - dist/
    - build/
  findings: []        # suppress specific finding IDs

secrets:
  enabled: true
  min_entropy: 3.5

sourcemaps:
  enabled: true

packaging:
  enabled: true

dependencies:
  enabled: true

risky_patterns:
  enabled: true

tests:
  enabled: true

ai_footprints:
  enabled: true
```

---

## GitHub Actions Usage

Add to your pull request workflow:

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
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install vibeguard
      - run: vibeguard gate --diff --fail-on high
```

For local development (before publishing to PyPI):

```yaml
      - run: pip install -e .
      - run: vibeguard gate --fail-on high
```

---

## Rules

### `secrets` — Secret Detection

Detects likely committed secrets using regex patterns and Shannon entropy heuristics.

Patterns: AWS access keys, GitHub tokens, OpenAI keys, private keys, bearer tokens, Stripe keys, Slack tokens, hardcoded passwords, database URLs with credentials, committed `.env` files.

### `sourcemaps` — Source Map Exposure

Source maps in distribution directories expose your original source code to anyone who downloads your package or opens browser DevTools.

Checks: `.map` files in `dist/`, `build/`, `public/`; `sourceMappingURL` comments in JS bundles; `package.json` `files` arrays that include `.map` patterns.

### `packaging` — Packaging Hygiene

Checks common package manifests for files that should not be published.

Checks: `package.json`, `.npmignore`, `pyproject.toml`, `MANIFEST.in`, `setup.cfg`.

Flags: `.env` files, test directories, source maps, `.github/`, coverage reports, broad include patterns.

### `dependencies` — Dependency Risk

Checks for risky dependency declarations.

Flags: git/URL/path dependencies (bypass registry integrity), typosquatting-like package names (heuristic), broad version constraints in strict mode.

### `risky_diff` — Risky Code Patterns

Flags changes to security-sensitive areas for human review. **Does not claim a vulnerability** — says "risk-sensitive area changed, human review recommended."

Areas: auth/authz, crypto, eval/exec, subprocess/shell, file deletion, network calls, database writes, payment logic, CORS, SQL construction, deserialization, JWT handling, certificate validation.

### `tests` — Missing Tests

If source files changed but no test files changed, emits a low/medium finding.

### `ai_footprints` — AI Footprint Detection

Detects common AI-generated artifacts that indicate incomplete, insecure, or placeholder code.

Patterns: AI generation comments, placeholder credentials, disabled security controls, trust-all-certs, CORS wildcards, temporary bypasses, skip-validation patterns, hallucinated TODO stubs.

---

## Roadmap

### v0.1 (current)
- [x] Deterministic local scanner
- [x] CLI (`scan`, `gate`, `init`, `explain`)
- [x] Config file with policy levels
- [x] All core rules: secrets, sourcemaps, packaging, dependencies, risky patterns, tests, AI footprints
- [x] Console, JSON, Markdown reporters
- [x] GitHub Actions integration
- [x] Example vulnerable packages

### v0.2
- [ ] SARIF output for GitHub Code Scanning
- [ ] GitHub PR comment reporter
- [ ] Baseline file (suppress existing findings, only alert on new ones)
- [ ] More language-specific rules (Go, Ruby, PHP)
- [ ] `.vibeguardignore` file support

### v0.3
- [ ] Package publish simulation (`vibeguard publish-check`)
- [ ] npm/PyPI pre-publish hooks
- [ ] Dependency reputation checks (via public advisories)
- [ ] Diff size / big-diff warning

### v0.4
- [ ] Optional LLM explanation mode (bring your own key)
- [ ] VS Code / IDE extension
- [ ] Policy packs for startups, enterprise, OSS maintainers
- [ ] Pre-commit hook integration

---

## Philosophy

VibeGuard is not a replacement for:
- SAST tools (Semgrep, CodeQL, Bandit)
- Secret scanners (truffleHog, gitleaks)
- Dependency scanners (Dependabot, Snyk, pip-audit)
- Human code review

It is a **fast first gate** specifically for the failure modes of AI-assisted coding — the things that fall through because the diff is too large to review carefully, or because AI agents bypass security controls to make things work quickly.

The goal is to catch the 80% of AI-coding mistakes in 5 seconds before your existing tools and reviewers spend time on a fundamentally broken diff.

**Deterministic > AI-powered for this use case.** No hallucinations, no API costs, no false confidence from an LLM that thinks the code looks fine.

---

## Contributing

Contributions welcome. See the [issues page](https://github.com/dgenio/vibeguard/issues) for ideas.

```bash
git clone https://github.com/dgenio/vibeguard
cd vibeguard
pip install -e ".[dev]"
pytest
ruff check vibeguard/ tests/
```

- **[docs/rules.md](docs/rules.md)** — auto-generated rule reference (`make docs` to regenerate).
- **[docs/how-to-add-a-rule.md](docs/how-to-add-a-rule.md)** — step-by-step guide for adding a built-in rule.
- **[docs/plugin-api.md](docs/plugin-api.md)** — public plugin API for shipping rules in your own package.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
