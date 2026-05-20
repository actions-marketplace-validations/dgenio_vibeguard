# Pre-publish safety guide

`vibeguard publish-check` simulates what your next `npm publish` or
`python -m build` would actually ship, then runs the relevant VibeGuard rules
against the simulated file set. It catches the classic publish leaks —
committed `.env` files, source maps, broad `MANIFEST.in` grafts, `.npmignore`
negations — *before* the artifact reaches a registry.

> The simulation is **deterministic and pure-Python** — it does not invoke
> `npm`, `npm pack`, or `python -m build`. That means it runs in seconds in
> any CI environment, but it is a heuristic of upstream behavior, not an
> exact replay. Always inspect the published artifact for real before a
> public release.

## When to run it

- Locally, before tagging a release.
- In CI, as a release-gate job after tests pass.
- Before publishing the first ever version of a new package, when packaging
  metadata is most likely to be misconfigured.

## Quick start

```bash
# auto-detect npm vs python from the package root
vibeguard publish-check --path .

# pick the artifact explicitly
vibeguard publish-check --ecosystem npm
vibeguard publish-check --ecosystem python-sdist
vibeguard publish-check --ecosystem python-wheel
```

Exit codes mirror `vibeguard gate`: `0` when no findings meet the threshold,
`1` when at least one does, `2` on invalid CLI arguments.

## What it inspects

For each simulated file in the artifact, `publish-check` runs:

| Rule         | Catches in the publish view                              |
|--------------|----------------------------------------------------------|
| `secrets`    | API keys, tokens, private keys baked into shipped files  |
| `sourcemaps` | `.map` files that would ship with a minified bundle      |
| `packaging`  | Risky `files`/`MANIFEST.in`/`.npmignore` configuration   |
| `ai_footprints` | Placeholder credentials, "trust all certs", commented-out auth |

It also synthesizes a `PUB-DANGEROUS-FILE` finding for hard-coded basenames
(`.env`, `.env.production`, `.npmrc`, `.pypirc`, `docker-compose.yml`,
`.map` files) that should never be in a published artifact regardless of
what the simulator decided.

## Finding IDs

| ID                       | Meaning                                                          |
|--------------------------|------------------------------------------------------------------|
| `PUB-DANGEROUS-FILE`     | A categorically unsafe file is in the publish manifest           |
| `PUB-RULE-ERROR`         | A rule failed while scanning the publish view (please report it) |
| `PKG-MANIFEST-GRAFT`     | `graft .`, `graft *` etc. in `MANIFEST.in` (ships everything)    |
| `PKG-MANIFEST-RECURSIVE` | `recursive-include .` / `global-include *` (matches everything)  |
| `PKG-NPMIGNORE-NEGATE`   | `!.env` style negation that re-includes a dangerous file         |

The remaining `PKG-*`, `SEC-*`, `MAP-*`, and `AI-*` finding IDs are the
standard rule IDs — see `vibeguard explain <ID>` for details.

## CLI reference

```text
vibeguard publish-check [OPTIONS]

  --path / -p PATH                Package root (default: ".")
  --config / -c PATH              Path to vibeguard.yaml
  --ecosystem TEXT                auto | npm | python-sdist | python-wheel
                                  (default: auto)
  --json                          Emit findings + manifest as one JSON document
  --markdown                      Emit the findings table as Markdown
  --manifest-out PATH             Write the publish manifest JSON to this path
  --fail-on TEXT                  Severity threshold for non-zero exit
                                  (default: vibeguard.yaml `publish_check.fail_on`)
  --verbose / -v                  Show full finding descriptions
```

## The publish manifest

`--json` and `--manifest-out` emit a deterministic JSON document with:

```jsonc
{
  "ecosystem": "npm",
  "package_root": "/abs/path/to/package",
  "package_name": "my-package",
  "package_version": "1.2.3",
  "files": [
    { "path": "package.json", "size_bytes": 412, "included_by": "always-included" },
    { "path": "src/index.js",  "size_bytes": 8123, "included_by": "files-allowlist" }
  ],
  "excluded": ["tests/test_index.js", ".env"],
  "total_bytes": 8535,
  "warnings": []
}
```

The `files` list is sorted by path, and the JSON itself is sorted by key, so
diffing two manifest outputs (e.g. before/after a refactor) gives a clean
record of what changed in the publish view.

## Configuration

Optional `vibeguard.yaml` section:

```yaml
publish_check:
  enabled: true
  ecosystem: auto     # auto | npm | python-sdist | python-wheel
  fail_on: high       # severity threshold used by the publish-check gate
```

CLI flags (`--ecosystem`, `--fail-on`) override the YAML when both are set.

## GitHub Actions example

```yaml
name: Release gate

on:
  push:
    tags: ["v*"]

permissions:
  contents: read

jobs:
  publish-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install vibeguard-gate
      - name: Simulate publish
        run: |
          vibeguard publish-check --path . --manifest-out publish-manifest.json
      - name: Upload manifest
        uses: actions/upload-artifact@v4
        with:
          name: publish-manifest
          path: publish-manifest.json
```

## Limitations

- The simulator approximates upstream tools — it doesn't read every backend's
  config (Poetry, PDM, maturin, etc.). For those, run the publish-check
  alongside the real backend's `pack`/`build` step in CI.
- The npm simulator falls back to `.gitignore` when `.npmignore` is absent;
  npm itself does the same, but the matching is via `pathspec` (gitignore
  semantics), which can diverge from `node-ignore` on edge-case globs.
- `publish-check` does not perform network checks (registry presence,
  typosquat lookups) — those belong to the `dependencies` rule run during
  a normal `vibeguard scan`.
