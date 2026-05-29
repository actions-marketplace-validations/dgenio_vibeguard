# Scenario 03 — "Package accidentally publishes source maps and .env"

**The PR:** *"make sure the build output ships in the npm package"*

**What the AI did:** to fix a "missing files in the published package"
complaint, the agent widened the `files` allowlist in `package.json` to include
`.env` and `**/*.map`. The next `npm publish` would ship the committed `.env`
secrets and the source maps (which reconstruct original source) to the public
registry.

Unsafe tree: [`package.json`](./package.json), [`.env`](./.env),
[`dist/index.js.map`](./dist/index.js.map).

## Scan it

```bash
vibeguard scan --path examples/pr-scenarios/03-package-leaks-env-and-sourcemaps
```

## Expected findings

| ID | Severity | Why |
|---|---|---|
| `SEC-ENV` | high | a `.env` file is committed to the repo |
| `MAP-PKG` | high | `package.json` `files` includes source maps (`**/*.map`) |
| `PKG-NPMLEAK` | high | `files` allowlist would publish environment files / source maps |

## How to fix

Ship only the built artifacts; never the `.env` or maps:

```json
"files": ["dist/**/*.js", "README.md"]
```

Remove `.env` from version control, rotate any real secrets, and drop
`sourceMap` output from the published build (or exclude `*.map`).

## Does it block?

Has **high** findings, so it blocks under all policies:

| Policy | Blocks? |
|---|---|
| `relaxed` | ✅ yes |
| `balanced` (default) | ✅ yes |
| `strict` | ✅ yes |

> Related: the bundled [`examples/vulnerable-node-package`](../../vulnerable-node-package)
> additionally exercises `PKG-PREPARE-SCRIPT` and `PKG-NPMIGNORE-BROAD`.
