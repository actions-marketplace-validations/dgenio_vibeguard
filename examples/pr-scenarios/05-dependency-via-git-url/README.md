# Scenario 05 — "Dependency introduced via a git URL"

**The PR:** *"use the patched payments lib"*

**What the AI did:** to pull in an unreleased fix, the agent added a dependency
pointing at a git branch (`git+https://…#main`) instead of a pinned registry
version. Git-URL dependencies float with the upstream branch, bypass the
registry's immutability and provenance, and are an easy supply-chain foothold.

The unsafe file is [`package.json`](./package.json).

## Scan it

```bash
vibeguard scan --path examples/pr-scenarios/05-dependency-via-git-url
```

## Expected findings

| ID | Severity | Why |
|---|---|---|
| `DEP-URLNODE` | high | `payments-lib` resolves to a git URL rather than a pinned version |

## How to fix

Publish the patched library (or a fork) to the registry and pin it:

```json
"payments-lib": "1.4.2"
```

If you must consume a fork temporarily, pin to an immutable commit SHA and
track removal in an issue — not a moving branch ref.

## Does it block?

Has a **high** finding, so it blocks under all policies:

| Policy | Blocks? |
|---|---|
| `relaxed` | ✅ yes |
| `balanced` (default) | ✅ yes |
| `strict` | ✅ yes |
