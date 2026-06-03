# Scenario 07 — Slopsquatted (AI-hallucinated) dependency

An AI assistant suggested `super-fast-vector-db-client` and the agent added it
to `package.json`. The package was never resolved, so it is **absent from
`package-lock.json`** — the shape of a hallucinated dependency before anyone
runs `npm install`. Attackers register exactly these plausible-but-nonexistent
names ("slopsquatting") so the next install pulls malicious code.

## What VibeGuard catches

| Finding | Why |
|---|---|
| `SLOP-HALLUCINATION-SHAPE` | A descriptive multi-token dependency name that no lockfile vouches for. |

Run it:

```bash
vibeguard scan --path examples/pr-scenarios/07-slopsquatted-dependency
```

The offline heuristic runs with no network. Enabling `slopsquat.registry_check`
in `vibeguard.yaml` additionally verifies the package exists on the registry
(`SLOP-REGISTRY-MISSING`) — at the cost of a network call.
