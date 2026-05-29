# PR scenarios — realistic AI coding failures

The [`vulnerable-node-package`](../vulnerable-node-package) and
[`vulnerable-python-package`](../vulnerable-python-package) fixtures pack many
issues into one tree for a fast demo. These **PR scenarios** are the opposite:
each is a small, self-contained change that mirrors a mistake teams actually
ship when working with AI coding agents (Copilot, Cursor, Claude Code, …), so
you can recognise the situation and see exactly what VibeGuard would say.

Every scenario directory contains the unsafe code plus a `README.md` with:

- what the AI did and why it looked reasonable,
- the exact `vibeguard scan` command,
- the expected findings (IDs + severities),
- how to fix it,
- whether it blocks under the `relaxed` / `balanced` / `strict` policies.

> Scan each scenario **with its own directory as the root** (as the commands
> below do). Some rules — e.g. `agent_memory` — intentionally skip paths
> containing `examples/`, so scanning the whole repo would suppress them.

## The scenarios

| # | Scenario | Headline finding(s) | Category |
|---|---|---|---|
| 01 | [Disable TLS verification to pass tests](./01-tls-verify-disabled) | `AUTH-VERIFY-FALSE`, `AI-TRUSTALLCERTS` | transport security |
| 02 | [Temporary auth bypass left in place](./02-auth-bypass-left-in) | `AUTH-BYPASS-COMMENT` | auth |
| 03 | [Package publishes source maps and `.env`](./03-package-leaks-env-and-sourcemaps) | `SEC-ENV`, `MAP-PKG`, `PKG-NPMLEAK` | packaging leak |
| 04 | [Agent memory / tool traces committed](./04-agent-memory-committed) | `AGENT-MEMORY-LOG`, `AGENT-TOOL-TRACE` | agent hygiene |
| 05 | [Dependency via a git URL](./05-dependency-via-git-url) | `DEP-URLNODE` | supply chain |
| 06 | [Risky DB write with no tests](./06-risky-db-write-no-tests) | `SQL-PY-FSTRING`, `SQL-PY-CONCAT` | injection / tests |

## Run them all

```bash
for d in examples/pr-scenarios/*/; do
  echo "== $d =="
  vibeguard scan --path "$d"
done
```

The expected findings for each scenario are pinned in
[`tests/test_pr_scenarios.py`](../../tests/test_pr_scenarios.py), so a rule or
fixture change that stops a scenario from firing is caught in CI.

All tokens, keys, and credentials in these fixtures are obviously fake and for
demonstration only.
