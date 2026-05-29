# Scenario 06 — "Risky database write with no tests"

**The PR:** *"add bulk price update for the sale"*

**What the AI did:** built an `UPDATE` (and a `DELETE`) by interpolating
request-derived values straight into the SQL string — once with an f-string,
once with `+` concatenation — and shipped no accompanying test. Both are
classic SQL-injection vectors.

The unsafe file is [`src/repository.py`](./src/repository.py).

## Scan it

```bash
vibeguard scan --path examples/pr-scenarios/06-risky-db-write-no-tests
```

## Expected findings

| ID | Severity | Why |
|---|---|---|
| `SQL-PY-FSTRING` | high | f-string interpolation into a SQL `UPDATE` |
| `SQL-PY-CONCAT` | high | string concatenation into a SQL `DELETE` |
| `RISK-DBWRITE` | medium | risk-sensitive: database write path changed |

> **Diff-only finding:** in a real PR this change adds source with no matching
> test, so VibeGuard also emits **`TEST-MISSING`** when run as a gate over the
> diff (`vibeguard gate --diff`). `TEST-MISSING` is a diff-aware rule and does
> not fire on a static fixture scan, so it is documented here rather than
> pinned in the scenario test.

## How to fix

Use parameterised queries and add a test:

```python
conn.execute(
    "UPDATE products SET price = price * ? WHERE category = ?",
    (pct, category),
)
```

## Does it block?

Has **high** findings, so it blocks under all policies:

| Policy | Blocks? |
|---|---|
| `relaxed` | ✅ yes |
| `balanced` (default) | ✅ yes |
| `strict` | ✅ yes |
