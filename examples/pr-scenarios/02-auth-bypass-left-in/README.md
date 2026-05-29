# Scenario 02 — "Temporary auth bypass left in place"

**The PR:** *"unblock local dev for the admin dashboard"*

**What the AI did:** the auth middleware failed locally, so the agent stubbed
it with an early `return next()` and left a `TODO` to fix it "before merging".
The TODO never got actioned and the bypass shipped, leaving the admin route
unauthenticated.

The unsafe file is [`middleware.js`](./middleware.js).

## Scan it

```bash
vibeguard scan --path examples/pr-scenarios/02-auth-bypass-left-in
```

## Expected findings

| ID | Severity | Why |
|---|---|---|
| `AUTH-BYPASS-COMMENT` | high | auth-bypass TODO/FIXME/HACK comment next to an early return |
| `AI-TEMPBYPASS` | medium | "temporary bypass for testing" footprint |

## How to fix

Restore the real check and make local dev work *without* weakening prod:

```js
function requireAuth(req, res, next) {
  if (!req.session?.user) return res.status(401).end();
  return next();
}
```

Use a seeded dev session or a test login flow locally — never an
unconditional `next()`.

## Does it block?

Has a **high** finding, so it blocks under all policies:

| Policy | Blocks? |
|---|---|
| `relaxed` | ✅ yes |
| `balanced` (default) | ✅ yes |
| `strict` | ✅ yes |
