# Scenario 01 — "Make the tests pass by disabling TLS verification"

**The PR:** *"fix flaky integration tests against staging"*

**What the AI did:** staging serves a self-signed certificate, so instead of
trusting the staging CA the agent passed `verify=False` to `requests` and
silenced the resulting warnings. The change makes CI green while disabling
certificate validation for every call on that path — a permanent
man-in-the-middle hole shipped as a "test fix".

The unsafe file is [`client.py`](./client.py).

## Scan it

```bash
vibeguard scan --path examples/pr-scenarios/01-tls-verify-disabled
```

## Expected findings

| ID | Severity | Why |
|---|---|---|
| `AUTH-VERIFY-FALSE` | high | `verify=False` disables TLS certificate validation |
| `AI-TRUSTALLCERTS` | high | trust-all-certificates footprint |
| `RISK-TRUSTCERTS` | medium | risk-sensitive: certificate trust changed |
| `RISK-NETWORKCALL` | medium | risk-sensitive: outbound network call |

## How to fix

Trust the staging CA explicitly instead of disabling verification:

```python
resp = requests.get(url, verify="/etc/ssl/certs/staging-ca.pem", timeout=30)
```

For local-only test doubles, point the test at a fixture/mock server rather
than turning off verification in shipped code.

## Does it block?

Has a **high** finding, so it blocks under all policies:

| Policy | Blocks? |
|---|---|
| `relaxed` (surfaces critical/high) | ✅ yes |
| `balanced` (default) | ✅ yes |
| `strict` | ✅ yes |
