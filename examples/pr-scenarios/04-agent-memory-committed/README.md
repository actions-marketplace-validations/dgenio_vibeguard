# Scenario 04 — "Agent memory / tool traces committed"

**The PR:** *"add billing refactor"* (with noisy extra files)

**What the AI did:** the coding agent persisted its working memory and tool
traces into the repo and committed them alongside the real change. These
artifacts often embed architecture notes, task history, internal URLs, and
sometimes credentials — none of which belong in version control.

Unsafe tree: [`memories/session.jsonl`](./memories/session.jsonl),
[`tool_calls.jsonl`](./tool_calls.jsonl).

## Scan it

```bash
vibeguard scan --path examples/pr-scenarios/04-agent-memory-committed
```

## Expected findings

| ID | Severity | Why |
|---|---|---|
| `AGENT-MEMORY-LOG` | high | `session.jsonl` matches an agent transcript/memory log pattern |
| `AGENT-MEMORY-DIR` | high | `memories/session…` matches an agent memory storage path |
| `AGENT-TOOL-TRACE` | medium | `tool_calls.jsonl` matches an agent tool-execution trace |

## How to fix

Delete the artifacts and ignore them so they never come back:

```gitignore
memories/
*.jsonl
.copilot-memory/
.claude-memory/
```

If anything sensitive was committed (tokens, internal hosts), rotate it and
scrub history.

> **Note:** the `agent_memory` rule deliberately skips paths containing
> `examples/`, `tests/`, `fixtures/`, etc. to avoid false positives. That is
> why this scenario must be scanned with its **own directory as the root**
> (as the command above does) rather than from the repo root.

## Does it block?

Has **high** findings, so it blocks under all policies:

| Policy | Blocks? |
|---|---|
| `relaxed` | ✅ yes |
| `balanced` (default) | ✅ yes |
| `strict` | ✅ yes |
