# Explanation adapters

VibeGuard's `vibeguard explain <FINDING-ID>` command surfaces remediation
guidance for a finding. The text comes from an **explanation adapter** — a
small, pluggable component that the CLI invokes with a `Finding`.

The default adapter (`static`) is offline, deterministic, ships with the
package, and requires no API keys or network access. Third parties can ship
richer adapters — for example, a local Ollama model or a hosted LLM — without
making any optional dependency part of VibeGuard's core.

> **VibeGuard does not require, and will never require, an API key as a core
> feature.** Network-backed adapters are strictly opt-in.

---

## Using a different adapter

### From `vibeguard.yaml`

```yaml
explain:
  adapter: static       # default — always available
  # adapter: ollama     # example of a community-contributed adapter
```

### From the command line

The `--adapter` flag (alias: `--explain-adapter`) overrides the config:

```bash
vibeguard explain SEC-ENV --adapter static
```

Unknown adapter names exit with code `2` and a list of registered adapters.

---

## Writing a custom adapter

The full contract lives in `vibeguard/explain/base.py`. A minimal adapter
looks like this:

```python
from vibeguard.api import ExplainAdapter, Finding


class EchoAdapter(ExplainAdapter):
    name = "echo"

    def explain(self, finding: Finding, context: str | None = None) -> str:
        return f"{finding.id}: {finding.description}\n\nFix: {finding.recommendation}"
```

### Requirements

Implementations **must**:

- Be constructible with no arguments (`cls()`). Adapters that need
  credentials should read them from environment variables in their
  constructor — never from a config file the adapter doesn't own.
- Return a non-empty string from `explain()` for every `Finding`. If the
  adapter cannot answer (network down, model missing, API key absent),
  return a graceful fallback rather than raising.
- Be safe to import. VibeGuard discovers adapters via the
  `vibeguard.explain_adapters` entry-point group; an `ImportError` during
  module load surfaces as a warning, not a crash.

### Registering the adapter

Two equivalent paths — declarative or imperative.

#### Declarative (recommended)

In your plugin package's `pyproject.toml`:

```toml
[project.entry-points."vibeguard.explain_adapters"]
echo = "my_plugin:EchoAdapter"
```

The left-hand side becomes the adapter name users put in `vibeguard.yaml` or
pass via `--adapter`. The right-hand side resolves to your adapter class.
VibeGuard auto-discovers entry points the first time
`vibeguard explain --adapter <name>` runs for a non-built-in name.

#### Imperative

When you control adapter loading directly (for example, in a test fixture or
an embedded use of VibeGuard), call `register_explain_adapter`:

```python
from vibeguard.api import register_explain_adapter

register_explain_adapter("echo", EchoAdapter)
```

The registry rejects re-registration of the same name to a *different* class
(re-registering the same class is a harmless no-op).

---

## What the adapter receives

The `Finding` argument is the standard VibeGuard finding model (see
`vibeguard/models.py`). Useful fields:

| Field            | Type                | Description                                           |
|------------------|---------------------|-------------------------------------------------------|
| `id`             | `str`               | Finding identifier (e.g. `SEC-ENV`).                  |
| `rule`           | `str`               | Parent rule ID (e.g. `secrets`).                      |
| `severity`       | `Severity`          | One of `info`/`low`/`medium`/`high`/`critical`.       |
| `path`           | `str`               | Relative file path the finding refers to.             |
| `line`           | `int \| None`       | 1-based line number, when known.                      |
| `evidence`       | `str \| None`       | Snippet of the offending content (truncated to 200).  |
| `description`    | `str`               | Detailed description from the rule.                   |
| `recommendation` | `str`               | Static remediation text from the rule.                |
| `tags`           | `list[str]`         | Rule-defined tags.                                    |

The optional `context` argument is reserved for callers that want to pass
extra context (e.g. surrounding source code, PR description) to a smarter
adapter. The static adapter ignores it.

---

## The built-in `static` adapter

`StaticExplainAdapter` answers from two sources, in order:

1. A small set of hand-written explanations for the highest-impact finding
   IDs (e.g. `SEC-AWSACCESSKEY`, `SEC-ENV`, `RISK-EVALEXEC`,
   `AI-DISABLESECURITY`).
2. The rule metadata registry (`vibeguard/rules/registry.py`) — rule title,
   description, tags, and `applies_to` list, plus the finding's own
   `recommendation`.

It performs no I/O, never raises, and runs identically across operating
systems and CI environments.

---

## Versioning

The `ExplainAdapter` interface is part of the [VibeGuard plugin API](plugin-api.md).
Backwards-incompatible changes to the interface bump the major component of
`PLUGIN_API_VERSION` (`vibeguard.__init__`). The current version is `1.0`.
