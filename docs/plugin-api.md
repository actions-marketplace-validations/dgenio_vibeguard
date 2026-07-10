# VibeGuard Plugin API

VibeGuard rules are pluggable. A third-party package can ship its own rules
and have them picked up automatically by every `vibeguard scan`, `gate`,
`publish-check`, and `rules list` invocation — without modifying the core.

This page is the stable reference for plugin authors. Anything documented
here will only break on a major bump of `PLUGIN_API_VERSION`.

## Stability contract

The public surface lives in **`vibeguard.api`**. Plugins must import
exclusively from there:

```python
from vibeguard.api import (
    BaseRule,        # the rule base class to subclass
    Confidence,      # finding confidence enum
    Finding,         # finding payload model
    GitMetadata,     # optional git context
    PLUGIN_API_VERSION,  # current API major.minor
    RULE_REGISTRY,   # read-only access to metadata
    RuleMetadata,    # the metadata to register
    register_rule,   # register your rule's metadata
    Rule,            # alias of BaseRule, for code that prefers the short name
    ScanContext,     # everything a rule needs to scan
    ScanResult,
    Severity,        # finding severity enum
    scan_patch,      # programmatic --patch scan (since API 1.1)
)
```

Everything else under `vibeguard.*` is internal and may change without
notice. Don't import from `vibeguard.scanner`, `vibeguard.config`, or
deeper paths — open an issue if you need something that isn't exposed in
`vibeguard.api`.

`PLUGIN_API_VERSION` is a `"MAJOR.MINOR"` string. Plugins should pin a
range in their dependency metadata that tracks **the API version**, not
the release version of `vibeguard-gate`. Today `PLUGIN_API_VERSION` is
`1.1` (the `1.1` minor added the additive `scan_patch` entry point), so a
safe pin is:

```toml
dependencies = ["vibeguard-gate>=0.8"]
```

The lower bound is the current release floor (i.e. the oldest release
that exposes the API surface you import). There's intentionally no upper
bound: minor `vibeguard-gate` releases (`0.8.x` → `0.9.0`) keep
`PLUGIN_API_VERSION` at `1.x`, so they stay compatible. When VibeGuard
ships a `PLUGIN_API_VERSION` major bump (`1.x` → `2.0`) the release
notes will tell you to add an upper bound (e.g. `<1.0` if you can't
yet support the new major) and update your imports.

## Programmatic scanning: `scan_patch`

Besides authoring rules, the API exposes a scanning entry point for callers
that hold a diff in memory — an agent harness, a review bot, or an MCP tool that
wants to ask "is this patch safe?" without a checkout:

```python
from vibeguard.api import Severity, scan_patch

result = scan_patch(patch_text)              # patch_text is `git diff` output
blocking = [f for f in result.findings if f.severity >= Severity.HIGH]
```

`scan_patch(patch_text, base_path=None)` reconstructs the **new side** of every
file in the diff into a throwaway temporary tree, scans it, and restricts
findings to the **added** lines (context lines give multi-line rules structure
but are never reported). It returns the standard `ScanResult`; its
`scan_path` is the stable placeholder `"<patch>"`, never a temp directory. Pass
`base_path` to auto-discover a `vibeguard.yaml` so your rule configuration and
suppressions apply; otherwise built-in defaults are used. This is the same
engine behind the `vibeguard scan --patch` CLI — see
[scan-scope.md](scan-scope.md#--patch-gate-a-diff-before-it-is-applied).

## Rule contract

A rule subclasses `BaseRule` and implements `scan(self, context) ->
list[Finding]`. The `context.config` field is fully typed as
`VibeGuardConfig`, so `context.config.<section>` access is checked by mypy and
autocompletes in editors — a typo like `context.config.secrest` fails
`mypy` rather than surfacing at runtime.

The implementation:

| Must                                                          | Must not                                             |
|---------------------------------------------------------------|------------------------------------------------------|
| Be pure and deterministic                                     | Perform network I/O                                  |
| Return `list[Finding]` (empty list if nothing is found)       | Raise out of `scan()` — the scanner wraps every call, but you should handle errors internally |
| Be fast (< 100 ms per file is the soft target)                | Mutate global state in ways that bleed across rules  |
| Use a unique `id` and use it as the `rule` field on findings  | Reuse another rule's finding IDs                     |

### `is_applicable(self, path) -> bool`

Defaults to `True`. Override it when your rule only makes sense for a
specific file family (e.g. Dockerfiles, Terraform, `*.go`) so the scanner
skips unrelated files. The contract:

- **When it's called:** once per candidate file, per rule, before
  `scan()`. The scanner removes every path you return `False` for from the
  `ScanContext` your `scan()` receives — both `context.files` and
  `context.changed_files`. A path you reject is guaranteed never to reach
  your `scan()`.
- **What `path` is:** the absolute `pathlib.Path` the scanner collected
  (resolved against the scan root). Match on `path.name`, `path.suffix`,
  or `path.parts` — do not assume a repo-relative form.
- **Keep it side-effect free and a superset.** Overriding is a pure
  scoping optimisation; it must not change which findings your rule would
  otherwise emit. If your rule inspects sibling files directly (not via
  `context.files`), leave the default in place — the scanner filters the
  whole context, so narrowing it could hide the siblings you rely on.
- Rules that keep the default pay no cost: the scanner detects the
  un-overridden hook and passes the shared context through unchanged.

The built-in `go_rules`, `iac`, and `ci_docker` rules override it as
reference examples.

## Registering metadata

`RULE_REGISTRY` powers `vibeguard rules list`, `vibeguard rules explain`,
and the auto-generated rule reference (`docs/rules.md`). Register at
module import time:

```python
from vibeguard.api import RuleMetadata, register_rule

register_rule(
    RuleMetadata(
        rule_id="my-rule",
        title="My Custom Rule",
        description="One sentence on what the rule detects.",
        finding_ids=["MYRULE-TODO"],
        default_severity="low",     # info | low | medium | high | critical
        confidence="high",          # low | medium | high
        tags=["custom"],
        applies_to=["*.py"],
    )
)
```

`register_rule` raises `ValueError` if a `rule_id` is already taken.
Picking a unique, kebab-cased identifier prefixed with your distribution
name (e.g. `acme-foo`) is the safest convention.

## Distribution & discovery

Plugins are loaded through `importlib.metadata` entry points. Declare them
in your package's `pyproject.toml`:

```toml
[project.entry-points."vibeguard.rules"]
my-rule = "my_package.rules:MyRule"
```

The entry point can resolve to **either** a `BaseRule` subclass *or* a
zero-arg factory returning a `BaseRule` instance — the discovery layer
calls the resolved object once and validates the result.

On scanner startup the `vibeguard.rules` entry-point group is enumerated
and each plugin is instantiated in turn:

* Import errors, missing attributes, or wrong base class are caught and
  logged to stderr with a `[vibeguard] plugin warning:` prefix. A broken
  plugin **never** prevents the scan from running.
* Failed plugins also show up in `vibeguard rules list --list-plugins`
  with their failure reason.

To temporarily silence a plugin without uninstalling it, add it to your
`vibeguard.yaml`:

```yaml
plugins:
  disabled:
    - my-rule
```

The entry-point name (the left-hand side in the entry point declaration)
is the canonical disable key.

## Minimal worked example

A complete plugin distribution:

```
acme-vibeguard-rules/
├── pyproject.toml
└── acme_vg_rules/
    ├── __init__.py
    └── todo.py
```

`pyproject.toml`:

```toml
[project]
name = "acme-vibeguard-rules"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["vibeguard-gate>=0.8"]

[project.entry-points."vibeguard.rules"]
acme-todo = "acme_vg_rules.todo:TodoRule"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

`acme_vg_rules/todo.py`:

```python
from __future__ import annotations

from vibeguard.api import (
    BaseRule,
    Confidence,
    Finding,
    RuleMetadata,
    ScanContext,
    Severity,
    register_rule,
)


class TodoRule(BaseRule):
    id = "acme-todo"
    name = "ACME TODO scanner"
    description = "Flags TODO comments that mention an unresolved ticket."

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in context.files:
            if path.suffix != ".py":
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if "TODO" in line and "ACME-" in line:
                    findings.append(
                        Finding(
                            id="ACMETODO",
                            rule=self.id,
                            title="Unresolved ACME TODO",
                            description="Found a TODO referencing an ACME ticket.",
                            severity=Severity.LOW,
                            path=self._rel(context, path),
                            line=lineno,
                            recommendation="Resolve the ticket or remove the TODO.",
                            tags=["acme", "todo"],
                            confidence=Confidence.HIGH,
                        )
                    )
        return findings


register_rule(
    RuleMetadata(
        rule_id="acme-todo",
        title="ACME TODO scanner",
        description="Flags TODO comments that mention an unresolved ACME ticket.",
        finding_ids=["ACMETODO"],
        default_severity="low",
        confidence="high",
        tags=["acme", "todo"],
        applies_to=["*.py"],
    )
)
```

`pip install acme-vibeguard-rules` is enough — the next `vibeguard scan`
run picks up the rule and `vibeguard rules list --list-plugins` shows it
under `Discovered plugins`.

## Versioning policy

Backwards-incompatible changes to any symbol exported from
`vibeguard.api` bump the **major** component of `PLUGIN_API_VERSION`.
Backwards-compatible additions bump the minor.

* Major bumps (e.g. `1.0` → `2.0`): plugins pinned to `<2` will need
  updating. A future version of the discovery system will flag
  incompatible plugins and skip them at discovery time with a warning.
  Until that check is implemented, plugins must self-verify compatibility.
* Minor bumps (e.g. `1.0` → `1.1`): no plugin action required — new
  symbols become available; existing symbols keep their behaviour.

When VibeGuard ships a major bump, the release notes will document the
breaking changes and a migration recipe.
