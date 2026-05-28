# How to add a new VibeGuard rule

This guide walks through adding a rule to VibeGuard itself — the same
process every built-in rule under `vibeguard/rules/` follows today. If
you're shipping rules in your own package without merging to core, read
[`plugin-api.md`](plugin-api.md) instead.

The end-to-end checklist for any new rule:

1. [Pick a rule ID, finding IDs and severity](#1-pick-identifiers)
2. [Implement the rule file](#2-implement-the-rule-file)
3. [Register metadata](#3-register-metadata)
4. [Wire the rule into the scanner](#4-wire-the-rule-into-the-scanner)
5. [Write unit tests](#5-write-unit-tests)
6. [Regenerate docs and run CI](#6-regenerate-docs-and-run-ci)

We'll use a worked example throughout: a hypothetical
**`js_proto_pollution`** rule that flags `Object.assign({}, …)` calls
into a freshly created object — a common JavaScript prototype-pollution
sink AI agents introduce when refactoring "merge defaults" helpers.

---

## 1. Pick identifiers

Three things to settle before writing code:

- **Rule ID** — snake_cased, unique across `RULE_REGISTRY`. Match the
  module file name (`vibeguard/rules/<rule_id>.py`). Examples in tree:
  `secrets`, `risky_diff`, `ci_docker`. For our example: `js_proto_pollution`.
- **Finding IDs** — uppercase, prefixed with the rule family.
  Existing examples: `SEC-ENV`, `MAP-DIST`, `AUTH-JWT-NONE`. Pick
  IDs that explain the *failure mode*, not just the rule. We'll use
  `JSPP-OBJECT-ASSIGN-NEW`.
- **Severity** — match the framing the README uses: "risk-sensitive
  change, human review recommended". Most rules ship `medium` or `high`;
  `critical` is reserved for "almost-certainly a secret/breach".

| When to pick                    | What to use                                                |
|---------------------------------|------------------------------------------------------------|
| Definitely a credential / leak  | `critical`                                                 |
| Disabled security control       | `high`                                                     |
| Risk-sensitive area changed     | `medium`                                                   |
| Test gap / hygiene              | `low`                                                      |
| Informational, never blocking   | `info`                                                     |

For `js_proto_pollution` we'll pick `medium` — the pattern is suspicious
but legitimate codebases use it intentionally.

## 2. Implement the rule file

Create `vibeguard/rules/js_proto_pollution.py`. Every rule subclasses
`Rule` (or `BaseRule` — they're the same class) from
`vibeguard.rules.base`. Match the file structure of an existing rule for
consistency; `vibeguard/rules/sourcemaps.py` is a good template at ~150
lines, `vibeguard/rules/auth.py` is a good template when you need regex
groups.

```python
"""Prototype-pollution detection for JavaScript code."""

from __future__ import annotations

import re
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

_OBJECT_ASSIGN_NEW = re.compile(
    r"Object\.assign\s*\(\s*\{\s*\}\s*,",
    re.MULTILINE,
)


class JsProtoPollutionRule(Rule):
    id = "js_proto_pollution"
    name = "JS Prototype Pollution Sink"
    description = (
        "Flags Object.assign({}, ...) patterns that may copy attacker-"
        "controlled keys into a fresh object."
    )

    def is_applicable(self, path: Path) -> bool:
        return path.suffix in {".js", ".ts", ".mjs", ".cjs"}

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in context.files:
            if not self.is_applicable(path):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for match in _OBJECT_ASSIGN_NEW.finditer(text):
                lineno = text.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        id="JSPP-OBJECT-ASSIGN-NEW",
                        rule=self.id,
                        title="Object.assign into a new object",
                        description=(
                            "`Object.assign({}, …)` copies arbitrary keys into a "
                            "freshly created object. If any source argument is "
                            "attacker-controlled, this is a prototype-pollution sink."
                        ),
                        severity=Severity.MEDIUM,
                        path=self._rel(context, path),
                        line=lineno,
                        evidence=match.group(0),
                        recommendation=(
                            "Validate keys against an allowlist before merging, "
                            "or use `Object.create(null)` for the target."
                        ),
                        tags=["security", "js", "prototype-pollution"],
                        confidence=Confidence.MEDIUM,
                    )
                )
        return findings
```

**Conventions to match**:

- Module docstring at the top.
- `from __future__ import annotations` (every rule has it).
- Regex constants at module scope, named with `_LEADING_UPPER`.
- `self._rel(context, path)` for finding paths — it returns
  scan-root-relative paths the reporters expect.
- `Finding(... severity=Severity.MEDIUM, confidence=Confidence.MEDIUM)`
  — use the enums, not string literals.
- Wrap file reads in `try/except OSError`. Never raise out of `scan`.

## 3. Register metadata

Add a `register_rule(...)` block at the bottom of the same file. This is
what powers `vibeguard rules list`, `vibeguard rules explain`, and the
generated `docs/rules.md`.

```python
register_rule(
    RuleMetadata(
        rule_id="js_proto_pollution",
        title="JS Prototype Pollution Sink",
        description=(
            "Flags Object.assign({}, ...) patterns that may copy "
            "attacker-controlled keys into a fresh object."
        ),
        finding_ids=["JSPP-OBJECT-ASSIGN-NEW"],
        default_severity="medium",
        confidence="medium",
        tags=["security", "js", "prototype-pollution"],
        applies_to=["*.js", "*.ts", "*.mjs", "*.cjs"],
    )
)
```

**Conventions**:

- `rule_id` matches the class `id` attribute exactly.
- `finding_ids` is the complete set of finding IDs the rule can emit.
  This is what `vibeguard rules explain <FINDING_ID>` matches against.
- `tags` include `security` whenever the rule is security-related; this
  is what `vibeguard rules list --tag security` filters on.

## 4. Wire the rule into the scanner **and** the registry loader

Built-in rules need to be wired in two places. Both are required, because
they serve different call paths.

**4a. `vibeguard/scanner.py`** — this is what `vibeguard scan`/`gate`
runs. Add two things:

1. Import the rule class with the other rules at the top of the file.
2. Add an `if config.<name>.enabled: rules.append(...)` block inside
   `run_scan`, matching the pattern of the surrounding rules.

**4b. `vibeguard/rules/__init__.py:load_all_builtin_rules`** — this
populates `RULE_REGISTRY` for code paths that don't go through the
scanner (the CLI `rules list` / `rules explain` / `explain` commands,
`scripts/generate_rule_docs.py`, plugin discovery, etc.). Add a single
`import vibeguard.rules.<your_module>  # noqa: F401` line alongside the
existing imports. The metadata in your module's `register_rule(...)`
call only runs when the module is imported, so missing this step makes
your rule invisible to every non-scanner code path.

If your rule needs a config toggle, also add a `XxxConfig` model to
`vibeguard/config.py` and reference it from `VibeGuardConfig`. The
default for new rules is **`enabled: true`** unless there's a clear
reason to opt in. Pass `config_key="..."` to `RuleMetadata` only when
the YAML section name differs from the `rule_id` (rare — see
`risky_diff` for the only built-in mismatch).

## 5. Write unit tests

Create `tests/test_js_proto_pollution.py`. Match the existing test
style — class-based grouping, pytest `tmp_path`, direct rule
instantiation. `tests/test_sourcemaps.py` is a good template.

```python
"""Tests for the js_proto_pollution rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext
from vibeguard.rules.js_proto_pollution import JsProtoPollutionRule


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(
        root=tmp_path,
        config=VibeGuardConfig(),
        files=[p for p in tmp_path.rglob("*") if p.is_file()],
    )


class TestJsProtoPollutionRule:
    def test_object_assign_new_target_flagged(self, tmp_path: Path):
        (tmp_path / "merge.js").write_text(
            "export const merge = (a, b) => Object.assign({}, a, b);\n"
        )
        findings = JsProtoPollutionRule().scan(_context(tmp_path))
        assert [f.id for f in findings] == ["JSPP-OBJECT-ASSIGN-NEW"]
        assert findings[0].line == 1
        assert findings[0].path == "merge.js"

    def test_object_assign_existing_target_not_flagged(self, tmp_path: Path):
        (tmp_path / "merge.js").write_text(
            "Object.assign(existing, a, b);\n"
        )
        assert JsProtoPollutionRule().scan(_context(tmp_path)) == []

    def test_python_file_not_inspected(self, tmp_path: Path):
        (tmp_path / "merge.py").write_text("Object.assign({}, a, b)\n")
        assert JsProtoPollutionRule().scan(_context(tmp_path)) == []

    def test_multiple_matches_emit_multiple_findings(self, tmp_path: Path):
        (tmp_path / "merge.js").write_text(
            "Object.assign({}, a);\nObject.assign({}, b);\n"
        )
        findings = JsProtoPollutionRule().scan(_context(tmp_path))
        assert [f.line for f in findings] == [1, 2]
```

**Checklist**:

- One **happy path** test (positive match).
- One **negative** test (similar-but-safe code stays quiet).
- One **applicability** test (rule does not fire on unrelated file types).
- One **boundary** test (multi-match, empty file, etc.).

If your rule reads the diff or git context, also add a test that
constructs a `ScanContext` with `diff_only=True` and `changed_files=[…]`.

## 6. Regenerate docs and run CI

Three commands before you push:

```bash
make docs        # regenerate docs/rules.md from RULE_REGISTRY
make ci          # ruff + ruff format --check + mypy + docs-check + pytest
```

`make ci` includes `make docs-check`, which fails when `docs/rules.md`
isn't in sync with the registry — `make docs` is the fix.

That's it. A rule that lands all six steps is ready for review.

---

## What makes a good rule

| Trait                                  | Why it matters                                       |
|----------------------------------------|------------------------------------------------------|
| High signal / noise                    | A noisy rule is one users will mute permanently.     |
| Deterministic                          | Same input → same output. No timestamps, no PRNG.    |
| No network, no I/O side effects        | VibeGuard runs offline, in CI, on every PR.          |
| Fast                                   | < 100 ms per file is the soft target.                |
| Clear remediation                      | A finding without a fix is just noise.               |
| Framed as "risk-sensitive", not "vuln" | We surface review prompts, not vulnerability claims. |

## What makes a bad rule

- Too broad — fires on every occurrence of a string that looks like a
  pattern but rarely indicates a real issue.
- Too narrow — fires only on a synthetic pattern that doesn't appear in
  real code.
- Requires installed tooling (npm, docker, terraform) to make a
  decision. VibeGuard is offline-only.
- Uses severity to express importance rather than risk (high ≠ "I
  really care about this").
- Talks about "vulnerabilities" — the framing is *risk-sensitive
  change, human review recommended*.

If you're unsure whether your rule earns its keep, open a draft PR with
the rule plus 3–5 corpus fixtures and ask in the thread.
