"""Scaffolding for new built-in VibeGuard rules (#100).

Generating a good rule means touching several moving parts (module, finding
IDs, metadata, scanner wiring, tests, docs). This module produces the
mechanical pieces — the rule module and its test — so a contributor or AI
coding agent can start from a convention-correct skeleton instead of a blank
file, and prints a checklist of the steps that still need human judgement.

The CLI surface is ``vibeguard dev new-rule`` (see :mod:`vibeguard.cli`); the
logic lives here so it is unit-testable without spawning the CLI.

A freshly-scaffolded rule is intentionally a **failing** stub, not a passing
no-op: the generated positive test asserts a finding the empty ``scan`` does
not yet produce, so CI stays red until the author implements detection. Pass
``draft=True`` to mark the test skipped instead, keeping CI green for
work-in-progress branches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# A rule id is the module file name and the registry key: snake_case, starts
# with a letter. A finding prefix is the upper-case family stem of finding IDs
# (e.g. ``SEC-SUPABASE`` → ``SEC-SUPABASE-KEY``).
_RULE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_FINDING_PREFIX_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*$")


class ScaffoldError(ValueError):
    """Raised for invalid input or a refused overwrite."""


@dataclass
class ScaffoldResult:
    """Outcome of a scaffold run."""

    created: list[Path] = field(default_factory=list)
    skipped: list[Path] = field(default_factory=list)
    checklist: list[str] = field(default_factory=list)
    rendered: dict[Path, str] = field(default_factory=dict)
    dry_run: bool = False


def validate_rule_id(rule_id: str) -> None:
    if not _RULE_ID_RE.match(rule_id):
        raise ScaffoldError(
            f"Invalid rule id {rule_id!r}: use snake_case starting with a letter "
            "(e.g. 'exposed_supabase_key')."
        )


def validate_finding_prefix(prefix: str) -> None:
    if not _FINDING_PREFIX_RE.match(prefix):
        raise ScaffoldError(
            f"Invalid finding prefix {prefix!r}: use UPPER-CASE with optional hyphens "
            "(e.g. 'SEC-SUPABASE')."
        )


def class_name(rule_id: str) -> str:
    """``exposed_supabase_key`` → ``ExposedSupabaseKeyRule``."""
    return "".join(part.capitalize() for part in rule_id.split("_")) + "Rule"


def _finding_id(prefix: str) -> str:
    """A concrete example finding id derived from the family prefix."""
    return f"{prefix}-PLACEHOLDER"


def render_rule_module(rule_id: str, finding_prefix: str, *, draft: bool) -> str:
    cls = class_name(rule_id)
    finding_id = _finding_id(finding_prefix)
    title = " ".join(part.capitalize() for part in rule_id.split("_"))
    draft_note = (
        "\n        # NOTE: scaffolded draft — implement detection before enabling.\n"
        if draft
        else "\n"
    )
    return f'''"""{title} rule.

Scaffolded by ``vibeguard dev new-rule``. Replace the TODO in ``scan`` with the
real detection logic, then wire the rule in following docs/how-to-add-a-rule.md.
"""

from __future__ import annotations

from vibeguard.models import Finding, ScanContext
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule


class {cls}(Rule):
    id = "{rule_id}"
    name = "{title}"
    description = "TODO: one-sentence description of what {rule_id} detects."

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files
{draft_note}        for path in files_to_check:
            # TODO({rule_id}): implement detection and append Finding(...) with
            #   id="{finding_id}", severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            #   path=self._rel(context, path), recommendation="...".
            # See docs/how-to-add-a-rule.md and an existing rule such as
            # vibeguard/rules/sourcemaps.py for the full pattern.
            del path  # remove once detection is implemented
        return findings


register_rule(
    RuleMetadata(
        rule_id="{rule_id}",
        title="{title}",
        description="TODO: registry description for {rule_id}.",
        finding_ids=["{finding_id}"],
        default_severity="medium",
        confidence="medium",
        tags=["TODO"],
        applies_to=["*"],
        remediations={{
            "{finding_id}": "TODO: how to fix a {finding_id} finding.",
        }},
    )
)
'''


def render_test_module(rule_id: str, finding_prefix: str, *, draft: bool) -> str:
    cls = class_name(rule_id)
    finding_id = _finding_id(finding_prefix)
    skip_marker = (
        "\nimport pytest\n\n"
        'pytestmark = pytest.mark.skip(reason="draft rule — implement before enabling")\n'
        if draft
        else "\n"
    )
    return f'''"""Tests for the {rule_id} rule (scaffolded by `vibeguard dev new-rule`)."""

from __future__ import annotations

from pathlib import Path
{skip_marker}
from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext
from vibeguard.rules.{rule_id} import {cls}


def _ctx(tmp_path: Path, files: dict[str, str]) -> ScanContext:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return ScanContext(
        root=tmp_path,
        config=VibeGuardConfig(),
        files=[tmp_path / n for n in files],
    )


class Test{cls[:-4]}:
    rule = {cls}()

    def test_positive_case_is_flagged(self, tmp_path: Path):
        # TODO: replace the fixture with code the rule should flag. This test
        # fails until detection is implemented — that is intentional, it keeps
        # the scaffolded no-op from passing CI silently.
        ctx = _ctx(tmp_path, {{"example.txt": "TODO: offending content\\n"}})
        findings = self.rule.scan(ctx)
        assert any(f.id == "{finding_id}" for f in findings), (
            "Implement {rule_id} detection so this fixture produces {finding_id}."
        )

    def test_clean_input_not_flagged(self, tmp_path: Path):
        # TODO: a similar-but-safe fixture must stay quiet (no false positives).
        ctx = _ctx(tmp_path, {{"clean.txt": "nothing to see here\\n"}})
        assert self.rule.scan(ctx) == []
'''


def _checklist(rule_id: str, finding_prefix: str) -> list[str]:
    return [
        f"Implement detection in vibeguard/rules/{rule_id}.py (replace the TODO).",
        f"Complete the positive/negative fixtures in tests/test_{rule_id}.py.",
        f"Register the rule in vibeguard/rules/builtin.py: import {class_name(rule_id)} "
        "and add it to the BUILTIN_RULES tuple. This single edit wires the rule into "
        "the scanner, `vibeguard rules list`, and the generated docs.",
        f"Add a {class_name(rule_id)[:-4]}Config model + field to "
        "vibeguard/config.py (and DEFAULT_CONFIG_YAML) if the rule needs a toggle.",
        "Add a row to the README 'What It Catches' and rule-reference tables.",
        "Run `make docs` to regenerate docs/rules.md, then `make ci`.",
    ]


def scaffold_rule(
    rule_id: str,
    finding_prefix: str,
    *,
    root: Path,
    force: bool = False,
    draft: bool = False,
    dry_run: bool = False,
) -> ScaffoldResult:
    """Generate the rule module + test for ``rule_id``.

    Returns a :class:`ScaffoldResult`. Raises :class:`ScaffoldError` on invalid
    identifiers, or on an existing target file when ``force`` is not set.
    """
    validate_rule_id(rule_id)
    validate_finding_prefix(finding_prefix)

    targets: dict[Path, str] = {
        root / "vibeguard" / "rules" / f"{rule_id}.py": render_rule_module(
            rule_id, finding_prefix, draft=draft
        ),
        root / "tests" / f"test_{rule_id}.py": render_test_module(
            rule_id, finding_prefix, draft=draft
        ),
    }

    result = ScaffoldResult(checklist=_checklist(rule_id, finding_prefix), dry_run=dry_run)

    # Refuse to clobber existing files up front (atomic-ish: check all before
    # writing any) unless --force was passed.
    if not force:
        existing = [p for p in targets if p.exists()]
        if existing and not dry_run:
            rels = ", ".join(str(p.relative_to(root)) for p in existing)
            raise ScaffoldError(
                f"Refusing to overwrite existing file(s): {rels}. Pass --force to overwrite."
            )

    for path, content in targets.items():
        result.rendered[path] = content
        if dry_run:
            continue
        if path.exists() and not force:
            result.skipped.append(path)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        result.created.append(path)

    return result
