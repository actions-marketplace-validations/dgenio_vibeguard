"""Missing tests rule."""

from __future__ import annotations

from pathlib import Path

import pathspec

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# Source directories that indicate "real" code
_SOURCE_DIRS = {"src", "app", "lib", "vibeguard", "api", "server", "core", "pkg"}

# Patterns that indicate test files
_TEST_INDICATORS = {
    "tests",
    "test",
    "__tests__",
    "spec",
    "specs",
}

_TEST_SUFFIXES = {"_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"}
_TEST_PREFIXES = {"test_"}


def _is_source_file(path: Path) -> bool:
    """Return True if this looks like a non-test source file."""
    if _is_test_file(path):
        return False
    parts_lower = {p.lower() for p in path.parts}
    if parts_lower & _SOURCE_DIRS:
        return True
    # Also consider top-level .py files in the package
    return path.suffix in {".py", ".js", ".ts"} and len(path.parts) <= 3


def _is_test_file(path: Path) -> bool:
    name = path.name.lower()
    for suf in _TEST_SUFFIXES:
        if name.endswith(suf):
            return True
    for pre in _TEST_PREFIXES:
        if name.startswith(pre):
            return True
    parts_lower = {p.lower() for p in path.parts}
    return bool(parts_lower & _TEST_INDICATORS)


class MissingTestsRule(Rule):
    id = "tests"
    name = "Missing Tests"
    description = "Flags source file changes that lack corresponding test file changes"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # This rule only makes sense when we have changed file information
        if not context.changed_files and not context.diff_only:
            return findings

        files_to_check = context.changed_files if context.changed_files else context.files

        changed_source = [f for f in files_to_check if _is_source_file(f)]
        changed_tests = [f for f in files_to_check if _is_test_file(f)]

        if not changed_source:
            return findings

        mappings = getattr(context.config.tests, "mapping", []) or []

        if not mappings:
            # No mapping configured — preserve the original heuristic exactly.
            # This branch is the hot path for most repos and must stay cheap;
            # in particular, no pathspec compilation happens here (#69).
            if changed_tests:
                return findings
            uncovered_rels = [self._rel(context, f) for f in changed_source]
        else:
            uncovered_rels = self._uncovered_with_mappings(
                context, files_to_check, changed_source, changed_tests, mappings
            )
            if not uncovered_rels:
                return findings

        policy = context.config.policy
        severity = Severity.MEDIUM if policy == "strict" else Severity.LOW

        source_rels = uncovered_rels[:5]
        extra = len(uncovered_rels) - 5
        paths_summary = ", ".join(f"`{r}`" for r in source_rels)
        if extra > 0:
            paths_summary += f" and {extra} more"

        findings.append(
            Finding(
                id="TEST-MISSING",
                rule=self.id,
                title="Source changes without test changes",
                description=(
                    f"{len(uncovered_rels)} source file(s) changed but no test files were "
                    f"modified. Changed files include: {paths_summary}"
                ),
                severity=severity,
                path=source_rels[0] if source_rels else ".",
                recommendation=(
                    "Add or update tests to cover the changed code. "
                    "Untested AI-generated code is a common source of bugs and regressions."
                ),
                tags=["tests", "coverage"],
                confidence=Confidence.MEDIUM,
            )
        )

        return findings

    def _uncovered_with_mappings(
        self,
        context: ScanContext,
        files_to_check: list[Path],
        changed_source: list[Path],
        changed_tests: list[Path],
        mappings: list,  # list[SourceTestMapping]; avoid TYPE_CHECKING cycle
    ) -> list[str]:
        """Return changed source files not covered by any mapping or heuristic.

        Per-source decision rule (in order):

        * If the file matches **at least one** mapping's ``source`` glob,
          it is "covered" iff any of those matched mappings has a ``tests``
          glob that matches some changed file. Files that match a mapping
          do NOT fall back to the heuristic — the user has explicitly
          claimed responsibility for them via configuration.
        * If the file matches **no** mapping, it falls back to the legacy
          rule: covered iff at least one changed test file exists in the
          change set.
        """
        spec_pairs = [
            (
                pathspec.PathSpec.from_lines("gitignore", [m.source]),
                pathspec.PathSpec.from_lines("gitignore", m.tests),
            )
            for m in mappings
        ]
        changed_rels = [self._rel(context, f).replace("\\", "/") for f in files_to_check]
        has_any_test_change = bool(changed_tests)

        uncovered: list[str] = []
        for src_file in changed_source:
            rel = self._rel(context, src_file).replace("\\", "/")
            matching_pairs = [
                (src_spec, test_spec)
                for src_spec, test_spec in spec_pairs
                if src_spec.match_file(rel)
            ]
            if matching_pairs:
                covered = any(
                    test_spec.match_file(other_rel)
                    for _, test_spec in matching_pairs
                    for other_rel in changed_rels
                )
                if not covered:
                    uncovered.append(rel)
            elif not has_any_test_change:
                uncovered.append(rel)
        return uncovered


register_rule(
    RuleMetadata(
        rule_id="tests",
        title="Missing Tests",
        description="Flags source file changes that lack corresponding test file changes.",
        finding_ids=["TEST-MISSING"],
        default_severity="low",
        confidence="medium",
        tags=["tests", "coverage"],
        applies_to=["*.py", "*.js", "*.ts"],
    )
)
