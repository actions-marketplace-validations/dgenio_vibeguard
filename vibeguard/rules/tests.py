"""Missing tests rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule

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

        if changed_tests:
            # Tests were changed — no finding needed
            return findings

        # Source changed but no test files changed
        policy = context.config.policy
        severity = Severity.MEDIUM if policy == "strict" else Severity.LOW

        source_rels = [self._rel(context, f) for f in changed_source[:5]]
        extra = len(changed_source) - 5
        paths_summary = ", ".join(f"`{r}`" for r in source_rels)
        if extra > 0:
            paths_summary += f" and {extra} more"

        findings.append(
            Finding(
                id="TEST-MISSING",
                rule=self.id,
                title="Source changes without test changes",
                description=(
                    f"{len(changed_source)} source file(s) changed but no test files were modified. "
                    f"Changed files include: {paths_summary}"
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
