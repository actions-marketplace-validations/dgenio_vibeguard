"""Test-integrity rule (#203).

Flags changes that weaken the test suite itself — the well-documented
"make a red CI green by disabling the check" failure mode of AI coding agents.
The existing :mod:`vibeguard.rules.tests` rule only detects *missing* test
changes (``TEST-MISSING``); it cannot see a diff that **deletes** tests,
**skips** them, or **lowers** a coverage threshold, because in all of those
cases test/config files *were* touched.

Four findings, each a risk signal (the ``risky_diff`` framing — "human, please
look"), not a vulnerability claim:

* ``TEST-SKIP-ADDED`` — a skip / ``xit`` / ``skipif`` marker (line-based; in
  ``--diff`` mode the scanner restricts these to newly changed lines).
* ``TEST-ONLY-ADDED`` — a focused ``.only`` / ``fit`` / ``fdescribe`` marker
  that silently disables every *other* test in the file.
* ``TEST-DELETED`` — a deleted test file or a removed test function in the diff.
* ``TEST-COVERAGE-LOWERED`` — a coverage threshold (``fail_under``,
  ``--cov-fail-under``, Jest ``coverageThreshold``) reduced in the diff.

``TEST-DELETED`` and ``TEST-COVERAGE-LOWERED`` are inherently before/after
signals, so they read :attr:`vibeguard.models.ScanContext.diff_text` and only
fire in ``--diff`` mode. They are emitted as file-level findings (``line=None``)
so the scanner's changed-line filter passes them through.
"""

from __future__ import annotations

import re
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules._util import is_comment_line, is_test_file, is_test_path
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# (finding_id, label, pattern). ``skipif`` is matched separately so it can be
# down-ranked: a conditional skip is far less risky than a bare one.
_SKIP_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "TEST-SKIP-ADDED",
        "test skip marker",
        re.compile(
            r"(?:@(?:pytest\.mark\.)?skip\b"  # @pytest.mark.skip / @skip
            r"|@unittest\.skip\b"
            r"|(?:pytest|unittest)\.skip\s*\("  # pytest.skip(...)
            r"|self\.skipTest\s*\("
            r"|\b(?:it|test|describe|context)\.skip\s*\("  # jest/mocha it.skip(
            r"|\bx(?:it|describe|test)\s*\()"  # xit( / xdescribe(
        ),
    ),
]

# Conditional skip — real condition attached, so it is a weaker signal.
_SKIPIF_PATTERN = re.compile(
    r"@(?:pytest\.mark\.)?skipif\b|@unittest\.skip(?:If|Unless)\b",
)

# Focused-test markers: running "only" this test silently disables the rest.
_ONLY_PATTERN = re.compile(
    r"\b(?:it|test|describe|context)\.only\s*\(|\bf(?:it|describe)\s*\(",
)

# Removed test definitions (matched against ``-`` diff lines in a test file).
_REMOVED_TEST_DEF = re.compile(
    r"^\s*(?:async\s+def|def)\s+test\w*\s*\("  # python test functions
    r"|^\s*class\s+Test\w*\b"  # python test classes
    r"|^\s*(?:it|test)\s*\(\s*['\"`]",  # jest/mocha test cases
)

# Coverage-threshold tokens that appear in build/test config.
_THRESHOLD_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("fail_under", re.compile(r"fail_under\s*[=:]\s*(\d+(?:\.\d+)?)")),
    ("cov-fail-under", re.compile(r"--cov-fail-under[=\s]+(\d+(?:\.\d+)?)")),
]
# Jest ``coverageThreshold`` per-metric numbers — only trusted inside package.json.
_JS_METRIC = re.compile(r'"(branches|functions|lines|statements)"\s*:\s*(\d+(?:\.\d+)?)')

# Source extensions where a skip/only marker is meaningful.
_TEST_CODE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}


class TestIntegrityRule(Rule):
    id = "test_integrity"
    name = "Test Integrity"
    description = (
        "Flags changes that weaken the test suite: added skip/only markers, "
        "deleted tests, or lowered coverage thresholds. A risk signal, not a "
        "vulnerability claim."
    )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_markers(context))
        findings.extend(self._scan_diff(context))
        return findings

    # -- line-based skip/only markers --------------------------------------
    def _scan_markers(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files
        base_skip = Severity.MEDIUM if context.diff_only else Severity.LOW

        for path in files_to_check:
            if path.suffix.lower() not in _TEST_CODE_EXTENSIONS:
                continue
            if not is_test_file(path):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = self._rel(context, path)
            for lineno, line in enumerate(content.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or is_comment_line(stripped):
                    continue

                if _ONLY_PATTERN.search(line):
                    findings.append(
                        self._finding(
                            "TEST-ONLY-ADDED",
                            "Focused test marker added",
                            (
                                f"`{rel}` line {lineno} adds a focused-test marker "
                                "(`.only`/`fit`/`fdescribe`). This silently disables "
                                "every other test in the file."
                            ),
                            base_skip,
                            rel,
                            lineno,
                            stripped,
                            "Remove the focused-test marker before merging so the "
                            "full suite runs in CI.",
                        )
                    )
                    continue

                if _SKIPIF_PATTERN.search(line):
                    # Conditional skip — weaker signal, always low.
                    findings.append(
                        self._finding(
                            "TEST-SKIP-ADDED",
                            "Conditional test skip added",
                            (
                                f"`{rel}` line {lineno} adds a conditional skip "
                                "(`skipif`/`skipUnless`). Confirm the condition is "
                                "intended and not masking a real failure."
                            ),
                            Severity.LOW,
                            rel,
                            lineno,
                            stripped,
                            "Confirm the skip condition is correct and document why "
                            "the test cannot run in the affected environment.",
                        )
                    )
                    continue

                if _SKIP_PATTERNS[0][2].search(line):
                    findings.append(
                        self._finding(
                            "TEST-SKIP-ADDED",
                            "Test skip marker added",
                            (
                                f"`{rel}` line {lineno} adds a test skip marker. "
                                "Skipping a test to get CI green can hide a real "
                                "regression — human review recommended."
                            ),
                            base_skip,
                            rel,
                            lineno,
                            stripped,
                            "Re-enable the test or replace the skip with a fix. If the "
                            "skip is intentional, document why and add a tracking issue.",
                        )
                    )

        return findings

    # -- diff-only signals (deletions, coverage) ---------------------------
    def _scan_diff(self, context: ScanContext) -> list[Finding]:
        if not context.diff_text:
            return []

        findings: list[Finding] = []
        deleted = _deleted_paths(context.diff_text)
        deleted_set = set(deleted)

        for path in deleted:
            if is_test_path(path):
                findings.append(
                    self._finding(
                        "TEST-DELETED",
                        "Test file deleted",
                        (
                            f"`{path}` is a test file deleted in this change. "
                            "Removing tests reduces coverage of behaviour that was "
                            "previously guarded."
                        ),
                        Severity.MEDIUM,
                        path,
                        None,
                        None,
                        "Confirm the deletion is intentional and the behaviour it "
                        "covered is either removed or still tested elsewhere.",
                        Confidence.HIGH,
                    )
                )

        for path in _removed_test_defs(context.diff_text):
            if path in deleted_set:
                continue  # already reported as a whole-file deletion
            findings.append(
                self._finding(
                    "TEST-DELETED",
                    "Test removed in diff",
                    (
                        f"`{path}` removes one or more test definitions in this "
                        "change. Deleting tests can silently drop coverage."
                    ),
                    Severity.MEDIUM,
                    path,
                    None,
                    None,
                    "Confirm the removed tests are obsolete, not deleted to make a "
                    "failing pipeline pass.",
                    Confidence.HIGH,
                )
            )

        for path, key, old, new in _coverage_lowered(context.diff_text):
            findings.append(
                self._finding(
                    "TEST-COVERAGE-LOWERED",
                    "Coverage threshold lowered",
                    (
                        f"`{path}` lowers a coverage threshold (`{key}`) from {old} "
                        f"to {new}. Lowering the bar to pass CI hides untested code."
                    ),
                    Severity.MEDIUM,
                    path,
                    None,
                    f"{key}: {old} -> {new}",
                    "Restore the previous threshold, or justify the reduction in the "
                    "PR description and track regaining the coverage.",
                    Confidence.HIGH,
                )
            )

        return findings

    def _finding(
        self,
        fid: str,
        title: str,
        description: str,
        severity: Severity,
        path: str,
        line: int | None,
        evidence: str | None,
        recommendation: str,
        confidence: Confidence = Confidence.MEDIUM,
    ) -> Finding:
        return Finding(
            id=fid,
            rule=self.id,
            title=title,
            description=description,
            severity=severity,
            path=path,
            line=line,
            evidence=evidence[:120] if evidence else None,
            recommendation=recommendation,
            tags=["test-integrity"],
            confidence=confidence,
        )


def _b_path(line: str) -> str | None:
    """Extract the new-file path from a ``diff --git a/X b/Y`` header."""
    marker = " b/"
    idx = line.find(marker)
    if idx == -1:
        return None
    return line[idx + len(marker) :].strip() or None


def _deleted_paths(diff_text: str) -> list[str]:
    """Return paths the diff deletes (``deleted file mode`` blocks)."""
    deleted: list[str] = []
    current: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current = _b_path(line)
        elif line.startswith("deleted file mode") and current:
            deleted.append(current)
            current = None
    return deleted


def _removed_test_defs(diff_text: str) -> list[str]:
    """Return distinct test-file paths whose diff removes a test definition."""
    paths: list[str] = []
    seen: set[str] = set()
    current: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            current = None if target == "/dev/null" else target.removeprefix("b/")
            continue
        if line.startswith("--- "):
            continue
        if current is None or current in seen:
            continue
        if not is_test_path(current):
            continue
        # A removed line is a ``-`` that is not the ``---`` file header.
        if (
            line.startswith("-")
            and not line.startswith("---")
            and _REMOVED_TEST_DEF.search(line[1:])
        ):
            seen.add(current)
            paths.append(current)
    return paths


def _coverage_lowered(diff_text: str) -> list[tuple[str, str, str, str]]:
    """Return ``(path, key, old, new)`` for each lowered coverage threshold."""
    files: dict[str, dict[str, dict[str, float]]] = {}
    current: str | None = None

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            current = None if target == "/dev/null" else target.removeprefix("b/")
            if current:
                files.setdefault(current, {"removed": {}, "added": {}})
            continue
        if line.startswith("--- "):
            continue
        if current is None:
            continue
        if line.startswith("-") and not line.startswith("---"):
            _collect_thresholds(line[1:], current, files[current]["removed"])
        elif line.startswith("+") and not line.startswith("+++"):
            _collect_thresholds(line[1:], current, files[current]["added"])

    results: list[tuple[str, str, str, str]] = []
    for path, sides in files.items():
        for key, new_val in sides["added"].items():
            old_val = sides["removed"].get(key)
            if old_val is not None and new_val < old_val:
                results.append((path, key, _fmt(old_val), _fmt(new_val)))
    return results


def _collect_thresholds(text: str, path: str, into: dict[str, float]) -> None:
    for key, pattern in _THRESHOLD_PATTERNS:
        match = pattern.search(text)
        if match:
            into[key] = float(match.group(1))
    # Jest metrics are only trustworthy inside a package.json (the key name
    # ``lines``/``branches`` is too generic to trust everywhere).
    if Path(path).name == "package.json":
        for metric_match in _JS_METRIC.finditer(text):
            into[metric_match.group(1)] = float(metric_match.group(2))


def _fmt(value: float) -> str:
    return str(int(value)) if value.is_integer() else str(value)


register_rule(
    RuleMetadata(
        rule_id="test_integrity",
        title="Test Integrity",
        description=(
            "Flags changes that weaken the test suite: added skip/only markers, "
            "deleted tests, and lowered coverage thresholds."
        ),
        finding_ids=[
            "TEST-SKIP-ADDED",
            "TEST-ONLY-ADDED",
            "TEST-DELETED",
            "TEST-COVERAGE-LOWERED",
        ],
        default_severity="medium",
        confidence="high",
        tags=["testing", "ai", "test-integrity"],
        applies_to=["*.py", "*.js", "*.ts", "pyproject.toml", ".coveragerc", "package.json"],
        remediations={
            "TEST-SKIP-ADDED": (
                "Re-enable the test or fix the underlying failure. A skip added to "
                "get CI green hides a regression; if the skip is genuinely needed, "
                "document why and link a tracking issue."
            ),
            "TEST-ONLY-ADDED": (
                "Remove the focused-test marker (`.only`/`fit`/`fdescribe`). It "
                "silently disables every other test in the file, so CI stops "
                "guarding the rest of the suite."
            ),
            "TEST-DELETED": (
                "Confirm the deleted tests are obsolete rather than removed to make "
                "a failing pipeline pass. Ensure the behaviour they covered is gone "
                "or still tested elsewhere."
            ),
            "TEST-COVERAGE-LOWERED": (
                "Restore the previous coverage threshold. If the reduction is "
                "deliberate, justify it in the PR description and track regaining "
                "the lost coverage."
            ),
        },
    )
)
