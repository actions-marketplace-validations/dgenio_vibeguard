"""Blanket lint/type suppression rule (#204).

Detects diff-introduced *blanket* suppressions that silence quality and
security tooling without a code or reason: bare ``# noqa``, ``# type: ignore``
(no error code), file-level ``/* eslint-disable */``, ``@ts-ignore`` /
``@ts-nocheck``, bare ``#nosec``, and bare ``//nolint``.

Scoped forms — ``# noqa: E501``, ``# type: ignore[arg-type]``, ``# nosec B101``,
``//nolint:errcheck`` — are intentionally **not** flagged, so the rule teaches
better hygiene rather than banning suppression outright. This mirrors
VibeGuard's own ``SUPPRESSION-NO-REASON`` stance (an unexplained suppression is
a finding) extended to third-party tools.

Findings are line-based, so in ``--diff`` mode the scanner restricts them to
newly changed lines; in full-scan mode they report at LOW severity.
"""

from __future__ import annotations

import re

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules._util import is_test_file
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# (finding_id, label, pattern). Each pattern matches only the *bare* form;
# scoped variants carry a code/list and are excluded via negative lookahead.
_SUPPRESSION_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "SUPPRESS-BARE-NOQA",
        "bare # noqa (no rule code)",
        re.compile(r"(?i)#\s*noqa\b(?!\s*:)"),
    ),
    (
        "SUPPRESS-TYPE-IGNORE",
        "bare # type: ignore (no error code)",
        re.compile(r"(?i)#\s*type:\s*ignore\b(?!\[)"),
    ),
    (
        "SUPPRESS-ESLINT-FILE",
        "file-level /* eslint-disable */ (no rule list)",
        re.compile(r"/\*\s*eslint-disable\s*\*/"),
    ),
    (
        "SUPPRESS-TS-NOCHECK",
        "@ts-ignore / @ts-nocheck (prefer @ts-expect-error)",
        re.compile(r"@ts-(?:nocheck|ignore)\b"),
    ),
    (
        "SUPPRESS-NOSEC-BARE",
        "bare #nosec (no Bandit rule ID)",
        re.compile(r"(?i)#\s*nosec\b(?!\s+\w)"),
    ),
    (
        "SUPPRESS-NOLINT-BARE",
        "bare //nolint (no linter list)",
        re.compile(r"(?i)//\s*nolint\b(?!:)"),
    ),
]

# Where these suppression comments are meaningful.
_CODE_EXTENSIONS = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go"}

# Remediation text per finding, reused for the Finding.recommendation and the
# registry's ``explain`` remediation map.
_REMEDIATIONS: dict[str, str] = {
    "SUPPRESS-BARE-NOQA": (
        "Scope the suppression to the specific rule(s): `# noqa: E501`. A bare "
        "`# noqa` hides every current and future lint error on the line."
    ),
    "SUPPRESS-TYPE-IGNORE": (
        "Add the specific error code: `# type: ignore[arg-type]`. A bare "
        "`# type: ignore` silences all type errors on the line, including future "
        "regressions."
    ),
    "SUPPRESS-ESLINT-FILE": (
        "Replace the file-wide `/* eslint-disable */` with a scoped disable for "
        "the specific rule(s), or fix the underlying issues."
    ),
    "SUPPRESS-TS-NOCHECK": (
        "Prefer `@ts-expect-error` (which fails when the error is fixed) over "
        "`@ts-ignore`/`@ts-nocheck`, and scope it to the single line that needs it."
    ),
    "SUPPRESS-NOSEC-BARE": (
        "Add the Bandit test ID so the suppression is auditable: `# nosec B101`. "
        "A bare `#nosec` disables every Bandit check on the line."
    ),
    "SUPPRESS-NOLINT-BARE": (
        "List the linter(s) the suppression applies to: `//nolint:errcheck`. A "
        "bare `//nolint` disables all linters on the line."
    ),
}


class LintSuppressionsRule(Rule):
    id = "lint_suppressions"
    name = "Blanket Lint Suppressions"
    description = (
        "Flags newly introduced blanket linter/type-checker suppressions "
        "(bare # noqa, # type: ignore, eslint-disable, @ts-nocheck, #nosec, "
        "//nolint). Scoped suppressions with codes are not flagged."
    )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        for path in files_to_check:
            if path.suffix.lower() not in _CODE_EXTENSIONS:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = self._rel(context, path)
            # Test files are a weaker signal — keep them, but never above LOW.
            is_test = is_test_file(path)
            base = Severity.MEDIUM if context.diff_only else Severity.LOW
            severity = Severity.LOW if is_test else base

            for lineno, line in enumerate(content.splitlines(), start=1):
                # Don't flag VibeGuard's own inline suppression markers.
                if "vibeguard:" in line.lower():
                    continue
                for fid, label, pattern in _SUPPRESSION_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            Finding(
                                id=fid,
                                rule=self.id,
                                title=f"Blanket suppression added: {label}",
                                description=(
                                    f"`{rel}` line {lineno} introduces a {label}. "
                                    "Blanket suppressions silence the tooling that "
                                    "would otherwise catch regressions — human review "
                                    "recommended."
                                ),
                                severity=severity,
                                path=rel,
                                line=lineno,
                                evidence=line.strip()[:120],
                                recommendation=_REMEDIATIONS[fid],
                                tags=["lint-suppressions", fid.lower()],
                                confidence=Confidence.MEDIUM,
                            )
                        )

        return findings


register_rule(
    RuleMetadata(
        rule_id="lint_suppressions",
        title="Blanket Lint Suppressions",
        description=(
            "Flags newly introduced blanket linter/type-checker suppressions "
            "(bare # noqa, # type: ignore, eslint-disable, @ts-nocheck, #nosec, "
            "//nolint). Scoped suppressions with codes are not flagged."
        ),
        finding_ids=list(_REMEDIATIONS.keys()),
        default_severity="low",
        confidence="medium",
        tags=["developer-experience", "testing", "ai", "lint-suppressions"],
        applies_to=sorted(f"*{ext}" for ext in _CODE_EXTENSIONS),
        remediations=_REMEDIATIONS,
    )
)
