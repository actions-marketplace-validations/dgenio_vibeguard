"""SQL construction heuristic rule."""

from __future__ import annotations

import re

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# ---------------------------------------------------------------------------
# Python SQL patterns (.py)
# ---------------------------------------------------------------------------
_PY_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "SQL-PY-FSTRING",
        "f-string SQL query",
        re.compile(r'f["\'].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{', re.IGNORECASE),
    ),
    (
        "SQL-PY-CONCAT",
        "Concatenated SQL query",
        re.compile(
            r'(?i)("SELECT\s|"INSERT\s|"UPDATE\s|"DELETE\s).*"\s*\+|'
            r'query\s*=\s*".*\+'
        ),
    ),
    (
        "SQL-PY-FORMAT",
        ".format() SQL query",
        re.compile(r'(?i)("SELECT\s|"INSERT\s|"UPDATE\s|"DELETE\s).*"\.format\('),
    ),
]

# ---------------------------------------------------------------------------
# JavaScript/TypeScript SQL patterns (.js, .ts)
# ---------------------------------------------------------------------------
_JS_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "SQL-JS-TEMPLATE",
        "Template literal SQL query",
        re.compile(r"(?i)`\s*(SELECT|INSERT|UPDATE|DELETE)\s.*\$\{"),
    ),
    (
        "SQL-JS-CONCAT",
        "Concatenated SQL query",
        re.compile(
            r'(?i)("SELECT\s|"INSERT\s|"UPDATE\s|"DELETE\s).*"\s*\+|'
            r"query\s*=\s*[\"'].*\"\s*\+",
        ),
    ),
]

# ---------------------------------------------------------------------------
# Go SQL patterns (.go)
# ---------------------------------------------------------------------------
_GO_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "SQL-GO-SPRINTF",
        "fmt.Sprintf SQL query",
        re.compile(r"(?i)fmt\.Sprintf\s*\([^)]*\b(SELECT|INSERT|UPDATE|DELETE)\b"),
    ),
]

_EXTENSION_MAP: dict[str, list[tuple[str, str, re.Pattern[str]]]] = {
    ".py": _PY_PATTERNS,
    ".go": _GO_PATTERNS,
    ".js": _JS_PATTERNS,
    ".ts": _JS_PATTERNS,
    ".jsx": _JS_PATTERNS,
    ".tsx": _JS_PATTERNS,
}


class SqlRule(Rule):
    id = "sql"
    name = "SQL Construction Risk"
    description = "Detects risk-sensitive SQL construction patterns for injection review"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files
        seen: set[tuple[str, str]] = set()

        for path in files_to_check:
            ext = path.suffix.lower()
            patterns = _EXTENSION_MAP.get(ext)
            if patterns is None:
                continue

            rel = self._rel(context, path)
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                stripped = line.strip()
                # Skip comment lines
                if stripped.startswith(("#", "//", "/*", "*")):
                    continue

                for finding_id, label, pattern in patterns:
                    key = (rel, finding_id)
                    if key in seen:
                        continue
                    if pattern.search(line):
                        seen.add(key)
                        findings.append(
                            Finding(
                                id=finding_id,
                                rule=self.id,
                                title=f"SQL: {label}",
                                description=(
                                    f"`{rel}` line {lineno}: Risk-sensitive SQL construction "
                                    f"detected ({label}). Review for injection risk."
                                ),
                                severity=Severity.HIGH,
                                path=rel,
                                line=lineno,
                                evidence=stripped[:120],
                                recommendation=(
                                    "Use parameterized queries or prepared statements instead "
                                    "of string interpolation/concatenation for SQL."
                                ),
                                tags=["sql", "injection", finding_id.lower()],
                                confidence=Confidence.MEDIUM,
                            )
                        )

        return findings


register_rule(
    RuleMetadata(
        rule_id="sql",
        title="SQL Construction Risk",
        description=(
            "Detects risk-sensitive SQL construction patterns (f-strings, concatenation, "
            "template literals, fmt.Sprintf) that may indicate injection risks."
        ),
        finding_ids=[
            "SQL-PY-FSTRING",
            "SQL-PY-CONCAT",
            "SQL-PY-FORMAT",
            "SQL-JS-TEMPLATE",
            "SQL-JS-CONCAT",
            "SQL-GO-SPRINTF",
        ],
        default_severity="high",
        confidence="medium",
        tags=["security", "sql", "injection"],
        applies_to=["*.py", "*.js", "*.ts", "*.go"],
    )
)
