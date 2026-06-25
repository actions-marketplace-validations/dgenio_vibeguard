"""SQL construction heuristic rule."""

from __future__ import annotations

import re

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules._util import is_comment_line, mask_triple_quoted_spans
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# ---------------------------------------------------------------------------
# Python SQL patterns (.py)
# ---------------------------------------------------------------------------
_PY_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "SQL-PY-FSTRING",
        "f-string SQL query",
        # Require structural SQL evidence, not a lone keyword (#137): the
        # f-string must contain an interpolation (the lookahead ``\{``) *and* a
        # verb paired with its companion clause (SELECT…FROM, UPDATE…SET,
        # INSERT…INTO, DELETE…FROM). This stops prose like
        # ``f"Update on your request: {topic}"`` from masquerading as a query
        # while still matching genuine interpolated SQL.
        re.compile(
            r"""f["'](?=[^"']*\{)[^"']*(?:\bSELECT\b[^"']*\bFROM\b"""
            r"""|\bUPDATE\b[^"']*\bSET\b|\bINSERT\b[^"']*\bINTO\b"""
            r"""|\bDELETE\b[^"']*\bFROM\b)""",
            re.IGNORECASE,
        ),
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

            # Mask Python docstring / multiline-string spans: a query quoted as
            # documentation is prose, not an executed statement (#138). Patterns
            # run against the masked text; evidence comes from the original line.
            lines = content.splitlines()
            masked = mask_triple_quoted_spans(content) if ext == ".py" else lines

            for lineno, (line, scan_line) in enumerate(zip(lines, masked, strict=True), start=1):
                stripped = line.strip()
                # Skip comment lines (shared heuristic — #178).
                if is_comment_line(stripped):
                    continue

                for finding_id, label, pattern in patterns:
                    key = (rel, finding_id)
                    if key in seen:
                        continue
                    if pattern.search(scan_line):
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
        remediations={
            "SQL-PY-FSTRING": (
                "Use parameterised queries: pass user values as positional "
                "or named bind parameters (e.g. `cursor.execute(sql, (a,))`). "
                "F-strings in SQL invite injection."
            ),
            "SQL-PY-CONCAT": (
                "Replace string concatenation with parameterised queries. "
                "Use your driver's `?`/`%s`/named-param syntax instead of "
                "`+` or `%` on user input."
            ),
            "SQL-PY-FORMAT": (
                "Avoid `.format(...)` on SQL strings. Build the query with "
                "bind parameters so the driver escapes values."
            ),
            "SQL-JS-TEMPLATE": (
                "Use the database client's parameter binding API (`?`, `$1`, "
                "or prepared statements). Template literals concatenate user "
                "input directly into SQL."
            ),
            "SQL-JS-CONCAT": (
                "Replace string concatenation with parameterised queries via "
                "the driver. Even `+`-joined SQL with sanitisation drifts "
                "out of sync over time."
            ),
            "SQL-GO-SPRINTF": (
                "Use `db.QueryContext` / `db.ExecContext` with `?` "
                "placeholders. `fmt.Sprintf` to assemble SQL is the canonical "
                "Go injection pattern."
            ),
        },
    )
)
