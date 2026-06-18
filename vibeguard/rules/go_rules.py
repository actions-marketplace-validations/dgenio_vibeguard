"""Go-specific risky pattern checks."""

from __future__ import annotations

import re
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

_GO_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    (
        "GO-INSECURE-TLS",
        "TLS verification disabled",
        re.compile(r"InsecureSkipVerify\s*:\s*true"),
        Severity.HIGH,
    ),
    (
        "GO-EXEC-SHELL",
        "Shell injection via exec.Command",
        re.compile(r'exec\.Command\s*\([^)]*\bsh\b[^)]*,\s*["\']?-c'),
        Severity.HIGH,
    ),
    (
        "GO-CORS-WILDCARD",
        "CORS wildcard origin",
        re.compile(
            r'(?i)(AllowOrigins.*\*|w\.Header\(\)\.Set\(\s*"Access-Control-Allow-Origin"\s*,\s*"\*")'
        ),
        Severity.MEDIUM,
    ),
    (
        "GO-SQL-SPRINTF",
        "SQL construction via Sprintf",
        re.compile(r"(?i)fmt\.Sprintf\s*\([^)]*\b(SELECT|INSERT|UPDATE|DELETE)\b"),
        Severity.HIGH,
    ),
    (
        "GO-HARDCODED-TOKEN",
        "Hardcoded credential in Go",
        re.compile(r'(?i)(apikey|token|password|secret)\s*:?=\s*"[A-Za-z0-9+/]{16,}"'),
        Severity.HIGH,
    ),
    (
        "GO-AUTH-BYPASS",
        "Auth bypass comment",
        re.compile(r"(?i)//\s*(TODO|FIXME|HACK).*auth"),
        Severity.MEDIUM,
    ),
    (
        "GO-UNSAFE-DELETE",
        "Unsafe file deletion with user input",
        re.compile(r"os\.RemoveAll\s*\(\s*(r\.|req\.|request\.|params\.|vars\[)"),
        Severity.MEDIUM,
    ),
]


class GoRulesRule(Rule):
    id = "go_rules"
    name = "Go Risky Patterns"
    description = "Detects Go-specific risky patterns: TLS bypass, shell injection, SQL via Sprintf"

    def is_applicable(self, path: Path) -> bool:
        # Scoped to Go source files; matches the per-file filter in scan (#193).
        return path.suffix.lower() == ".go"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files
        seen: set[tuple[str, str]] = set()

        for path in files_to_check:
            if path.suffix.lower() != ".go":
                continue

            rel = self._rel(context, path)
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith("//") and not any(
                    p[0] == "GO-AUTH-BYPASS" for p in _GO_PATTERNS if p[2].search(stripped)
                ):
                    continue

                for finding_id, label, pattern, severity in _GO_PATTERNS:
                    key = (rel, finding_id)
                    if key in seen:
                        continue
                    if pattern.search(line):
                        seen.add(key)
                        findings.append(
                            Finding(
                                id=finding_id,
                                rule=self.id,
                                title=f"Go: {label}",
                                description=(
                                    f"`{rel}` line {lineno}: {label}. "
                                    "Review this change for security implications."
                                ),
                                severity=severity,
                                path=rel,
                                line=lineno,
                                evidence=stripped[:120],
                                recommendation=(
                                    "Review this pattern carefully. Ensure it is intentional "
                                    "and follows your security conventions."
                                ),
                                tags=["go", finding_id.lower()],
                                confidence=Confidence.MEDIUM,
                            )
                        )

        return findings


register_rule(
    RuleMetadata(
        rule_id="go_rules",
        title="Go Risky Patterns",
        description=(
            "Detects Go-specific security risks including TLS bypass, "
            "shell injection, CORS wildcards, SQL via Sprintf, hardcoded tokens, "
            "auth bypass comments, and unsafe file deletion."
        ),
        finding_ids=[
            "GO-INSECURE-TLS",
            "GO-EXEC-SHELL",
            "GO-CORS-WILDCARD",
            "GO-SQL-SPRINTF",
            "GO-HARDCODED-TOKEN",
            "GO-AUTH-BYPASS",
            "GO-UNSAFE-DELETE",
        ],
        default_severity="high",
        confidence="medium",
        tags=["security", "go"],
        applies_to=["*.go"],
        remediations={
            "GO-INSECURE-TLS": (
                "Remove `InsecureSkipVerify: true` from the `tls.Config`. "
                "Use the system CA bundle, or pin a known root via "
                "`x509.CertPool`."
            ),
            "GO-EXEC-SHELL": (
                "Use `exec.Command(name, args...)` with arguments as separate "
                "strings. Avoid `sh -c` and never interpolate user input "
                "into the command string."
            ),
            "GO-CORS-WILDCARD": (
                "Set `Access-Control-Allow-Origin` to an explicit allow-list, "
                "not `*`. Wildcard + credentials is a known account-takeover "
                "vector."
            ),
            "GO-SQL-SPRINTF": (
                "Replace `fmt.Sprintf` SQL with `db.QueryContext`/"
                "`db.ExecContext` and `?` placeholders so the driver handles "
                "escaping."
            ),
            "GO-HARDCODED-TOKEN": (
                "Move the token to an environment variable or secret manager. "
                "Rotate it immediately and audit any downstream system that "
                "may have logged the value."
            ),
            "GO-AUTH-BYPASS": (
                "Re-enable the authentication middleware/check. If a public "
                "route is intentional, mark it on the route itself rather "
                "than removing global guards."
            ),
            "GO-UNSAFE-DELETE": (
                "Guard `os.RemoveAll`/`os.Remove` with explicit path "
                "validation. Confirm the path stays within an expected root "
                "before deleting."
            ),
        },
    )
)
