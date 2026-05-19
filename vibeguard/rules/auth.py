"""Auth/authz bypass detection rule."""

from __future__ import annotations

import re

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

_CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".go",
    ".rb",
    ".java",
    ".cs",
}

_AUTH_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity, Confidence]] = [
    (
        "AUTH-BYPASS-COMMENT",
        "Auth bypass TODO/FIXME/HACK comment",
        re.compile(r"(?i)(//|#)\s*(TODO|FIXME|HACK).*auth"),
        Severity.HIGH,
        Confidence.MEDIUM,
    ),
    (
        "AUTH-DISABLED-MIDDLEWARE",
        "Commented-out auth middleware",
        re.compile(
            r"(?i)(//|#)\s*.*(authenticate\(|authorize\(|requireAuth\(|isAuthenticated\(|"
            r"checkPermission\(|middleware\.use\(.*auth|app\.use\(.*auth|"
            r"import\s+.*(?:authenticate|authorize|requireAuth))"
        ),
        Severity.HIGH,
        Confidence.MEDIUM,
    ),
    (
        "AUTH-VERIFY-FALSE",
        "Verification disabled",
        re.compile(
            r"(?i)(verify\s*=\s*False|verify_ssl\s*=\s*False|"
            r"verifySSL\s*:\s*false|verify_token\s*=\s*[Ff]alse)"
        ),
        Severity.HIGH,
        Confidence.HIGH,
    ),
    (
        "AUTH-ALLOW-ALL",
        "Admin or auth allow-all pattern",
        re.compile(
            r'(?i)(role\s*=\s*["\']admin["\']|isAdmin\s*=\s*true|'
            r"if\s*\(\s*true\s*\).*auth)"
        ),
        Severity.MEDIUM,
        Confidence.MEDIUM,
    ),
    (
        "AUTH-JWT-NONE",
        "JWT algorithm set to none",
        re.compile(r'(?i)(algorithm|alg)\s*[=:]\s*["\']none["\']'),
        Severity.CRITICAL,
        Confidence.HIGH,
    ),
    (
        "AUTH-HARDCODED-ADMIN",
        "Hardcoded admin/default password",
        re.compile(
            r'(?i)password\s*[=:]\s*["\']'
            r"(admin|password|123456|12345678|qwerty|abc123|letmein)[\"']"
        ),
        Severity.HIGH,
        Confidence.HIGH,
    ),
    (
        "AUTH-RETURN-NIL-AUTH",
        "Auth function returns nil/True without logic",
        re.compile(
            r"(?i)(func\s+\w*[Aa]uth\w*\s*\([^)]*\)\s*\{?\s*\n?\s*return\s+nil|"
            r"def\s+\w*auth\w*\s*\([^)]*\)\s*:\s*\n?\s*return\s+True)"
        ),
        Severity.MEDIUM,
        Confidence.MEDIUM,
    ),
    (
        "AUTH-COMMENTED-AUTH",
        "Commented-out auth/authz block",
        re.compile(
            r"(?i)(//|#)\s*.*(authenticate\(|authorize\(|checkPermission\(|requireAuth\(|"
            r"ensureAuthenticated|verifyToken\()"
        ),
        Severity.HIGH,
        Confidence.MEDIUM,
    ),
]


class AuthRule(Rule):
    id = "auth"
    name = "Auth/Authz Bypass Detection"
    description = "Detects patterns indicating authentication or authorization bypasses"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files
        seen: set[tuple[str, str]] = set()

        for path in files_to_check:
            if path.suffix.lower() not in _CODE_EXTENSIONS:
                continue

            rel = self._rel(context, path)
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for finding_id, label, pattern, severity, confidence in _AUTH_PATTERNS:
                    key = (rel, finding_id)
                    if key in seen:
                        continue
                    if pattern.search(line):
                        seen.add(key)
                        findings.append(
                            Finding(
                                id=finding_id,
                                rule=self.id,
                                title=f"Auth: {label}",
                                description=(
                                    f"`{rel}` line {lineno}: {label} detected. "
                                    "This may indicate an authentication or authorization bypass."
                                ),
                                severity=severity,
                                path=rel,
                                line=lineno,
                                evidence=line.strip()[:120],
                                recommendation=(
                                    "Ensure authentication and authorization checks are active "
                                    "and properly configured. Remove commented-out auth code "
                                    "or document why it is disabled."
                                ),
                                tags=["auth", finding_id.lower()],
                                confidence=confidence,
                            )
                        )

        return findings


register_rule(
    RuleMetadata(
        rule_id="auth",
        title="Auth/Authz Bypass Detection",
        description=(
            "Detects patterns indicating authentication or authorization bypasses: "
            "commented-out auth, JWT none algorithm, hardcoded admin passwords, "
            "disabled verification, auth functions returning nil/True."
        ),
        finding_ids=[
            "AUTH-BYPASS-COMMENT",
            "AUTH-DISABLED-MIDDLEWARE",
            "AUTH-VERIFY-FALSE",
            "AUTH-ALLOW-ALL",
            "AUTH-JWT-NONE",
            "AUTH-HARDCODED-ADMIN",
            "AUTH-RETURN-NIL-AUTH",
            "AUTH-COMMENTED-AUTH",
        ],
        default_severity="high",
        confidence="medium",
        tags=["security", "auth"],
        applies_to=["*.py", "*.js", "*.ts", "*.go", "*.rb", "*.java", "*.cs"],
    )
)
