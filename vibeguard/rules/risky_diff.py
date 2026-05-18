"""Risky diff / code pattern rule."""

from __future__ import annotations

import re
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule

# (id_suffix, label, pattern, extensions_hint)
_RISKY_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # Auth / permissions
    ("auth-bypass", "Authentication bypass", re.compile(
        r"(?i)(skip_auth|bypass_auth|no[_\-]?auth|disable[_\-]?auth|isAuthenticated\s*=\s*true|authenticated\s*=\s*True)"
    )),
    ("authz-check", "Authorization / permission change", re.compile(
        r"(?i)(hasPermission|checkPermission|isAuthorized|can\(|allow\(|deny\(|require[_\-]?role|admin\s*=\s*[Tt]rue)"
    )),
    ("crypto-usage", "Cryptographic operation", re.compile(
        r"(?i)(AES|RSA|SHA[0-9]+|MD5|HMAC|encrypt|decrypt|cipher|hashlib\.|bcrypt|argon2|pbkdf2|scrypt)"
    )),
    ("eval-exec", "eval() or exec() usage", re.compile(
        r"\beval\s*\(|\bexec\s*\("
    )),
    ("subprocess-shell", "Subprocess / shell execution", re.compile(
        r"(?i)(subprocess\.|os\.system|os\.popen|shell\s*=\s*True|Runtime\.exec|ProcessBuilder|child_process|spawn\(|execSync|spawnSync)"
    )),
    ("file-delete", "File deletion", re.compile(
        r"(?i)(os\.remove|os\.unlink|shutil\.rmtree|fs\.unlink|fs\.rmdir|rimraf|rm\s+-rf)"
    )),
    ("network-call", "Outbound network call", re.compile(
        r"(?i)(requests\.(get|post|put|delete|patch)|fetch\(|axios\.|http\.request|urllib\.request|curl\b|wget\b)"
    )),
    ("db-write", "Database write operation", re.compile(
        r"(?i)(\.execute\s*\(|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|\.save\(\)|\.commit\(|\.bulk_create\(|\.update\()"
    )),
    ("payment-logic", "Payment or billing logic", re.compile(
        r"(?i)(stripe|paypal|braintree|charge\(|payment|billing|invoice|refund|webhook.*payment)"
    )),
    ("env-access", "Environment variable access", re.compile(
        r"(?i)(os\.environ|process\.env|getenv\(|dotenv)"
    )),
    ("cors-config", "CORS configuration", re.compile(
        r"(?i)(cors\(|allow_origins|Access-Control-Allow-Origin|allowedOrigins|origins\s*=\s*[\[\(]\s*[\"\']\*)"
    )),
    ("sql-construct", "SQL query construction", re.compile(
        r"(?i)(\"SELECT|\"INSERT|\"UPDATE|\"DELETE|f\".*SELECT|f\".*INSERT|\braw\(|\.raw_query|cursor\.execute)"
    )),
    ("deserialization", "Unsafe deserialization", re.compile(
        r"(?i)(pickle\.loads|pickle\.load|yaml\.load\s*\([^,)]+\)|marshal\.loads|jsonpickle\.decode|unserialize\()"
    )),
    ("jwt-handling", "JWT handling", re.compile(
        r"(?i)(jwt\.decode|verify\s*=\s*False|algorithms\s*=\s*\[\"none\"\]|jwt\.sign|jsonwebtoken)"
    )),
    ("trust-certs", "Certificate validation disabled", re.compile(
        r"(?i)(verify\s*=\s*False|ssl_verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER)"
    )),
    ("perm-change", "File/system permission change", re.compile(
        r"(?i)(os\.chmod|chmod\s+777|chmod\s+a\+[rwx]|setuid|setgid)"
    )),
]

# File extensions where risky patterns are meaningful
_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php",
    ".cs", ".cpp", ".c", ".h", ".rs", ".swift", ".kt", ".scala", ".sh",
    ".bash", ".ps1",
}

# Skip files that are very commonly benign matches
_SKIP_FILENAMES = {"package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock"}


class RiskyDiffRule(Rule):
    id = "risky_diff"
    name = "Risky Code Pattern"
    description = (
        "Flags changes to risk-sensitive areas (auth, crypto, shell, network, etc.) "
        "for human review. Does not claim a vulnerability."
    )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # This rule is most useful in diff mode; in full scan mode, limit to source files
        files_to_check = context.changed_files if context.diff_only else context.files

        # Track which (file, pattern) combos we've flagged to avoid duplicates
        seen: set[tuple[str, str]] = set()

        for path in files_to_check:
            if path.name in _SKIP_FILENAMES:
                continue
            if path.suffix.lower() not in _CODE_EXTENSIONS:
                continue

            rel = self._rel(context, path)
            is_test = _is_test_file(path)

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                # Skip comment lines (simple heuristic)
                stripped = line.strip()
                # "* " prefix is a block comment continuation (Javadoc, JSDoc, etc.)
                if stripped.startswith(("#", "//", "<!--")) or stripped.startswith("* ") or stripped == "*":
                    continue

                for pat_id, label, pattern in _RISKY_PATTERNS:
                    key = (rel, pat_id)
                    if key in seen:
                        continue

                    if pattern.search(line):
                        seen.add(key)
                        sev = Severity.LOW if is_test else Severity.MEDIUM
                        findings.append(
                            Finding(
                                id=f"RISK-{pat_id.upper().replace('-', '')}",
                                rule=self.id,
                                title=f"Risk-sensitive area changed: {label}",
                                description=(
                                    f"`{rel}` line {lineno} touches a risk-sensitive area "
                                    f"({label}). This is not a confirmed vulnerability — "
                                    "human review is recommended."
                                ),
                                severity=sev,
                                path=rel,
                                line=lineno,
                                evidence=stripped[:120],
                                recommendation=(
                                    "Review this change carefully. Ensure it is intentional, "
                                    "tested, and follows your security conventions."
                                ),
                                tags=["risky-diff", pat_id],
                                confidence=Confidence.MEDIUM,
                            )
                        )

        return findings


def _is_test_file(path: Path) -> bool:
    name = path.name.lower()
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith(".test.js")
        or name.endswith(".spec.ts")
        or "test" in path.parts
        or "tests" in path.parts
        or "spec" in path.parts
    )
