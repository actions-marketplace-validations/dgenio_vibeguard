"""Risky diff / code pattern rule."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules._util import is_comment_line, is_test_file
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# (id_suffix, label, pattern, extensions_hint)
_RISKY_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # Auth / permissions
    (
        "auth-bypass",
        "Authentication bypass",
        re.compile(
            r"(?i)(skip_auth|bypass_auth|no[_\-]?auth|disable[_\-]?auth|isAuthenticated\s*=\s*true|authenticated\s*=\s*True)"
        ),
    ),
    (
        "authz-check",
        "Authorization / permission change",
        re.compile(
            r"(?i)(hasPermission|checkPermission|isAuthorized|can\(|allow\(|deny\(|require[_\-]?role|admin\s*=\s*[Tt]rue)"
        ),
    ),
    (
        "crypto-usage",
        "Cryptographic operation",
        re.compile(
            r"(?i)(AES|RSA|SHA[0-9]+|MD5|HMAC|encrypt|decrypt|cipher|hashlib\.|bcrypt|argon2|pbkdf2|scrypt)"
        ),
    ),
    ("eval-exec", "eval() or exec() usage", re.compile(r"\beval\s*\(|\bexec\s*\(")),
    (
        "subprocess-shell",
        "Subprocess / shell execution",
        re.compile(
            r"(?i)(subprocess\.|os\.system|os\.popen|shell\s*=\s*True|Runtime\.exec|ProcessBuilder|child_process|spawn\(|execSync|spawnSync)"
        ),
    ),
    (
        "file-delete",
        "File deletion",
        re.compile(
            r"(?i)(os\.remove|os\.unlink|shutil\.rmtree|fs\.unlink|fs\.rmdir|rimraf|rm\s+-rf)"
        ),
    ),
    (
        "network-call",
        "Outbound network call",
        re.compile(
            r"(?i)(requests\.(get|post|put|delete|patch)|fetch\(|axios\.|http\.request|urllib\.request|curl\b|wget\b)"
        ),
    ),
    (
        "db-write",
        "Database write operation",
        re.compile(
            r"(?i)(\.execute\s*\(|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|\.save\(\)|\.commit\(|\.bulk_create\(|\.update\()"
        ),
    ),
    (
        "payment-logic",
        "Payment or billing logic",
        re.compile(
            r"(?i)(stripe|paypal|braintree|charge\(|payment|billing|invoice|refund|webhook.*payment)"
        ),
    ),
    (
        "env-access",
        "Environment variable access",
        re.compile(r"(?i)(os\.environ|process\.env|getenv\(|dotenv)"),
    ),
    (
        "cors-config",
        "CORS configuration",
        re.compile(
            r"(?i)(cors\(|allow_origins|Access-Control-Allow-Origin|allowedOrigins|origins\s*=\s*[\[\(]\s*[\"\']\*)"
        ),
    ),
    (
        "deserialization",
        "Unsafe deserialization",
        re.compile(
            r"(?i)(pickle\.loads|pickle\.load|yaml\.load\s*\([^,)]+\)|marshal\.loads|jsonpickle\.decode|unserialize\()"
        ),
    ),
    (
        "jwt-handling",
        "JWT handling",
        re.compile(
            r"(?i)(jwt\.decode|verify\s*=\s*False|algorithms\s*=\s*\[\"none\"\]|jwt\.sign|jsonwebtoken)"
        ),
    ),
    (
        "trust-certs",
        "Certificate validation disabled",
        re.compile(
            r"(?i)(verify\s*=\s*False|ssl_verify\s*=\s*False|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER)"
        ),
    ),
    (
        "perm-change",
        "File/system permission change",
        re.compile(r"(?i)(os\.chmod|chmod\s+777|chmod\s+a\+[rwx]|setuid|setgid)"),
    ),
]

# Framework debug artifacts left enabled (#206). Kept separate from the generic
# risk patterns above because they carry their own finding IDs and a
# settings-file severity boost. Patterns are anchored to literal assignment
# forms so env-driven config (``DEBUG = os.environ.get(...)``) does not match.
_DEBUG_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "RISK-DEBUGMODE",
        "Debug mode enabled",
        re.compile(
            r"(?i)(?:^|[^.\w])DEBUG\s*=\s*True\b"  # Django/Flask DEBUG = True
            r"|app\.run\([^)]*\bdebug\s*=\s*True"  # Flask app.run(debug=True)
            r"|\.debug\s*=\s*True\b"  # app.debug = True
            r"|FLASK_DEBUG\s*=\s*1\b"
        ),
    ),
    (
        "RISK-ALLOWEDHOSTSWILDCARD",
        "Wildcard ALLOWED_HOSTS",
        re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]"),
    ),
]

# Filename stems / directory names where a debug artifact is
# production-affecting rather than incidental (#206 severity boost).
_SETTINGS_FILE_PATTERNS = ("settings", "config", "conf")

# File extensions where risky patterns are meaningful
_CODE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".rs",
    ".swift",
    ".kt",
    ".scala",
    ".sh",
    ".bash",
    ".ps1",
}

# Skip files that are very commonly benign matches
_SKIP_FILENAMES = {"package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock"}


def _is_settings_file(path: Path) -> bool:
    """Return True for framework settings/config files (#206 severity boost).

    A debug artifact in ``settings.py``/``config.py`` or under a ``config/``
    directory is production-affecting; the same pattern in an arbitrary script
    is incidental. Both the filename stem and any directory component are
    matched against :data:`_SETTINGS_FILE_PATTERNS`.
    """
    if path.name.lower().startswith(_SETTINGS_FILE_PATTERNS):
        return True
    return bool({p.lower() for p in path.parts} & set(_SETTINGS_FILE_PATTERNS))


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
            is_test = is_test_file(path)
            is_settings = _is_settings_file(path)

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                # Skip comment lines (shared heuristic — #178).
                stripped = line.strip()
                if is_comment_line(stripped):
                    continue

                # Debug artifacts (#206): own finding IDs, settings-file boost.
                for fid, label, pattern in _DEBUG_PATTERNS:
                    key = (rel, fid)
                    if key in seen:
                        continue
                    if pattern.search(line):
                        seen.add(key)
                        if is_test:
                            sev = Severity.LOW
                        elif is_settings:
                            sev = Severity.HIGH
                        else:
                            sev = Severity.MEDIUM
                        findings.append(
                            Finding(
                                id=fid,
                                rule=self.id,
                                title=f"Debug artifact left enabled: {label}",
                                description=(
                                    f"`{rel}` line {lineno} enables a framework debug "
                                    f"artifact ({label}). Debug mode in production "
                                    "exposes stack traces, interactive debuggers, and "
                                    "secrets — confirm this is not shipped."
                                ),
                                severity=sev,
                                path=rel,
                                line=lineno,
                                evidence=stripped[:120],
                                recommendation=(
                                    "Drive debug flags from an environment variable "
                                    "defaulting to off, and ensure production config "
                                    "disables them."
                                ),
                                tags=["risky-diff", "debug-artifact", fid.lower()],
                                confidence=Confidence.MEDIUM,
                            )
                        )

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

        # Diff scope checks (only in diff mode)
        findings.extend(self._check_diff_scope(context))

        return findings

    def _check_diff_scope(self, context: ScanContext) -> list[Finding]:
        """Check diff-level breadth, size, and risk-file signals."""
        findings: list[Finding] = []
        if not context.diff_only or not context.changed_files:
            return findings

        changed_paths = [self._rel(context, p) for p in context.changed_files]
        config = context.config.risky_patterns

        # DIFF-SIZE: too many files changed
        max_files = getattr(config, "diff_size_threshold", 30)
        if len(changed_paths) > max_files:
            findings.append(
                Finding(
                    id="DIFF-SIZE",
                    rule=self.id,
                    title="Large diff: many files changed",
                    description=(
                        f"This diff touches {len(changed_paths)} files "
                        f"(threshold: {max_files}). Large diffs warrant extra review."
                    ),
                    severity=Severity.LOW,
                    path=".",
                    recommendation=("Consider splitting this change into smaller, reviewable PRs."),
                    tags=["diff-scope", "size"],
                    confidence=Confidence.HIGH,
                )
            )

        # DIFF-BREADTH: too many top-level directories
        max_dirs = getattr(config, "diff_breadth_threshold", 5)
        top_dirs = set()
        for p in changed_paths:
            parts = Path(p).parts
            if len(parts) > 1:
                top_dirs.add(parts[0])
        if len(top_dirs) > max_dirs:
            findings.append(
                Finding(
                    id="DIFF-BREADTH",
                    rule=self.id,
                    title="Wide diff: many directories touched",
                    description=(
                        f"This diff spans {len(top_dirs)} top-level directories "
                        f"(threshold: {max_dirs}): {', '.join(sorted(top_dirs)[:8])}. "
                        "Broad diffs may indicate unfocused changes."
                    ),
                    severity=Severity.MEDIUM,
                    path=".",
                    recommendation=(
                        "Verify all changes are related. Consider splitting unrelated changes."
                    ),
                    tags=["diff-scope", "breadth"],
                    confidence=Confidence.HIGH,
                )
            )

        # DIFF-RISK-FILES: high-risk file types in diff
        risk_patterns = [
            "**/auth*",
            "**/middleware*",
            "**/*secret*",
            "**/crypto*",
            "**/iam*",
            "**/Dockerfile",
            "**/*.tf",
            "**/.github/workflows/*.yml",
        ]
        risk_files = []
        for p in changed_paths:
            posix_p = p.replace("\\", "/")
            for rp in risk_patterns:
                if fnmatch.fnmatch(posix_p, rp) or fnmatch.fnmatch(posix_p, rp.removeprefix("**/")):
                    risk_files.append(p)
                    break
        if risk_files:
            findings.append(
                Finding(
                    id="DIFF-RISK-FILES",
                    rule=self.id,
                    title="High-risk files modified in diff",
                    description=(
                        f"This diff includes {len(risk_files)} high-risk file(s): "
                        f"{', '.join(risk_files[:5])}. These files require careful review."
                    ),
                    severity=Severity.MEDIUM,
                    path=risk_files[0],
                    recommendation=(
                        "Give extra attention to changes in auth, crypto, CI, and IaC files."
                    ),
                    tags=["diff-scope", "risk-files"],
                    confidence=Confidence.HIGH,
                )
            )

        return findings


register_rule(
    RuleMetadata(
        rule_id="risky_diff",
        title="Risky Code Pattern",
        description=(
            "Flags changes to risk-sensitive areas (auth, crypto, shell, network, etc.) "
            "and diff-scope signals (breadth, size, risk files) for human review."
        ),
        finding_ids=[
            "RISK-AUTHBYPASS",
            "RISK-AUTHZCHECK",
            "RISK-CRYPTOUSAGE",
            "RISK-EVALEXEC",
            "RISK-SUBPROCESSSHELL",
            "RISK-FILEDELETE",
            "RISK-NETWORKCALL",
            "RISK-DBWRITE",
            "RISK-PAYMENTLOGIC",
            "RISK-ENVACCESS",
            "RISK-CORSCONFIG",
            "RISK-DESERIALIZATION",
            "RISK-JWTHANDLING",
            "RISK-TRUSTCERTS",
            "RISK-PERMCHANGE",
            "RISK-DEBUGMODE",
            "RISK-ALLOWEDHOSTSWILDCARD",
            "DIFF-BREADTH",
            "DIFF-SIZE",
            "DIFF-RISK-FILES",
        ],
        default_severity="medium",
        confidence="medium",
        tags=["security", "risky-diff"],
        applies_to=["*.py", "*.js", "*.ts", "*.go", "*.java", "*.rb"],
        config_key="risky_patterns",
        remediations={
            "RISK-AUTHBYPASS": (
                "Verify the auth check is intentional and tested. Audit every "
                "code path that bypasses authentication before merging."
            ),
            "RISK-AUTHZCHECK": (
                "Confirm the authorization check still enforces the expected "
                "policy. Add a test that asserts a non-permitted role is denied."
            ),
            "RISK-CRYPTOUSAGE": (
                "Use vetted primitives from the standard library (e.g. "
                "`hashlib`, `secrets`, `cryptography`). Avoid rolling your own "
                "crypto and review changes with a security-aware reviewer."
            ),
            "RISK-EVALEXEC": (
                "Eliminate `eval`/`exec` if possible. If unavoidable, "
                "validate and whitelist inputs strictly before execution and "
                "document why the dynamic execution is required."
            ),
            "RISK-SUBPROCESSSHELL": (
                "Pass arguments as a list, never as a single shell string. "
                "Avoid `shell=True`. Validate any user input before it reaches "
                "the subprocess."
            ),
            "RISK-FILEDELETE": (
                "Confirm the deletion path is intentional and scoped to "
                "expected directories. Add a dry-run option or guardrails to "
                "prevent accidental data loss."
            ),
            "RISK-NETWORKCALL": (
                "Ensure the network call respects timeouts, TLS verification, "
                "and retry policies. Document any new outbound destinations."
            ),
            "RISK-DBWRITE": (
                "Add tests for the new database write. Confirm transactional "
                "boundaries, error handling, and rollback semantics are correct."
            ),
            "RISK-PAYMENTLOGIC": (
                "Payment logic changes need a dedicated review with the "
                "finance/billing owner. Add tests that cover currency rounding, "
                "refund paths, and idempotency keys."
            ),
            "RISK-ENVACCESS": (
                "Confirm the environment variable is documented in deployment "
                "configs and has a safe default. Avoid reading secrets directly "
                "from `os.environ` in request paths."
            ),
            "RISK-CORSCONFIG": (
                "Avoid wildcard origins (`*`) in CORS configuration. Allow "
                "only the specific origins your frontend needs and reject the "
                "rest."
            ),
            "RISK-DESERIALIZATION": (
                "Replace `pickle`/`yaml.load`/`marshal` with a safe serialiser "
                "(JSON, `yaml.safe_load`, msgpack). Untrusted deserialisation "
                "is a common RCE vector."
            ),
            "RISK-JWTHANDLING": (
                "Validate `alg`, `iss`, `aud`, and `exp` claims. Never accept "
                "the `none` algorithm. Pin the verification key to a known set "
                "of issuers."
            ),
            "RISK-TRUSTCERTS": (
                "Re-enable TLS certificate verification. Use a proper CA "
                "bundle (e.g. `certifi`) or pin the specific CA your "
                "environment trusts."
            ),
            "RISK-PERMCHANGE": (
                "File-permission changes should be narrow and explicit. Avoid "
                "world-writable bits (`0o777`) and document any setuid usage."
            ),
            "RISK-DEBUGMODE": (
                "Never ship debug mode to production. Drive the flag from an "
                "environment variable that defaults to off (e.g. "
                '`DEBUG = os.environ.get("DEBUG") == "1"`) and confirm the '
                "production configuration disables it."
            ),
            "RISK-ALLOWEDHOSTSWILDCARD": (
                "Replace the wildcard `ALLOWED_HOSTS = ['*']` with the explicit "
                "list of hostnames your app serves. A wildcard disables Django's "
                "Host-header validation."
            ),
            "DIFF-BREADTH": (
                "Split the change into smaller, reviewable PRs. Wide-breadth "
                "diffs hide regressions and slow down review."
            ),
            "DIFF-SIZE": (
                "Large diffs are hard to review carefully. Break the change "
                "into incremental PRs each with their own tests."
            ),
            "DIFF-RISK-FILES": (
                "This diff touches security-sensitive files. Request a "
                "security-aware reviewer and add tests covering the changed "
                "code paths."
            ),
        },
    )
)
