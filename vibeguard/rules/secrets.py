"""Secrets detection rule."""

from __future__ import annotations

import math
import re

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule

# ---------------------------------------------------------------------------
# Patterns: (id_suffix, label, regex, severity)
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    (
        "aws-access-key",
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        Severity.CRITICAL,
    ),
    (
        "aws-secret-key",
        "AWS Secret Access Key",
        re.compile(
            r'(?i)aws[_\-\s]*(secret|secret_access_key)[_\-\s]*[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?'
        ),
        Severity.CRITICAL,
    ),
    (
        "github-token",
        "GitHub Token",
        re.compile(r"(ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})"),
        Severity.CRITICAL,
    ),
    (
        "openai-key",
        "OpenAI API Key",
        re.compile(r"sk-[A-Za-z0-9]{32,64}"),
        Severity.CRITICAL,
    ),
    (
        "private-key",
        "Private Key Material",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    (
        "bearer-token",
        "Bearer Token in code",
        re.compile(r'(?i)bearer\s+["\']?([A-Za-z0-9\-_.~+/]{20,})["\']?'),
        Severity.HIGH,
    ),
    (
        "hardcoded-password",
        "Hardcoded Password",
        re.compile(
            r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\'\s]{8,})["\']'
        ),
        Severity.HIGH,
    ),
    (
        "database-url",
        "Database URL with credentials",
        re.compile(
            r'(?i)(?:postgres|mysql|mongodb|redis|amqp)://[^:]+:([^@\s"\']{6,})@[^\s"\'<>]+'
        ),
        Severity.HIGH,
    ),
    (
        "slack-token",
        "Slack Token",
        re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        Severity.HIGH,
    ),
    (
        "stripe-key",
        "Stripe Secret Key",
        re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
        Severity.CRITICAL,
    ),
    (
        "generic-api-key",
        "Generic API Key assignment",
        re.compile(
            r'(?i)(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']'
        ),
        Severity.HIGH,
    ),
]

# Files that should never be committed (outside of examples)
_SENSITIVE_FILENAMES = {".env", ".env.local", ".env.production", ".env.staging"}

# Extensions to skip (binary, images, etc.)
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".wav", ".zip", ".tar",
    ".gz", ".tgz", ".bz2", ".lock", ".pdf",
}


def _shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_likely_placeholder(value: str) -> bool:
    """Return True if the value looks like a placeholder rather than a real secret."""
    lower = value.lower()
    placeholders = {
        "your_api_key_here", "changeme", "secret", "password", "example",
        "placeholder", "xxx", "todo", "test", "fake", "dummy", "replace_me",
        "xxxxxxxx", "insert_key_here", "your-token-here", "your-secret-here",
    }
    if lower in placeholders:
        return True
    if re.match(r"^[x*]{6,}$", lower):
        return True
    return bool(re.match(r"^[a-z]{1,3}[_\-][a-z]{1,3}[_\-][a-z]{1,3}$", lower))


class SecretsRule(Rule):
    id = "secrets"
    name = "Secrets Detection"
    description = "Detects likely committed secrets using regex patterns and entropy heuristics"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        for path in files_to_check:
            if path.suffix.lower() in _SKIP_EXTENSIONS:
                continue
            rel = self._rel(context, path)
            # Skip test fixtures and examples unless they look dangerous
            is_example = "example" in rel.lower() or "fixture" in rel.lower()

            # Check sensitive filenames
            if path.name in _SENSITIVE_FILENAMES:
                if not is_example:
                    findings.append(
                        Finding(
                            id="SEC-ENV",
                            rule=self.id,
                            title=f"Sensitive file committed: {path.name}",
                            description=(
                                f"The file `{rel}` is a secrets/environment file and should "
                                "not be committed to version control."
                            ),
                            severity=Severity.HIGH,
                            path=rel,
                            recommendation=(
                                f"Add `{path.name}` to .gitignore and rotate any secrets it contains."
                            ),
                            tags=["secrets", "env"],
                            confidence=Confidence.HIGH,
                        )
                    )
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for idx, line in enumerate(content.splitlines(), start=1):
                findings.extend(
                    self._check_line(line, idx, rel, is_example, context)
                )

        return findings

    def _check_line(
        self,
        line: str,
        lineno: int,
        rel: str,
        is_example: bool,
        context: ScanContext,
    ) -> list[Finding]:
        results: list[Finding] = []
        min_entropy: float = context.config.secrets.min_entropy

        for pat_id, label, pattern, severity in _SECRET_PATTERNS:
            for match in pattern.finditer(line):
                # Get the most interesting group (the value itself)
                value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)

                if _is_likely_placeholder(value):
                    continue

                entropy = _shannon_entropy(value)
                if entropy < min_entropy and severity not in (Severity.CRITICAL, Severity.HIGH):
                    continue

                # Downgrade severity in example/fixture files
                effective_severity = severity
                if is_example and severity == Severity.CRITICAL:
                    effective_severity = Severity.HIGH

                # Redact most of the matched value for display
                if len(value) > 8:
                    display = value[:4] + "****" + (value[-2:] if len(value) > 6 else "")
                else:
                    display = "****"
                evidence = line.replace(value, display).strip()[:150]

                results.append(
                    Finding(
                        id=f"SEC-{pat_id.upper().replace('-', '')}",
                        rule="secrets",
                        title=f"{label} detected",
                        description=(
                            f"A likely {label} was found in `{rel}` at line {lineno}. "
                            "Committed secrets can be exploited by anyone with repo access."
                        ),
                        severity=effective_severity,
                        path=rel,
                        line=lineno,
                        evidence=evidence,
                        recommendation=(
                            "Remove the secret from source code. Rotate it immediately. "
                            "Use environment variables or a secrets manager instead."
                        ),
                        tags=["secrets", pat_id],
                        confidence=Confidence.HIGH if entropy > 4.0 else Confidence.MEDIUM,
                    )
                )

        return results


# ---------------------------------------------------------------------------
# Finding explanations (used by `vibeguard explain`)
# ---------------------------------------------------------------------------
EXPLANATIONS: dict[str, str] = {
    "SEC-AWSACCESSKEY": """\
AWS Access Key IDs (starting with AKIA) are credentials for AWS services.
Committing them exposes your AWS account to unauthorized access, data theft,
and unexpected charges. Rotate the key immediately via the AWS IAM console
and enable AWS CloudTrail to audit any unauthorized usage.
""",
    "SEC-ENV": """\
.env files commonly contain database passwords, API keys, and other credentials.
They should never be committed. Add them to .gitignore and use a secrets manager
or CI environment variables instead.
""",
}
