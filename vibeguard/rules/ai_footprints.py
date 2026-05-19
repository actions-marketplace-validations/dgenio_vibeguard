"""AI footprint detection rule."""

from __future__ import annotations

import re

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# (id_suffix, label, pattern, severity)
_AI_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    # AI generation markers
    (
        "ai-generated",
        "AI-generated code comment",
        re.compile(
            r"(?i)(generated\s+by\s+(chatgpt|gpt|claude|copilot|cursor|codeium)|"
            r"auto[\-_]?generated\s+by\s+(ai|llm)|"
            r"this\s+code\s+was\s+(written|generated)\s+by\s+(ai|chatgpt|an?\s+ai))"
        ),
        Severity.INFO,
    ),
    # Placeholder credentials
    (
        "placeholder-cred",
        "Placeholder credential",
        re.compile(
            r'(?i)(password\s*=\s*["\']?(admin|password|123456|test|demo|default|changeme|pass)["\']?|'
            r'secret\s*=\s*["\']?(secret|mysecret|topsecret|supersecret)["\']?|'
            r'token\s*=\s*["\']?(token|mytoken|test_token|fake_token)["\']?)'
        ),
        Severity.HIGH,
    ),
    # Security bypass comments
    (
        "disable-security",
        "Security disabled in code",
        re.compile(
            r"(?i)(disable\s+(security|auth|authentication|authorization|validation|csrf)|"
            r"security\s*=\s*[Ff]alse|auth\s+disabled|skip\s+(auth|security|validation))"
        ),
        Severity.HIGH,
    ),
    # Trust-all certificates
    (
        "trust-all-certs",
        "Trust-all certificates",
        re.compile(
            r"(?i)(trust\s+all\s+(certs?|certificates?)|"
            r"verify\s*=\s*False|"
            r"ssl_verify\s*=\s*False|"
            r"InsecureRequestWarning|"
            r"urllib3.*disable_warnings)"
        ),
        Severity.HIGH,
    ),
    # Allow all CORS origins
    (
        "cors-wildcard",
        "Wildcard CORS origin",
        re.compile(
            r'(?i)(allow[_\-]?origins?\s*[=:]\s*[\[\(]?\s*["\']?\*["\']?|'
            r'Access-Control-Allow-Origin["\']?\s*:\s*["\']?\*)'
        ),
        Severity.HIGH,
    ),
    # Temporary bypass / mock
    (
        "temp-bypass",
        "Temporary security bypass or mock",
        re.compile(
            r"(?i)(temporary\s+bypass|mock\s+for\s+now|"
            r"TODO[\s:]+remove\s+(this|auth|security|check)|"
            r"FIXME[\s:]+security|"
            r"HACK[\s:]+.{0,30}(auth|security|bypass)|"
            r"# noqa.*security)"
        ),
        Severity.MEDIUM,
    ),
    # Skip validation
    (
        "skip-validation",
        "Validation skipped",
        re.compile(
            r"(?i)(skip[_\-]?validation|bypass[_\-]?validation|"
            r"no[_\-]?validate|validate\s*=\s*[Ff]alse|"
            r"unsafe\s+.*\s*(load|parse|exec))"
        ),
        Severity.MEDIUM,
    ),
    # Hallucinated-looking TODOs
    (
        "hallucinated-todo",
        "TODO that looks auto-generated",
        re.compile(
            r"(?i)(# TODO[\s:]+implement\s+(this|the|a)\s+(function|method|logic|code)|"
            r"# TODO[\s:]+add\s+(error\s+handling|validation|authentication|tests?)\s+here|"
            r"# TODO[\s:]+replace\s+with\s+(actual|real|proper)\s+(implementation|logic))"
        ),
        Severity.LOW,
    ),
]

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
    ".sh",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
}


class AIFootprintsRule(Rule):
    id = "ai_footprints"
    name = "AI Footprint Detection"
    description = "Detects AI-generated artifacts, placeholders, and security bypasses"

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
                for pat_id, label, pattern, severity in _AI_PATTERNS:
                    key = (rel, pat_id)
                    if key in seen:
                        continue

                    if pattern.search(line):
                        seen.add(key)
                        stripped = line.strip()[:120]
                        findings.append(
                            Finding(
                                id=f"AI-{pat_id.upper().replace('-', '')}",
                                rule=self.id,
                                title=f"AI footprint: {label}",
                                description=(
                                    f"`{rel}` line {lineno}: {label} detected. "
                                    "This is a common artifact of AI-generated code and may "
                                    "indicate incomplete, insecure, or placeholder logic."
                                ),
                                severity=severity,
                                path=rel,
                                line=lineno,
                                evidence=stripped,
                                recommendation=self._recommendation(pat_id),
                                tags=["ai-footprint", pat_id],
                                confidence=Confidence.MEDIUM,
                            )
                        )

        return findings

    def _recommendation(self, pat_id: str) -> str:
        recs = {
            "ai-generated": (
                "Review AI-generated code carefully before merging. "
                "Remove generation comments if the code has been reviewed and approved."
            ),
            "placeholder-cred": (
                "Replace placeholder credentials with real secrets stored in a secrets manager "
                "or environment variables. Never commit real credentials."
            ),
            "disable-security": (
                "Re-enable the security control. If this is intentional, document why "
                "and get a security review."
            ),
            "trust-all-certs": (
                "Enable certificate verification. Use a proper CA bundle or add the specific "
                "certificate you trust."
            ),
            "cors-wildcard": (
                "Restrict CORS origins to the specific domains that need access. "
                "Wildcard CORS disables same-origin protection."
            ),
            "temp-bypass": (
                "Remove the temporary bypass before merging. If it cannot be removed, "
                "track it as a security debt issue."
            ),
            "skip-validation": (
                "Enable input validation. Skipping validation is a common source of "
                "injection vulnerabilities."
            ),
            "hallucinated-todo": (
                "Replace the placeholder TODO with real implementation. "
                "AI-generated TODO stubs often indicate incomplete logic."
            ),
        }
        return recs.get(pat_id, "Review and address this finding before merging.")


register_rule(
    RuleMetadata(
        rule_id="ai_footprints",
        title="AI Footprint Detection",
        description=(
            "Detects AI-generated artifacts, placeholders, security bypasses, "
            "trust-all certificates, CORS wildcards, and hallucinated TODOs."
        ),
        finding_ids=[
            "AI-AIGENERATED",
            "AI-PLACEHOLDERCRED",
            "AI-DISABLESECURITY",
            "AI-TRUSTALLCERTS",
            "AI-CORSWILDCARD",
            "AI-TEMPBYPASS",
            "AI-SKIPVALIDATION",
            "AI-HALLUCINATEDTODO",
        ],
        default_severity="medium",
        confidence="medium",
        tags=["ai-footprint", "security"],
        applies_to=["*.py", "*.js", "*.ts", "*.go", "*.yaml"],
    )
)
