"""Dockerfile and GitHub Actions workflow checks."""

from __future__ import annotations

import re
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# ---------------------------------------------------------------------------
# Dockerfile patterns
# ---------------------------------------------------------------------------
_DOCKER_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    (
        "DOCKER-PRIVILEGED",
        "Privileged container",
        re.compile(r"--privileged"),
        Severity.CRITICAL,
    ),
    (
        "DOCKER-LATEST-TAG",
        "Using :latest tag",
        re.compile(r"^FROM\s+\S+:latest", re.IGNORECASE | re.MULTILINE),
        Severity.MEDIUM,
    ),
    (
        "DOCKER-CURL-BASH",
        "Curl-pipe-bash pattern",
        re.compile(r"(?i)(curl|wget)\s+[^\|]+\|\s*(ba)?sh"),
        Severity.HIGH,
    ),
    (
        "DOCKER-BROAD-CHMOD",
        "Overly permissive chmod 777",
        re.compile(r"chmod\s+(-R\s+)?777"),
        Severity.HIGH,
    ),
    (
        "DOCKER-SECRET-ENV",
        "Secret in ENV instruction",
        re.compile(r"(?i)^ENV\s+(PASSWORD|SECRET|TOKEN|API_KEY)\s*=", re.MULTILINE),
        Severity.HIGH,
    ),
    (
        "DOCKER-ADD-URL",
        "ADD with remote URL",
        re.compile(r"^ADD\s+https?://", re.IGNORECASE | re.MULTILINE),
        Severity.MEDIUM,
    ),
]

# ---------------------------------------------------------------------------
# GitHub Actions patterns
# ---------------------------------------------------------------------------
_GHA_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    (
        "GHA-PULL-REQUEST-TARGET",
        "pull_request_target trigger",
        re.compile(r"on:\s*pull_request_target|pull_request_target:", re.MULTILINE),
        Severity.HIGH,
    ),
    (
        "GHA-BROAD-PERMISSIONS",
        "Overly broad workflow permissions",
        re.compile(r"(?i)permissions\s*:\s*(write-all|\*)"),
        Severity.HIGH,
    ),
    (
        "GHA-SECRET-ECHO",
        "Secret leaked via echo",
        re.compile(r"echo\s+.*\$\{\{\s*secrets\."),
        Severity.CRITICAL,
    ),
    (
        "GHA-DISABLE-CHECK",
        "continue-on-error on potentially security-related step",
        re.compile(r"continue-on-error\s*:\s*true"),
        Severity.MEDIUM,
    ),
    (
        "GHA-UNVERSIONED-ACTION",
        "Action without version pin",
        re.compile(r"uses\s*:\s*[\w\-]+/[\w\-]+\s*$", re.MULTILINE),
        Severity.MEDIUM,
    ),
]


def _is_dockerfile(path: Path) -> bool:
    """Check if a path is a Dockerfile."""
    name = path.name.lower()
    return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")


def _is_gha_workflow(path: Path) -> bool:
    """Check if a path is a GitHub Actions workflow file."""
    parts = path.parts
    # Look for .github/workflows/*.yml pattern
    for i, part in enumerate(parts):
        if part == ".github" and i + 1 < len(parts) and parts[i + 1] == "workflows":
            return path.suffix.lower() in (".yml", ".yaml")
    return False


class CiDockerRule(Rule):
    id = "ci_docker"
    name = "Docker/CI Security"
    description = "Detects risky Dockerfile and GitHub Actions workflow patterns"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        for path in files_to_check:
            rel = self._rel(context, path)

            if _is_dockerfile(path):
                findings.extend(self._check_dockerfile(path, rel))
            elif _is_gha_workflow(path):
                findings.extend(self._check_gha(path, rel))

        return findings

    def _check_dockerfile(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        for finding_id, label, pattern, severity in _DOCKER_PATTERNS:
            match = pattern.search(content)
            if match:
                # Find line number
                lineno = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[lineno - 1].strip()[:120] if lineno > 0 else ""
                findings.append(
                    Finding(
                        id=finding_id,
                        rule=self.id,
                        title=f"Dockerfile: {label}",
                        description=(
                            f"`{rel}` line {lineno}: {label} detected in Dockerfile. "
                            "This may introduce security or reliability risks."
                        ),
                        severity=severity,
                        path=rel,
                        line=lineno,
                        evidence=line_text,
                        recommendation=_DOCKER_RECOMMENDATIONS.get(finding_id, "Review carefully."),
                        tags=["docker", finding_id.lower()],
                        confidence=Confidence.HIGH,
                    )
                )

        return findings

    def _check_gha(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        lines = content.splitlines()

        for finding_id, label, pattern, severity in _GHA_PATTERNS:
            # GHA-DISABLE-CHECK: only flag continue-on-error near security-related steps
            if finding_id == "GHA-DISABLE-CHECK":
                _SECURITY_KEYWORDS = re.compile(
                    r"(?i)(audit|scan|lint|bandit|trivy|snyk|codeql|security|sast|"
                    r"dast|vulnerability|semgrep|gitleaks|checkov|tfsec)"
                )
                for i, line in enumerate(lines):
                    if pattern.search(line):
                        # Check surrounding 5 lines for security context
                        context_start = max(0, i - 5)
                        context_end = min(len(lines), i + 6)
                        context_block = "\n".join(lines[context_start:context_end])
                        if _SECURITY_KEYWORDS.search(context_block):
                            lineno = i + 1
                            line_text = line.strip()[:120]
                            findings.append(
                                Finding(
                                    id=finding_id,
                                    rule=self.id,
                                    title=f"GitHub Actions: {label}",
                                    description=(
                                        f"`{rel}` line {lineno}: {label} in workflow file. "
                                        "This may suppress security check failures."
                                    ),
                                    severity=severity,
                                    path=rel,
                                    line=lineno,
                                    evidence=line_text,
                                    recommendation=_GHA_RECOMMENDATIONS.get(
                                        finding_id, "Review carefully."
                                    ),
                                    tags=["github-actions", finding_id.lower()],
                                    confidence=Confidence.HIGH,
                                )
                            )
                continue

            match = pattern.search(content)
            if match:
                lineno = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[lineno - 1].strip()[:120] if lineno > 0 else ""
                findings.append(
                    Finding(
                        id=finding_id,
                        rule=self.id,
                        title=f"GitHub Actions: {label}",
                        description=(
                            f"`{rel}` line {lineno}: {label} in workflow file. "
                            "This may expose secrets or allow unauthorized actions."
                        ),
                        severity=severity,
                        path=rel,
                        line=lineno,
                        evidence=line_text,
                        recommendation=_GHA_RECOMMENDATIONS.get(finding_id, "Review carefully."),
                        tags=["github-actions", finding_id.lower()],
                        confidence=Confidence.HIGH,
                    )
                )

        return findings


_DOCKER_RECOMMENDATIONS: dict[str, str] = {
    "DOCKER-PRIVILEGED": (
        "Remove --privileged flag. Use specific capabilities (--cap-add) instead."
    ),
    "DOCKER-LATEST-TAG": ("Pin to a specific image version/digest for reproducible builds."),
    "DOCKER-CURL-BASH": ("Download the script first, verify its checksum, then execute it."),
    "DOCKER-BROAD-CHMOD": (
        "Use more restrictive permissions. chmod 777 grants full access to all users."
    ),
    "DOCKER-SECRET-ENV": (
        "Use build secrets (--mount=type=secret) or runtime secrets instead of ENV."
    ),
    "DOCKER-ADD-URL": (
        "Use COPY with a prior RUN curl/wget step for better caching and verification."
    ),
}

_GHA_RECOMMENDATIONS: dict[str, str] = {
    "GHA-PULL-REQUEST-TARGET": (
        "pull_request_target runs with write access to the base repo. "
        "Ensure you never checkout or run untrusted PR code in this context."
    ),
    "GHA-BROAD-PERMISSIONS": (
        "Use least-privilege permissions. Specify only the permissions the workflow needs."
    ),
    "GHA-SECRET-ECHO": (
        "Never echo secrets in workflow logs. Use masking or write to a file instead."
    ),
    "GHA-DISABLE-CHECK": (
        "Avoid continue-on-error on security-sensitive steps. "
        "Failures in these steps may indicate a real problem."
    ),
    "GHA-UNVERSIONED-ACTION": (
        "Pin actions to a specific version (commit SHA preferred, tag acceptable). "
        "Unpinned actions can be modified by the action author."
    ),
}


register_rule(
    RuleMetadata(
        rule_id="ci_docker",
        title="Docker/CI Security",
        description=(
            "Detects risky patterns in Dockerfiles and GitHub Actions workflows: "
            "privileged containers, secret leaks, unversioned actions, curl-pipe-bash."
        ),
        finding_ids=[
            "DOCKER-PRIVILEGED",
            "DOCKER-LATEST-TAG",
            "DOCKER-CURL-BASH",
            "DOCKER-BROAD-CHMOD",
            "DOCKER-SECRET-ENV",
            "DOCKER-ADD-URL",
            "GHA-PULL-REQUEST-TARGET",
            "GHA-BROAD-PERMISSIONS",
            "GHA-SECRET-ECHO",
            "GHA-DISABLE-CHECK",
            "GHA-UNVERSIONED-ACTION",
        ],
        default_severity="high",
        confidence="high",
        tags=["security", "docker", "ci", "github-actions"],
        applies_to=["Dockerfile", "Dockerfile.*", "*.dockerfile", ".github/workflows/*.yml"],
    )
)
