"""Terraform and Kubernetes IaC checks."""

from __future__ import annotations

import re
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# ---------------------------------------------------------------------------
# Terraform patterns (*.tf files)
# ---------------------------------------------------------------------------
_TF_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    (
        "TF-IAM-WILDCARD",
        "IAM wildcard action",
        re.compile(r'actions\s*=\s*\[.*"\*"', re.MULTILINE),
        Severity.CRITICAL,
    ),
    (
        "TF-SG-OPEN",
        "Security group open to 0.0.0.0/0",
        re.compile(r'cidr_blocks\s*=\s*\[.*"0\.0\.0\.0/0"', re.MULTILINE),
        Severity.HIGH,
    ),
    (
        "TF-S3-PUBLIC",
        "S3 bucket with public ACL",
        re.compile(r'(?i)acl\s*=\s*"public-read(-write)?"'),
        Severity.HIGH,
    ),
    (
        "TF-UNENCRYPTED",
        "Resource without encryption",
        re.compile(r"(?i)encrypted\s*=\s*false"),
        Severity.MEDIUM,
    ),
    (
        "TF-NO-VERSION-PIN",
        "Module source without version pin",
        re.compile(r'source\s*=\s*".*github\.com(?!.*\?ref=)'),
        Severity.MEDIUM,
    ),
]

# ---------------------------------------------------------------------------
# Kubernetes patterns (YAML files with kind: + apiVersion:)
# ---------------------------------------------------------------------------
_K8S_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    (
        "K8S-PRIVILEGED",
        "Privileged container",
        re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
        Severity.CRITICAL,
    ),
    (
        "K8S-HOST-PATH",
        "hostPath volume mount",
        re.compile(r"hostPath\s*:", re.IGNORECASE),
        Severity.HIGH,
    ),
    (
        "K8S-NO-TLS",
        "Ingress without TLS",
        # Detects Ingress kind without tls: block
        re.compile(r"kind\s*:\s*Ingress", re.IGNORECASE),
        Severity.MEDIUM,
    ),
    (
        "K8S-ALLOW-ALL",
        "NetworkPolicy allows all traffic",
        re.compile(r"podSelector\s*:\s*\{\s*\}", re.IGNORECASE),
        Severity.MEDIUM,
    ),
    (
        "K8S-ROOT-CONTAINER",
        "Container running as root",
        re.compile(r"(?i)(runAsNonRoot\s*:\s*false|runAsUser\s*:\s*0)"),
        Severity.HIGH,
    ),
]


def _is_k8s_yaml(path: Path, content: str) -> bool:
    """Check if a YAML file looks like a Kubernetes manifest."""
    if path.suffix.lower() not in (".yaml", ".yml"):
        return False
    # Check first 500 chars for k8s markers
    header = content[:500]
    return "apiVersion:" in header and "kind:" in header


class IaCRule(Rule):
    id = "iac"
    name = "Infrastructure-as-Code Security"
    description = "Detects risky patterns in Terraform and Kubernetes manifests"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        for path in files_to_check:
            rel = self._rel(context, path)

            if path.suffix.lower() == ".tf":
                findings.extend(self._check_terraform(path, rel))
            elif path.suffix.lower() in (".yaml", ".yml"):
                findings.extend(self._check_k8s(path, rel))

        return findings

    def _check_terraform(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        for finding_id, label, pattern, severity in _TF_PATTERNS:
            match = pattern.search(content)
            if match:
                lineno = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[lineno - 1].strip()[:120] if lineno > 0 else ""
                findings.append(
                    Finding(
                        id=finding_id,
                        rule=self.id,
                        title=f"Terraform: {label}",
                        description=(
                            f"`{rel}` line {lineno}: {label}. "
                            "This may expose infrastructure to unauthorized access."
                        ),
                        severity=severity,
                        path=rel,
                        line=lineno,
                        evidence=line_text,
                        recommendation=_TF_RECOMMENDATIONS.get(finding_id, "Review carefully."),
                        tags=["iac", "terraform", finding_id.lower()],
                        confidence=Confidence.HIGH,
                    )
                )

        return findings

    def _check_k8s(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        if not _is_k8s_yaml(path, content):
            return findings

        for finding_id, label, pattern, severity in _K8S_PATTERNS:
            # Special case: K8S-NO-TLS checks for Ingress without tls: block per document
            if finding_id == "K8S-NO-TLS":
                # Split on YAML document separators for multi-doc files
                docs = re.split(r"^---\s*$", content, flags=re.MULTILINE)
                line_offset = 0
                for doc in docs:
                    if pattern.search(doc) and "tls:" not in doc:
                        lineno = line_offset + 1
                        for i, line in enumerate(doc.splitlines(), 1):
                            if re.search(r"kind\s*:\s*Ingress", line, re.IGNORECASE):
                                lineno = line_offset + i
                                break
                        findings.append(
                            Finding(
                                id=finding_id,
                                rule=self.id,
                                title=f"Kubernetes: {label}",
                                description=(
                                    f"`{rel}` line {lineno}: Ingress resource without TLS configured."
                                ),
                                severity=severity,
                                path=rel,
                                line=lineno,
                                evidence="kind: Ingress (no tls: block found)",
                                recommendation=_K8S_RECOMMENDATIONS.get(finding_id, "Review."),
                                tags=["iac", "kubernetes", finding_id.lower()],
                                confidence=Confidence.MEDIUM,
                            )
                        )
                    # Track line offset for multi-doc positioning
                    line_offset += doc.count("\n") + 1  # +1 for the --- separator line
                continue

            # Special case: K8S-ALLOW-ALL requires NetworkPolicy kind with no ingress/egress rules
            if finding_id == "K8S-ALLOW-ALL":
                docs = re.split(r"^---\s*$", content, flags=re.MULTILINE)
                line_offset = 0
                for doc in docs:
                    is_network_policy = re.search(
                        r"kind\s*:\s*NetworkPolicy", doc, re.IGNORECASE
                    )
                    has_empty_pod_selector = pattern.search(doc)
                    has_ingress_egress = re.search(
                        r"^\s*(ingress|egress)\s*:", doc, re.MULTILINE
                    )
                    if is_network_policy and has_empty_pod_selector and not has_ingress_egress:
                        lineno = line_offset + 1
                        for i, line in enumerate(doc.splitlines(), 1):
                            if pattern.search(line):
                                lineno = line_offset + i
                                break
                        findings.append(
                            Finding(
                                id=finding_id,
                                rule=self.id,
                                title=f"Kubernetes: {label}",
                                description=(
                                    f"`{rel}` line {lineno}: NetworkPolicy with empty "
                                    "podSelector and no ingress/egress rules allows all traffic."
                                ),
                                severity=severity,
                                path=rel,
                                line=lineno,
                                evidence="podSelector: {} (no ingress/egress rules)",
                                recommendation=_K8S_RECOMMENDATIONS.get(
                                    finding_id, "Review carefully."
                                ),
                                tags=["iac", "kubernetes", finding_id.lower()],
                                confidence=Confidence.HIGH,
                            )
                        )
                    line_offset += doc.count("\n") + 1
                continue

            match = pattern.search(content)
            if match:
                lineno = content[: match.start()].count("\n") + 1
                line_text = content.splitlines()[lineno - 1].strip()[:120] if lineno > 0 else ""
                findings.append(
                    Finding(
                        id=finding_id,
                        rule=self.id,
                        title=f"Kubernetes: {label}",
                        description=(
                            f"`{rel}` line {lineno}: {label}. "
                            "This may weaken pod isolation or expose sensitive data."
                        ),
                        severity=severity,
                        path=rel,
                        line=lineno,
                        evidence=line_text,
                        recommendation=_K8S_RECOMMENDATIONS.get(finding_id, "Review carefully."),
                        tags=["iac", "kubernetes", finding_id.lower()],
                        confidence=Confidence.HIGH,
                    )
                )

        return findings


_TF_RECOMMENDATIONS: dict[str, str] = {
    "TF-IAM-WILDCARD": (
        "Replace wildcard (*) actions with specific required permissions (least privilege)."
    ),
    "TF-SG-OPEN": ("Restrict CIDR blocks to known IP ranges. Avoid 0.0.0.0/0 for production."),
    "TF-S3-PUBLIC": ("Use private ACL and serve content through CloudFront or pre-signed URLs."),
    "TF-UNENCRYPTED": ("Enable encryption at rest. Use KMS keys for managed encryption."),
    "TF-NO-VERSION-PIN": (
        "Pin module source to a specific ref (commit SHA or tag), e.g. ?ref=v1.0.0."
    ),
}

_K8S_RECOMMENDATIONS: dict[str, str] = {
    "K8S-PRIVILEGED": ("Remove privileged: true. Use specific capabilities if needed."),
    "K8S-HOST-PATH": ("Avoid hostPath volumes. Use PersistentVolumeClaims or ConfigMaps instead."),
    "K8S-NO-TLS": ("Add a tls: section to the Ingress resource to enable HTTPS."),
    "K8S-ALLOW-ALL": (
        "Specify explicit ingress/egress rules. Empty podSelector with no rules allows all traffic."
    ),
    "K8S-ROOT-CONTAINER": ("Set runAsNonRoot: true and use a non-zero runAsUser."),
}


register_rule(
    RuleMetadata(
        rule_id="iac",
        title="Infrastructure-as-Code Security",
        description=(
            "Detects risky patterns in Terraform (IAM wildcards, open security groups, "
            "public S3) and Kubernetes (privileged containers, hostPath, root user)."
        ),
        finding_ids=[
            "TF-IAM-WILDCARD",
            "TF-SG-OPEN",
            "TF-S3-PUBLIC",
            "TF-UNENCRYPTED",
            "TF-NO-VERSION-PIN",
            "K8S-PRIVILEGED",
            "K8S-HOST-PATH",
            "K8S-NO-TLS",
            "K8S-ALLOW-ALL",
            "K8S-ROOT-CONTAINER",
        ],
        default_severity="high",
        confidence="high",
        tags=["security", "iac", "terraform", "kubernetes"],
        applies_to=["*.tf", "*.yaml", "*.yml"],
    )
)
