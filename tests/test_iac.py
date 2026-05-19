"""Tests for IaC rule (Terraform + Kubernetes)."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.iac import IaCRule


def _ctx(tmp_path: Path, files: dict[str, str]) -> ScanContext:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    all_files = [tmp_path / n for n in files]
    return ScanContext(
        root=tmp_path,
        config=VibeGuardConfig(),
        files=all_files,
    )


class TestIaCRule:
    rule = IaCRule()

    # Terraform checks
    def test_iam_wildcard_detected(self, tmp_path: Path):
        content = 'resource "aws_iam_policy" "test" {\n  actions = ["*"]\n}'
        ctx = _ctx(tmp_path, {"main.tf": content})
        findings = self.rule.scan(ctx)
        assert any(f.id == "TF-IAM-WILDCARD" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_sg_open_detected(self, tmp_path: Path):
        content = 'resource "aws_security_group" "web" {\n  cidr_blocks = ["0.0.0.0/0"]\n}'
        ctx = _ctx(tmp_path, {"network.tf": content})
        findings = self.rule.scan(ctx)
        assert any(f.id == "TF-SG-OPEN" for f in findings)

    def test_s3_public_detected(self, tmp_path: Path):
        content = 'resource "aws_s3_bucket" "data" {\n  acl = "public-read"\n}'
        ctx = _ctx(tmp_path, {"storage.tf": content})
        findings = self.rule.scan(ctx)
        assert any(f.id == "TF-S3-PUBLIC" for f in findings)

    def test_unencrypted_detected(self, tmp_path: Path):
        content = 'resource "aws_ebs_volume" "data" {\n  encrypted = false\n}'
        ctx = _ctx(tmp_path, {"storage.tf": content})
        findings = self.rule.scan(ctx)
        assert any(f.id == "TF-UNENCRYPTED" for f in findings)

    def test_no_version_pin_detected(self, tmp_path: Path):
        content = 'module "vpc" {\n  source = "github.com/org/terraform-module"\n}'
        ctx = _ctx(tmp_path, {"modules.tf": content})
        findings = self.rule.scan(ctx)
        assert any(f.id == "TF-NO-VERSION-PIN" for f in findings)

    def test_pinned_module_not_flagged(self, tmp_path: Path):
        content = 'module "vpc" {\n  source = "github.com/org/module?ref=v1.0.0"\n}'
        ctx = _ctx(tmp_path, {"modules.tf": content})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "TF-NO-VERSION-PIN" for f in findings)

    # Kubernetes checks
    def test_k8s_privileged_detected(self, tmp_path: Path):
        content = "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        privileged: true"
        ctx = _ctx(tmp_path, {"pod.yaml": content})
        findings = self.rule.scan(ctx)
        assert any(f.id == "K8S-PRIVILEGED" for f in findings)

    def test_k8s_host_path_detected(self, tmp_path: Path):
        content = "apiVersion: v1\nkind: Pod\nspec:\n  volumes:\n    - hostPath:\n        path: /var/run/docker.sock"
        ctx = _ctx(tmp_path, {"pod.yaml": content})
        findings = self.rule.scan(ctx)
        assert any(f.id == "K8S-HOST-PATH" for f in findings)

    def test_k8s_no_tls_detected(self, tmp_path: Path):
        content = "apiVersion: networking.k8s.io/v1\nkind: Ingress\nspec:\n  rules:\n    - host: example.com"
        ctx = _ctx(tmp_path, {"ingress.yaml": content})
        findings = self.rule.scan(ctx)
        assert any(f.id == "K8S-NO-TLS" for f in findings)

    def test_k8s_root_container_detected(self, tmp_path: Path):
        content = "apiVersion: v1\nkind: Pod\nspec:\n  securityContext:\n    runAsUser: 0"
        ctx = _ctx(tmp_path, {"pod.yaml": content})
        findings = self.rule.scan(ctx)
        assert any(f.id == "K8S-ROOT-CONTAINER" for f in findings)

    # Negative tests
    def test_non_k8s_yaml_not_flagged(self, tmp_path: Path):
        content = "policy: balanced\nfail_on: high\n"
        ctx = _ctx(tmp_path, {"vibeguard.yaml": content})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_non_tf_file_not_flagged(self, tmp_path: Path):
        content = 'actions = ["*"]'
        ctx = _ctx(tmp_path, {"main.py": content})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_k8s_with_tls_not_flagged(self, tmp_path: Path):
        content = "apiVersion: networking.k8s.io/v1\nkind: Ingress\nspec:\n  tls:\n    - hosts: [example.com]\n  rules:\n    - host: example.com"
        ctx = _ctx(tmp_path, {"ingress.yaml": content})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "K8S-NO-TLS" for f in findings)
