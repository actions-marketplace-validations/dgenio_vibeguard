"""Tests for secrets rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.secrets import SecretsRule


def _make_context(tmp_path: Path, files: dict[str, str]) -> ScanContext:
    """Create a ScanContext with given files."""
    for name, content in files.items():
        file_path = tmp_path / name
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)

    all_files = [tmp_path / name for name in files]
    cfg = VibeGuardConfig()
    return ScanContext(root=tmp_path, config=cfg, files=all_files)


class TestSecretsRule:
    rule = SecretsRule()

    def test_aws_access_key_detected(self, tmp_path: Path):
        ctx = _make_context(tmp_path, {"config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "SEC-AWSACCESSKEY" for f in findings)

    def test_github_token_detected(self, tmp_path: Path):
        ctx = _make_context(tmp_path, {"config.py": 'TOKEN = "ghp_' + "A" * 36 + '"'})
        findings = self.rule.scan(ctx)
        assert any("github" in f.id.lower() or "github" in " ".join(f.tags) for f in findings)

    def test_private_key_detected(self, tmp_path: Path):
        ctx = _make_context(
            tmp_path,
            {
                "private.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK\n-----END RSA PRIVATE KEY-----"
            },
        )
        findings = self.rule.scan(ctx)
        assert any("private" in f.title.lower() for f in findings)

    def test_database_url_detected(self, tmp_path: Path):
        ctx = _make_context(
            tmp_path,
            {"settings.py": 'DB_URL = "postgres://admin:supersecret123@db.example.com/prod"'},
        )
        findings = self.rule.scan(ctx)
        assert any("database" in f.title.lower() for f in findings)

    def test_hardcoded_password_detected(self, tmp_path: Path):
        ctx = _make_context(
            tmp_path,
            {"auth.py": 'password = "MyStrongP@ss1234"'},
        )
        findings = self.rule.scan(ctx)
        assert any("password" in f.title.lower() for f in findings)

    def test_env_file_detected(self, tmp_path: Path):
        env_path = tmp_path / ".env"
        env_path.write_text("SECRET_KEY=abc123\nDB_PASS=hunter2\n")
        cfg = VibeGuardConfig()
        ctx = ScanContext(root=tmp_path, config=cfg, files=[env_path])
        findings = self.rule.scan(ctx)
        assert any(f.id == "SEC-ENV" for f in findings)

    def test_placeholder_not_flagged(self, tmp_path: Path):
        ctx = _make_context(
            tmp_path,
            {"config.py": 'API_KEY = "your_api_key_here"'},
        )
        findings = self.rule.scan(ctx)
        # Should not flag clear placeholders
        assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)

    def test_benign_string_not_flagged(self, tmp_path: Path):
        ctx = _make_context(
            tmp_path,
            {"main.py": "def hello():\n    return 'hello world'\n"},
        )
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_openai_key_detected(self, tmp_path: Path):
        ctx = _make_context(
            tmp_path,
            {"openai_client.py": 'api_key = "sk-' + "A" * 48 + '"'},
        )
        findings = self.rule.scan(ctx)
        assert any("openai" in f.id.lower() or "openai" in f.title.lower() for f in findings)

    def test_evidence_is_redacted(self, tmp_path: Path):
        ctx = _make_context(tmp_path, {"config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'})
        findings = self.rule.scan(ctx)
        for f in findings:
            if f.evidence:
                # Full key should not appear in evidence
                assert "AKIAIOSFODNN7EXAMPLE" not in f.evidence

    def test_binary_files_skipped(self, tmp_path: Path):
        # PNG file with "secret" bytes — should be skipped
        png = tmp_path / "image.png"
        png.write_bytes(b"\x89PNG\r\nAKIAIOSFODNN7EXAMPLE")
        cfg = VibeGuardConfig()
        ctx = ScanContext(root=tmp_path, config=cfg, files=[png])
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_diff_only_mode(self, tmp_path: Path):
        """In diff mode, only changed_files are checked."""
        all_files = {
            "safe.py": "x = 1",
            "secret.py": 'token = "ghp_' + "B" * 36 + '"',
        }
        for name, content in all_files.items():
            (tmp_path / name).write_text(content)

        cfg = VibeGuardConfig()
        # Only safe.py in changed_files
        ctx = ScanContext(
            root=tmp_path,
            config=cfg,
            files=[tmp_path / n for n in all_files],
            changed_files=[tmp_path / "safe.py"],
            diff_only=True,
        )
        findings = self.rule.scan(ctx)
        assert len(findings) == 0
