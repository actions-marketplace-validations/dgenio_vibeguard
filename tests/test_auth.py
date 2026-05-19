"""Tests for auth/authz bypass detection rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.auth import AuthRule


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


class TestAuthRule:
    rule = AuthRule()

    def test_bypass_comment_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"auth.py": "# TODO: fix auth check"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AUTH-BYPASS-COMMENT" for f in findings)

    def test_disabled_middleware_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.js": "// app.use(authenticate)"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AUTH-DISABLED-MIDDLEWARE" for f in findings)

    def test_verify_false_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"client.py": "resp = requests.get(url, verify=False)"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AUTH-VERIFY-FALSE" for f in findings)

    def test_allow_all_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"config.js": 'role = "admin"'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AUTH-ALLOW-ALL" for f in findings)

    def test_jwt_none_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"auth.py": 'algorithm = "none"'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AUTH-JWT-NONE" for f in findings)
        jwt_finding = [f for f in findings if f.id == "AUTH-JWT-NONE"]
        assert jwt_finding[0].severity == Severity.CRITICAL

    def test_hardcoded_admin_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"config.py": 'password = "admin"'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AUTH-HARDCODED-ADMIN" for f in findings)

    def test_commented_auth_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"middleware.ts": "// authenticate(req, res, next)"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AUTH-COMMENTED-AUTH" for f in findings)

    def test_non_code_file_skipped(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"readme.md": "# TODO: fix auth check"})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_safe_code_no_findings(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"main.py": "def greet():\n    return 'hello'\n"})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_go_file_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"auth.go": "// HACK: bypass auth for testing"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AUTH-BYPASS-COMMENT" for f in findings)
