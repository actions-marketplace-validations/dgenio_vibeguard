"""Tests for Go risky pattern rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.go_rules import GoRulesRule


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


class TestGoRulesRule:
    rule = GoRulesRule()

    def test_insecure_tls_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"main.go": "TLSClientConfig: &tls.Config{InsecureSkipVerify: true}"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "GO-INSECURE-TLS" for f in findings)

    def test_exec_shell_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"main.go": 'cmd := exec.Command("sh", "-c", userInput)'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "GO-EXEC-SHELL" for f in findings)

    def test_cors_wildcard_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"server.go": 'AllowOrigins: []string{"*"}'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "GO-CORS-WILDCARD" for f in findings)

    def test_sql_sprintf_detected(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path, {"db.go": 'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)'}
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "GO-SQL-SPRINTF" for f in findings)

    def test_hardcoded_token_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"config.go": 'apikey := "ABCDEFGHIJKLMNOP1234"'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "GO-HARDCODED-TOKEN" for f in findings)

    def test_auth_bypass_comment_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"auth.go": "// TODO: fix auth check later"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "GO-AUTH-BYPASS" for f in findings)

    def test_unsafe_delete_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"handler.go": 'os.RemoveAll(req.FormValue("path"))'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "GO-UNSAFE-DELETE" for f in findings)

    def test_non_go_file_skipped(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"main.py": "InsecureSkipVerify: true"})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_safe_go_file_no_findings(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path, {"main.go": 'package main\n\nfunc main() {\n\tfmt.Println("hello")\n}'}
        )
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_severity_is_correct(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"main.go": "TLSClientConfig: &tls.Config{InsecureSkipVerify: true}"})
        findings = self.rule.scan(ctx)
        tls_finding = [f for f in findings if f.id == "GO-INSECURE-TLS"]
        assert tls_finding[0].severity == Severity.HIGH
