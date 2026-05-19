"""Tests for SQL construction heuristic rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.sql import SqlRule


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


class TestSqlRule:
    rule = SqlRule()

    # Python checks
    def test_py_fstring_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"db.py": 'query = f"SELECT * FROM users WHERE id = {user_id}"'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "SQL-PY-FSTRING" for f in findings)

    def test_py_concat_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"db.py": 'query = "SELECT * FROM users WHERE id = " + user_id'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "SQL-PY-CONCAT" for f in findings)

    def test_py_format_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"db.py": '"SELECT * FROM users WHERE id = {}".format(user_id)'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "SQL-PY-FORMAT" for f in findings)

    # JavaScript checks
    def test_js_template_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"db.js": "const q = `SELECT * FROM users WHERE id = ${userId}`"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "SQL-JS-TEMPLATE" for f in findings)

    def test_js_concat_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"db.ts": 'const q = "SELECT * FROM users WHERE id = " + userId'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "SQL-JS-CONCAT" for f in findings)

    # Go checks
    def test_go_sprintf_detected(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path, {"db.go": 'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)'}
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "SQL-GO-SPRINTF" for f in findings)

    # Negative tests - parameterized queries should NOT trigger
    def test_parameterized_py_not_flagged(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path, {"db.py": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'}
        )
        findings = self.rule.scan(ctx)
        # Should not flag parameterized queries
        assert not any(f.id == "SQL-PY-FSTRING" for f in findings)
        assert not any(f.id == "SQL-PY-FORMAT" for f in findings)

    def test_comment_not_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"db.py": '# query = f"SELECT * FROM users WHERE id = {user_id}"'})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_non_sql_file_not_checked(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"readme.md": 'query = f"SELECT * FROM users WHERE id = {user_id}"'})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_severity_is_high(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"db.py": 'query = f"SELECT * FROM users WHERE id = {user_id}"'})
        findings = self.rule.scan(ctx)
        sql_findings = [f for f in findings if f.id == "SQL-PY-FSTRING"]
        assert sql_findings[0].severity == Severity.HIGH
