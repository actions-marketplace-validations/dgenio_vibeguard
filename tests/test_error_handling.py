"""Tests for the error_handling rule (#205)."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.error_handling import ErrorHandlingRule


def _ctx(tmp_path: Path, files: dict[str, str], *, diff_only: bool = False) -> ScanContext:
    paths = []
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        paths.append(p)
    return ScanContext(
        root=tmp_path,
        config=VibeGuardConfig(),
        files=paths,
        changed_files=paths if diff_only else [],
        diff_only=diff_only,
    )


class TestPython:
    rule = ErrorHandlingRule()

    def test_bare_except_pass_flagged(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(tmp_path, {"a.py": "try:\n    risky()\nexcept:\n    pass\n"})
        )
        assert [f.id for f in findings] == ["ERR-BARE-EXCEPT-PASS"]
        assert findings[0].line == 3

    def test_except_exception_pass_flagged(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(tmp_path, {"a.py": "try:\n    risky()\nexcept Exception:\n    pass\n"})
        )
        assert [f.id for f in findings] == ["ERR-BARE-EXCEPT-PASS"]

    def test_except_exception_ellipsis_flagged(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(tmp_path, {"a.py": "try:\n    risky()\nexcept Exception:\n    ...\n"})
        )
        assert [f.id for f in findings] == ["ERR-BARE-EXCEPT-PASS"]

    def test_inline_except_pass_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.py": "try:\n    risky()\nexcept: pass\n"}))
        assert [f.id for f in findings] == ["ERR-BARE-EXCEPT-PASS"]

    def test_specific_except_pass_not_flagged(self, tmp_path: Path):
        # Narrowing the catch is the recommended fix, not a finding.
        assert (
            self.rule.scan(
                _ctx(tmp_path, {"a.py": "try:\n    risky()\nexcept ValueError:\n    pass\n"})
            )
            == []
        )

    def test_except_with_handling_not_flagged(self, tmp_path: Path):
        assert (
            self.rule.scan(
                _ctx(
                    tmp_path,
                    {"a.py": "try:\n    risky()\nexcept Exception as e:\n    logger.error(e)\n"},
                )
            )
            == []
        )

    def test_contextlib_suppress_not_flagged(self, tmp_path: Path):
        assert (
            self.rule.scan(
                _ctx(tmp_path, {"a.py": "with contextlib.suppress(KeyError):\n    d['x']\n"})
            )
            == []
        )

    def test_comment_then_pass_not_misread(self, tmp_path: Path):
        # The body line is a comment within lookahead, then real handling follows.
        assert (
            self.rule.scan(
                _ctx(
                    tmp_path,
                    {"a.py": "try:\n    risky()\nexcept Exception:\n    # explain\n    handle()\n"},
                )
            )
            == []
        )


class TestJavaScript:
    rule = ErrorHandlingRule()

    def test_inline_empty_catch_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.js": "try { risky() } catch (e) {}\n"}))
        assert [f.id for f in findings] == ["ERR-EMPTY-CATCH"]

    def test_multiline_empty_catch_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.ts": "try {\n  risky()\n} catch (e) {\n}\n"}))
        assert [f.id for f in findings] == ["ERR-EMPTY-CATCH"]

    def test_log_only_catch_flagged(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(tmp_path, {"a.js": "try {\n  risky()\n} catch (e) {\n  console.log(e)\n}\n"})
        )
        assert [f.id for f in findings] == ["ERR-EMPTY-CATCH"]

    def test_handled_catch_not_flagged(self, tmp_path: Path):
        assert (
            self.rule.scan(
                _ctx(tmp_path, {"a.js": "try {\n  risky()\n} catch (e) {\n  reportError(e)\n}\n"})
            )
            == []
        )


class TestGo:
    rule = ErrorHandlingRule()

    def test_empty_err_check_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.go": "if err != nil {\n}\n"}))
        assert [f.id for f in findings] == ["ERR-DISCARDED-GO"]

    def test_discarded_err_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.go": "_ = err\n"}))
        assert [f.id for f in findings] == ["ERR-DISCARDED-GO"]

    def test_handled_err_not_flagged(self, tmp_path: Path):
        assert (
            self.rule.scan(_ctx(tmp_path, {"a.go": "if err != nil {\n    return err\n}\n"})) == []
        )


class TestSeverity:
    rule = ErrorHandlingRule()

    def test_medium_in_diff_mode(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(tmp_path, {"a.py": "try:\n    x()\nexcept:\n    pass\n"}, diff_only=True)
        )
        assert findings[0].severity == Severity.MEDIUM

    def test_low_in_full_scan(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.py": "try:\n    x()\nexcept:\n    pass\n"}))
        assert findings[0].severity == Severity.LOW

    def test_test_file_downgraded_in_diff(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(
                tmp_path, {"tests/test_a.py": "try:\n    x()\nexcept:\n    pass\n"}, diff_only=True
            )
        )
        assert findings[0].severity == Severity.LOW
