"""Tests for the lint_suppressions rule (#204)."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.lint_suppressions import LintSuppressionsRule


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


class TestBareForms:
    rule = LintSuppressionsRule()

    def test_bare_noqa_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.py": "x = bad()  # noqa\n"}))
        assert [f.id for f in findings] == ["SUPPRESS-BARE-NOQA"]
        assert findings[0].line == 1

    def test_bare_type_ignore_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.py": "x = bad()  # type: ignore\n"}))
        assert [f.id for f in findings] == ["SUPPRESS-TYPE-IGNORE"]

    def test_bare_nosec_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.py": "os.system(cmd)  # nosec\n"}))
        assert [f.id for f in findings] == ["SUPPRESS-NOSEC-BARE"]

    def test_eslint_disable_file_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.js": "/* eslint-disable */\n"}))
        assert [f.id for f in findings] == ["SUPPRESS-ESLINT-FILE"]

    def test_ts_nocheck_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.ts": "// @ts-nocheck\n"}))
        assert [f.id for f in findings] == ["SUPPRESS-TS-NOCHECK"]

    def test_ts_ignore_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.ts": "// @ts-ignore\nconst x = y\n"}))
        assert [f.id for f in findings] == ["SUPPRESS-TS-NOCHECK"]

    def test_bare_nolint_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.go": "x := f()  //nolint\n"}))
        assert [f.id for f in findings] == ["SUPPRESS-NOLINT-BARE"]


class TestScopedFormsExempt:
    rule = LintSuppressionsRule()

    def test_scoped_noqa_not_flagged(self, tmp_path: Path):
        assert self.rule.scan(_ctx(tmp_path, {"a.py": "x = bad()  # noqa: E501\n"})) == []

    def test_scoped_type_ignore_not_flagged(self, tmp_path: Path):
        assert (
            self.rule.scan(_ctx(tmp_path, {"a.py": "x = bad()  # type: ignore[arg-type]\n"})) == []
        )

    def test_scoped_nosec_not_flagged(self, tmp_path: Path):
        assert self.rule.scan(_ctx(tmp_path, {"a.py": "os.system(cmd)  # nosec B605\n"})) == []

    def test_scoped_nolint_not_flagged(self, tmp_path: Path):
        assert self.rule.scan(_ctx(tmp_path, {"a.go": "x := f()  //nolint:errcheck\n"})) == []

    def test_scoped_eslint_disable_not_flagged(self, tmp_path: Path):
        # A rule-scoped disable carries the rule name, so the bare-form regex misses it.
        assert self.rule.scan(_ctx(tmp_path, {"a.js": "/* eslint-disable no-console */\n"})) == []

    def test_ts_expect_error_not_flagged(self, tmp_path: Path):
        assert self.rule.scan(_ctx(tmp_path, {"a.ts": "// @ts-expect-error narrow reason\n"})) == []


class TestScopingAndSeverity:
    rule = LintSuppressionsRule()

    def test_medium_in_diff_mode(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.py": "x = 1  # noqa\n"}, diff_only=True))
        assert findings[0].severity == Severity.MEDIUM

    def test_low_in_full_scan(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.py": "x = 1  # noqa\n"}))
        assert findings[0].severity == Severity.LOW

    def test_test_file_downgraded_to_low_in_diff(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(tmp_path, {"tests/test_a.py": "x = 1  # noqa\n"}, diff_only=True)
        )
        assert findings[0].severity == Severity.LOW

    def test_own_vibeguard_marker_exempt(self, tmp_path: Path):
        # VibeGuard's own inline suppression must not trip the rule.
        assert (
            self.rule.scan(_ctx(tmp_path, {"a.py": "x = 1  # vibeguard: ignore=SEC-ENV\n"})) == []
        )

    def test_non_code_file_skipped(self, tmp_path: Path):
        assert self.rule.scan(_ctx(tmp_path, {"notes.md": "# noqa everywhere\n"})) == []

    def test_per_line_findings_for_diff_scoping(self, tmp_path: Path):
        # One finding per matching line so the scanner's changed-line filter can
        # keep the right one in diff mode.
        findings = self.rule.scan(_ctx(tmp_path, {"a.py": "a = 1  # noqa\nb = 2  # noqa\n"}))
        assert [f.line for f in findings] == [1, 2]
