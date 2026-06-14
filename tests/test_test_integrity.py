"""Tests for the test_integrity rule (#203)."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.test_integrity import TestIntegrityRule


def _ctx(
    tmp_path: Path,
    files: dict[str, str] | None = None,
    *,
    diff_only: bool | None = None,
    diff_text: str = "",
) -> ScanContext:
    files = files or {}
    paths = []
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        paths.append(p)
    # A diff_text only ever exists in a real diff scan, so default diff_only to
    # match — keeping these test contexts consistent with the live scanner.
    if diff_only is None:
        diff_only = bool(diff_text)
    return ScanContext(
        root=tmp_path,
        config=VibeGuardConfig(),
        files=paths,
        changed_files=paths if diff_only else [],
        diff_only=diff_only,
        diff_text=diff_text,
    )


class TestSkipMarkers:
    rule = TestIntegrityRule()

    def test_pytest_skip_flagged(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(tmp_path, {"tests/test_a.py": "@pytest.mark.skip\ndef test_x():\n    pass\n"})
        )
        assert [f.id for f in findings] == ["TEST-SKIP-ADDED"]
        assert findings[0].line == 1

    def test_unittest_skip_flagged(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(tmp_path, {"tests/test_a.py": "@unittest.skip('wip')\ndef test_x():\n    pass\n"})
        )
        assert [f.id for f in findings] == ["TEST-SKIP-ADDED"]

    def test_jest_skip_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.test.js": "it.skip('x', () => {})\n"}))
        assert [f.id for f in findings] == ["TEST-SKIP-ADDED"]

    def test_xit_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.spec.ts": "xit('x', () => {})\n"}))
        assert [f.id for f in findings] == ["TEST-SKIP-ADDED"]

    def test_only_flagged_as_distinct_id(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"a.spec.js": "describe.only('x', () => {})\n"}))
        assert [f.id for f in findings] == ["TEST-ONLY-ADDED"]

    def test_skipif_is_low_severity(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(
                tmp_path,
                {
                    "tests/test_a.py": "@pytest.mark.skipif(sys.platform == 'win32')\ndef test_x():\n    pass\n"
                },
            )
        )
        assert [f.id for f in findings] == ["TEST-SKIP-ADDED"]
        assert findings[0].severity == Severity.LOW

    def test_skip_is_medium_in_diff_mode(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(tmp_path, {"tests/test_a.py": "@pytest.mark.skip\n"}, diff_only=True)
        )
        assert findings[0].severity == Severity.MEDIUM

    def test_skip_is_low_in_full_scan(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"tests/test_a.py": "@pytest.mark.skip\n"}))
        assert findings[0].severity == Severity.LOW

    def test_non_test_file_not_scanned(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"src/app.py": "@pytest.mark.skip\n"}))
        assert findings == []

    def test_commented_skip_not_flagged(self, tmp_path: Path):
        findings = self.rule.scan(_ctx(tmp_path, {"tests/test_a.py": "# @pytest.mark.skip\n"}))
        assert findings == []

    def test_clean_test_file_quiet(self, tmp_path: Path):
        findings = self.rule.scan(
            _ctx(tmp_path, {"tests/test_a.py": "def test_x():\n    assert add(1, 2) == 3\n"})
        )
        assert findings == []


class TestDeletedTests:
    rule = TestIntegrityRule()

    def test_deleted_test_file(self, tmp_path: Path):
        diff = (
            "diff --git a/tests/test_old.py b/tests/test_old.py\n"
            "deleted file mode 100644\n"
            "--- a/tests/test_old.py\n"
            "+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n"
            "-def test_x():\n"
            "-    assert True\n"
        )
        findings = self.rule.scan(_ctx(tmp_path, diff_text=diff))
        assert [f.id for f in findings] == ["TEST-DELETED"]
        assert findings[0].path == "tests/test_old.py"
        assert findings[0].line is None

    def test_deleted_non_test_file_ignored(self, tmp_path: Path):
        diff = (
            "diff --git a/src/app.py b/src/app.py\n"
            "deleted file mode 100644\n"
            "--- a/src/app.py\n"
            "+++ /dev/null\n"
        )
        assert self.rule.scan(_ctx(tmp_path, diff_text=diff)) == []

    def test_removed_test_function_in_modified_file(self, tmp_path: Path):
        diff = (
            "diff --git a/tests/test_a.py b/tests/test_a.py\n"
            "--- a/tests/test_a.py\n"
            "+++ b/tests/test_a.py\n"
            "@@ -1,6 +1,2 @@\n"
            " def test_keep():\n"
            "     assert True\n"
            "-def test_dropped():\n"
            "-    assert risky()\n"
        )
        findings = self.rule.scan(_ctx(tmp_path, diff_text=diff))
        assert [f.id for f in findings] == ["TEST-DELETED"]

    def test_no_diff_text_means_no_deletion_findings(self, tmp_path: Path):
        # Full-scan mode (no diff text) never emits deletion/coverage findings.
        assert (
            self.rule.scan(_ctx(tmp_path, {"tests/test_a.py": "def test_x():\n    pass\n"})) == []
        )


class TestCoverageLowered:
    rule = TestIntegrityRule()

    def test_fail_under_lowered(self, tmp_path: Path):
        diff = (
            "diff --git a/pyproject.toml b/pyproject.toml\n"
            "--- a/pyproject.toml\n"
            "+++ b/pyproject.toml\n"
            "@@ -1,1 +1,1 @@\n"
            "-fail_under = 90\n"
            "+fail_under = 50\n"
        )
        findings = self.rule.scan(_ctx(tmp_path, diff_text=diff))
        assert [f.id for f in findings] == ["TEST-COVERAGE-LOWERED"]
        assert "90 -> 50" in findings[0].evidence

    def test_fail_under_raised_is_not_flagged(self, tmp_path: Path):
        diff = (
            "diff --git a/pyproject.toml b/pyproject.toml\n"
            "--- a/pyproject.toml\n"
            "+++ b/pyproject.toml\n"
            "-fail_under = 50\n"
            "+fail_under = 90\n"
        )
        assert self.rule.scan(_ctx(tmp_path, diff_text=diff)) == []

    def test_jest_coverage_threshold_lowered(self, tmp_path: Path):
        diff = (
            "diff --git a/package.json b/package.json\n"
            "--- a/package.json\n"
            "+++ b/package.json\n"
            '-      "branches": 80\n'
            '+      "branches": 40\n'
        )
        findings = self.rule.scan(_ctx(tmp_path, diff_text=diff))
        assert [f.id for f in findings] == ["TEST-COVERAGE-LOWERED"]

    def test_cov_fail_under_flag_lowered(self, tmp_path: Path):
        diff = (
            "diff --git a/Makefile b/Makefile\n"
            "--- a/Makefile\n"
            "+++ b/Makefile\n"
            "-\tpytest --cov-fail-under=85\n"
            "+\tpytest --cov-fail-under=20\n"
        )
        findings = self.rule.scan(_ctx(tmp_path, diff_text=diff))
        assert [f.id for f in findings] == ["TEST-COVERAGE-LOWERED"]
