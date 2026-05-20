"""Tests for diff-line filtering."""

from __future__ import annotations

from vibeguard.git import parse_changed_lines
from vibeguard.models import Confidence, Finding, Severity
from vibeguard.scanner import _filter_by_changed_lines


def _make_finding(path: str = "src/app.py", line: int | None = 10) -> Finding:
    return Finding(
        id="TEST-FINDING",
        rule="test",
        title="Test finding",
        description="A test finding.",
        severity=Severity.MEDIUM,
        path=path,
        line=line,
        recommendation="Fix it.",
        tags=["test"],
        confidence=Confidence.MEDIUM,
    )


class TestParseChangedLines:
    def test_single_hunk(self):
        diff = """\
diff --git a/src/app.py b/src/app.py
index abc..def 100644
--- a/src/app.py
+++ b/src/app.py
@@ -5,3 +5,4 @@ def main():
     x = 1
+    y = 2
     z = 3
"""
        result = parse_changed_lines(diff)
        assert "src/app.py" in result
        assert (5, 8) in result["src/app.py"]

    def test_multiple_hunks(self):
        diff = """\
diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,4 @@
+import os
 x = 1
 y = 2
@@ -10,3 +11,5 @@ def foo():
     a = 1
+    b = 2
+    c = 3
     d = 4
"""
        result = parse_changed_lines(diff)
        assert "src/app.py" in result
        ranges = result["src/app.py"]
        assert (1, 4) in ranges
        assert (11, 15) in ranges

    def test_multiple_files(self):
        diff = """\
diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1,2 +1,3 @@
+new line
 old line
diff --git a/b.py b/b.py
--- a/b.py
+++ b/b.py
@@ -5,2 +5,3 @@
 existing
+added
"""
        result = parse_changed_lines(diff)
        assert "a.py" in result
        assert "b.py" in result

    def test_empty_diff(self):
        result = parse_changed_lines("")
        assert result == {}


class TestFilterByChangedLines:
    def test_in_range_kept(self):
        findings = [_make_finding(line=5)]
        changed = {"src/app.py": [(1, 10)]}
        filtered = _filter_by_changed_lines(findings, changed)
        assert len(filtered) == 1

    def test_out_of_range_removed(self):
        findings = [_make_finding(line=50)]
        changed = {"src/app.py": [(1, 10)]}
        filtered = _filter_by_changed_lines(findings, changed)
        assert len(filtered) == 0

    def test_file_level_always_kept(self):
        """Findings with line=None are file-level and always kept."""
        findings = [_make_finding(line=None)]
        changed = {"src/app.py": [(1, 10)]}
        filtered = _filter_by_changed_lines(findings, changed)
        assert len(filtered) == 1

    def test_line_zero_always_kept(self):
        findings = [_make_finding(line=0)]
        changed = {"src/app.py": [(1, 10)]}
        filtered = _filter_by_changed_lines(findings, changed)
        assert len(filtered) == 1

    def test_file_not_in_changed_lines_kept(self):
        """If a file isn't in the changed_lines dict, its findings are kept."""
        findings = [_make_finding(path="other.py", line=5)]
        changed = {"src/app.py": [(1, 10)]}
        filtered = _filter_by_changed_lines(findings, changed)
        assert len(filtered) == 1

    def test_boundary_line_included(self):
        """Lines at exact boundary of range are included."""
        findings = [_make_finding(line=10)]
        changed = {"src/app.py": [(10, 10)]}
        filtered = _filter_by_changed_lines(findings, changed)
        assert len(filtered) == 1

    def test_multiple_ranges(self):
        findings = [_make_finding(line=15)]
        changed = {"src/app.py": [(1, 5), (14, 20)]}
        filtered = _filter_by_changed_lines(findings, changed)
        assert len(filtered) == 1
