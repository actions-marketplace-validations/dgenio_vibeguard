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
        # Only the single added line ("+    y = 2" at new-file line 6) — not
        # the surrounding context lines from the hunk range.
        assert result["src/app.py"] == [(6, 6)]

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
        # Hunk 1: "+import os" at new-file line 1.
        # Hunk 2: "+    b = 2" and "+    c = 3" at new-file lines 12-13
        # (context "a = 1" at 11, "d = 4" at 14).
        assert ranges == [(1, 1), (12, 13)]

    def test_context_only_lines_excluded(self):
        """A hunk with no '+' lines (pure deletions/context) produces no ranges."""
        diff = """\
diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,4 +1,3 @@
 x = 1
-y = 2
 z = 3
 w = 4
"""
        result = parse_changed_lines(diff)
        assert result == {"src/app.py": []}

    def test_adjacent_hunks_coalesce(self):
        """Added lines that are contiguous across hunks coalesce into one range."""
        diff = """\
diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,1 +1,2 @@
 x = 1
+y = 2
@@ -2,0 +3,1 @@
+z = 3
"""
        result = parse_changed_lines(diff)
        assert result == {"src/app.py": [(2, 3)]}

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
