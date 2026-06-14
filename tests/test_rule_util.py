"""Tests for the shared rule helpers (#178).

These previously lived as divergent private copies inside individual rules.
Consolidating them here means the behavior is specified and tested once.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vibeguard.rules._util import (
    is_comment_line,
    is_test_file,
    is_test_path,
    load_toml,
)


class TestLoadToml:
    def test_parses_valid_toml(self):
        data = load_toml('[project]\nname = "x"\n')
        assert data == {"project": {"name": "x"}}

    def test_malformed_returns_none(self):
        assert load_toml("this is = = not toml") is None

    def test_empty_string_is_empty_table(self):
        assert load_toml("") == {}


class TestIsTestFile:
    @pytest.mark.parametrize(
        "path",
        [
            "test_foo.py",
            "foo_test.py",
            "widget.test.js",
            "widget.test.ts",
            "widget.spec.js",
            "widget.spec.ts",
            "tests/foo.py",
            "test/foo.py",
            "pkg/__tests__/foo.js",
            "pkg/spec/foo.rb",
            "pkg/specs/foo.rb",
            "fixtures/sample.py",
            "a/fixture/sample.py",
        ],
    )
    def test_positive(self, path: str):
        assert is_test_file(Path(path)) is True

    @pytest.mark.parametrize(
        "path",
        [
            "src/foo.py",
            "app/main.js",
            "lib/util.ts",
            "contest.py",  # contains "test" as a substring but not a test path
            "latest/build.py",
        ],
    )
    def test_negative(self, path: str):
        assert is_test_file(Path(path)) is False

    def test_string_wrapper_matches_path(self):
        assert is_test_path("tests/foo.py") is True
        assert is_test_path("tests\\foo.py") is True  # windows separator
        assert is_test_path("src/foo.py") is False


class TestIsCommentLine:
    @pytest.mark.parametrize(
        "line",
        [
            "# python comment",
            "  // js comment",
            "/* block open",
            " * javadoc continuation",
            "<!-- html comment",
        ],
    )
    def test_positive(self, line: str):
        assert is_comment_line(line) is True

    @pytest.mark.parametrize(
        "line",
        [
            "x = 1  # trailing comment is not a comment line",
            'query = f"SELECT * FROM t"',
            "value = a / b",
        ],
    )
    def test_negative(self, line: str):
        assert is_comment_line(line) is False
