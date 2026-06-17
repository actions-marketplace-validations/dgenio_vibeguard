"""Table-driven regression tests for the git-diff edge-case corpus (#226).

Each fixture under ``tests/fixtures/diffs/`` is real ``git diff`` output (see the
directory README for the generating scenario). The expected changed-line ranges
below are frozen from verified-correct parser output; they pin the supported
diff dialect so hardening or refactoring ``parse_changed_lines`` cannot silently
change scoping.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vibeguard.git import _diff_target_path, parse_changed_lines

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "diffs"

# fixture filename -> {path: [(start, end), ...]} expected added-line ranges.
_EXPECTED: dict[str, dict[str, list[tuple[int, int]]]] = {
    "single_hunk_add.diff": {"app.py": [(2, 2)]},
    "multi_hunk.diff": {"app.py": [(1, 1), (9, 9)]},
    # Pure rename / deletion / mode-only changes introduce no added lines.
    "rename_only.diff": {},
    "rename_with_edit.diff": {"new.py": [(3, 3)]},
    "deletion_only.diff": {},
    "mode_change_only.diff": {},
    # A new empty file contributes no hunk; only the file with content appears.
    "new_files.diff": {"created.py": [(1, 2)]},
    # The binary stanza is ignored; the sibling text file is scoped normally.
    "binary_added.diff": {"also.py": [(1, 1)]},
    "crlf_content.diff": {"app.py": [(1, 3)]},
    "no_newline_eof.diff": {"app.py": [(3, 3)]},
    "hunk_at_line_1.diff": {"app.py": [(1, 1)]},
    "multi_file.diff": {"a.py": [(2, 2)], "b.py": [(3, 3)]},
    # quotePath=true: unicode path is C-quoted, spaced path is trailing-tab
    # disambiguated — both must decode to their literal repo-relative form.
    "quoted_unicode_paths.diff": {"café.py": [(1, 1)], "my file.py": [(1, 1)]},
    # diff.noprefix=true: headers carry no a/ b/ prefix.
    "noprefix_config.diff": {"app.py": [(2, 2)]},
    "empty.diff": {},
}


def test_corpus_is_present_and_wired() -> None:
    """Every checked-in fixture has an expected mapping, and vice versa (no drift)."""
    on_disk = {p.name for p in _FIXTURE_DIR.glob("*.diff")}
    assert on_disk == set(_EXPECTED), (
        "diff corpus drifted from expectations: "
        f"on-disk-only={on_disk - set(_EXPECTED)} expected-only={set(_EXPECTED) - on_disk}"
    )
    # Acceptance criterion: at least 10 distinct diff-dialect fixtures.
    assert len(_EXPECTED) >= 10


@pytest.mark.parametrize("fixture", sorted(_EXPECTED))
def test_parse_changed_lines_matches_corpus(fixture: str) -> None:
    text = (_FIXTURE_DIR / fixture).read_text(encoding="utf-8", errors="replace")
    result = parse_changed_lines(text)
    assert result == _EXPECTED[fixture]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("b/normal.py", "normal.py"),
        ("a/normal.py", "normal.py"),
        ("/dev/null", None),
        # git appends a disambiguating TAB after an unquoted path; strip only it.
        ("b/my file.py\t", "my file.py"),
        # A trailing space that belongs to the filename (tab-disambiguated) survives.
        ("b/trailing .py\t", "trailing .py"),
        # noprefix output: a leading space that is part of the name is preserved.
        (" leading.py", " leading.py"),
        # C-quoted unicode decodes back to its literal form.
        (r'"b/caf\303\251.py"', "café.py"),
    ],
)
def test_diff_target_path_whitespace_and_quoting(raw: str, expected: str | None) -> None:
    assert _diff_target_path(raw) == expected
