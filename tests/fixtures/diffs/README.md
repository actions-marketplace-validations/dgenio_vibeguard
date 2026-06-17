# Git-diff edge-case corpus (#226)

A checked-in corpus of real `git diff` output exercising the long tail of diff
shapes that `vibeguard.git.parse_changed_lines` must handle. Each fixture is
paired with its exact expected `{path: [(start, end), …]}` mapping in
`tests/test_diff_corpus.py`, so a refactor that changes changed-line scoping is
caught immediately.

These fixtures are **generated from real git output, not hand-typed**. Unless
noted, each was produced with VibeGuard's pinned diff contract (see
`vibeguard/git.py`):

```
git -c color.diff=never -c core.quotePath=false diff \
    --no-ext-diff --src-prefix=a/ --dst-prefix=b/ [<rev>]
```

| Fixture | Generating scenario / non-default config |
|---|---|
| `single_hunk_add.diff` | One line inserted into an existing file. |
| `multi_hunk.diff` | Two separate hunks in one file. |
| `rename_only.diff` | `git mv` with no content change (`--find-renames`). |
| `rename_with_edit.diff` | `git mv` plus an inserted line (`--find-renames`). |
| `deletion_only.diff` | `git rm` of a file (deletion stanza). |
| `new_files.diff` | A new empty file and a new file with content (staged). |
| `binary_added.diff` | A new binary file alongside a new text file (staged). |
| `mode_change_only.diff` | `chmod +x` with no content change. |
| `crlf_content.diff` | CRLF line endings (`core.autocrlf=false`). |
| `no_newline_eof.diff` | Final line added without a trailing newline. |
| `hunk_at_line_1.diff` | Insertion at the first line of the file. |
| `multi_file.diff` | Two files changed in a single diff. |
| `quoted_unicode_paths.diff` | `core.quotePath=true`; a unicode filename (C-quoted) and a filename with a space (trailing-tab disambiguated). |
| `noprefix_config.diff` | `diff.noprefix=true` (headers have no `a/`/`b/` prefix). |
| `empty.diff` | Empty input (no changes). |

To regenerate after changing the parser contract, reproduce the scenario in a
throwaway repo and re-freeze; update the expected mapping in the test in the
same commit.
