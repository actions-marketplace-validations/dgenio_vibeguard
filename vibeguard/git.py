"""Git utilities for VibeGuard.

Diff mode is VibeGuard's flagship CI workflow, so this module pins the git
output contract rather than parsing whatever a user's local configuration
produces. Every diff is requested with explicit output-stabilising flags
(``color.diff=never``, ``core.quotePath=false``, ``--no-ext-diff``, and explicit
``a/``/``b/`` prefixes) so that user-level settings — ``diff.noprefix``,
``diff.mnemonicPrefix``, ``color.diff=always``, external diff drivers — cannot
change the text the parser sees (#220).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Literal

from vibeguard.models import GitMetadata

# Matches unified diff hunk headers: @@ -old_start,old_count +new_start,new_count @@
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

# Flags that pin the diff output format so local git config cannot perturb the
# text the parser consumes (#220). ``core.quotePath=false`` keeps unicode paths
# literal; explicit prefixes defeat ``diff.noprefix``/``diff.mnemonicPrefix``;
# ``--no-ext-diff`` ignores external diff drivers; ``color.diff=never`` strips
# ANSI escapes from ``color.diff=always`` users.
_DIFF_STABILISERS: list[str] = [
    "-c",
    "color.diff=never",
    "-c",
    "core.quotePath=false",
]


def get_git_metadata(root: Path, base_branch: str | None = None) -> GitMetadata:
    """Collect git metadata and changed file list.

    ``base_branch`` (from ``--base`` or ``git.base_branch`` config) takes
    precedence over automatic detection. An explicit ref that cannot be
    verified is **not** silently ignored: a warning is recorded and detection
    falls back to the usual ``origin/main`` → ``origin/master`` → ``main`` →
    ``master`` detection order (#208, #182).
    """
    warnings: list[str] = []
    try:
        # Verify we are in a git repo
        result = subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return GitMetadata(is_available=False, error="Not a git repository")

        branch = _run_git(root, ["git", "rev-parse", "--abbrev-ref", "HEAD"])
        commit = _run_git(root, ["git", "rev-parse", "--short", "HEAD"])
        is_shallow = _is_shallow(root)

        # Resolve the base ref: explicit request (validated) wins over detection.
        resolved_base: str | None = None
        if base_branch:
            if _ref_exists(root, base_branch):
                resolved_base = base_branch
            else:
                warnings.append(
                    f"Requested base ref {base_branch!r} could not be verified; "
                    "falling back to automatic base-branch detection."
                )
        if resolved_base is None:
            resolved_base = _detect_base_branch(root)

        diff_strategy: Literal["merge-base", "head-only"] = (
            "merge-base" if resolved_base else "head-only"
        )
        changed_files: list[str] = []

        if resolved_base:
            raw = _run_git(
                root,
                ["git", *_DIFF_STABILISERS, "diff", "--name-only", f"{resolved_base}...HEAD"],
            )
            if raw:
                changed_files = [f for f in raw.splitlines() if f.strip()]

        if not changed_files:
            # Fall back to uncommitted + staged changes
            raw = _run_git(root, ["git", *_DIFF_STABILISERS, "diff", "--name-only", "HEAD"])
            if raw:
                changed_files = [f for f in raw.splitlines() if f.strip()]

        return GitMetadata(
            branch=branch or None,
            base_branch=resolved_base,
            commit=commit or None,
            changed_files=changed_files,
            is_available=True,
            diff_strategy=diff_strategy,
            is_shallow=is_shallow,
            warnings=warnings,
        )

    except Exception as exc:  # noqa: BLE001
        return GitMetadata(is_available=False, error=str(exc))


def get_tracked_files(root: Path) -> set[str] | None:
    """Return git-tracked paths (repo-relative to ``root``), or ``None`` if git is unavailable.

    Used by the file collector's ``.gitignore`` carve-out (#211): a file git
    already tracks is scanned even when a ``.gitignore`` rule would otherwise
    exclude it, so a committed-but-usually-ignored file — e.g. the checked-in
    ``.env`` in the demo fixtures — still triggers ``SEC-ENV``.

    Returns an empty set for a git repo with no tracked files, and ``None`` when
    ``root`` is not inside a working tree, letting the caller fall back to pure
    ``pathspec`` matching with the carve-out disabled. ``core.quotePath=false``
    keeps unicode paths literal so they line up with the collector's relative
    paths (#220).
    """
    if not _run_git(root, ["git", "rev-parse", "--git-dir"]):
        return None
    raw = _run_git(root, ["git", "-c", "core.quotePath=false", "ls-files"])
    return {line for line in raw.splitlines() if line}


def _run_git(root: Path, cmd: list[str]) -> str:
    try:
        result = subprocess.run(
            cmd,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def _ref_exists(root: Path, ref: str) -> bool:
    """Return True if ``ref`` resolves to a commit in the repo at ``root``.

    Uses ``rev-parse --verify --quiet`` so an unknown ref produces empty output
    (and a non-zero exit) rather than noise on stderr.
    """
    return bool(_run_git(root, ["git", "rev-parse", "--verify", "--quiet", ref]))


def _is_shallow(root: Path) -> bool:
    """Return True for a shallow clone (``git clone --depth=N``)."""
    return _run_git(root, ["git", "rev-parse", "--is-shallow-repository"]) == "true"


def _detect_base_branch(root: Path) -> str | None:
    """Try to detect the default base branch (main or master)."""
    for candidate in ("origin/main", "origin/master", "main", "master"):
        if _ref_exists(root, candidate):
            return candidate
    return None


def _diff_cmd(rev: str) -> list[str]:
    """Build a ``git diff`` argv for ``rev`` with the pinned output contract."""
    return [
        "git",
        *_DIFF_STABILISERS,
        "diff",
        "--no-ext-diff",
        "--src-prefix=a/",
        "--dst-prefix=b/",
        rev,
    ]


def get_diff_text(root: Path, base_branch: str | None = None) -> str:
    """Get the unified diff text for changed files.

    The diff is requested with :data:`_DIFF_STABILISERS` plus explicit
    ``a/``/``b/`` prefixes so the output shape is independent of the user's git
    configuration and :func:`parse_changed_lines` can rely on it (#220).

    Mirrors :func:`get_git_metadata`'s changed-file resolution exactly: try
    ``base...HEAD`` first and fall back to ``git diff HEAD`` when that is empty
    (no commits ahead of the base, e.g. scanning uncommitted work on the base
    branch). Keeping the two in lockstep prevents ``changed_files`` and
    ``diff_text`` from describing different comparisons, which would leave files
    in the change set with no parsed line ranges (#258 review).
    """
    resolved_base = base_branch or _detect_base_branch(root)
    if resolved_base:
        text = _run_git(root, _diff_cmd(f"{resolved_base}...HEAD"))
        if text:
            return text
    return _run_git(root, _diff_cmd("HEAD"))


def parse_changed_lines(diff_text: str) -> dict[str, list[tuple[int, int]]]:
    """Parse unified diff to extract per-file added/modified line ranges.

    Returns a dict mapping relative file paths to lists of (start_line, end_line)
    tuples covering the added (``+``) lines in the new file. Context lines and
    deletions are excluded so that ``--diff`` mode filters findings down to the
    lines this change actually introduced.

    Robust to the long tail of real diff shapes (#220, #226): C-quoted paths
    (spaces/unicode), ``diff.noprefix`` output, deletions (``+++ /dev/null``),
    renames, binary stanzas, and mode-only changes. A ``+++`` line is treated as
    a file header only when preceded by a ``---`` line, so an added content line
    that happens to start with ``+++`` is not mistaken for one.
    """
    added: dict[str, list[int]] = {}
    current_file: str | None = None
    new_line: int | None = None
    prev_line = ""

    for line in diff_text.splitlines():
        # A new-file header (``+++ b/path``) always follows the old-file header
        # (``--- a/path``); requiring that pairing avoids misreading an added
        # content line as a header.
        is_file_header = line.startswith("+++ ") and prev_line.startswith("--- ")
        prev_line = line

        if is_file_header:
            current_file = _diff_target_path(line[4:])
            if current_file is not None:
                added.setdefault(current_file, [])
            new_line = None
            continue

        if line.startswith("@@") and current_file is not None:
            match = _HUNK_RE.match(line)
            new_line = int(match.group(1)) if match else None
            continue

        if current_file is None or new_line is None:
            continue

        # Skip the leftover old-file header (``--- a/path`` / ``--- /dev/null``)
        # that precedes the next file's ``+++`` header; a removed content line
        # ("--…") is skipped here too and, like any deletion, must not advance
        # the new-file counter. The real ``+++ b/path`` header was already
        # consumed by the ``is_file_header`` pairing above, so any ``+++`` line
        # reaching this point is an *added* content line whose text starts with
        # ``++`` — it must be counted, not skipped (#258 review).
        if line.startswith("---"):
            continue

        if line.startswith("+"):
            added[current_file].append(new_line)
            new_line += 1
        elif line.startswith("-"):
            # Removed line — does not advance the new-file counter.
            pass
        elif line.startswith("\\"):
            # "\ No newline at end of file" — metadata, skip.
            pass
        else:
            # Context line — advances the new-file counter but is not "changed".
            new_line += 1

    return {path: _coalesce_lines(lines) for path, lines in added.items()}


def _diff_target_path(raw: str) -> str | None:
    """Normalise a ``+++`` header target into a repo-relative path.

    Handles C-quoted paths (git wraps paths with special bytes in double quotes
    and backslash/octal escapes), the ``/dev/null`` deletion target, and the
    ``a/``/``b/`` prefix (absent under ``diff.noprefix``). Returns ``None`` for
    a deletion so the caller skips the (now non-existent) file.
    """
    # git appends a single TAB after an *unquoted* path when it needs
    # disambiguation (e.g. the path has a trailing space). Strip only that tab —
    # never a general ``.strip()``, which would discard leading/trailing spaces
    # that are part of a pathological-but-valid filename (#258 review). A path
    # containing a literal tab would have been C-quoted, so this is unambiguous.
    raw = _unquote_git_path(raw.rstrip("\t"))
    if raw == "/dev/null":
        return None
    for prefix in ("a/", "b/"):
        if raw.startswith(prefix):
            return raw[len(prefix) :]
    return raw


def _unquote_git_path(raw: str) -> str:
    """Decode a git C-quoted path (``"pa\\tth"``) back to its literal form.

    Git quotes a path in the diff header when it contains control characters,
    a double-quote, a backslash, or (with ``core.quotePath`` on) non-ASCII
    bytes, escaping them with C-style ``\\n``/``\\t``/``\\\\``/``\\"`` and octal
    ``\\NNN`` byte escapes. We force ``core.quotePath=false`` for our own diffs,
    but the corpus regression net (#226) feeds raw output from other configs.
    """
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return raw

    inner = raw[1:-1]
    out = bytearray()
    simple = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, "\\": 92, '"': 34}
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch == "\\" and i + 1 < len(inner):
            nxt = inner[i + 1]
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if nxt in "01234567":
                j = i + 1
                digits = ""
                while j < len(inner) and len(digits) < 3 and inner[j] in "01234567":
                    digits += inner[j]
                    j += 1
                out.append(int(digits, 8) & 0xFF)
                i = j
                continue
            # Unknown escape — keep the escaped character verbatim.
            out.extend(nxt.encode("utf-8"))
            i += 2
            continue
        out.extend(ch.encode("utf-8"))
        i += 1
    return out.decode("utf-8", errors="replace")


def _coalesce_lines(lines: list[int]) -> list[tuple[int, int]]:
    """Collapse a list of line numbers into contiguous (start, end) ranges."""
    if not lines:
        return []
    ordered = sorted(set(lines))
    ranges: list[tuple[int, int]] = []
    start = end = ordered[0]
    for n in ordered[1:]:
        if n == end + 1:
            end = n
        else:
            ranges.append((start, end))
            start = end = n
    ranges.append((start, end))
    return ranges
