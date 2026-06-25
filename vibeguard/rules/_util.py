"""Shared internal helpers for built-in rules (#178).

Several rules independently re-implemented the same small helpers — TOML
loading, test-file detection, and comment-line detection — and the copies had
drifted apart, so the *same* line could be classified differently depending on
which rule looked at it. This module is the single, tested home for those
helpers; rules import from here instead of carrying private copies.

Nothing in this module imports a concrete rule, so it is safe for any rule (and
the publish subsystem) to depend on without risking an import cycle.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# TOML loading
# ---------------------------------------------------------------------------


def load_toml(text: str) -> dict[str, Any] | None:
    """Parse TOML ``text``, returning ``None`` if it is malformed or unparseable.

    Uses the stdlib ``tomllib`` on Python 3.11+ and falls back to the ``tomli``
    backport (a dependency floor on 3.10). Never raises: a missing parser or a
    syntactically invalid document both yield ``None`` so callers can treat
    "no usable data" uniformly.
    """
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return None
    try:
        return tomllib.loads(text)
    except Exception:  # noqa: BLE001 — malformed TOML is "no data", not an error
        return None


# ---------------------------------------------------------------------------
# Test-file detection
# ---------------------------------------------------------------------------

# Directory names anywhere in a path that mark it as test/fixture material.
TEST_DIR_NAMES: frozenset[str] = frozenset(
    {"test", "tests", "__tests__", "spec", "specs", "fixture", "fixtures"}
)

# Filename prefixes that mark a test file.
TEST_NAME_PREFIXES: tuple[str, ...] = ("test_",)

# Filename suffixes that mark a test file (union of the conventions the rules
# previously checked individually: pytest, jest, mocha/jasmine specs).
TEST_NAME_SUFFIXES: tuple[str, ...] = (
    "_test.py",
    ".test.js",
    ".test.ts",
    ".spec.js",
    ".spec.ts",
)


def is_test_file(path: Path) -> bool:
    """Return ``True`` if ``path`` looks like test, spec, or fixture material.

    A path qualifies if its filename matches a test prefix/suffix, or if any
    component of the path is a known test directory name. This is the single
    definition shared by every rule that wants to special-case test files
    (e.g. down-ranking findings or excluding files from a "source changed
    without tests" check).
    """
    name = path.name.lower()
    if name.startswith(TEST_NAME_PREFIXES):
        return True
    if name.endswith(TEST_NAME_SUFFIXES):
        return True
    return bool({p.lower() for p in path.parts} & TEST_DIR_NAMES)


def is_test_path(rel: str) -> bool:
    """``is_test_file`` for a string path (``/`` or ``\\`` separated)."""
    return is_test_file(Path(rel.replace("\\", "/")))


# ---------------------------------------------------------------------------
# Comment-line detection
# ---------------------------------------------------------------------------

# Stripped-line prefixes that begin a single-line or block comment across the
# languages the line-oriented rules scan (Python, JS/TS, C-family, HTML/XML).
COMMENT_LINE_PREFIXES: tuple[str, ...] = ("#", "//", "/*", "*", "<!--")


def is_comment_line(line: str) -> bool:
    """Return ``True`` if ``line`` is (heuristically) a comment line.

    Operates on the raw line — it strips leading whitespace itself — so callers
    can pass either the raw or already-stripped line. The heuristic is
    deliberately simple (prefix match); it is meant to skip obvious comment
    lines in keyword-based scanners, not to fully tokenize source.
    """
    stripped = line.strip()
    return stripped.startswith(COMMENT_LINE_PREFIXES)


# ---------------------------------------------------------------------------
# Triple-quoted (docstring / multiline-string) span detection
# ---------------------------------------------------------------------------

# Python triple-quote string delimiters.
_TRIPLE_DELIMS: tuple[str, ...] = ('"""', "'''")


def _next_triple(line: str, start: int) -> tuple[int, str | None]:
    """Find the earliest triple-quote delimiter in ``line`` at/after ``start``."""
    best = -1
    best_delim: str | None = None
    for delim in _TRIPLE_DELIMS:
        pos = line.find(delim, start)
        if pos != -1 and (best == -1 or pos < best):
            best = pos
            best_delim = delim
    return best, best_delim


def _advance_triple_state(line: str, state: str | None) -> tuple[bool, str | None]:
    """Advance triple-quote state across one ``line``.

    Returns ``(is_noncode, new_state)`` where ``is_noncode`` is ``True`` when any
    part of the line lies inside a triple-quoted span and ``new_state`` is the
    still-open delimiter (or ``None``) carried to the next line.
    """
    noncode = state is not None
    i = 0
    n = len(line)
    while i < n:
        if state is None:
            pos, delim = _next_triple(line, i)
            if pos == -1:
                break
            state = delim
            noncode = True
            i = pos + 3
        else:
            close = line.find(state, i)
            if close == -1:
                break  # span continues onto the next line
            state = None
            i = close + 3
    return noncode, state


def docstring_line_numbers(content: str) -> set[int]:
    """Return the 1-based line numbers that fall inside triple-quoted spans.

    Python docstrings and multi-line ``\"\"\"``/``'''`` string literals are prose,
    not executable code, yet the keyword-based line scanners (``risky_diff``,
    ``sql``) would otherwise flag a keyword that appears only in a docstring
    (e.g. "refund" in a module docstring — #138). This is the line-oriented
    companion to :func:`is_comment_line`: it tracks triple-quote open/close state
    across lines and reports every line wholly or partly inside a span so callers
    can skip it.

    The heuristic is deliberately simple — it does not model escaped quotes or
    triple-quotes embedded inside single-quoted strings — matching the
    "skip the obvious, do not tokenize" posture of :func:`is_comment_line`.
    """
    inside: set[int] = set()
    state: str | None = None  # the open delimiter, or None when outside a span
    for lineno, line in enumerate(content.splitlines(), start=1):
        noncode, state = _advance_triple_state(line, state)
        if noncode:
            inside.add(lineno)
    return inside
