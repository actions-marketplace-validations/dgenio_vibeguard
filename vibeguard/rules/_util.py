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
