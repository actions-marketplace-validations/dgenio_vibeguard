"""Single home for dependency manifest and lockfile parsing (#179).

Two rules — ``dependencies`` and ``slopsquat`` — previously parsed the same
npm/PyPI manifest and lockfile formats with their own private helpers, so a fix
to one parser never reached the other. This module is the shared parser: rules
import the accessor they need and apply their own policy on top.

Design notes
------------
* **Per-file, not per-root.** The accessors operate on the *text* of a single
  manifest/lockfile rather than a repository root. Both rules rely on
  monorepo-aware lockfile scoping (a manifest is only governed by a lockfile in
  its own directory or an ancestor — see the slopsquat docstring and the
  contract in commit dcd6a19); a root-level "flatten everything" accessor would
  destroy that scoping, so the scoping logic stays in the rules and this module
  stays a pure text→data layer.
* **Never raises.** Every accessor degrades gracefully: malformed JSON/TOML or
  an unparseable line yields empty data, never an exception, so a rule can
  treat "no data" uniformly and never crashes mid-scan on a hostile file.
"""

from __future__ import annotations

import json
import re
from typing import Any

from vibeguard.rules._util import load_toml

# ---------------------------------------------------------------------------
# Manifest / lockfile name constants (shared by the rules)
# ---------------------------------------------------------------------------

NODE_MANIFEST = "package.json"
PY_MANIFEST = "pyproject.toml"
PY_REQUIREMENTS_RE = re.compile(r"requirements.*\.txt$")

# Lockfiles whose presence means a declared dependency has been resolved.
NODE_LOCKFILES: frozenset[str] = frozenset({"package-lock.json", "yarn.lock", "pnpm-lock.yaml"})
PY_LOCKFILES: frozenset[str] = frozenset({"poetry.lock", "uv.lock", "Pipfile.lock"})

# Lockfile -> the manifest it is generated from, used by drift detection.
LOCKFILE_TO_MANIFEST: dict[str, str] = {
    "package-lock.json": "package.json",
    "yarn.lock": "package.json",
    "pnpm-lock.yaml": "package.json",
    "poetry.lock": "pyproject.toml",
    "uv.lock": "pyproject.toml",
    "Pipfile.lock": "Pipfile",
}

# Npm dependency groups whose members count as declared dependencies.
_NODE_DEP_GROUPS = ("dependencies", "devDependencies", "optionalDependencies")

# Package-name boundary for a Python requirement specifier
# (e.g. ``requests>=2,<3 ; extra == 'x'`` → ``requests``).
_PY_NAME_RE = re.compile(r"[>=<!~;\s\[\]()]")


def _load_json(text: str) -> Any | None:
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001 — malformed JSON is "no data", not an error
        return None


# ---------------------------------------------------------------------------
# Declared dependencies (manifests)
# ---------------------------------------------------------------------------


def node_dependency_versions(text: str) -> dict[str, str]:
    """Return ``{name: version}`` declared across a ``package.json``'s dep groups.

    Later groups override earlier ones on a name collision (dict semantics),
    matching how the ``dependencies`` rule built its merged view.
    """
    data = _load_json(text)
    out: dict[str, str] = {}
    if not isinstance(data, dict):
        return out
    for group in _NODE_DEP_GROUPS:
        block = data.get(group)
        if isinstance(block, dict):
            for name, version in block.items():
                out[str(name)] = str(version)
    return out


def node_dependency_names(text: str) -> list[str]:
    """Return declared dependency names from a ``package.json``, group by group.

    Preserves the order/duplication of iterating the dep groups in turn (the
    shape the ``slopsquat`` rule consumed).
    """
    data = _load_json(text)
    names: list[str] = []
    if not isinstance(data, dict):
        return names
    for group in _NODE_DEP_GROUPS:
        block = data.get(group)
        if isinstance(block, dict):
            names.extend(str(k) for k in block)
    return names


def pyproject_dependency_specifiers(text: str) -> list[str]:
    """Return the raw ``[project].dependencies`` specifier strings.

    The full specifier is returned (not just the name) because callers inspect
    it for URL/VCS markers and version pins.
    """
    data = load_toml(text)
    if data is None:
        return []
    raw = data.get("project", {}).get("dependencies", [])
    return [str(dep) for dep in raw]


def split_python_name(spec: str) -> str:
    """Return the bare package name from a Python requirement specifier."""
    return _PY_NAME_RE.split(spec)[0].strip()


def pyproject_dependency_names(text: str) -> list[str]:
    """Return declared dependency names from a ``pyproject.toml``."""
    names: list[str] = []
    for spec in pyproject_dependency_specifiers(text):
        name = split_python_name(spec)
        if name:
            names.append(name)
    return names


def requirements_dependency_names(text: str) -> list[str]:
    """Return declared dependency names from a ``requirements*.txt`` body."""
    names: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        name = split_python_name(line)
        if name:
            names.append(name)
    return names


# ---------------------------------------------------------------------------
# Locked dependencies (lockfiles)
# ---------------------------------------------------------------------------

# Loose name extractors for lockfiles. These are intentionally permissive — a
# false *inclusion* only suppresses a heuristic finding, which is the safe
# direction.
_PKG_LOCK_NAME_RE = re.compile(r'"node_modules/((?:@[^/"]+/)?[^/"]+)"')
_YARN_NAME_RE = re.compile(r'^"?((?:@[^/@\s]+/)?[^@\s"]+)@', re.MULTILINE)
_POETRY_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"', re.MULTILINE)


def lock_package_names(filename: str, text: str) -> set[str]:
    """Best-effort set of lower-cased package names declared in one lockfile.

    Structured (JSON) formats are parsed structurally; line-oriented formats
    (yarn v1, poetry/uv, pnpm) fall back to permissive regexes. Unknown
    filenames and malformed content yield an empty set.
    """
    names: set[str] = set()
    if filename == "package-lock.json":
        data = _load_json(text)
        if isinstance(data, dict):
            for key in ("packages", "dependencies"):
                block = data.get(key)
                if isinstance(block, dict):
                    for raw in block:
                        leaf = str(raw).rsplit("node_modules/", 1)[-1]
                        if leaf:
                            names.add(leaf.lower())
        names.update(m.group(1).lower() for m in _PKG_LOCK_NAME_RE.finditer(text))
    elif filename in {"yarn.lock", "pnpm-lock.yaml"}:
        names.update(m.group(1).lower() for m in _YARN_NAME_RE.finditer(text))
    elif filename in {"poetry.lock", "uv.lock"}:
        names.update(m.group(1).lower() for m in _POETRY_NAME_RE.finditer(text))
    elif filename == "Pipfile.lock":
        data = _load_json(text)
        if isinstance(data, dict):
            for section in ("default", "develop"):
                block = data.get(section)
                if isinstance(block, dict):
                    names.update(str(k).lower() for k in block)
    return names
