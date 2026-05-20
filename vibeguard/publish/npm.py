"""npm pack simulation.

Re-implements the file selection logic that `npm publish`/`npm pack` uses,
without shelling out to npm itself. The selection order, after the npm docs:

1. If `package.json` has a `files` field, that allowlist drives inclusion
   on its own — `.npmignore`/`.gitignore` are NOT consulted in this mode.
   (npm itself does apply some `.npmignore` patterns even with `files`, but
   only for files matched by the allowlist; this simulator approximates the
   allowlist-only behavior, which is the dominant case in practice.)
2. Otherwise, the directory is walked and `.npmignore` (or `.gitignore` if
   `.npmignore` is absent) excludes files from the result.
3. A hard-coded always-included set (`package.json` at root, plus root-level
   `README*`, `LICENSE*`, `NOTICE*`, `CHANGES*`, `CHANGELOG*`, `HISTORY*`) is
   added regardless of `files`/ignore rules — per npm's behavior.
4. A hard-coded always-excluded set (`.git`, `node_modules`, `.npmrc`,
   `.DS_Store`, lockfiles, etc.) is removed regardless of `files`/ignore
   rules.

References:
- https://docs.npmjs.com/cli/v10/configuring-npm/package-json#files
- https://docs.npmjs.com/cli/v10/using-npm/developers#keeping-files-out-of-your-package
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pathspec

from vibeguard.publish.manifest import PublishedFile, PublishManifest

# npm always publishes these regardless of files/ignore settings.
# Names are matched case-insensitively against the *file name* in the package root.
_ALWAYS_INCLUDED_BASENAMES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^package\.json$", re.IGNORECASE),
    re.compile(r"^README(\..*)?$", re.IGNORECASE),
    re.compile(r"^LICEN[SC]E(\..*)?$", re.IGNORECASE),
    re.compile(r"^NOTICE(\..*)?$", re.IGNORECASE),
    re.compile(r"^CHANGES(\..*)?$", re.IGNORECASE),
    re.compile(r"^CHANGELOG(\..*)?$", re.IGNORECASE),
    re.compile(r"^HISTORY(\..*)?$", re.IGNORECASE),
)

# npm never publishes these regardless of files/ignore settings.
_ALWAYS_EXCLUDED_EXACT: frozenset[str] = frozenset(
    {
        ".git",
        ".npmrc",
        ".DS_Store",
        ".gitignore",
        ".npmignore",
        "node_modules",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-debug.log",
    }
)

_ALWAYS_EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        ".npm",
        ".vscode",
        ".idea",
        "CVS",
    }
)


def _is_always_included(rel_path: str) -> bool:
    """Return True if the relative path is one of npm's always-included files.

    npm auto-includes `package.json` and `README*` / `LICENSE*` / `CHANGELOG*`
    style files **at the package root only** — nested copies (e.g.
    `src/package.json`, `docs/README.md`) are not auto-included and must
    come in via the `files` allowlist or the directory walk.
    """
    if "/" in rel_path:
        return False
    return any(p.fullmatch(rel_path) for p in _ALWAYS_INCLUDED_BASENAMES)


def _walk_files(root: Path) -> list[Path]:
    """Walk all files under root, skipping always-excluded directory names."""
    out: list[Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(root).parts
        if any(part in _ALWAYS_EXCLUDED_DIR_NAMES for part in rel_parts[:-1]):
            continue
        if p.name in _ALWAYS_EXCLUDED_EXACT:
            continue
        out.append(p)
    return out


def _load_npmignore(root: Path) -> pathspec.PathSpec | None:
    """Load `.npmignore` if present, else fall back to `.gitignore`."""
    for candidate in (".npmignore", ".gitignore"):
        f = root / candidate
        if f.exists():
            try:
                lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                return None
            return pathspec.PathSpec.from_lines("gitignore", lines)
    return None


def _files_allowlist_match(rel_path: str, patterns: list[str]) -> bool:
    """Return True if the path matches any glob in the npm `files` field.

    npm's `files` matches either:
    - exact file paths
    - directory paths (everything under that directory is included)
    - glob patterns (handled via pathspec gitignore semantics, which is the
      closest single-library approximation to npm's globbing)
    """
    if not patterns:
        return False
    spec = pathspec.PathSpec.from_lines("gitignore", patterns)
    if spec.match_file(rel_path):
        return True
    # Bare directory entries: e.g. "src/" should also include "src" itself and descendants
    for pat in patterns:
        clean = pat.rstrip("/")
        if not clean:
            continue
        if rel_path == clean or rel_path.startswith(clean + "/"):
            return True
    return False


def simulate_npm_pack(package_root: Path) -> PublishManifest:
    """Simulate `npm pack` and return the manifest of included files.

    Raises FileNotFoundError if `package.json` is missing.
    """
    package_root = package_root.resolve()
    pkg_json_path = package_root / "package.json"
    if not pkg_json_path.is_file():
        raise FileNotFoundError(f"{pkg_json_path} not found")

    try:
        pkg = json.loads(pkg_json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return PublishManifest(
            ecosystem="npm",
            package_root=str(package_root),
            warnings=[f"package.json is not valid JSON: {exc}"],
        )

    files_field: list[str] = pkg.get("files", []) if isinstance(pkg.get("files"), list) else []
    use_allowlist = bool(files_field)
    ignore_spec = None if use_allowlist else _load_npmignore(package_root)

    warnings: list[str] = []
    if not use_allowlist and ignore_spec is None:
        warnings.append(
            "No `files` field and no .npmignore/.gitignore present — "
            "everything in the package directory would be published."
        )

    included: list[PublishedFile] = []
    excluded: list[str] = []
    total = 0

    # _walk_files() filters out always-excluded paths before they reach the
    # inclusion logic. Surface them here so the manifest's `excluded` list is
    # a complete publish view (matches the documented field semantics).
    # Directories are reported with a trailing "/" to disambiguate from files.
    seen: set[str] = set()
    for name in _ALWAYS_EXCLUDED_EXACT | _ALWAYS_EXCLUDED_DIR_NAMES:
        candidate = package_root / name
        if candidate.is_dir():
            marker = name + "/"
        elif candidate.is_file():
            marker = name
        else:
            continue
        if marker in seen:
            continue
        seen.add(marker)
        excluded.append(marker)

    for path in _walk_files(package_root):
        try:
            rel = str(path.relative_to(package_root)).replace("\\", "/")
        except ValueError:
            continue

        is_pkg_json = rel == "package.json"
        included_by: str | None = None

        if _is_always_included(rel):
            included_by = "always-included"
        elif use_allowlist:
            if _files_allowlist_match(rel, files_field):
                included_by = "files-allowlist"
        else:
            # Default walk: include unless ignored.
            if ignore_spec is None or not ignore_spec.match_file(rel):
                included_by = "default-walk"

        # package.json is unconditionally included
        if is_pkg_json:
            included_by = "always-included"

        if included_by is None:
            excluded.append(rel)
            continue

        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        total += size
        included.append(
            PublishedFile(path=rel, size_bytes=size, included_by=included_by),
        )

    return PublishManifest(
        ecosystem="npm",
        package_root=str(package_root),
        package_name=pkg.get("name"),
        package_version=pkg.get("version"),
        files=included,
        excluded=excluded,
        total_bytes=total,
        warnings=warnings,
    )
