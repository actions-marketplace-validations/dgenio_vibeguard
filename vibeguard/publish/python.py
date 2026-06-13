"""Python sdist/wheel content simulation.

Re-implements the file selection logic that `python -m build` would apply
for sdist and wheel artifacts, without invoking the build backend itself.

Supported backends:
- hatchling (`[tool.hatch.build.targets.sdist]`, `[tool.hatch.build.targets.wheel]`)
- setuptools (`[tool.setuptools]`, `[tool.setuptools.packages.find]`, optional `MANIFEST.in`)
- flit_core (`[tool.flit.module]`)
- PEP 517 fallback: read `pyproject.toml` only, assume the project root is the package

References:
- https://hatch.pypa.io/latest/config/build/
- https://setuptools.pypa.io/en/latest/userguide/pyproject_config.html
- https://peps.python.org/pep-0517/
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vibeguard.publish.manifest import Ecosystem, PublishedFile, PublishManifest
from vibeguard.rules._util import load_toml

# Sdist always-included files (basename match at the package root).
_SDIST_ALWAYS_INCLUDED: tuple[re.Pattern[str], ...] = (
    re.compile(r"^pyproject\.toml$", re.IGNORECASE),
    re.compile(r"^setup\.cfg$", re.IGNORECASE),
    re.compile(r"^setup\.py$", re.IGNORECASE),
    re.compile(r"^README(\..*)?$", re.IGNORECASE),
    re.compile(r"^LICEN[SC]E(\..*)?$", re.IGNORECASE),
    re.compile(r"^NOTICE(\..*)?$", re.IGNORECASE),
    re.compile(r"^CHANGES(\..*)?$", re.IGNORECASE),
    re.compile(r"^CHANGELOG(\..*)?$", re.IGNORECASE),
    re.compile(r"^MANIFEST\.in$", re.IGNORECASE),
)

# Directories that should never appear in a published artifact.
_NEVER_INCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".git",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        ".idea",
        ".vscode",
        ".github",
        "htmlcov",
    }
)


def _walk(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        parts = p.relative_to(root).parts
        if any(part in _NEVER_INCLUDED_DIR_NAMES for part in parts[:-1]):
            continue
        if p.name == ".DS_Store":
            continue
        out.append(p)
    return out


def _basename_always_included(rel_path: str) -> bool:
    if "/" in rel_path:
        return False
    return any(p.fullmatch(rel_path) for p in _SDIST_ALWAYS_INCLUDED)


def _detect_backend(toml: dict[str, Any]) -> str:
    backend = toml.get("build-system", {}).get("build-backend", "")
    if not isinstance(backend, str):
        return "unknown"
    backend = backend.lower()
    if backend.startswith("hatch"):
        return "hatch"
    if backend.startswith("setuptools"):
        return "setuptools"
    if backend.startswith("flit"):
        return "flit"
    if backend.startswith("poetry"):
        return "poetry"
    return backend or "unknown"


def _project_name_version(toml: dict[str, Any]) -> tuple[str | None, str | None]:
    project = toml.get("project", {})
    name = project.get("name") if isinstance(project, dict) else None
    version = project.get("version") if isinstance(project, dict) else None
    return name, version


def _hatch_sdist_paths(
    root: Path,
    toml: dict[str, Any],
    all_files: list[Path],
) -> tuple[list[tuple[Path, str]], list[str]]:
    """Resolve hatch sdist include/exclude rules."""
    cfg = toml.get("tool", {}).get("hatch", {}).get("build", {}).get("targets", {}).get("sdist", {})
    include: list[str] = cfg.get("include", []) if isinstance(cfg.get("include"), list) else []
    exclude: list[str] = cfg.get("exclude", []) if isinstance(cfg.get("exclude"), list) else []

    import pathspec

    inc_spec = pathspec.PathSpec.from_lines("gitignore", include) if include else None
    exc_spec = pathspec.PathSpec.from_lines("gitignore", exclude) if exclude else None

    matched: list[tuple[Path, str]] = []
    for path in all_files:
        rel = str(path.relative_to(root)).replace("\\", "/")
        if exc_spec and exc_spec.match_file(rel):
            continue
        if _basename_always_included(rel):
            matched.append((path, "always-included"))
            continue
        if inc_spec and (
            inc_spec.match_file(rel)
            or any(rel == p.rstrip("/") or rel.startswith(p.rstrip("/") + "/") for p in include)
        ):
            matched.append((path, "hatch-include"))
    return matched, include


def _setuptools_packages(root: Path, toml: dict[str, Any]) -> list[str]:
    """Resolve the list of setuptools packages from `[tool.setuptools]`."""
    setuptools_cfg = toml.get("tool", {}).get("setuptools", {})
    packages_decl = setuptools_cfg.get("packages")
    out: list[str] = []
    if isinstance(packages_decl, list):
        out.extend(str(p) for p in packages_decl)
    elif isinstance(packages_decl, dict):
        find_cfg = packages_decl.get("find", {})
        where = find_cfg.get("where", ["."])
        if isinstance(where, list):
            for w in where:
                d = root / str(w).strip("/")
                if d.is_dir():
                    out.extend(
                        sub.name
                        for sub in d.iterdir()
                        if sub.is_dir() and (sub / "__init__.py").exists()
                    )
    return out


def _read_manifest_in(root: Path) -> list[str]:
    """Return the raw lines of `MANIFEST.in`, or [] if missing."""
    mf = root / "MANIFEST.in"
    if not mf.is_file():
        return []
    try:
        return [
            ln.strip()
            for ln in mf.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
    except OSError:
        return []


def _apply_manifest_in(
    root: Path,
    lines: list[str],
    all_files: list[Path],
    *,
    seeded: dict[str, tuple[Path, str]] | None = None,
) -> list[tuple[Path, str]]:
    """Best-effort `MANIFEST.in` directive interpretation.

    If `seeded` is provided, those entries form the starting set so that
    `exclude`/`prune`/`recursive-exclude`/`global-exclude` directives can
    subtract from existing package-discovery results.
    """
    import fnmatch

    matched: dict[str, tuple[Path, str]] = dict(seeded) if seeded else {}

    def add(p: Path, reason: str) -> None:
        rel = str(p.relative_to(root)).replace("\\", "/")
        matched.setdefault(rel, (p, reason))

    def remove_match(pattern: str) -> None:
        to_drop = [k for k in matched if fnmatch.fnmatch(k, pattern)]
        for k in to_drop:
            matched.pop(k, None)

    for raw in lines:
        parts = raw.split()
        if not parts:
            continue
        cmd = parts[0].lower()
        args = parts[1:]
        if cmd == "include" and args:
            for pat in args:
                for p in all_files:
                    rel = str(p.relative_to(root)).replace("\\", "/")
                    if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(p.name, pat):
                        add(p, "manifest-in:include")
        elif cmd == "exclude" and args:
            for pat in args:
                remove_match(pat)
        elif cmd == "recursive-include" and len(args) >= 2:
            base = args[0].rstrip("/")
            globs = args[1:]
            for p in all_files:
                rel = str(p.relative_to(root)).replace("\\", "/")
                if not (rel == base or rel.startswith(base + "/")):
                    continue
                if any(fnmatch.fnmatch(p.name, g) for g in globs):
                    add(p, "manifest-in:recursive-include")
        elif cmd == "recursive-exclude" and len(args) >= 2:
            base = args[0].rstrip("/")
            globs = args[1:]
            for k in list(matched):
                if k == base or k.startswith(base + "/"):
                    name = k.rsplit("/", 1)[-1]
                    if any(fnmatch.fnmatch(name, g) for g in globs):
                        matched.pop(k, None)
        elif cmd == "graft" and args:
            for arg in args:
                base = arg.rstrip("/")
                for p in all_files:
                    rel = str(p.relative_to(root)).replace("\\", "/")
                    if rel == base or rel.startswith(base + "/"):
                        add(p, "manifest-in:graft")
        elif cmd == "prune" and args:
            for arg in args:
                base = arg.rstrip("/")
                for k in list(matched):
                    if k == base or k.startswith(base + "/"):
                        matched.pop(k, None)
        elif cmd == "global-include" and args:
            for pat in args:
                for p in all_files:
                    if fnmatch.fnmatch(p.name, pat):
                        add(p, "manifest-in:global-include")
        elif cmd == "global-exclude" and args:
            for pat in args:
                for k in list(matched):
                    name = k.rsplit("/", 1)[-1]
                    if fnmatch.fnmatch(name, pat):
                        matched.pop(k, None)

    return list(matched.values())


def _setuptools_sdist_paths(
    root: Path, toml: dict[str, Any], all_files: list[Path]
) -> list[tuple[Path, str]]:
    """Resolve setuptools sdist contents from package discovery + MANIFEST.in.

    Files added by package discovery can be subtracted by MANIFEST.in
    `prune`, `exclude`, `recursive-exclude`, and `global-exclude` directives.
    """
    # Build a unified working set keyed by relative path so manifest-in
    # exclude/prune directives can subtract from package-discovery results.
    seeded: dict[str, tuple[Path, str]] = {}

    for path in all_files:
        rel = str(path.relative_to(root)).replace("\\", "/")
        if _basename_always_included(rel):
            seeded[rel] = (path, "always-included")

    packages = _setuptools_packages(root, toml)
    for pkg in packages:
        pkg_path = pkg.replace(".", "/")
        for path in all_files:
            rel = str(path.relative_to(root)).replace("\\", "/")
            if rel.startswith(pkg_path + "/") or rel.startswith("src/" + pkg_path + "/"):
                seeded.setdefault(rel, (path, "package-discovery"))

    lines = _read_manifest_in(root)
    if lines:
        return _apply_manifest_in(root, lines, all_files, seeded=seeded)
    return list(seeded.values())


def _wheel_paths(
    root: Path,
    toml: dict[str, Any],
    all_files: list[Path],
    backend: str,
) -> list[tuple[Path, str]]:
    """Resolve wheel contents — package source code only, no metadata files."""
    matched: list[tuple[Path, str]] = []

    if backend == "hatch":
        cfg = (
            toml.get("tool", {})
            .get("hatch", {})
            .get("build", {})
            .get("targets", {})
            .get("wheel", {})
        )
        packages: list[str] = (
            cfg.get("packages", []) if isinstance(cfg.get("packages"), list) else []
        )
    else:
        packages = _setuptools_packages(root, toml)

    if not packages:
        # Fall back to the project name as the package directory
        name, _ = _project_name_version(toml)
        if name:
            packages = [name.replace("-", "_")]

    for pkg in packages:
        pkg_path = str(pkg).replace(".", "/")
        for path in all_files:
            rel = str(path.relative_to(root)).replace("\\", "/")
            base = pkg_path.lstrip("./")
            if rel.startswith(base + "/") or rel == base + "/__init__.py":
                matched.append((path, "package-discovery"))

    return matched


def _deduplicate(matched: list[tuple[Path, str]]) -> list[tuple[Path, str]]:
    """Drop duplicates by path, keeping the first reason recorded."""
    seen: set[str] = set()
    out: list[tuple[Path, str]] = []
    for path, reason in matched:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append((path, reason))
    return out


def simulate_python(
    package_root: Path,
    *,
    target: Ecosystem = "python-sdist",
) -> PublishManifest:
    """Simulate a Python build for the given target ('python-sdist' or 'python-wheel')."""
    package_root = package_root.resolve()
    pyproject = package_root / "pyproject.toml"
    if not pyproject.is_file():
        raise FileNotFoundError(f"{pyproject} not found")

    toml_text = pyproject.read_text(encoding="utf-8", errors="replace")
    toml = load_toml(toml_text)
    if toml is None:
        return PublishManifest(
            ecosystem=target,
            package_root=str(package_root),
            warnings=["pyproject.toml is not valid TOML"],
        )

    name, version = _project_name_version(toml)
    backend = _detect_backend(toml)
    all_files = _walk(package_root)
    warnings: list[str] = []

    if backend == "unknown":
        warnings.append(
            "No build-system.build-backend declared — falling back to setuptools-style heuristics."
        )

    matched: list[tuple[Path, str]] = []
    if target == "python-sdist":
        if backend == "hatch":
            hatch_matched, include = _hatch_sdist_paths(package_root, toml, all_files)
            matched.extend(hatch_matched)
            if not include:
                warnings.append(
                    "Hatch sdist has no `include` patterns — only always-included root files are shipped."
                )
        else:
            matched.extend(_setuptools_sdist_paths(package_root, toml, all_files))
            if (
                not (package_root / "MANIFEST.in").is_file()
                and backend in {"setuptools", "unknown"}
                and not _setuptools_packages(package_root, toml)
            ):
                warnings.append(
                    "No MANIFEST.in and no package discovery configured — "
                    "sdist will only contain always-included root files."
                )
    elif target == "python-wheel":
        matched.extend(_wheel_paths(package_root, toml, all_files, backend))
        if not matched:
            warnings.append(
                "Could not resolve any package directory for the wheel — "
                "check `[tool.hatch.build.targets.wheel]` or `[tool.setuptools]`."
            )
    else:  # pragma: no cover — defensive
        raise ValueError(f"Unsupported target: {target!r}")

    matched = _deduplicate(matched)
    matched_paths = {p for p, _ in matched}

    files: list[PublishedFile] = []
    total = 0
    for path, reason in matched:
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        rel = str(path.relative_to(package_root)).replace("\\", "/")
        files.append(PublishedFile(path=rel, size_bytes=size, included_by=reason))
        total += size

    excluded: list[str] = []
    for path in all_files:
        if path in matched_paths:
            continue
        excluded.append(str(path.relative_to(package_root)).replace("\\", "/"))

    return PublishManifest(
        ecosystem=target,
        package_root=str(package_root),
        package_name=name,
        package_version=version,
        files=files,
        excluded=excluded,
        total_bytes=total,
        warnings=warnings,
    )
