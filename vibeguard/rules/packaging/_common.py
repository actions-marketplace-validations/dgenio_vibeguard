"""Shared infrastructure for the packaging rule's ecosystem modules (#201).

The packaging rule audits two largely independent domains — npm publish
semantics and Python sdist/wheel packaging — that share only a small amount of
machinery: the dangerous-pattern catalogue, the root-level artifact (coverage /
CI) leak detector, and a couple of path helpers. That shared machinery lives
here so :mod:`._npm` and :mod:`._python` can each stay focused on one ecosystem.

Finding ids, severities, and messages are byte-identical to the pre-split
single module — this is a pure file reorganisation.
"""

from __future__ import annotations

import json
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity

#: The rule id every packaging finding carries. Kept as a constant so the
#: ecosystem modules don't need a reference to the rule instance.
RULE_ID = "packaging"

# Patterns that should not be published.
DANGEROUS_INCLUDE_PATTERNS: list[tuple[str, str]] = [
    (r"\.env", "Environment files (.env)"),
    (r"\.github", "GitHub Actions / workflows"),
    (r"tests?/", "Test directories"),
    (r"__tests__", "Test directories (__tests__)"),
    (r"\.map$", "Source map files"),
    (r"coverage/", "Coverage reports"),
    (r"htmlcov/", "Coverage HTML reports"),
    (r"\.pytest_cache", "pytest cache"),
    (r"Makefile", "Makefile (dev tool)"),
    (r"docker-compose", "Docker Compose config"),
    (r"Dockerfile", "Dockerfile"),
    (r"\.secrets", "Secrets files"),
    (r"\.key$", "Private key files"),
    (r"\.pem$", "PEM certificate/key files"),
]

# Overly broad patterns that publish everything.
BROAD_PATTERNS = ["**", "*", "./", "."]

# Coverage artifact directories — present in many repos but never useful to ship.
COVERAGE_DIRS: tuple[tuple[str, str], ...] = (
    ("coverage", "JavaScript coverage report"),
    ("htmlcov", "Python coverage HTML report"),
    (".nyc_output", "nyc raw coverage data"),
    ("lcov-report", "LCOV HTML coverage report"),
    (".coverage", "coverage.py data file"),
)

# CI/CD configuration files and directories that frequently get swept into
# publish artifacts when no allowlist is configured.
CI_PATHS: tuple[tuple[str, str], ...] = (
    (".github", "GitHub Actions workflows"),
    (".circleci", "CircleCI configuration"),
    (".travis.yml", "Travis CI configuration"),
    (".gitlab-ci.yml", "GitLab CI configuration"),
    ("azure-pipelines.yml", "Azure Pipelines configuration"),
    ("bitbucket-pipelines.yml", "Bitbucket Pipelines configuration"),
    (".drone.yml", "Drone CI configuration"),
)


def rel(context: ScanContext, path: Path) -> str:
    """Return ``path`` relative to the scan root (mirrors ``Rule._rel``)."""
    try:
        return str(path.relative_to(context.root))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# Root-level artifact leak detection (coverage, CI) — shared by both ecosystems
# ---------------------------------------------------------------------------


def check_root_artifacts(pkg_root: Path, context: ScanContext, *, ecosystem: str) -> list[Finding]:
    """Flag coverage and CI artifacts at a package root that aren't excluded.

    The check runs once per package root (gated by the caller). For npm
    packages we consult ``.npmignore`` plus the ``files`` allowlist in
    ``package.json``; for Python packages we consult ``MANIFEST.in``.
    ``.gitignore`` is intentionally not consulted — npm honours it as a
    fallback when no ``.npmignore`` is present, but Python packaging does not,
    and "ignored from git" is a much weaker signal than "explicitly excluded
    from the publish set".
    """
    findings: list[Finding] = []

    exclusions = _collect_root_exclusions(pkg_root, ecosystem=ecosystem)
    allowlist = _collect_root_allowlist(pkg_root, ecosystem=ecosystem)

    rel_root = rel(context, pkg_root)

    # Coverage artifacts
    for name, label in COVERAGE_DIRS:
        artifact = pkg_root / name
        if not artifact.exists():
            continue
        if _is_root_artifact_excluded(name, exclusions, allowlist):
            continue
        rel_artifact = rel(context, artifact)
        findings.append(
            Finding(
                id="PKG-COVERAGE-LEAK",
                rule=RULE_ID,
                title=f"{label} present at package root: {name}",
                description=(
                    f"`{rel_root}` contains `{name}` ({label}) and no "
                    "`.npmignore`/`MANIFEST.in`/`files` rule excludes it. "
                    "Publishing coverage artifacts wastes bandwidth and may "
                    "leak filenames, branch names, or commit metadata."
                ),
                severity=Severity.LOW,
                path=rel_artifact,
                evidence=rel_artifact,
                recommendation=_root_exclusion_hint(name, artifact),
                tags=["packaging", "leak", "coverage"],
                confidence=Confidence.HIGH,
            )
        )

    # CI configuration
    for name, label in CI_PATHS:
        artifact = pkg_root / name
        if not artifact.exists():
            continue
        if _is_root_artifact_excluded(name, exclusions, allowlist):
            continue
        rel_artifact = rel(context, artifact)
        findings.append(
            Finding(
                id="PKG-CI-LEAK",
                rule=RULE_ID,
                title=f"{label} present at package root: {name}",
                description=(
                    f"`{rel_root}` ships `{name}` ({label}) because no ignore "
                    "rule excludes it and there is no `files` allowlist. CI "
                    "configuration occasionally embeds secrets, internal "
                    "URLs, or runner setup that should not reach the registry."
                ),
                severity=Severity.LOW,
                path=rel_artifact,
                evidence=rel_artifact,
                recommendation=_root_exclusion_hint(name, artifact),
                tags=["packaging", "leak", "ci"],
                confidence=Confidence.HIGH,
            )
        )

    return findings


def _root_exclusion_hint(name: str, artifact: Path) -> str:
    """Build a correct publish-exclusion recommendation for a root artifact.

    ``MANIFEST.in`` uses ``prune`` for directory trees and ``exclude`` for
    individual files — ``prune`` silently matches nothing for a file.
    """
    if artifact.is_dir():
        manifest = f"a `prune {name}` directive in `MANIFEST.in`"
        target = "directory"
    else:
        manifest = f"an `exclude {name}` directive in `MANIFEST.in`"
        target = "file"
    return (
        f"Add `{name}` to your `.npmignore`, add {manifest}, or exclude it "
        f"via the `package.json` `files` allowlist — or remove the {target}."
    )


def _collect_root_exclusions(pkg_root: Path, *, ecosystem: str) -> set[str]:
    """Return the set of top-level names that ignore files explicitly exclude.

    Only top-level basenames are tracked — that's the only granularity we need
    to decide whether a root artifact like ``coverage/`` or ``.github/`` would
    survive a publish. Pattern matching beyond literal equality (e.g. globs in
    ``.npmignore``) is intentionally out of scope and falls back to the
    dedicated MANIFEST.in / package.json rules.
    """
    names: set[str] = set()
    if ecosystem == "npm":
        names.update(_parse_gitignore_style(pkg_root / ".npmignore"))
    elif ecosystem == "python":
        names.update(_parse_manifest_excludes(pkg_root / "MANIFEST.in"))
    return names


def _collect_root_allowlist(pkg_root: Path, *, ecosystem: str) -> set[str] | None:
    """Return the set of top-level names explicitly allowed for publish.

    Returns ``None`` when no allowlist is configured. ``None`` means "we cannot
    decide from an allowlist whether this artifact is excluded" — the caller
    then falls back to checking the exclusion list.
    """
    if ecosystem != "npm":
        return None
    pkg_json = pkg_root / "package.json"
    if not pkg_json.exists():
        return None
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    files = data.get("files")
    if not isinstance(files, list) or not files:
        return None
    out: set[str] = set()
    for entry in files:
        if not isinstance(entry, str):
            continue
        # Reduce to the leading path component so that `dist/`, `dist`,
        # `./dist`, and `dist/*` all collapse to `dist` for comparison.
        cleaned = entry.strip()
        if cleaned.startswith("./"):
            cleaned = cleaned[2:]
        cleaned = cleaned.rstrip("/")
        if not cleaned:
            continue
        head = cleaned.split("/", 1)[0]
        out.add(head)
    return out


def _is_root_artifact_excluded(name: str, exclusions: set[str], allowlist: set[str] | None) -> bool:
    """Return True when a top-level artifact would not survive publish."""
    # An npm `files` allowlist makes publication exclusive: anything not listed
    # (or listed via its head component) stays out. We deliberately use the head
    # component (see ``_collect_root_allowlist``) because npm's allowlist
    # matches against directory roots.
    if allowlist is not None and name not in allowlist:
        return True
    return name in exclusions


def _parse_gitignore_style(path: Path) -> set[str]:
    """Return the set of top-level literal names ignored by a `.npmignore`.

    We only honour bare names (e.g. ``coverage``, ``coverage/``, ``/coverage``)
    and skip negations / globs — the dedicated PKG-NPMIGNORE-* checks already
    audit those independently. The goal here is a tight "did the user
    explicitly exclude this exact path" check, not a full gitignore matcher.
    """
    if not path.exists():
        return set()
    names: set[str] = set()
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            # gitignore allows a leading `/` to anchor to the repo root; for our
            # literal-basename matching, an anchored entry is equivalent to its
            # un-anchored form.
            cleaned = line[1:] if line.startswith("/") else line
            cleaned = cleaned.rstrip("/")
            # A literal top-level name has no remaining slashes. Anything nested
            # or globbed is left for the dedicated checks.
            if not cleaned or "/" in cleaned or "*" in cleaned or "?" in cleaned:
                continue
            names.add(cleaned)
    except OSError:
        return names
    return names


def _parse_manifest_excludes(path: Path) -> set[str]:
    """Return the set of top-level names explicitly pruned from a sdist.

    Only ``prune`` / ``recursive-exclude`` / ``exclude`` directives that target
    a literal top-level basename are honoured. Glob-only directives like
    ``global-exclude *.pyc`` are ignored on purpose — they don't tell us whether
    a specific directory artifact would be excluded.
    """
    if not path.exists():
        return set()
    names: set[str] = set()
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if not parts:
                continue
            cmd = parts[0].lower()
            args = parts[1:]
            if cmd in {"prune", "exclude"} and args:
                for arg in args:
                    cleaned = arg[2:] if arg.startswith("./") else arg
                    cleaned = cleaned.rstrip("/")
                    if cleaned and "/" not in cleaned and "*" not in cleaned:
                        names.add(cleaned)
            elif cmd == "recursive-exclude" and args:
                cleaned = args[0][2:] if args[0].startswith("./") else args[0]
                cleaned = cleaned.rstrip("/")
                if cleaned and "/" not in cleaned and "*" not in cleaned:
                    names.add(cleaned)
    except OSError:
        return names
    return names
