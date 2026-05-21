"""Packaging hygiene rule — detect publish leaks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule


# Lazily load tomllib/tomli
def _load_toml(text: str) -> dict[str, Any] | None:
    """Parse TOML text, returning None if no TOML parser is available."""
    try:
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        return tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return None


# Patterns that should not be published
_DANGEROUS_INCLUDE_PATTERNS = [
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

# Overly broad patterns that publish everything
_BROAD_PATTERNS = ["**", "*", "./", "."]

# Coverage artifact directories — present in many repos but never useful to ship.
# Keyed by display label so the finding message tells the reader what they have.
_COVERAGE_DIRS: tuple[tuple[str, str], ...] = (
    ("coverage", "JavaScript coverage report"),
    ("htmlcov", "Python coverage HTML report"),
    (".nyc_output", "nyc raw coverage data"),
    ("lcov-report", "LCOV HTML coverage report"),
    (".coverage", "coverage.py data file"),
)

# CI/CD configuration files and directories that frequently get swept into
# publish artifacts when no allowlist is configured.
_CI_PATHS: tuple[tuple[str, str], ...] = (
    (".github", "GitHub Actions workflows"),
    (".circleci", "CircleCI configuration"),
    (".travis.yml", "Travis CI configuration"),
    (".gitlab-ci.yml", "GitLab CI configuration"),
    ("azure-pipelines.yml", "Azure Pipelines configuration"),
    ("bitbucket-pipelines.yml", "Bitbucket Pipelines configuration"),
    (".drone.yml", "Drone CI configuration"),
)

# `.npmignore` re-include patterns whose effect is to defeat the protective
# default of "ignore everything except the allowlist". These never overlap
# with the secret-negation patterns caught by PKG-NPMIGNORE-NEGATE.
_BROAD_NPMIGNORE_NEGATIONS: frozenset[str] = frozenset({"*", "**", "**/*", "/", "./", "."})

# npm lifecycle scripts that can produce additional, unexpected files at
# publish time. `prepare` and `prepack` run *before* the tarball is built, so
# whatever they write lands inside the published artifact unless explicitly
# excluded.
_PUBLISH_TIME_SCRIPTS: tuple[str, ...] = ("prepare", "prepack")


class PackagingRule(Rule):
    id = "packaging"
    name = "Packaging Hygiene"
    description = "Detects files that should not be published in Python or Node packages"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        # `package.json` / `pyproject.toml` are the publish-entry manifests we
        # use to anchor leakage checks. Track which package roots we've already
        # audited so a monorepo with multiple manifests still produces one set
        # of root-level findings per package (not N copies).
        audited_roots: set[Path] = set()

        for path in files_to_check:
            rel = self._rel(context, path)

            if path.name == "package.json":
                findings.extend(self._check_package_json(path, rel, context))
                pkg_root = path.parent
                if pkg_root not in audited_roots:
                    audited_roots.add(pkg_root)
                    findings.extend(self._check_root_artifacts(pkg_root, context, ecosystem="npm"))

            elif path.name == "pyproject.toml":
                findings.extend(self._check_pyproject(path, rel, context))
                pkg_root = path.parent
                if pkg_root not in audited_roots:
                    audited_roots.add(pkg_root)
                    findings.extend(
                        self._check_root_artifacts(pkg_root, context, ecosystem="python")
                    )

            elif path.name == "MANIFEST.in":
                findings.extend(self._check_manifest_in(path, rel))

            elif path.name == "setup.cfg":
                findings.extend(self._check_setup_cfg(path, rel))

            elif path.name == ".npmignore":
                findings.extend(self._check_npmignore(path, rel))

        return findings

    # ------------------------------------------------------------------
    # Node / npm
    # ------------------------------------------------------------------

    def _check_package_json(self, path: Path, rel: str, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return findings

        pkg_files: list[str] = data.get("files", [])
        if not pkg_files:
            # No "files" whitelist — everything gets published by default
            # Check if there is an .npmignore
            npmignore = path.parent / ".npmignore"
            if not npmignore.exists():
                findings.append(
                    Finding(
                        id="PKG-NPMFILES",
                        rule=self.id,
                        title="package.json has no 'files' allowlist or .npmignore",
                        description=(
                            f"`{rel}` does not define a `files` field and there is no "
                            "`.npmignore`. Everything in the package directory will be "
                            "published to npm, including tests, dotfiles, and secrets."
                        ),
                        severity=Severity.MEDIUM,
                        path=rel,
                        recommendation=(
                            "Add a `files` array to package.json listing only what should "
                            "be published, or create a `.npmignore` with appropriate exclusions."
                        ),
                        tags=["packaging", "npm"],
                        confidence=Confidence.HIGH,
                    )
                )
        else:
            for pattern in pkg_files:
                if pattern in _BROAD_PATTERNS:
                    findings.append(
                        Finding(
                            id="PKG-NPMBROAD",
                            rule=self.id,
                            title=f"Overly broad npm 'files' pattern: {pattern!r}",
                            description=(
                                f"`{rel}` has the pattern `{pattern}` in its `files` field, "
                                "which publishes everything."
                            ),
                            severity=Severity.HIGH,
                            path=rel,
                            evidence=pattern,
                            recommendation=(
                                "Replace the broad pattern with an explicit list of files/dirs to publish."
                            ),
                            tags=["packaging", "npm"],
                            confidence=Confidence.HIGH,
                        )
                    )
                for danger_re, label in _DANGEROUS_INCLUDE_PATTERNS:
                    if re.search(danger_re, pattern, re.IGNORECASE):
                        findings.append(
                            Finding(
                                id="PKG-NPMLEAK",
                                rule=self.id,
                                title=f"npm package may publish {label}",
                                description=(
                                    f"`{rel}` includes pattern `{pattern}` in `files`, "
                                    f"which may publish {label}."
                                ),
                                severity=Severity.HIGH,
                                path=rel,
                                evidence=pattern,
                                recommendation=f"Remove `{pattern}` from the npm `files` list.",
                                tags=["packaging", "npm", "leak"],
                                confidence=Confidence.MEDIUM,
                            )
                        )

        # Detect `prepare` / `prepack` scripts. Both run *before* npm builds
        # the publish tarball, so any files they emit ride along unless the
        # package has a tight `files` allowlist or a corresponding ignore
        # entry. The scripts themselves are not bad — we flag them as a
        # reminder to audit what they write.
        scripts: dict = data.get("scripts") or {}
        for script_name in _PUBLISH_TIME_SCRIPTS:
            cmd = scripts.get(script_name)
            if not cmd or not isinstance(cmd, str):
                continue
            findings.append(
                Finding(
                    id="PKG-PREPARE-SCRIPT",
                    rule=self.id,
                    title=f"package.json runs `{script_name}` at publish time",
                    description=(
                        f"`{rel}` defines a `{script_name}` script (`{cmd}`) which npm "
                        "executes before building the publish tarball. Any files written "
                        "by the script will be included in the published package unless "
                        "explicitly excluded by `files` or `.npmignore`."
                    ),
                    severity=Severity.LOW,
                    path=rel,
                    evidence=f"{script_name}: {cmd}",
                    recommendation=(
                        f"Audit what `{script_name}` writes. Move build output to a "
                        "dedicated directory you list in `files`, or add an "
                        "explicit `.npmignore` rule for generated artifacts."
                    ),
                    tags=["packaging", "npm", "lifecycle"],
                    confidence=Confidence.HIGH,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Python / pyproject.toml
    # ------------------------------------------------------------------

    def _check_pyproject(self, path: Path, rel: str, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        data = _load_toml(path.read_text(encoding="utf-8"))
        if data is None:
            return findings

        # Check [tool.hatch.build.targets.sdist] / [tool.setuptools.package-data]
        # or the simpler include patterns
        tool = data.get("tool", {})

        # Hatch
        hatch_include = (
            tool.get("hatch", {})
            .get("build", {})
            .get("targets", {})
            .get("sdist", {})
            .get("include", [])
        )
        findings.extend(self._audit_include_list(hatch_include, rel, "hatch sdist include"))

        # Setuptools find_packages with include all is fine, but check for explicit bad patterns
        setuptools = tool.get("setuptools", {})
        pkg_data: dict = setuptools.get("package-data", {})
        for pkg, patterns in pkg_data.items():
            for pattern in patterns:
                for danger_re, label in _DANGEROUS_INCLUDE_PATTERNS:
                    if re.search(danger_re, pattern, re.IGNORECASE):
                        findings.append(
                            Finding(
                                id="PKG-PYLEAK",
                                rule=self.id,
                                title=f"pyproject.toml package-data may include {label}",
                                description=(
                                    f"`{rel}` includes `{pattern}` in package-data for `{pkg}`, "
                                    f"which may publish {label}."
                                ),
                                severity=Severity.MEDIUM,
                                path=rel,
                                evidence=pattern,
                                recommendation=f"Remove `{pattern}` from package-data.",
                                tags=["packaging", "python", "leak"],
                                confidence=Confidence.MEDIUM,
                            )
                        )

        return findings

    def _audit_include_list(self, patterns: list, rel: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in patterns:
            if str(pattern) in _BROAD_PATTERNS:
                findings.append(
                    Finding(
                        id="PKG-PYBROAD",
                        rule=self.id,
                        title=f"Overly broad include pattern in {source}: {pattern!r}",
                        description=(
                            f"`{rel}` has pattern `{pattern}` in `{source}`, "
                            "which may publish unintended files."
                        ),
                        severity=Severity.MEDIUM,
                        path=rel,
                        evidence=str(pattern),
                        recommendation="Use explicit include patterns instead of broad wildcards.",
                        tags=["packaging", "python"],
                        confidence=Confidence.MEDIUM,
                    )
                )
            for danger_re, label in _DANGEROUS_INCLUDE_PATTERNS:
                if re.search(danger_re, str(pattern), re.IGNORECASE):
                    findings.append(
                        Finding(
                            id="PKG-PYLEAK",
                            rule=self.id,
                            title=f"pyproject.toml may publish {label}",
                            description=(
                                f"`{rel}` includes `{pattern}` in `{source}`, "
                                f"which may publish {label}."
                            ),
                            severity=Severity.MEDIUM,
                            path=rel,
                            evidence=str(pattern),
                            recommendation=f"Remove `{pattern}` from `{source}`.",
                            tags=["packaging", "python", "leak"],
                            confidence=Confidence.MEDIUM,
                        )
                    )
        return findings

    # ------------------------------------------------------------------
    # MANIFEST.in
    # ------------------------------------------------------------------

    def _check_manifest_in(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return findings

        for lineno, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            cmd = parts[0].lower() if parts else ""
            args = parts[1:]

            # `graft <dir>` recursively includes everything under <dir>; flag overly broad grafts.
            if cmd == "graft" and args:
                for arg in args:
                    if arg in {".", "./", "*", "**"}:
                        findings.append(
                            Finding(
                                id="PKG-MANIFEST-GRAFT",
                                rule=self.id,
                                title=f"Overly broad `graft` in MANIFEST.in: {arg!r}",
                                description=(
                                    f"`{rel}` line {lineno}: `graft {arg}` will include the "
                                    "entire repository in the sdist, including dotfiles, "
                                    "tests, secrets, and CI configuration."
                                ),
                                severity=Severity.HIGH,
                                path=rel,
                                line=lineno,
                                evidence=line,
                                recommendation=(
                                    "Restrict the graft to specific package directories."
                                ),
                                tags=["packaging", "python", "leak"],
                                confidence=Confidence.HIGH,
                            )
                        )

            # `recursive-include <dir> <glob>` with `*` is fine; with no constraint it sweeps everything.
            if cmd == "recursive-include" and len(args) >= 2:
                base = args[0]
                globs = args[1:]
                if base in {".", "./"} and any(g in {"*", "**", "*.*"} for g in globs):
                    findings.append(
                        Finding(
                            id="PKG-MANIFEST-RECURSIVE",
                            rule=self.id,
                            title=(
                                f"Overly broad `recursive-include` in MANIFEST.in: "
                                f"{base} {' '.join(globs)}"
                            ),
                            description=(
                                f"`{rel}` line {lineno}: `recursive-include {base} {' '.join(globs)}` "
                                "matches every file in the repository — including dotfiles, "
                                "tests, and credentials."
                            ),
                            severity=Severity.HIGH,
                            path=rel,
                            line=lineno,
                            evidence=line,
                            recommendation=(
                                "Restrict the recursive-include to a specific subdirectory and "
                                "pattern, e.g. `recursive-include src/your_pkg *.py`."
                            ),
                            tags=["packaging", "python", "leak"],
                            confidence=Confidence.HIGH,
                        )
                    )

            # `global-include` of unbounded patterns reaches every directory.
            if cmd == "global-include" and args and any(g in {"*", "**", "*.*"} for g in args):
                findings.append(
                    Finding(
                        id="PKG-MANIFEST-RECURSIVE",
                        rule=self.id,
                        title=f"Overly broad `global-include` in MANIFEST.in: {' '.join(args)}",
                        description=(
                            f"`{rel}` line {lineno}: `global-include {' '.join(args)}` "
                            "matches every file in every directory of the sdist."
                        ),
                        severity=Severity.HIGH,
                        path=rel,
                        line=lineno,
                        evidence=line,
                        recommendation=(
                            "Replace with `global-include <specific>.py` or remove the directive."
                        ),
                        tags=["packaging", "python", "leak"],
                        confidence=Confidence.HIGH,
                    )
                )

            for danger_re, label in _DANGEROUS_INCLUDE_PATTERNS:
                if re.search(danger_re, line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            id="PKG-MANIFESTLEAK",
                            rule=self.id,
                            title=f"MANIFEST.in may include {label}",
                            description=(
                                f"`{rel}` line {lineno}: `{line}` may include {label} "
                                "in the sdist distribution."
                            ),
                            severity=Severity.MEDIUM,
                            path=rel,
                            line=lineno,
                            evidence=line,
                            recommendation=f"Remove or restrict the pattern `{line}` in MANIFEST.in.",
                            tags=["packaging", "python", "leak"],
                            confidence=Confidence.MEDIUM,
                        )
                    )
                    break

        return findings

    # ------------------------------------------------------------------
    # .npmignore
    # ------------------------------------------------------------------

    def _check_npmignore(self, path: Path, rel: str) -> list[Finding]:
        """Flag overly broad and protective-undoing patterns in .npmignore."""
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return findings

        # Lines starting with `!` re-include files that would otherwise be ignored.
        # Re-including sensitive paths is a classic AI footprint pattern.
        for lineno, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("!"):
                continue
            negate = line[1:].strip()

            # `!*`, `!**`, `!/` and friends wipe out every preceding ignore
            # rule in the file — there is no legitimate reason to undo every
            # protective default at once. This is distinct from the targeted
            # `!.env`-style pattern caught by PKG-NPMIGNORE-NEGATE.
            if negate in _BROAD_NPMIGNORE_NEGATIONS:
                findings.append(
                    Finding(
                        id="PKG-NPMIGNORE-BROAD",
                        rule=self.id,
                        title=f"Overly broad .npmignore negation: {line!r}",
                        description=(
                            f"`{rel}` line {lineno}: the negation pattern `{line}` "
                            "re-includes every file in the package, defeating the "
                            "purpose of having an `.npmignore` file at all."
                        ),
                        severity=Severity.MEDIUM,
                        path=rel,
                        line=lineno,
                        evidence=line,
                        recommendation=(
                            "Replace the broad negation with explicit re-inclusion "
                            "patterns for the specific files you intended to ship."
                        ),
                        tags=["packaging", "npm", "leak"],
                        confidence=Confidence.HIGH,
                    )
                )
                # Fall through so PKG-NPMIGNORE-NEGATE may also fire if the
                # broad negation overlaps a dangerous-pattern match (unlikely
                # in practice but harmless to surface both).

            for danger_re, label in _DANGEROUS_INCLUDE_PATTERNS:
                if re.search(danger_re, negate, re.IGNORECASE):
                    findings.append(
                        Finding(
                            id="PKG-NPMIGNORE-NEGATE",
                            rule=self.id,
                            title=f".npmignore re-includes {label}: {line!r}",
                            description=(
                                f"`{rel}` line {lineno}: the negation pattern `{line}` "
                                f"re-includes {label} into the npm package, undoing a "
                                "protective ignore rule."
                            ),
                            severity=Severity.HIGH,
                            path=rel,
                            line=lineno,
                            evidence=line,
                            recommendation=(
                                f"Remove the `{line}` line so the protective ignore stays in effect."
                            ),
                            tags=["packaging", "npm", "leak"],
                            confidence=Confidence.HIGH,
                        )
                    )
                    break

        return findings

    # ------------------------------------------------------------------
    # Root-level artifact leak detection (coverage, CI)
    # ------------------------------------------------------------------

    def _check_root_artifacts(
        self, pkg_root: Path, context: ScanContext, *, ecosystem: str
    ) -> list[Finding]:
        """Flag coverage and CI artifacts at a package root that aren't excluded.

        The check runs once per package root (gated by the caller). For npm
        packages we consult `.npmignore` plus the `files` allowlist in
        ``package.json``; for Python packages we consult ``MANIFEST.in``.
        ``.gitignore`` is intentionally not consulted — npm honours it as a
        fallback when no `.npmignore` is present, but Python packaging does
        not, and "ignored from git" is a much weaker signal than "explicitly
        excluded from the publish set".
        """
        del context  # reserved for future per-file diff filtering
        findings: list[Finding] = []

        exclusions = self._collect_root_exclusions(pkg_root, ecosystem=ecosystem)
        allowlist = self._collect_root_allowlist(pkg_root, ecosystem=ecosystem)

        rel_root = self._format_root(pkg_root)

        # Coverage artifacts
        for name, label in _COVERAGE_DIRS:
            artifact = pkg_root / name
            if not artifact.exists():
                continue
            if self._is_root_artifact_excluded(name, exclusions, allowlist):
                continue
            findings.append(
                Finding(
                    id="PKG-COVERAGE-LEAK",
                    rule=self.id,
                    title=f"{label} present at package root: {name}",
                    description=(
                        f"`{rel_root}` contains `{name}` ({label}) and no "
                        "`.npmignore`/`MANIFEST.in`/`files` rule excludes it. "
                        "Publishing coverage artifacts wastes bandwidth and may "
                        "leak filenames, branch names, or commit metadata."
                    ),
                    severity=Severity.LOW,
                    path=name,
                    evidence=name,
                    recommendation=(
                        f"Add `{name}` to your `.npmignore` / `MANIFEST.in` "
                        f"`prune {name}` directive, or remove the directory."
                    ),
                    tags=["packaging", "leak", "coverage"],
                    confidence=Confidence.HIGH,
                )
            )

        # CI configuration
        for name, label in _CI_PATHS:
            artifact = pkg_root / name
            if not artifact.exists():
                continue
            if self._is_root_artifact_excluded(name, exclusions, allowlist):
                continue
            findings.append(
                Finding(
                    id="PKG-CI-LEAK",
                    rule=self.id,
                    title=f"{label} present at package root: {name}",
                    description=(
                        f"`{rel_root}` ships `{name}` ({label}) because no ignore "
                        "rule excludes it and there is no `files` allowlist. CI "
                        "configuration occasionally embeds secrets, internal "
                        "URLs, or runner setup that should not reach the registry."
                    ),
                    severity=Severity.LOW,
                    path=name,
                    evidence=name,
                    recommendation=(
                        f"Add `{name}` to `.npmignore` / `MANIFEST.in` "
                        f"`prune {name}`, or tighten the `files` allowlist."
                    ),
                    tags=["packaging", "leak", "ci"],
                    confidence=Confidence.HIGH,
                )
            )

        return findings

    @staticmethod
    def _format_root(pkg_root: Path) -> str:
        try:
            return str(pkg_root.relative_to(Path.cwd())) or "."
        except ValueError:
            return str(pkg_root)

    def _collect_root_exclusions(self, pkg_root: Path, *, ecosystem: str) -> set[str]:
        """Return the set of top-level names that ignore files explicitly exclude.

        Only top-level basenames are tracked — that's the only granularity we
        need to decide whether a root artifact like ``coverage/`` or
        ``.github/`` would survive a publish. Pattern matching beyond literal
        equality (e.g. globs in ``.npmignore``) is intentionally out of scope
        and falls back to the dedicated MANIFEST.in / package.json rules.
        """
        names: set[str] = set()
        if ecosystem == "npm":
            names.update(self._parse_gitignore_style(pkg_root / ".npmignore"))
        elif ecosystem == "python":
            names.update(self._parse_manifest_excludes(pkg_root / "MANIFEST.in"))
        return names

    def _collect_root_allowlist(self, pkg_root: Path, *, ecosystem: str) -> set[str] | None:
        """Return the set of top-level names explicitly allowed for publish.

        Returns ``None`` when no allowlist is configured. ``None`` means "we
        cannot decide from an allowlist whether this artifact is excluded" —
        the caller then falls back to checking the exclusion list.
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

    @staticmethod
    def _is_root_artifact_excluded(
        name: str, exclusions: set[str], allowlist: set[str] | None
    ) -> bool:
        """Return True when a top-level artifact would not survive publish."""
        # An npm `files` allowlist makes publication exclusive: anything not
        # listed (or listed via its head component) stays out. We deliberately
        # use the head component (see ``_collect_root_allowlist``) because
        # npm's allowlist matches against directory roots.
        if allowlist is not None and name not in allowlist:
            return True
        return name in exclusions

    @staticmethod
    def _parse_gitignore_style(path: Path) -> set[str]:
        """Return the set of top-level literal names ignored by a `.npmignore`.

        We only honour bare names (e.g. ``coverage``, ``coverage/``,
        ``/coverage``) and skip negations / globs — the dedicated
        PKG-NPMIGNORE-* checks already audit those independently. The goal
        here is a tight "did the user explicitly exclude this exact path"
        check, not a full gitignore matcher.
        """
        if not path.exists():
            return set()
        names: set[str] = set()
        try:
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                # gitignore allows a leading `/` to anchor to the repo root;
                # for our literal-basename matching, an anchored entry is
                # equivalent to its un-anchored form.
                cleaned = line[1:] if line.startswith("/") else line
                cleaned = cleaned.rstrip("/")
                # A literal top-level name has no remaining slashes. Anything
                # nested or globbed is left for the dedicated checks.
                if not cleaned or "/" in cleaned or "*" in cleaned or "?" in cleaned:
                    continue
                names.add(cleaned)
        except OSError:
            return names
        return names

    @staticmethod
    def _parse_manifest_excludes(path: Path) -> set[str]:
        """Return the set of top-level names explicitly pruned from a sdist.

        Only ``prune`` / ``recursive-exclude`` / ``exclude`` directives that
        target a literal top-level basename are honoured. Glob-only directives
        like ``global-exclude *.pyc`` are ignored on purpose — they don't tell
        us whether a specific directory artifact would be excluded.
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

    # ------------------------------------------------------------------
    # setup.cfg
    # ------------------------------------------------------------------

    def _check_setup_cfg(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            import configparser

            cfg = configparser.ConfigParser()
            cfg.read_string(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return findings

        # Check [options.package_data]
        if cfg.has_section("options.package_data"):
            for _pkg, patterns_str in cfg.items("options.package_data"):
                for pattern in patterns_str.split():
                    for danger_re, label in _DANGEROUS_INCLUDE_PATTERNS:
                        if re.search(danger_re, pattern, re.IGNORECASE):
                            findings.append(
                                Finding(
                                    id="PKG-SETUPPYLEAK",
                                    rule=self.id,
                                    title=f"setup.cfg package_data may include {label}",
                                    description=(
                                        f"`{rel}` includes `{pattern}` in `options.package_data`, "
                                        f"which may publish {label}."
                                    ),
                                    severity=Severity.MEDIUM,
                                    path=rel,
                                    evidence=pattern,
                                    recommendation=f"Remove `{pattern}` from options.package_data.",
                                    tags=["packaging", "python", "leak"],
                                    confidence=Confidence.MEDIUM,
                                )
                            )

        return findings


register_rule(
    RuleMetadata(
        rule_id="packaging",
        title="Packaging Hygiene",
        description=(
            "Detects files that should not be published in npm/PyPI packages: "
            "secrets, test data, build configs, source maps."
        ),
        finding_ids=[
            "PKG-NPMFILES",
            "PKG-NPMBROAD",
            "PKG-NPMLEAK",
            "PKG-PYBROAD",
            "PKG-PYLEAK",
            "PKG-MANIFESTLEAK",
            "PKG-MANIFEST-GRAFT",
            "PKG-MANIFEST-RECURSIVE",
            "PKG-NPMIGNORE-NEGATE",
            "PKG-NPMIGNORE-BROAD",
            "PKG-COVERAGE-LEAK",
            "PKG-CI-LEAK",
            "PKG-PREPARE-SCRIPT",
            "PKG-SETUPPYLEAK",
        ],
        default_severity="medium",
        confidence="high",
        tags=["packaging", "supply-chain"],
        applies_to=["package.json", "pyproject.toml", "MANIFEST.in", "setup.cfg", ".npmignore"],
    )
)
