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


class PackagingRule(Rule):
    id = "packaging"
    name = "Packaging Hygiene"
    description = "Detects files that should not be published in Python or Node packages"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        for path in files_to_check:
            rel = self._rel(context, path)

            if path.name == "package.json":
                findings.extend(self._check_package_json(path, rel, context))

            elif path.name == "pyproject.toml":
                findings.extend(self._check_pyproject(path, rel, context))

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
        """Flag .npmignore patterns that *negate* protective ignores."""
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return findings

        # Lines starting with `!` re-include files that would otherwise be ignored.
        # Re-including sensitive paths is a classic AI footprint pattern.
        for lineno, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line.startswith("!"):
                continue
            negate = line[1:].strip()
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
            "PKG-SETUPPYLEAK",
        ],
        default_severity="medium",
        confidence="high",
        tags=["packaging", "supply-chain"],
        applies_to=["package.json", "pyproject.toml", "MANIFEST.in", "setup.cfg", ".npmignore"],
    )
)
