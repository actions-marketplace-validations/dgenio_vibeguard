"""Dependency risk rule."""

from __future__ import annotations

import re
from pathlib import Path

from vibeguard.manifests import (
    LOCKFILE_TO_MANIFEST,
    node_dependency_versions,
    pyproject_dependency_specifiers,
)
from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# Common package names that are frequent typosquatting targets
_POPULAR_PACKAGES_NODE = {
    "lodash",
    "react",
    "express",
    "axios",
    "moment",
    "chalk",
    "debug",
    "commander",
    "yargs",
    "inquirer",
    "webpack",
    "babel",
    "eslint",
    "jest",
    "mocha",
    "chai",
    "sinon",
    "typescript",
    "prettier",
    "rollup",
    "vite",
}

_POPULAR_PACKAGES_PYTHON = {
    "requests",
    "numpy",
    "pandas",
    "flask",
    "django",
    "fastapi",
    "sqlalchemy",
    "pydantic",
    "click",
    "boto3",
    "urllib3",
    "pillow",
    "scipy",
    "matplotlib",
    "pytest",
    "setuptools",
    "pip",
    "wheel",
    "cryptography",
    "paramiko",
}

# Suspicious name patterns (typosquatting signals)
_TYPOSQUAT_RE = re.compile(
    r"(python-|py-|-python|-py|node-|-node|js-).*|.*(-js|js$)"
    r"|.*[0-9]{2,}.*"  # unusual number sequences
)

# URL / path / git dependency patterns for npm
_URL_DEP_RE = re.compile(r"^(https?://|git\+|git://|file:|\.\.?/)")

# Broad version constraint patterns
_BROAD_VERSION_RE = re.compile(r"^[*x]$|^\s*$")


def _is_suspicious_name(name: str, popular_set: set[str]) -> bool:
    """Heuristic: is this package name suspiciously similar to a popular one?"""
    name_lower = name.lower().replace("-", "").replace("_", "")
    for popular in popular_set:
        pop_lower = popular.lower().replace("-", "").replace("_", "")
        # Simple edit-distance check (1-2 char difference)
        if name_lower != pop_lower and _levenshtein(name_lower, pop_lower) <= 2:
            return True
    return False


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two strings (small strings only)."""
    if len(a) > 30 or len(b) > 30:
        return 99
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if a[i - 1] == b[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]


class DependenciesRule(Rule):
    id = "dependencies"
    name = "Dependency Risk"
    description = "Detects risky dependency changes: typosquatting, git deps, broad versions"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        for path in files_to_check:
            rel = self._rel(context, path)
            if path.name == "package.json":
                findings.extend(self._check_package_json(path, rel, context))
            elif path.name == "pyproject.toml":
                findings.extend(self._check_pyproject(path, rel, context))
            elif path.name in (".npmrc", "pip.conf"):
                findings.extend(self._check_registry_change(path, rel))

        # Diff-mode-only checks: lockfile vs manifest mismatch
        if context.diff_only and context.changed_files:
            findings.extend(self._check_lockfile_drift(context))

        return findings

    # ------------------------------------------------------------------
    # Node / npm
    # ------------------------------------------------------------------

    def _check_package_json(self, path: Path, rel: str, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return findings

        all_deps = node_dependency_versions(text)
        is_strict = context.config.policy == "strict"

        for name, version in all_deps.items():
            version_str = str(version)

            # URL / git / path dependencies
            if _URL_DEP_RE.match(version_str):
                findings.append(
                    Finding(
                        id="DEP-URLNODE",
                        rule=self.id,
                        title=f"URL/git/path dependency: {name}",
                        description=(
                            f"`{rel}`: dependency `{name}` uses a URL/git/path specifier "
                            f"(`{version_str[:80]}`). These bypass npm's integrity checks."
                        ),
                        severity=Severity.HIGH,
                        path=rel,
                        evidence=f"{name}: {version_str[:80]}",
                        recommendation=(
                            "Publish the dependency to a registry and use a versioned specifier."
                        ),
                        tags=["dependencies", "npm", "supply-chain"],
                        confidence=Confidence.HIGH,
                    )
                )

            # Broad version constraints in strict mode
            if is_strict and _BROAD_VERSION_RE.match(version_str):
                findings.append(
                    Finding(
                        id="DEP-BROADVER",
                        rule=self.id,
                        title=f"Unpinned dependency version: {name}",
                        description=(
                            f"`{rel}`: `{name}` has an overly broad version `{version_str}`. "
                            "This allows any version to be installed, including malicious updates."
                        ),
                        severity=Severity.MEDIUM,
                        path=rel,
                        evidence=f"{name}: {version_str}",
                        recommendation="Pin to a specific version or narrow version range.",
                        tags=["dependencies", "npm"],
                        confidence=Confidence.HIGH,
                    )
                )

            # Typosquatting heuristic
            if _is_suspicious_name(name, _POPULAR_PACKAGES_NODE):
                findings.append(
                    Finding(
                        id="DEP-TYPOSQUATNPM",
                        rule=self.id,
                        title=f"Possible typosquatting: {name}",
                        description=(
                            f"`{rel}`: `{name}` is suspiciously similar to a popular npm package. "
                            "This may be a typosquatting attack."
                        ),
                        severity=Severity.HIGH,
                        path=rel,
                        evidence=name,
                        recommendation="Verify this is the intended package on npmjs.com.",
                        tags=["dependencies", "npm", "typosquatting", "supply-chain"],
                        confidence=Confidence.LOW,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Python / pyproject.toml
    # ------------------------------------------------------------------

    def _check_pyproject(self, path: Path, rel: str, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        deps = pyproject_dependency_specifiers(path.read_text(encoding="utf-8"))
        is_strict = context.config.policy == "strict"

        for dep in deps:
            # Extract package name (before any version specifier)
            name = re.split(r"[>=<!;\s\[]", dep)[0].strip()
            if not name:
                continue

            # URL / VCS dependencies (e.g. git+https://...)
            if re.search(r"(git\+|https?://|file://|\.\.?/)", dep):
                findings.append(
                    Finding(
                        id="DEP-URLPYTHON",
                        rule=self.id,
                        title=f"URL/VCS dependency: {name}",
                        description=(
                            f"`{rel}`: dependency `{name}` uses a URL/VCS specifier. "
                            "These bypass PyPI integrity checks."
                        ),
                        severity=Severity.HIGH,
                        path=rel,
                        evidence=dep[:100],
                        recommendation=(
                            "Publish the package to PyPI and use a versioned specifier."
                        ),
                        tags=["dependencies", "python", "supply-chain"],
                        confidence=Confidence.HIGH,
                    )
                )

            # Broad / unpinned in strict mode
            if is_strict and not re.search(r"[>=<~!]", dep):
                findings.append(
                    Finding(
                        id="DEP-UNPINNEDPY",
                        rule=self.id,
                        title=f"Unpinned Python dependency: {name}",
                        description=(
                            f"`{rel}`: `{name}` has no version constraint. "
                            "This allows any version to be installed."
                        ),
                        severity=Severity.LOW,
                        path=rel,
                        evidence=dep[:100],
                        recommendation="Add a version constraint, e.g. `name>=1.0,<2.0`.",
                        tags=["dependencies", "python"],
                        confidence=Confidence.HIGH,
                    )
                )

            # Typosquatting
            if _is_suspicious_name(name, _POPULAR_PACKAGES_PYTHON):
                findings.append(
                    Finding(
                        id="DEP-TYPOSQUATPY",
                        rule=self.id,
                        title=f"Possible typosquatting: {name}",
                        description=(
                            f"`{rel}`: `{name}` is suspiciously similar to a popular PyPI package."
                        ),
                        severity=Severity.HIGH,
                        path=rel,
                        evidence=name,
                        recommendation="Verify this is the intended package on pypi.org.",
                        tags=["dependencies", "python", "typosquatting", "supply-chain"],
                        confidence=Confidence.LOW,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Lockfile drift checks (diff-mode only)
    # ------------------------------------------------------------------

    def _check_lockfile_drift(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        # Group changed files by directory for monorepo-safe pairing
        changed_by_dir: dict[Path, set[str]] = {}
        for p in context.changed_files:
            dir_key = p.parent
            if dir_key not in changed_by_dir:
                changed_by_dir[dir_key] = set()
            changed_by_dir[dir_key].add(p.name)

        for dir_path, names_in_dir in changed_by_dir.items():
            for lockfile, manifest in LOCKFILE_TO_MANIFEST.items():
                if lockfile in names_in_dir and manifest not in names_in_dir:
                    rel_lockfile = str(dir_path / lockfile)
                    findings.append(
                        Finding(
                            id="DEP-LOCKFILE-MISMATCH",
                            rule=self.id,
                            title=f"Lockfile changed without manifest: {lockfile}",
                            description=(
                                f"`{rel_lockfile}` was modified but `{manifest}` in the same "
                                "directory was not. This may indicate lockfile tampering or an "
                                "incomplete update."
                            ),
                            severity=Severity.MEDIUM,
                            path=rel_lockfile,
                            recommendation=(
                                "Verify the lockfile change is intentional. "
                                "Regenerate from the manifest if uncertain."
                            ),
                            tags=["dependencies", "lockfile", "supply-chain"],
                            confidence=Confidence.MEDIUM,
                        )
                    )
                elif manifest in names_in_dir and lockfile not in names_in_dir:
                    # Only flag if the lockfile actually exists in the repo
                    lockfile_path = dir_path / lockfile
                    if lockfile_path.exists():
                        rel_manifest = str(dir_path / manifest)
                        findings.append(
                            Finding(
                                id="DEP-MANIFEST-NO-LOCK",
                                rule=self.id,
                                title=f"Manifest changed without lockfile: {manifest}",
                                description=(
                                    f"`{rel_manifest}` was modified but `{lockfile}` in the "
                                    "same directory was not updated. The lockfile may be stale."
                                ),
                                severity=Severity.MEDIUM,
                                path=rel_manifest,
                                recommendation=(
                                    "Run the package manager's install/lock command to update "
                                    "the lockfile."
                                ),
                                tags=["dependencies", "lockfile"],
                                confidence=Confidence.MEDIUM,
                            )
                        )

        return findings

    # ------------------------------------------------------------------
    # Registry change detection
    # ------------------------------------------------------------------

    def _check_registry_change(self, path: Path, rel: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return findings

        # Look for non-standard registry URLs
        registry_re = re.compile(r"(?i)(registry\s*=|index-url\s*=|--index-url)\s*(https?://\S+)")
        for match in registry_re.finditer(content):
            url = match.group(2)
            # Standard registries are fine
            if "registry.npmjs.org" in url or "pypi.org" in url:
                continue
            findings.append(
                Finding(
                    id="DEP-REGISTRY-CHANGE",
                    rule=self.id,
                    title=f"Non-standard package registry: {path.name}",
                    description=(
                        f"`{rel}` configures a non-standard package registry: `{url[:80]}`. "
                        "Verify this is a trusted registry."
                    ),
                    severity=Severity.HIGH,
                    path=rel,
                    evidence=url[:100],
                    recommendation=(
                        "Ensure the registry is a trusted source. "
                        "Non-standard registries may serve malicious packages."
                    ),
                    tags=["dependencies", "supply-chain", "registry"],
                    confidence=Confidence.HIGH,
                )
            )

        return findings


register_rule(
    RuleMetadata(
        rule_id="dependencies",
        title="Dependency Risk",
        description=(
            "Detects risky dependency changes: typosquatting, git/URL deps, "
            "broad versions, lockfile drift, and registry changes."
        ),
        finding_ids=[
            "DEP-URLNODE",
            "DEP-BROADVER",
            "DEP-TYPOSQUATNPM",
            "DEP-URLPYTHON",
            "DEP-UNPINNEDPY",
            "DEP-TYPOSQUATPY",
            "DEP-LOCKFILE-MISMATCH",
            "DEP-MANIFEST-NO-LOCK",
            "DEP-REGISTRY-CHANGE",
        ],
        default_severity="high",
        confidence="medium",
        tags=["security", "supply-chain", "dependencies"],
        applies_to=["package.json", "pyproject.toml", ".npmrc", "pip.conf"],
        remediations={
            "DEP-URLNODE": (
                "Publish the dependency to a registry and use a versioned "
                "specifier (`name@^1.2.3`). Direct git/URL deps bypass "
                "lockfiles and integrity checks."
            ),
            "DEP-BROADVER": (
                "Tighten the version range. Avoid `*`/`x`/`latest` and prefer "
                "a `^1.2` or pinned `1.2.3` constraint."
            ),
            "DEP-TYPOSQUATNPM": (
                "Verify this is the package you intended. Check npmjs.com "
                "ownership and weekly downloads before installing. Replace "
                "with the canonical package if this was a typo."
            ),
            "DEP-URLPYTHON": (
                "Publish the dependency to PyPI and use a versioned "
                "specifier. URL/git installs have no integrity hash and skip "
                "wheel signing."
            ),
            "DEP-UNPINNEDPY": (
                "Add a version constraint (e.g. `name>=1.0,<2.0`). Unpinned "
                "deps make builds non-reproducible."
            ),
            "DEP-TYPOSQUATPY": (
                "Confirm the package name on pypi.org. Replace with the "
                "canonical package if this was a typo (`requests` not "
                "`requesst`, etc.)."
            ),
            "DEP-LOCKFILE-MISMATCH": (
                "Regenerate the lockfile so it matches the manifest "
                "(`npm install`/`poetry lock`). Drift between the two is how "
                "supply-chain attacks slip into CI."
            ),
            "DEP-MANIFEST-NO-LOCK": (
                "Commit a lockfile alongside the manifest. Without one, every "
                "install resolves transitives non-deterministically."
            ),
            "DEP-REGISTRY-CHANGE": (
                "Confirm the new registry/index URL is intentional and "
                "trusted. Document the change in the PR description and "
                "monitor build integrity logs after merge."
            ),
        },
    )
)
