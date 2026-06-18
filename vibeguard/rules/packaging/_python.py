"""Python sdist/wheel packaging-hygiene checks for the packaging rule (#201).

Covers ``pyproject.toml`` (hatch sdist include, setuptools package-data),
``MANIFEST.in`` (broad grafts / recursive-includes / leaky patterns), and
``setup.cfg`` (``options.package_data``).
"""

from __future__ import annotations

import re
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules._util import load_toml
from vibeguard.rules.packaging._common import (
    BROAD_PATTERNS,
    DANGEROUS_INCLUDE_PATTERNS,
    RULE_ID,
)


def check_pyproject(path: Path, rel: str, context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    data = load_toml(path.read_text(encoding="utf-8"))
    if data is None:
        return findings

    # Check [tool.hatch.build.targets.sdist] / [tool.setuptools.package-data]
    # or the simpler include patterns.
    tool = data.get("tool", {})

    # Hatch
    hatch_include = (
        tool.get("hatch", {})
        .get("build", {})
        .get("targets", {})
        .get("sdist", {})
        .get("include", [])
    )
    findings.extend(audit_include_list(hatch_include, rel, "hatch sdist include"))

    # Setuptools find_packages with include all is fine, but check for explicit
    # bad patterns.
    setuptools = tool.get("setuptools", {})
    pkg_data: dict = setuptools.get("package-data", {})
    for pkg, patterns in pkg_data.items():
        for pattern in patterns:
            for danger_re, label in DANGEROUS_INCLUDE_PATTERNS:
                if re.search(danger_re, pattern, re.IGNORECASE):
                    findings.append(
                        Finding(
                            id="PKG-PYLEAK",
                            rule=RULE_ID,
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


def audit_include_list(patterns: list, rel: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for pattern in patterns:
        if str(pattern) in BROAD_PATTERNS:
            findings.append(
                Finding(
                    id="PKG-PYBROAD",
                    rule=RULE_ID,
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
        for danger_re, label in DANGEROUS_INCLUDE_PATTERNS:
            if re.search(danger_re, str(pattern), re.IGNORECASE):
                findings.append(
                    Finding(
                        id="PKG-PYLEAK",
                        rule=RULE_ID,
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


def check_manifest_in(path: Path, rel: str) -> list[Finding]:
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

        # `graft <dir>` recursively includes everything under <dir>; flag overly
        # broad grafts.
        if cmd == "graft" and args:
            for arg in args:
                if arg in {".", "./", "*", "**"}:
                    findings.append(
                        Finding(
                            id="PKG-MANIFEST-GRAFT",
                            rule=RULE_ID,
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
                            recommendation=("Restrict the graft to specific package directories."),
                            tags=["packaging", "python", "leak"],
                            confidence=Confidence.HIGH,
                        )
                    )

        # `recursive-include <dir> <glob>` with `*` is fine; with no constraint
        # it sweeps everything.
        if cmd == "recursive-include" and len(args) >= 2:
            base = args[0]
            globs = args[1:]
            if base in {".", "./"} and any(g in {"*", "**", "*.*"} for g in globs):
                findings.append(
                    Finding(
                        id="PKG-MANIFEST-RECURSIVE",
                        rule=RULE_ID,
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
                    rule=RULE_ID,
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

        for danger_re, label in DANGEROUS_INCLUDE_PATTERNS:
            if re.search(danger_re, line, re.IGNORECASE):
                findings.append(
                    Finding(
                        id="PKG-MANIFESTLEAK",
                        rule=RULE_ID,
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


def check_setup_cfg(path: Path, rel: str) -> list[Finding]:
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
                for danger_re, label in DANGEROUS_INCLUDE_PATTERNS:
                    if re.search(danger_re, pattern, re.IGNORECASE):
                        findings.append(
                            Finding(
                                id="PKG-SETUPPYLEAK",
                                rule=RULE_ID,
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
