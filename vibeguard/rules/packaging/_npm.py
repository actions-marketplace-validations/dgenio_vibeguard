"""npm publish-hygiene checks for the packaging rule (#201).

Covers ``package.json`` (`files` allowlist, broad/leaky patterns, publish-time
lifecycle scripts) and ``.npmignore`` (broad and protective-undoing negations).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.packaging._common import (
    BROAD_PATTERNS,
    DANGEROUS_INCLUDE_PATTERNS,
    RULE_ID,
)

# `.npmignore` re-include patterns whose effect is to defeat the protective
# default of "ignore everything except the allowlist". These never overlap with
# the secret-negation patterns caught by PKG-NPMIGNORE-NEGATE.
_BROAD_NPMIGNORE_NEGATIONS: frozenset[str] = frozenset({"*", "**", "**/*", "/", "./", "."})

# npm lifecycle scripts that can produce additional, unexpected files at publish
# time. `prepare` and `prepack` run *before* the tarball is built, so whatever
# they write lands inside the published artifact unless explicitly excluded.
_PUBLISH_TIME_SCRIPTS: tuple[str, ...] = ("prepare", "prepack")


def check_package_json(path: Path, rel: str, context: ScanContext) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return findings

    pkg_files: list[str] = data.get("files", [])
    if not pkg_files:
        # No "files" whitelist — everything gets published by default.
        # Check if there is an .npmignore.
        npmignore = path.parent / ".npmignore"
        if not npmignore.exists():
            findings.append(
                Finding(
                    id="PKG-NPMFILES",
                    rule=RULE_ID,
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
            if pattern in BROAD_PATTERNS:
                findings.append(
                    Finding(
                        id="PKG-NPMBROAD",
                        rule=RULE_ID,
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
            for danger_re, label in DANGEROUS_INCLUDE_PATTERNS:
                if re.search(danger_re, pattern, re.IGNORECASE):
                    findings.append(
                        Finding(
                            id="PKG-NPMLEAK",
                            rule=RULE_ID,
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

    # Detect `prepare` / `prepack` scripts. Both run *before* npm builds the
    # publish tarball, so any files they emit ride along unless the package has a
    # tight `files` allowlist or a corresponding ignore entry. The scripts
    # themselves are not bad — we flag them as a reminder to audit what they write.
    scripts_obj = data.get("scripts")
    scripts: dict = scripts_obj if isinstance(scripts_obj, dict) else {}
    for script_name in _PUBLISH_TIME_SCRIPTS:
        cmd = scripts.get(script_name)
        if not cmd or not isinstance(cmd, str):
            continue
        findings.append(
            Finding(
                id="PKG-PREPARE-SCRIPT",
                rule=RULE_ID,
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


def check_npmignore(path: Path, rel: str) -> list[Finding]:
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

        # `!*`, `!**`, `!/` and friends wipe out every preceding ignore rule in
        # the file — there is no legitimate reason to undo every protective
        # default at once. This is distinct from the targeted `!.env`-style
        # pattern caught by PKG-NPMIGNORE-NEGATE.
        if negate in _BROAD_NPMIGNORE_NEGATIONS:
            findings.append(
                Finding(
                    id="PKG-NPMIGNORE-BROAD",
                    rule=RULE_ID,
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
            # Fall through so PKG-NPMIGNORE-NEGATE may also fire if the broad
            # negation overlaps a dangerous-pattern match (unlikely in practice
            # but harmless to surface both).

        for danger_re, label in DANGEROUS_INCLUDE_PATTERNS:
            if re.search(danger_re, negate, re.IGNORECASE):
                findings.append(
                    Finding(
                        id="PKG-NPMIGNORE-NEGATE",
                        rule=RULE_ID,
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
