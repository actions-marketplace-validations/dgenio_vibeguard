"""Source map exposure rule."""

from __future__ import annotations

import re
from pathlib import Path

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule

# Directories that indicate publishable / distribution output
_PUBLISH_DIRS = {"dist", "build", "public", "out", "release", "pkg"}

# sourceMappingURL comment pattern
_SOURCEMAP_URL_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")

# package.json "files" array — if .map is listed
_PACKAGE_FILES_MAP_RE = re.compile(r'"[^"]*\.map[^"]*"')


class SourceMapsRule(Rule):
    id = "sourcemaps"
    name = "Source Map Exposure"
    description = "Detects source maps that may expose original source code in published packages"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        for path in files_to_check:
            rel = self._rel(context, path)

            # Rule 1: .map files in publish directories
            if path.suffix == ".map":
                if self._in_publish_dir(path):
                    findings.append(
                        Finding(
                            id="MAP-DIST",
                            rule=self.id,
                            title="Source map file in publish directory",
                            description=(
                                f"`{rel}` is a source map inside a distribution directory. "
                                "Publishing source maps exposes your original source code to anyone."
                            ),
                            severity=Severity.HIGH,
                            path=rel,
                            recommendation=(
                                "Remove .map files from your distribution output, or add them to "
                                ".npmignore / package.json's `files` exclusion list."
                            ),
                            tags=["sourcemaps", "packaging"],
                            confidence=Confidence.HIGH,
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            id="MAP-FILE",
                            rule=self.id,
                            title="Source map file present in repository",
                            description=(
                                f"`{rel}` is a source map file. "
                                "Ensure it is excluded from published packages."
                            ),
                            severity=Severity.LOW,
                            path=rel,
                            recommendation=(
                                "Add `**/*.map` to .npmignore or exclude it from the package `files` list."
                            ),
                            tags=["sourcemaps"],
                            confidence=Confidence.HIGH,
                        )
                    )
                continue

            # Rule 2: JS/TS files with sourceMappingURL
            if path.suffix in {".js", ".mjs", ".cjs", ".ts"}:
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                for lineno, line in enumerate(content.splitlines(), start=1):
                    m = _SOURCEMAP_URL_RE.search(line)
                    if m:
                        url = m.group(1)
                        # Inline data URIs are less concerning
                        if url.startswith("data:"):
                            continue
                        sev = Severity.HIGH if self._in_publish_dir(path) else Severity.MEDIUM
                        findings.append(
                            Finding(
                                id="MAP-URL",
                                rule=self.id,
                                title="sourceMappingURL reference in bundled file",
                                description=(
                                    f"`{rel}` line {lineno} contains a sourceMappingURL comment "
                                    f"pointing to `{url}`. This may expose source paths."
                                ),
                                severity=sev,
                                path=rel,
                                line=lineno,
                                evidence=line.strip()[:120],
                                recommendation=(
                                    "Remove sourceMappingURL comments from published bundles, "
                                    "or use hidden source maps served only to authenticated users."
                                ),
                                tags=["sourcemaps"],
                                confidence=Confidence.HIGH,
                            )
                        )
                        break  # One finding per file is enough

            # Rule 3: package.json that includes .map in the files array
            if path.name == "package.json":
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                if _PACKAGE_FILES_MAP_RE.search(content):
                    findings.append(
                        Finding(
                            id="MAP-PKG",
                            rule=self.id,
                            title="package.json 'files' includes source maps",
                            description=(
                                f"`{rel}` has a `files` entry that includes .map files, "
                                "which will be published to npm."
                            ),
                            severity=Severity.HIGH,
                            path=rel,
                            recommendation=(
                                "Remove .map patterns from the `files` array in package.json."
                            ),
                            tags=["sourcemaps", "npm"],
                            confidence=Confidence.HIGH,
                        )
                    )

        return findings

    def _in_publish_dir(self, path: Path) -> bool:
        return any(part.lower() in _PUBLISH_DIRS for part in path.parts)
