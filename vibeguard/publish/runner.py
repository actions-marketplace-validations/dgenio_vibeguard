"""Orchestrator: detect ecosystem, simulate publish, apply rules, return results."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from vibeguard.config import VibeGuardConfig
from vibeguard.models import Confidence, Finding, GitMetadata, ScanContext, ScanResult, Severity
from vibeguard.publish.manifest import PublishManifest
from vibeguard.publish.npm import simulate_npm_pack
from vibeguard.publish.python import simulate_python
from vibeguard.rules.ai_footprints import AIFootprintsRule
from vibeguard.rules.base import Rule
from vibeguard.rules.packaging import PackagingRule
from vibeguard.rules.secrets import SecretsRule
from vibeguard.rules.sourcemaps import SourceMapsRule

EcosystemChoice = Literal["auto", "npm", "python-sdist", "python-wheel"]


def detect_ecosystem(package_root: Path) -> Literal["npm", "python-sdist"] | None:
    """Return the ecosystem to simulate for `--ecosystem auto`.

    Resolution order:
    - package.json present → npm
    - pyproject.toml present → python-sdist (sdist is the most inclusive view)
    - otherwise None
    """
    if (package_root / "package.json").is_file():
        return "npm"
    if (package_root / "pyproject.toml").is_file():
        return "python-sdist"
    return None


def _publish_rules(config: VibeGuardConfig) -> list[Rule]:
    """Rules that make sense on a *publish view*.

    The publish view is a curated file set (what would ship to npm/PyPI), so
    full-repo rules like missing-tests or risky-diff aren't meaningful here.
    These four are: any secret, source-map, AI footprint, or packaging-config
    issue surfaced from the published file set is critical for users.
    """
    rules: list[Rule] = []
    if config.secrets.enabled:
        rules.append(SecretsRule())
    if config.sourcemaps.enabled:
        rules.append(SourceMapsRule())
    if config.ai_footprints.enabled:
        rules.append(AIFootprintsRule())
    if config.packaging.enabled:
        rules.append(PackagingRule())
    return rules


def _scan_published_files(
    package_root: Path,
    config: VibeGuardConfig,
    manifest: PublishManifest,
) -> list[Finding]:
    """Run the publish-view rule set against the manifest's included files."""
    file_paths = [
        package_root / pf.path for pf in manifest.files if (package_root / pf.path).is_file()
    ]
    ctx = ScanContext(
        root=package_root,
        config=config,
        files=file_paths,
        changed_files=[],
        git=GitMetadata(is_available=False),
        diff_only=False,
    )
    findings: list[Finding] = []
    for rule in _publish_rules(config):
        try:
            rule_findings = rule.scan(ctx)
        except Exception as exc:  # noqa: BLE001
            findings.append(
                Finding(
                    id="PUB-RULE-ERROR",
                    rule="publish",
                    title=f"Rule {rule.id} failed during publish-check",
                    description=f"{rule.id} raised: {exc}",
                    severity=Severity.LOW,
                    path=str(package_root),
                    recommendation="Open an issue with the failing rule and the package layout.",
                    tags=["publish"],
                    confidence=Confidence.LOW,
                )
            )
            continue
        # Drop globally-suppressed finding IDs.
        for f in rule_findings:
            if f.id in config.ignore.findings:
                continue
            findings.append(f)
    return findings


def _published_file_finding(rel: str, label: str) -> Finding:
    """Synthesize a HIGH finding for a clearly-dangerous file that would ship."""
    return Finding(
        id="PUB-DANGEROUS-FILE",
        rule="publish",
        title=f"Dangerous file would be published: {rel}",
        description=(
            f"The publish simulation would include `{rel}`, which is a {label}. "
            "Files of this kind should never be in a published package."
        ),
        severity=Severity.HIGH,
        path=rel,
        recommendation=(
            "Remove the file from your package by tightening `files`/`.npmignore` "
            "(npm) or `[tool.hatch.build.targets.sdist].exclude` / `MANIFEST.in` (python)."
        ),
        tags=["publish", "packaging", "leak"],
        confidence=Confidence.HIGH,
    )


_DANGEROUS_BASENAMES: tuple[tuple[str, str], ...] = (
    (".env", "local environment / secrets file"),
    (".env.local", "local environment / secrets file"),
    (".env.production", "production environment / secrets file"),
    (".env.staging", "staging environment / secrets file"),
    (".npmrc", "npm registry/auth configuration"),
    (".pypirc", "PyPI credentials file"),
    ("docker-compose.yml", "Docker Compose configuration"),
    ("docker-compose.yaml", "Docker Compose configuration"),
)


def _direct_publish_findings(manifest: PublishManifest) -> list[Finding]:
    """Flag files in the manifest that are categorically unsafe to publish."""
    out: list[Finding] = []
    for pf in manifest.files:
        name = pf.path.rsplit("/", 1)[-1]
        for danger, label in _DANGEROUS_BASENAMES:
            if name == danger:
                out.append(_published_file_finding(pf.path, label))
                break
        if name.endswith(".map") or pf.path.startswith("dist/") and name.endswith(".map"):
            out.append(_published_file_finding(pf.path, "source map file"))
    return out


def run_publish_check(
    package_root: Path,
    config: VibeGuardConfig,
    *,
    ecosystem: EcosystemChoice = "auto",
) -> tuple[PublishManifest, ScanResult]:
    """Simulate a publish and scan the resulting file set.

    Returns the manifest plus a ScanResult whose findings reflect the publish view.
    """
    package_root = package_root.resolve()

    if ecosystem == "auto":
        detected = detect_ecosystem(package_root)
        if detected is None:
            return (
                PublishManifest(
                    ecosystem="npm",  # placeholder; warnings explain
                    package_root=str(package_root),
                    warnings=[
                        "Could not detect ecosystem — no package.json or pyproject.toml found."
                    ],
                ),
                ScanResult(
                    scanned_files=0,
                    changed_files=0,
                    scan_path=str(package_root),
                    policy=config.policy,
                    errors=[
                        "No package.json or pyproject.toml found in the package root.",
                    ],
                ),
            )
        target: Literal["npm", "python-sdist", "python-wheel"] = detected
    else:
        target = ecosystem

    if target == "npm":
        manifest = simulate_npm_pack(package_root)
    elif target in {"python-sdist", "python-wheel"}:
        manifest = simulate_python(package_root, target=target)
    else:  # pragma: no cover — defensive
        raise ValueError(f"Unsupported ecosystem: {target!r}")

    findings = _scan_published_files(package_root, config, manifest)
    findings.extend(_direct_publish_findings(manifest))
    # Drop globally-suppressed finding IDs once more (the synthesized ones).
    findings = [f for f in findings if f.id not in config.ignore.findings]

    errors = list(manifest.warnings)

    result = ScanResult(
        findings=findings,
        scanned_files=len(manifest.files),
        changed_files=0,
        scan_path=str(package_root),
        policy=config.policy,
        errors=errors,
    )
    return manifest, result
