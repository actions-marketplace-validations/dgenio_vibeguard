"""Core scanner that orchestrates rule execution."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.git import get_git_metadata
from vibeguard.models import Finding, GitMetadata, ScanContext, ScanResult, Severity
from vibeguard.rules.ai_footprints import AIFootprintsRule
from vibeguard.rules.dependencies import DependenciesRule
from vibeguard.rules.packaging import PackagingRule
from vibeguard.rules.risky_diff import RiskyDiffRule
from vibeguard.rules.secrets import SecretsRule
from vibeguard.rules.sourcemaps import SourceMapsRule
from vibeguard.rules.tests import MissingTestsRule


def _collect_files(root: Path, config: VibeGuardConfig) -> list[Path]:
    """Walk the root directory and return all non-ignored files."""
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if config.is_path_ignored(str(rel)):
            continue
        files.append(path)
    return sorted(files)


def _severity_from_str(s: str) -> Severity:
    try:
        return Severity(s.lower())
    except ValueError:
        return Severity.HIGH


def run_scan(
    path: Path,
    config: VibeGuardConfig,
    diff_only: bool = False,
    git_meta: GitMetadata | None = None,
) -> ScanResult:
    """Run all enabled rules and return a ScanResult."""
    root = path.resolve()

    if git_meta is None:
        git_meta = get_git_metadata(root) if diff_only else GitMetadata(is_available=False)

    all_files = _collect_files(root, config)

    changed_paths: list[Path] = []
    if git_meta.is_available and git_meta.changed_files:
        for cf in git_meta.changed_files:
            candidate = root / cf
            if candidate.exists():
                changed_paths.append(candidate)

    ctx = ScanContext(
        root=root,
        config=config,
        files=all_files,
        changed_files=changed_paths,
        git=git_meta,
        diff_only=diff_only,
    )

    rules = []
    if config.secrets.enabled:
        rules.append(SecretsRule())
    if config.sourcemaps.enabled:
        rules.append(SourceMapsRule())
    if config.packaging.enabled:
        rules.append(PackagingRule())
    if config.dependencies.enabled:
        rules.append(DependenciesRule())
    if config.risky_patterns.enabled:
        rules.append(RiskyDiffRule())
    if config.tests.enabled:
        rules.append(MissingTestsRule())
    if config.ai_footprints.enabled:
        rules.append(AIFootprintsRule())

    findings: list[Finding] = []
    errors: list[str] = []

    for rule in rules:
        try:
            rule_findings = rule.scan(ctx)
            # Filter out suppressed finding IDs
            rule_findings = [
                f for f in rule_findings if f.id not in config.ignore.findings
            ]
            findings.extend(rule_findings)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Rule {rule.id} failed: {exc}")

    return ScanResult(
        findings=findings,
        scanned_files=len(all_files),
        changed_files=len(changed_paths),
        scan_path=str(root),
        policy=config.policy,
        errors=errors,
    )
