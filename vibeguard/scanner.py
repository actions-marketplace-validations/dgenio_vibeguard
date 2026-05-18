"""Core scanner that orchestrates rule execution."""

from __future__ import annotations

from pathlib import Path

import pathspec

from vibeguard.config import VibeGuardConfig, load_ignorefile
from vibeguard.git import get_git_metadata
from vibeguard.models import Finding, GitMetadata, ScanContext, ScanResult
from vibeguard.rules.ai_footprints import AIFootprintsRule
from vibeguard.rules.base import Rule
from vibeguard.rules.dependencies import DependenciesRule
from vibeguard.rules.packaging import PackagingRule
from vibeguard.rules.risky_diff import RiskyDiffRule
from vibeguard.rules.secrets import SecretsRule
from vibeguard.rules.sourcemaps import SourceMapsRule
from vibeguard.rules.tests import MissingTestsRule

_BINARY_SNIFF_SIZE = 8192


def _is_binary(path: Path) -> bool:
    """Detect binary files via null-byte presence in the first 8 KB."""
    try:
        chunk = path.read_bytes()[:_BINARY_SNIFF_SIZE]
        return b"\x00" in chunk
    except OSError:
        return True


def _collect_files(
    root: Path,
    config: VibeGuardConfig,
    ignore_spec: pathspec.PathSpec | None = None,
) -> tuple[list[Path], list[str]]:
    """Walk the root directory and return non-ignored, non-binary, size-limited files."""
    files: list[Path] = []
    skipped: list[str] = []
    max_bytes = config.scanner.max_file_size_kb * 1024

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        rel_str = str(rel).replace("\\", "/")

        if config.is_path_ignored(rel_str):
            continue
        if ignore_spec and ignore_spec.match_file(rel_str):
            continue

        # Size check
        try:
            size = path.stat().st_size
        except OSError:
            skipped.append(f"Cannot stat: {rel_str}")
            continue

        if size > max_bytes:
            skipped.append(f"Skipped (>{config.scanner.max_file_size_kb} KB): {rel_str}")
            continue

        # Binary check
        if _is_binary(path):
            skipped.append(f"Skipped (binary): {rel_str}")
            continue

        files.append(path)

    return sorted(files), skipped


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

    # Load .vibeguardignore patterns
    ignore_patterns = load_ignorefile(root)
    ignore_spec = (
        pathspec.PathSpec.from_lines("gitignore", ignore_patterns) if ignore_patterns else None
    )

    all_files, skipped = _collect_files(root, config, ignore_spec)

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

    rules: list[Rule] = []
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

    # Report skipped files
    errors.extend(skipped)

    # Propagate git errors so callers know git context was degraded
    if diff_only and git_meta and not git_meta.is_available and git_meta.error:
        errors.append(f"Git context unavailable: {git_meta.error}")

    for rule in rules:
        try:
            rule_findings = rule.scan(ctx)
            # Filter out suppressed finding IDs
            rule_findings = [f for f in rule_findings if f.id not in config.ignore.findings]
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
