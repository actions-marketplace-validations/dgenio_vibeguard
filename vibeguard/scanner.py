"""Core scanner that orchestrates rule execution."""

from __future__ import annotations

from pathlib import Path

import pathspec

from vibeguard.config import VibeGuardConfig, load_ignorefile
from vibeguard.git import get_diff_text, get_git_metadata, parse_changed_lines
from vibeguard.models import Finding, GitMetadata, ScanContext, ScanResult
from vibeguard.rules.agent_memory import AgentMemoryRule
from vibeguard.rules.ai_footprints import AIFootprintsRule
from vibeguard.rules.auth import AuthRule
from vibeguard.rules.base import Rule
from vibeguard.rules.ci_docker import CiDockerRule
from vibeguard.rules.dependencies import DependenciesRule
from vibeguard.rules.go_rules import GoRulesRule
from vibeguard.rules.iac import IaCRule
from vibeguard.rules.packaging import PackagingRule
from vibeguard.rules.risky_diff import RiskyDiffRule
from vibeguard.rules.secrets import SecretsRule
from vibeguard.rules.sourcemaps import SourceMapsRule
from vibeguard.rules.sql import SqlRule
from vibeguard.rules.tests import MissingTestsRule
from vibeguard.suppressions import find_missing_reasons, parse_inline_suppressions

_BINARY_SNIFF_SIZE = 8192


def _is_binary(path: Path) -> bool | None:
    """Detect binary files via null-byte presence in the first 8 KB.

    Returns True if binary, False if text, None if the file could not be read.
    """
    try:
        with path.open("rb") as f:
            chunk = f.read(_BINARY_SNIFF_SIZE)
        return b"\x00" in chunk
    except OSError:
        return None


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
        binary = _is_binary(path)
        if binary is None:
            skipped.append(f"Cannot read: {rel_str}")
            continue
        if binary:
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
    if config.go_rules.enabled:
        rules.append(GoRulesRule())
    if config.ci_docker.enabled:
        rules.append(CiDockerRule())
    if config.iac.enabled:
        rules.append(IaCRule())
    if config.auth.enabled:
        rules.append(AuthRule())
    if config.sql.enabled:
        rules.append(SqlRule())
    if config.agent_memory.enabled:
        rules.append(AgentMemoryRule())

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

    # Apply diff-line filtering (#24): in diff mode, restrict line-based findings
    # to only those on changed lines
    if diff_only and git_meta and git_meta.is_available:
        diff_text = get_diff_text(root, git_meta.base_branch)
        if diff_text:
            changed_lines = parse_changed_lines(diff_text)
            findings = _filter_by_changed_lines(findings, changed_lines)

    # Apply inline suppressions (#44)
    findings, suppression_warnings = _apply_inline_suppressions(findings, all_files, root)
    findings.extend(suppression_warnings)

    return ScanResult(
        findings=findings,
        scanned_files=len(all_files),
        changed_files=len(changed_paths),
        scan_path=str(root),
        policy=config.policy,
        errors=errors,
    )


def _filter_by_changed_lines(
    findings: list[Finding],
    changed_lines: dict[str, list[tuple[int, int]]],
) -> list[Finding]:
    """Filter out line-based findings that are not on changed lines.

    File-level findings (line=None or line=0) are kept regardless.
    """
    filtered: list[Finding] = []
    for finding in findings:
        # File-level findings always pass through
        if not finding.line or finding.line == 0:
            filtered.append(finding)
            continue

        rel_path = finding.path.replace("\\", "/")
        if rel_path not in changed_lines:
            # File not in diff at all — keep finding (shouldn't happen in diff mode,
            # but be conservative)
            filtered.append(finding)
            continue

        # Check if finding line falls within any changed range
        ranges = changed_lines[rel_path]
        in_range = any(start <= finding.line <= end for start, end in ranges)
        if in_range:
            filtered.append(finding)

    return filtered


def _apply_inline_suppressions(
    findings: list[Finding],
    all_files: list[Path],
    root: Path,
) -> tuple[list[Finding], list[Finding]]:
    """Apply inline suppressions and return (filtered_findings, warnings)."""
    from vibeguard.models import Confidence, Severity

    # Build set of files with findings for optimized suppression filtering
    files_with_findings: set[str] = set()
    for finding in findings:
        if finding.path:
            files_with_findings.add(finding.path.replace("\\", "/"))

    # Build a map of file -> suppressions
    file_suppressions: dict[str, dict[int, list[str]]] = {}
    warnings: list[Finding] = []

    suppression_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java", ".cs"}
    # Cheap byte-substring filter — files without the literal `vibeguard:`
    # marker anywhere in their bytes can have neither suppressions nor
    # missing-reason warnings, so we skip the full text decode entirely.
    _MARKER = b"vibeguard:"

    for path in all_files:
        if path.suffix.lower() not in suppression_extensions:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        has_findings = rel in files_with_findings

        try:
            raw = path.read_bytes()
        except OSError:
            continue

        if _MARKER not in raw:
            # No suppression marker present — neither suppression parsing nor
            # the missing-reason warning pass have anything to do for this file.
            continue

        try:
            content = raw.decode("utf-8", errors="replace")
        except UnicodeDecodeError:
            continue

        # Parse suppressions only for files that have findings (M5 optimization)
        if has_findings:
            suppressions = parse_inline_suppressions(content)
            if suppressions:
                file_suppressions[rel] = suppressions

        # Check for missing reasons on files that contain the marker
        missing = find_missing_reasons(content)
        for lineno, ids in missing:
            warnings.append(
                Finding(
                    id="SUPPRESSION-NO-REASON",
                    rule="suppressions",
                    title="Inline suppression without reason",
                    description=(
                        f"`{rel}` line {lineno}: inline suppression for "
                        f"{', '.join(ids)} is missing a required reason= argument."
                    ),
                    severity=Severity.LOW,
                    path=rel,
                    line=lineno,
                    recommendation=('Add reason="..." to the inline suppression comment.'),
                    tags=["suppressions"],
                    confidence=Confidence.HIGH,
                )
            )

    if not file_suppressions:
        return findings, warnings

    # Filter findings that match suppressed (file, line, id) triples
    # Supports same-line and next-line suppression (comment on line N suppresses N and N+1)
    filtered: list[Finding] = []
    for finding in findings:
        rel_path = finding.path.replace("\\", "/")
        if rel_path in file_suppressions and finding.line is not None:
            # Check same-line suppression
            suppressed_ids = file_suppressions[rel_path].get(finding.line, [])
            if finding.id in suppressed_ids:
                continue
            # Check preceding-line suppression (comment on line N-1 suppresses line N)
            suppressed_ids_prev = file_suppressions[rel_path].get(finding.line - 1, [])
            if finding.id in suppressed_ids_prev:
                continue
        filtered.append(finding)

    return filtered, warnings
