"""Core scanner that orchestrates rule execution."""

from __future__ import annotations

from pathlib import Path

import pathspec

from vibeguard.config import VibeGuardConfig, load_ignorefile
from vibeguard.git import get_diff_text, get_git_metadata, parse_changed_lines
from vibeguard.models import Finding, GitMetadata, ScanContext, ScanResult
from vibeguard.rules.base import Rule
from vibeguard.rules.builtin import BUILTIN_RULES
from vibeguard.rules.plugins import discover_plugin_rules
from vibeguard.rules.registry import RULE_REGISTRY
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

    # Resolve the unified diff once, up front, so rules that need before/after
    # context (e.g. a deleted test file or a lowered coverage threshold) can
    # read it from the context — and reuse the very same text for the
    # changed-line filtering pass below (#24).
    diff_text = ""
    if diff_only and git_meta.is_available:
        diff_text = get_diff_text(root, git_meta.base_branch)

    ctx = ScanContext(
        root=root,
        config=config,
        files=all_files,
        changed_files=changed_paths,
        git=git_meta,
        diff_only=diff_only,
        diff_text=diff_text,
    )

    # Instantiate every enabled built-in rule from the single source of truth
    # (#175): iterate the canonical ordered list and gate each rule on the
    # ``enabled`` flag of the config section its metadata points at (the
    # ``config_key`` — e.g. ``risky_diff`` reads ``risky_patterns``). Replaces
    # the former 15-branch if-chain so the rule set and its order live in one
    # place that the registry and ``rules list`` also derive from.
    rules: list[Rule] = []
    for rule_cls in BUILTIN_RULES:
        # config_key is always populated at registration (defaults to rule id),
        # but its type is Optional — fall back to the id to satisfy the checker.
        config_key = RULE_REGISTRY[rule_cls.id].config_key or rule_cls.id
        section = getattr(config, config_key)
        if getattr(section, "enabled", True):
            rules.append(rule_cls())

    # Discover third-party rules registered via the ``vibeguard.rules``
    # entry-point group (#58). Failed plugins are recorded but do not
    # interrupt the scan — see vibeguard/rules/plugins.py for the contract.
    loaded_plugins, plugin_failures = discover_plugin_rules(disabled=config.plugins.disabled)
    for plugin in loaded_plugins:
        rules.append(plugin.rule)

    findings: list[Finding] = []
    errors: list[str] = []

    # Surface plugin load failures as scan errors so they appear in
    # console / JSON output without being fatal.
    for failure in plugin_failures:
        errors.append(
            f"Plugin '{failure.name}' "
            f"({failure.distribution or 'unknown dist'}) failed to load: {failure.reason}"
        )

    # Report skipped files
    errors.extend(skipped)

    # Propagate git errors so callers know git context was degraded
    if diff_only and git_meta and not git_meta.is_available and git_meta.error:
        errors.append(f"Git context unavailable: {git_meta.error}")

    # Surface degraded git context as diagnostics instead of silently scanning
    # a narrower scope (#182). A "head-only" strategy in diff mode means base
    # detection failed and the diff degraded to `git diff HEAD`, so a PR gate
    # may report "0 findings" simply because the diff was nearly empty.
    if diff_only and git_meta and git_meta.is_available:
        errors.extend(git_meta.warnings)
        if git_meta.diff_strategy == "head-only":
            hint = (
                "Could not detect a base branch; comparing against HEAD only — "
                "diff-mode findings may be incomplete. Pass --base, set "
                "git.base_branch, or fetch the base branch."
            )
            if git_meta.is_shallow:
                hint += " This is a shallow clone; use fetch-depth: 0 in CI."
            errors.append(hint)

    for rule in rules:
        try:
            rule_findings = rule.scan(_context_for_rule(rule, ctx))
            # Filter out suppressed finding IDs
            rule_findings = [f for f in rule_findings if f.id not in config.ignore.findings]
            findings.extend(rule_findings)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Rule {rule.id} failed: {exc}")

    # Apply diff-scope filtering (#24, #199): in diff mode, restrict findings to
    # the change set. Line-based findings are kept only on changed lines;
    # findings attributable to files that are NOT part of the diff (pre-existing
    # repository state) are dropped, so a PR gate reflects "findings introduced
    # or touched by this change" rather than blocking on unrelated history.
    # Reuses the diff text resolved above.
    if diff_only and git_meta and git_meta.is_available and diff_text:
        changed_lines = parse_changed_lines(diff_text)
        changed_set = {cf.replace("\\", "/") for cf in git_meta.changed_files}
        findings = _filter_by_changed_lines(findings, changed_lines, changed_set)

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


def _context_for_rule(rule: Rule, ctx: ScanContext) -> ScanContext:
    """Return the scan context a rule sees, honouring its ``is_applicable`` hook (#193).

    Rules that keep the default ``is_applicable`` (return ``True`` for every
    path) see the shared context unchanged — no per-file calls, no copy. A rule
    that overrides the hook gets a context whose ``files`` and ``changed_files``
    are filtered to the paths it accepts, so a path it rejects never reaches its
    ``scan``.
    """
    if type(rule).is_applicable is Rule.is_applicable:
        return ctx

    # Evaluate the hook at most once per unique path (a path can appear in both
    # files and changed_files), honouring the "once per candidate file per rule"
    # contract and keeping filtering O(n).
    cache: dict[Path, bool] = {}

    def applicable(path: Path) -> bool:
        # Membership test (not ``get(...) is None``) so a cached ``False`` is
        # reused rather than re-evaluated — the hook runs at most once per path.
        if path not in cache:
            cache[path] = rule.is_applicable(path)
        return cache[path]

    files = [p for p in ctx.files if applicable(p)]
    changed_files = [p for p in ctx.changed_files if applicable(p)]
    return ctx.model_copy(update={"files": files, "changed_files": changed_files})


def _filter_by_changed_lines(
    findings: list[Finding],
    changed_lines: dict[str, list[tuple[int, int]]],
    changed_files: set[str] | None = None,
) -> list[Finding]:
    """Filter findings down to the diff scope.

    Diff-mode semantics (#199): a finding survives only if it belongs to the
    change set.

    - When ``changed_files`` is given (real diff mode), a finding whose file is
      not in that set is **dropped** — it is pre-existing repository state, not
      something this change introduced. Diff-aggregate findings (path ``"."`` or
      empty, e.g. ``DIFF-SIZE``) are exempt and always kept.
    - File-level findings (line ``None``/``0``) on a changed file are kept.
    - Line-level findings are kept only when their line falls on a changed
      range. If the file changed but produced no parseable ranges (rename,
      binary, parse gap), findings are kept conservatively so scoping never
      *loses* signal.
    - When ``changed_files`` is ``None`` (legacy/unit callers), the file is not
      filtered — only the changed-line check applies.
    """
    filtered: list[Finding] = []
    for finding in findings:
        rel_path = finding.path.replace("\\", "/")

        # Diff-aggregate findings carry no concrete file path; never filter them.
        is_aggregate = rel_path in ("", ".")

        if changed_files is not None and not is_aggregate and rel_path not in changed_files:
            # Belongs to a file outside the diff — pre-existing state.
            continue

        # File-level findings (and aggregates) always pass through.
        if is_aggregate or not finding.line:
            filtered.append(finding)
            continue

        if rel_path not in changed_lines:
            # File is in the diff but has no parseable changed lines (rename,
            # binary, mode-only, or a parse gap) — keep conservatively.
            filtered.append(finding)
            continue

        # Keep only if the finding line falls within a changed range.
        ranges = changed_lines[rel_path]
        if any(start <= finding.line <= end for start, end in ranges):
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
