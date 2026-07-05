"""Core scanner that orchestrates rule execution."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

import pathspec

from vibeguard.config import (
    VibeGuardConfig,
    compile_pathspec,
    load_gitignore,
    load_ignorefile,
)
from vibeguard.git import (
    get_diff_text,
    get_git_metadata,
    get_tracked_files,
    parse_changed_lines,
    reconstruct_patch_files,
)
from vibeguard.models import Finding, GitMetadata, ScanContext, ScanDiagnostic, ScanResult
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


# A skip note pairs the human message with its operational severity at the point
# it is generated (#218): routine skips (binary/oversize/gitignored) are ``info``
# and never fail ``gate --strict-errors``; an unreadable/un-stattable file is a
# ``warning`` so a degraded scan stays loud. Recording severity here, rather than
# re-deriving it from the message text later, keeps strict mode off prose.
_SkipNote = tuple[str, Literal["info", "warning", "error"]]


def _size_binary_skip(path: Path, rel_str: str, max_bytes: int, max_kb: int) -> _SkipNote | None:
    """Apply the size + binary content checks to one file.

    Returns a skip note when the file should be excluded, or ``None`` when it is
    a scannable text file. Shared by the directory walker and explicit-file
    targets (#213) so both apply identical size/binary rules.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return (f"Cannot stat: {rel_str}", "warning")
    if size > max_bytes:
        return (f"Skipped (>{max_kb} KB): {rel_str}", "info")
    binary = _is_binary(path)
    if binary is None:
        return (f"Cannot read: {rel_str}", "warning")
    if binary:
        return (f"Skipped (binary): {rel_str}", "info")
    return None


def _collect_files(
    walk_root: Path,
    rel_root: Path,
    config: VibeGuardConfig,
    ignore_spec: pathspec.PathSpec,
    gitignore_spec: pathspec.PathSpec | None = None,
    tracked: set[str] | None = None,
) -> tuple[list[Path], list[_SkipNote]]:
    """Walk ``walk_root`` and return non-ignored, non-binary, size-limited files.

    Paths are relativised to ``rel_root`` (which may be an ancestor of
    ``walk_root`` when several targets are scanned under a common base — #213),
    so ignore patterns and finding paths stay anchored to one consistent root.

    Directory pruning (#219): ignored directories (``node_modules/``, ``.venv/``,
    …) are skipped *during* the walk by mutating ``dirnames`` in place, so their
    contents are never enumerated or stat'd — the cost that dominates scans of
    real JS/Python repos. Only the hard ignore set (``ignore.paths`` config +
    ``.vibeguardignore``, unified under gitignore semantics — #216) prunes
    directories; ``.gitignore`` (#211) is applied per file so a git-tracked file
    living under a gitignored directory is still scanned.

    ``.gitignore`` handling (#211): when ``gitignore_spec`` is given, a file it
    matches is skipped unless it is in ``tracked``. ``tracked`` is ``None`` when
    git is unavailable, which disables the carve-out.

    The returned ``files`` are ``sorted`` so the order is preserved regardless of
    walk order.
    """
    files: list[Path] = []
    skipped: list[_SkipNote] = []
    max_bytes = config.scanner.max_file_size_kb * 1024
    gitignored_skipped = 0

    for dirpath, dirnames, filenames in os.walk(walk_root):
        rel_dir = Path(dirpath).relative_to(rel_root)

        # Prune ignored directories in place so os.walk never descends into them
        # (#219). A directory matches a gitignore pattern only when its path
        # carries a trailing slash, so append one before testing.
        dirnames[:] = [
            d for d in dirnames if not ignore_spec.match_file((rel_dir / d).as_posix() + "/")
        ]

        for name in filenames:
            rel_str = (rel_dir / name).as_posix()

            if ignore_spec.match_file(rel_str):
                continue
            if (
                gitignore_spec is not None
                and gitignore_spec.match_file(rel_str)
                and (tracked is None or rel_str not in tracked)
            ):
                gitignored_skipped += 1
                continue

            path = Path(dirpath) / name
            # os.walk lists symlinks-to-files (and the odd special entry) under
            # filenames; keep the previous rglob behaviour of scanning only
            # regular files.
            if not path.is_file():
                continue

            note = _size_binary_skip(path, rel_str, max_bytes, config.scanner.max_file_size_kb)
            if note is not None:
                skipped.append(note)
                continue
            files.append(path)

    if gitignored_skipped:
        skipped.append(
            (
                f"Skipped {gitignored_skipped} gitignored file(s); "
                "set scanner.respect_gitignore: false to include them",
                "info",
            )
        )

    return sorted(files), skipped


def _normalize_targets(path: Path | str | Sequence[Path]) -> list[Path]:
    """Resolve the scan input into a non-empty list of absolute target paths (#213)."""
    targets = [Path(path)] if isinstance(path, (str, Path)) else [Path(p) for p in path]
    if not targets:
        targets = [Path(".")]
    return [t.resolve() for t in targets]


def _relativization_root(targets: list[Path]) -> Path:
    """Pick the root that finding paths are reported relative to (#213).

    A single directory target keeps the historic behaviour (the directory is the
    root). For a single file, the root is its parent. For several targets it is
    their common ancestor, so ``scan src/ tests/`` reports ``src/...`` /
    ``tests/...`` rather than absolute paths.
    """
    if len(targets) == 1 and targets[0].is_dir():
        return targets[0]
    dirs = [t if t.is_dir() else t.parent for t in targets]
    try:
        return Path(os.path.commonpath([str(d) for d in dirs]))
    except ValueError:
        # No common ancestor exists — e.g. targets span different drives on
        # Windows. Degrade to the first target's directory so finding paths
        # stay usable instead of letting ``commonpath`` raise out of the scan.
        return dirs[0]


def _collect_targets(
    targets: list[Path],
    rel_root: Path,
    config: VibeGuardConfig,
    ignore_spec: pathspec.PathSpec,
    gitignore_spec: pathspec.PathSpec | None = None,
    tracked: set[str] | None = None,
) -> tuple[list[Path], list[_SkipNote]]:
    """Collect scannable files across one or more targets (files and dirs — #213).

    Directory targets are walked (honouring all ignore layers); a file named
    explicitly is an intentional request, so it bypasses the ignore layers and
    is excluded only by the size/binary checks every file is subject to. Results
    are de-duplicated and ``sorted`` so the scan order is deterministic
    regardless of target order.
    """
    max_bytes = config.scanner.max_file_size_kb * 1024
    files: list[Path] = []
    skipped: list[_SkipNote] = []

    for target in targets:
        if target.is_dir():
            t_files, t_skipped = _collect_files(
                target, rel_root, config, ignore_spec, gitignore_spec, tracked
            )
            files.extend(t_files)
            skipped.extend(t_skipped)
        elif target.is_file():
            rel_str = target.relative_to(rel_root).as_posix()
            note = _size_binary_skip(target, rel_str, max_bytes, config.scanner.max_file_size_kb)
            if note is not None:
                skipped.append(note)
            else:
                files.append(target)

    return sorted(set(files)), skipped


def run_scan(
    path: Path | str | Sequence[Path],
    config: VibeGuardConfig,
    diff_only: bool = False,
    git_meta: GitMetadata | None = None,
    *,
    staged: bool = False,
    patch_text: str | None = None,
) -> ScanResult:
    """Run all enabled rules and return a ScanResult.

    ``path`` is one directory (the historic single-root scan) or, since #213, a
    sequence of files and/or directories to scan together; finding paths are
    reported relative to their common ancestor.

    Scope is otherwise selected by exactly one of the modes below — the CLI
    guarantees they are mutually exclusive (see ``docs/scan-scope.md``):

    * ``diff_only`` — restrict findings to the git change set (``base...HEAD``).
    * ``staged`` — restrict to the git index (``git diff --cached``), the fast
      pre-commit gate (#209). Only the staged files are collected (the scan cost
      scales with the change, not the repo), so cross-file rules see just the
      staged set in ``context.files``; rules already branch on
      ``context.changed_files``, which is unchanged. Implies diff-scope
      filtering.
    * ``patch_text`` — scan a unified diff standalone, gating a change before it
      is applied (#153); ``path`` is ignored.
    """
    if patch_text is not None:
        return _run_patch_scan(patch_text, config)

    targets = _normalize_targets(path)
    root = _relativization_root(targets)

    if git_meta is None:
        git_meta = (
            get_git_metadata(root, staged=staged)
            if (diff_only or staged)
            else GitMetadata(is_available=False)
        )

    # Build the unified hard-ignore spec: config ``ignore.paths`` followed by
    # ``.vibeguardignore``, both gitignore-syntax (#216). Order matters — a
    # ``!`` negation in ``.vibeguardignore`` can re-include a path the config
    # ignores.
    ignore_spec = compile_pathspec((*config.ignore.paths, *load_ignorefile(root)))

    # Optionally honor ``.gitignore`` (#211), with a git-tracked carve-out so a
    # committed-but-usually-ignored file (e.g. a checked-in ``.env``) is still
    # scanned. The carve-out (and the git call) is skipped when there is no
    # ``.gitignore`` at the scan root.
    gitignore_spec: pathspec.PathSpec | None = None
    tracked: set[str] | None = None
    if config.scanner.respect_gitignore:
        gitignore_patterns = load_gitignore(root)
        if gitignore_patterns:
            gitignore_spec = compile_pathspec(tuple(gitignore_patterns))
            tracked = get_tracked_files(root)

    # #209 fast staged path: collect only the staged files so the scan cost
    # scales with the change, not the whole repo (a full-tree gate on every
    # commit is the main reason developers disable the hook). The staged paths
    # are treated as explicit file targets — size/binary checks still apply, and
    # a deleted staged file simply isn't on disk to collect. Cross-file rules
    # therefore see only the staged set in ``context.files`` and are
    # correspondingly weaker in staged mode (documented in docs/scan-scope.md);
    # rules keyed on ``context.changed_files`` are unaffected.
    if staged and git_meta.is_available:
        staged_targets = [root / cf for cf in git_meta.changed_files]
        all_files, skipped = _collect_targets(
            staged_targets, root, config, ignore_spec, gitignore_spec, tracked
        )
    else:
        all_files, skipped = _collect_targets(
            targets, root, config, ignore_spec, gitignore_spec, tracked
        )

    changed_paths: list[Path] = []
    if git_meta.is_available and git_meta.changed_files:
        for cf in git_meta.changed_files:
            candidate = root / cf
            if candidate.exists():
                changed_paths.append(candidate)

    # Resolve the unified diff once, up front, so rules that need before/after
    # context (e.g. a deleted test file or a lowered coverage threshold) can
    # read it from the context — and reuse the very same text for the
    # changed-line filtering pass below (#24). ``staged`` selects the index diff.
    diff_text = ""
    if (diff_only or staged) and git_meta.is_available:
        diff_text = get_diff_text(root, git_meta.base_branch, staged=staged)

    ctx = ScanContext(
        root=root,
        config=config,
        files=all_files,
        changed_files=changed_paths,
        git=git_meta,
        diff_only=diff_only or staged,
        diff_text=diff_text,
    )

    # Diff-scope filtering runs whenever a change set is known and git context is
    # available — diff and staged modes alike (#199, #209).
    do_diff_filter = (diff_only or staged) and git_meta.is_available
    changed_set = (
        {cf.replace("\\", "/") for cf in git_meta.changed_files} if do_diff_filter else None
    )
    changed_lines = parse_changed_lines(diff_text) if do_diff_filter else {}

    return _execute(
        ctx,
        skipped,
        do_diff_filter=do_diff_filter,
        changed_set=changed_set,
        changed_lines=changed_lines,
    )


def _is_within(path: Path, root: Path) -> bool:
    """Return True when ``path`` is ``root`` or a descendant of it."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _run_patch_scan(patch_text: str, config: VibeGuardConfig) -> ScanResult:
    """Scan a unified diff standalone, before it is applied (#153).

    The new-side of every file in the patch is reconstructed
    (:func:`reconstruct_patch_files`) into a throwaway temporary tree and scanned
    with the change-set restricted to the patch's added lines, so a finding is
    reported only on content the patch actually introduces. The temp tree is
    removed before returning; findings already carry repo-relative paths.
    """
    reconstructed = reconstruct_patch_files(patch_text)
    changed_lines = parse_changed_lines(patch_text)

    with tempfile.TemporaryDirectory(prefix="vibeguard-patch-") as td:
        root = Path(td).resolve()
        all_files: list[Path] = []
        written_rels: set[str] = set()
        skipped: list[_SkipNote] = []
        for rel, content in reconstructed.items():
            dest = (root / rel).resolve()
            # A crafted diff could name "b/../../etc/passwd"; never write outside
            # the sandbox even though it is a throwaway directory. A refused path
            # is a degraded scan (error severity) so it is visible and trips
            # ``gate --strict-errors`` rather than silently scanning fewer files.
            if not _is_within(dest, root):
                skipped.append((f"Refused patch path outside sandbox: {rel}", "error"))
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            all_files.append(dest)
            written_rels.add(rel.replace("\\", "/"))
        all_files.sort()

        # Scope to the files actually materialised, not every path named in the
        # diff, so a refused path can't leave a changed_set entry with no file.
        changed_set = written_rels
        ctx = ScanContext(
            root=root,
            config=config,
            files=all_files,
            changed_files=all_files,
            git=GitMetadata(is_available=False),
            diff_only=True,
            diff_text=patch_text,
        )
        return _execute(
            ctx,
            skipped,
            do_diff_filter=True,
            changed_set=changed_set,
            changed_lines=changed_lines,
            # Patch scans run in a throwaway temp tree; report a stable,
            # deterministic path instead of leaking the temp directory.
            scan_path="<patch>",
        )


def _execute(
    ctx: ScanContext,
    skipped: list[_SkipNote],
    *,
    do_diff_filter: bool,
    changed_set: set[str] | None,
    changed_lines: dict[str, list[tuple[int, int]]],
    scan_path: str | None = None,
) -> ScanResult:
    """Run the enabled rules over ``ctx`` and assemble the :class:`ScanResult`.

    Shared by the directory/diff/staged scan (:func:`run_scan`) and the
    standalone patch scan (:func:`_run_patch_scan`) so every scope produces an
    identical diagnostics pipeline and finding-filtering contract.

    ``scan_path`` overrides the reported :attr:`ScanResult.scan_path` (defaults
    to the resolved root); the patch scan passes a stable placeholder so its
    output never leaks the throwaway temp directory.
    """
    config = ctx.config
    root = ctx.root
    all_files = ctx.files
    git_meta = ctx.git

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
    # Structured scan diagnostics (#195): every non-finding event is recorded
    # as a categorized ``ScanDiagnostic`` so consumers can react per category
    # (and ``gate --strict-errors`` can fail closed on a degraded scan, #218).
    # ``ScanResult.errors`` is then derived from these as the flat string view.
    diagnostics: list[ScanDiagnostic] = []

    # Surface plugin load failures so they appear in console / JSON output
    # without being fatal.
    for failure in plugin_failures:
        diagnostics.append(
            ScanDiagnostic(
                category="plugin_load",
                severity="error",
                message=(
                    f"Plugin '{failure.name}' "
                    f"({failure.distribution or 'unknown dist'}) failed to load: {failure.reason}"
                ),
                rule=failure.name,
                detail=failure.reason,
            )
        )

    # Report skipped files. The walker tags each skip with its severity at the
    # point it is generated (#218): routine skips (binary/oversize/gitignored)
    # are ``info`` and never fail strict mode; unreadable/un-stattable files are
    # ``warning`` so a degraded scan is loud. Severity is no longer inferred from
    # the message text, so a new degraded skip can't silently classify as info.
    for message, severity in skipped:
        diagnostics.append(
            ScanDiagnostic(
                category="skipped_file",
                severity=severity,
                message=message,
            )
        )

    # Propagate git errors so callers know git context was degraded.
    if ctx.diff_only and git_meta and not git_meta.is_available and git_meta.error:
        diagnostics.append(
            ScanDiagnostic(
                category="git_context",
                severity="warning",
                message=f"Git context unavailable: {git_meta.error}",
                detail=git_meta.error,
            )
        )

    # Surface degraded git context as diagnostics instead of silently scanning
    # a narrower scope (#182). A "head-only" strategy in diff mode means base
    # detection failed and the diff degraded to `git diff HEAD`, so a PR gate
    # may report "0 findings" simply because the diff was nearly empty.
    if ctx.diff_only and git_meta and git_meta.is_available:
        for warning in git_meta.warnings:
            diagnostics.append(
                ScanDiagnostic(category="git_context", severity="warning", message=warning)
            )
        if git_meta.diff_strategy == "head-only":
            hint = (
                "Could not detect a base branch; comparing against HEAD only — "
                "diff-mode findings may be incomplete. Pass --base, set "
                "git.base_branch, or fetch the base branch."
            )
            if git_meta.is_shallow:
                hint += " This is a shallow clone; use fetch-depth: 0 in CI."
            diagnostics.append(
                ScanDiagnostic(category="git_context", severity="warning", message=hint)
            )

    for rule in rules:
        try:
            rule_findings = rule.scan(_context_for_rule(rule, ctx))
            # Filter out suppressed finding IDs
            rule_findings = [f for f in rule_findings if f.id not in config.ignore.findings]
            findings.extend(rule_findings)
        except Exception as exc:  # noqa: BLE001
            diagnostics.append(
                ScanDiagnostic(
                    category="rule_error",
                    severity="error",
                    message=f"Rule {rule.id} failed: {exc}",
                    rule=rule.id,
                    detail=str(exc),
                )
            )

    # Apply diff-scope filtering (#24, #199): in diff mode, restrict findings to
    # the change set. Line-based findings are kept only on changed lines;
    # findings attributable to files that are NOT part of the diff (pre-existing
    # repository state) are dropped, so a PR gate reflects "findings introduced
    # or touched by this change" rather than blocking on unrelated history.
    # Reuses the change set resolved by the caller. Runs whenever a diff/staged/
    # patch scope is active (``do_diff_filter``) — even when ``changed_lines`` is
    # empty — so a clean or empty diff cannot leak unscoped full-scan findings
    # (#258 review).
    if do_diff_filter:
        findings = _filter_by_changed_lines(findings, changed_lines, changed_set)

    # Apply inline suppressions (#44)
    findings, suppression_warnings = _apply_inline_suppressions(findings, all_files, root)
    findings.extend(suppression_warnings)

    # Collect diagnostics rules emitted via the shared context sink (#191) —
    # e.g. slopsquat's aggregated registry-network failure notice. Appended
    # after the scanner-level diagnostics so the existing ordering is preserved.
    diagnostics.extend(ctx.diagnostics)

    # Canonical, contractual output ordering (#222): sort findings once here, by
    # (path, line, id), so the order is a stable property of the *result* rather
    # than an accident of rule-registration order and per-rule file iteration.
    # This decouples ordering from internals (protecting a future parallel
    # scanner, #164, from silently reshuffling downstream diffs/baselines) and
    # folds the appended suppression warnings into the same order. File-level
    # findings (no line) sort before line-scoped findings in the same file via
    # the ``line or 0`` key. The stability contract documents this guarantee.
    findings.sort(key=lambda f: (f.path, f.line or 0, f.id))

    return ScanResult(
        findings=findings,
        scanned_files=len(all_files),
        changed_files=len(ctx.changed_files),
        scan_path=scan_path if scan_path is not None else str(root),
        policy=config.policy,
        diagnostics=diagnostics,
        # Backward-compatible flat string view, derived from the structured
        # diagnostics so the two can never drift (#195).
        errors=[d.message for d in diagnostics],
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
