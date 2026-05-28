"""VibeGuard CLI — entry point."""

from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape

from vibeguard import __version__
from vibeguard.config import (
    DEFAULT_CONFIG_YAML,
    VibeGuardConfig,
    apply_policy_suppressions,
    apply_severity_overrides,
)
from vibeguard.git import get_git_metadata
from vibeguard.models import Severity
from vibeguard.policies import KNOWN_PACK_NAMES, load_policy_pack
from vibeguard.publish import run_publish_check
from vibeguard.reporters.annotations import emit_annotations, is_github_actions
from vibeguard.reporters.console import render_findings
from vibeguard.reporters.diagnostics import print_diagnostics
from vibeguard.reporters.json_reporter import print_json
from vibeguard.reporters.markdown import render_markdown, render_pr_comment
from vibeguard.reporters.sarif import print_sarif
from vibeguard.scanner import run_scan

if TYPE_CHECKING:
    from vibeguard.models import Finding, ScanResult

app = typer.Typer(
    name="vibeguard",
    help="Guardrails for vibe-coded software.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
err_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"vibeguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", "-V", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """VibeGuard — a pre-merge safety gate for AI-generated code."""


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


@app.command()
def init(
    path: Annotated[
        Path,
        typer.Option("--path", help="Directory to create vibeguard.yaml in"),
    ] = Path("."),
    policy_pack: Annotated[
        str | None,
        typer.Option(
            "--policy-pack",
            help=(f"Pre-populate with a built-in policy pack ({', '.join(KNOWN_PACK_NAMES)})"),
        ),
    ] = None,
) -> None:
    """Create a default vibeguard.yaml configuration file."""
    config_path = path / "vibeguard.yaml"
    if config_path.exists():
        err_console.print(f"[yellow]vibeguard.yaml already exists at {config_path}. Skipping.[/]")
        raise typer.Exit(0)

    if policy_pack is not None:
        try:
            load_policy_pack(policy_pack)
        except ValueError as exc:
            err_console.print(f"[red]{exc}[/]")
            raise typer.Exit(2) from exc
        body = (
            f"# VibeGuard configuration — generated from policy pack: {policy_pack}\n"
            f"# Run `vibeguard init` to regenerate without a pack.\n"
            "#\n"
            "# Pack defaults are applied at load time; any value you set below\n"
            "# overrides the pack. See docs/policy-packs.md for the full list.\n\n"
            f"policy_pack: {policy_pack}\n"
        )
    else:
        body = DEFAULT_CONFIG_YAML

    path.mkdir(parents=True, exist_ok=True)
    config_path.write_text(body)
    err_console.print(f"[green]✓[/] Created [bold]{config_path}[/]")
    if policy_pack is not None:
        err_console.print(
            f"  Pre-populated with policy pack [bold]{policy_pack}[/]. "
            "Add overrides below the policy_pack key."
        )
    else:
        err_console.print("  Edit it to customise your policy, ignores, and enabled rules.")


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Show version, Python, platform, and install path."""
    import vibeguard

    install_path = Path(vibeguard.__file__).resolve().parent
    lines = [
        f"vibeguard {__version__}",
        f"Python {sys.version.split()[0]}",
        f"Platform: {platform.platform()}",
        f"Install path: {install_path}",
    ]
    for line in lines:
        typer.echo(line)


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@app.command()
def validate(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Directory to search for vibeguard.yaml"),
    ] = Path("."),
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to vibeguard.yaml"),
    ] = None,
) -> None:
    """Validate a vibeguard.yaml config file and exit 0 (valid) or 1 (invalid)."""
    config_path = config or (path / "vibeguard.yaml")
    if not config_path.exists():
        err_console.print(f"[red]Config file not found: {config_path}[/]")
        raise typer.Exit(1)

    try:
        VibeGuardConfig.load(config_path)
    except ValidationError as exc:
        err_console.print(f"[red]Invalid config: {config_path}[/]\n")
        for error in exc.errors():
            loc = " → ".join(str(p) for p in error["loc"])
            err_console.print(f"  [bold]{loc}[/]: {error['msg']}")
        raise typer.Exit(1) from None
    except Exception as exc:
        err_console.print(f"[red]Error reading config: {exc}[/]")
        raise typer.Exit(1) from None

    typer.echo(f"✓ Config is valid: {config_path}")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _validate_output_options(
    json_output: bool,
    markdown_output: bool,
    sarif_output: bool = False,
    pr_comment_output: bool = False,
    diagnostics_output: bool = False,
    annotations_explicit: bool = False,
) -> None:
    """Fail fast if mutually exclusive output options are set together."""
    selected = sum(
        [json_output, markdown_output, sarif_output, pr_comment_output, diagnostics_output]
    )
    if selected > 1:
        err_console.print(
            "[red]Error: --json, --markdown, --sarif, --pr-comment, and --diagnostics are"
            " mutually exclusive. Choose one.[/]"
        )
        raise typer.Exit(2)
    if annotations_explicit and selected >= 1:
        # Annotations are workflow commands printed to stdout. Combining them
        # with structured output (JSON/SARIF/Markdown/diagnostics) interleaves
        # them into the report and breaks downstream parsers. Annotations
        # still auto-enable in GitHub Actions when no structured output is
        # selected.
        err_console.print(
            "[red]Error: --annotations cannot be combined with --json, --markdown,"
            " --sarif, --pr-comment, or --diagnostics (annotations would corrupt"
            " the structured output).[/]"
        )
        raise typer.Exit(2)


def _validate_scan_path(path: Path) -> None:
    """Reject a ``--path`` that is missing or is not a directory.

    The scanner walks ``path.rglob("*")``, which silently yields nothing for a
    missing path or a single file. Without this guard ``gate`` fails *open* —
    a typo'd or unchecked-out path prints "Gate passed" and exits 0. Validate
    at the CLI boundary so the gate fails closed instead.
    """
    # Escape the user-supplied path: Rich would otherwise interpret bracketed
    # segments (e.g. a dir literally named "[wip]") as markup tags and drop or
    # mangle them, so the error would show a different path than was typed.
    shown = escape(str(path))
    if not path.exists():
        err_console.print(
            f"[red]Error: --path does not exist: {shown}[/]\n"
            "Pass the repository root you want to scan."
        )
        raise typer.Exit(2)
    if not path.is_dir():
        err_console.print(
            f"[red]Error: --path must be a directory, but got a file: {shown}[/]\n"
            "Pass the repository root (a directory), not an individual file."
        )
        raise typer.Exit(2)


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Repository or directory to scan"),
    ] = Path("."),
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to vibeguard.yaml"),
    ] = None,
    diff: Annotated[
        bool,
        typer.Option("--diff", help="Scan only changed files (requires git)"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output findings as JSON"),
    ] = False,
    markdown_output: Annotated[
        bool,
        typer.Option("--markdown", help="Output findings as Markdown"),
    ] = False,
    sarif_output: Annotated[
        bool,
        typer.Option("--sarif", help="Output findings as SARIF 2.1.0 JSON"),
    ] = False,
    pr_comment_output: Annotated[
        bool,
        typer.Option("--pr-comment", help="Output PR-optimized Markdown comment"),
    ] = False,
    diagnostics_output: Annotated[
        bool,
        typer.Option(
            "--diagnostics",
            help="Output a stable JSON diagnostics array for IDE / editor integrations",
        ),
    ] = False,
    annotations: Annotated[
        bool | None,
        typer.Option(
            "--annotations/--no-annotations",
            help="Emit GitHub Actions annotations (auto-enabled in CI)",
        ),
    ] = None,
    baseline_path: Annotated[
        Path | None,
        typer.Option("--baseline", help="Path to baseline file for suppressing known findings"),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help=(
                "Severity threshold used to summarize blocking findings; scan always "
                "exits 0 (informational) — use `vibeguard gate` to fail CI. "
                "[info|low|medium|high|critical]"
            ),
        ),
    ] = None,
    policy_pack: Annotated[
        str | None,
        typer.Option(
            "--policy-pack",
            help=(
                "Apply a built-in policy pack as defaults under the user config "
                f"({', '.join(KNOWN_PACK_NAMES)})"
            ),
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show detailed finding descriptions"),
    ] = False,
) -> None:
    """Scan a repository for risky AI-generated code patterns."""
    _validate_scan_path(path)
    _validate_output_options(
        json_output,
        markdown_output,
        sarif_output,
        pr_comment_output,
        diagnostics_output,
        annotations_explicit=(annotations is True),
    )
    cfg = _load_config(config, path, policy_pack=policy_pack)
    if fail_on:
        cfg.fail_on = _parse_severity(fail_on)

    git_meta = None
    if diff:
        git_meta = get_git_metadata(path.resolve())
        if not git_meta.is_available:
            err_console.print(
                f"[yellow]⚠ Git not available: {git_meta.error}. Falling back to full scan.[/]"
            )
            diff = False

    result = run_scan(path, cfg, diff_only=diff, git_meta=git_meta)

    # Apply severity overrides and policy suppressions
    result = _apply_policy(result, cfg)

    # Apply baseline filtering
    result = _apply_baseline(result, baseline_path, cfg)

    # Determine annotation mode
    emit_annot = _should_emit_annotations(
        annotations,
        json_output,
        markdown_output,
        sarif_output,
        pr_comment_output,
        diagnostics_output,
    )

    if json_output:
        print_json(result)
    elif sarif_output:
        print_sarif(result)
    elif pr_comment_output:
        # scan still exits 0, but the PR-comment headline must reflect whether
        # blocking findings exist — otherwise it claims PASS while listing them.
        scan_gate_passed = not result.has_blocking(cfg.fail_on)
        typer.echo(render_pr_comment(result, gate_passed=scan_gate_passed, threshold=cfg.fail_on))
    elif markdown_output:
        typer.echo(render_markdown(result))
    elif diagnostics_output:
        print_diagnostics(result)
    else:
        render_findings(result, verbose=verbose)

    if emit_annot:
        emit_annotations(result)

    if result.errors:
        for err in result.errors:
            err_console.print(f"[yellow]⚠ {err}[/]")

    # scan command: always exit 0 (informational)


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------


@app.command()
def gate(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Repository or directory to scan"),
    ] = Path("."),
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to vibeguard.yaml"),
    ] = None,
    diff: Annotated[
        bool,
        typer.Option("--diff", help="Scan only changed files (requires git)"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output findings as JSON"),
    ] = False,
    markdown_output: Annotated[
        bool,
        typer.Option("--markdown", help="Output findings as Markdown"),
    ] = False,
    sarif_output: Annotated[
        bool,
        typer.Option("--sarif", help="Output findings as SARIF 2.1.0 JSON"),
    ] = False,
    pr_comment_output: Annotated[
        bool,
        typer.Option("--pr-comment", help="Output PR-optimized Markdown comment"),
    ] = False,
    diagnostics_output: Annotated[
        bool,
        typer.Option(
            "--diagnostics",
            help="Output a stable JSON diagnostics array for IDE / editor integrations",
        ),
    ] = False,
    annotations: Annotated[
        bool | None,
        typer.Option(
            "--annotations/--no-annotations",
            help="Emit GitHub Actions annotations (auto-enabled in CI)",
        ),
    ] = None,
    baseline_path: Annotated[
        Path | None,
        typer.Option("--baseline", help="Path to baseline file for suppressing known findings"),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Severity threshold for non-zero exit [info|low|medium|high|critical]",
        ),
    ] = None,
    policy_pack: Annotated[
        str | None,
        typer.Option(
            "--policy-pack",
            help=(
                "Apply a built-in policy pack as defaults under the user config "
                f"({', '.join(KNOWN_PACK_NAMES)})"
            ),
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show detailed finding descriptions"),
    ] = False,
) -> None:
    """Scan and exit non-zero if blocking findings are found (for CI gates)."""
    _validate_scan_path(path)
    _validate_output_options(
        json_output,
        markdown_output,
        sarif_output,
        pr_comment_output,
        diagnostics_output,
        annotations_explicit=(annotations is True),
    )
    cfg = _load_config(config, path, policy_pack=policy_pack)
    if fail_on:
        cfg.fail_on = _parse_severity(fail_on)

    git_meta = None
    if diff:
        git_meta = get_git_metadata(path.resolve())
        if not git_meta.is_available:
            err_console.print(
                f"[yellow]⚠ Git not available: {git_meta.error}. Falling back to full scan.[/]"
            )
            diff = False

    result = run_scan(path, cfg, diff_only=diff, git_meta=git_meta)

    # Apply severity overrides and policy suppressions
    result = _apply_policy(result, cfg)

    # Apply baseline filtering
    result = _apply_baseline(result, baseline_path, cfg)

    threshold = cfg.fail_on
    gate_passed = not result.has_blocking(threshold)

    # Determine annotation mode
    emit_annot = _should_emit_annotations(
        annotations,
        json_output,
        markdown_output,
        sarif_output,
        pr_comment_output,
        diagnostics_output,
    )

    if json_output:
        print_json(result)
    elif sarif_output:
        print_sarif(result)
    elif pr_comment_output:
        typer.echo(render_pr_comment(result, gate_passed=gate_passed, threshold=threshold))
    elif markdown_output:
        typer.echo(render_markdown(result))
    elif diagnostics_output:
        print_diagnostics(result)
    else:
        render_findings(result, verbose=verbose)

    if emit_annot:
        emit_annotations(result)

    if result.errors:
        for err in result.errors:
            err_console.print(f"[yellow]⚠ {err}[/]")

    if not gate_passed:
        err_console.print(
            f"\n[bold red]✗ Gate failed:[/] findings at or above "
            f"[bold]{threshold.value}[/] severity detected.\n"
        )
        raise typer.Exit(1)
    else:
        err_console.print(
            f"\n[bold green]✓ Gate passed:[/] no findings at or above "
            f"[bold]{threshold.value}[/] severity.\n"
        )


# ---------------------------------------------------------------------------
# publish-check
# ---------------------------------------------------------------------------


@app.command(name="publish-check")
def publish_check(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Package root containing package.json or pyproject.toml"),
    ] = Path("."),
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to vibeguard.yaml"),
    ] = None,
    ecosystem: Annotated[
        str | None,
        typer.Option(
            "--ecosystem",
            help=(
                "Which artifact to simulate [auto|npm|python-sdist|python-wheel]. "
                "Defaults to the value in vibeguard.yaml `publish_check.ecosystem`."
            ),
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output findings + manifest as JSON"),
    ] = False,
    markdown_output: Annotated[
        bool,
        typer.Option("--markdown", help="Output findings as Markdown"),
    ] = False,
    manifest_out: Annotated[
        Path | None,
        typer.Option(
            "--manifest-out",
            help="Write the publish manifest JSON to this path",
        ),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Severity threshold for non-zero exit [info|low|medium|high|critical]",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show detailed finding descriptions"),
    ] = False,
) -> None:
    """Simulate a publish and gate on any findings in the published file set."""
    _validate_scan_path(path)
    _validate_output_options(json_output, markdown_output)
    cfg = _load_config(config, path)
    if not cfg.publish_check.enabled:
        err_console.print(
            "[yellow]publish-check is disabled in vibeguard.yaml "
            "(publish_check.enabled = false). Skipping.[/]"
        )
        raise typer.Exit(0)

    threshold = _parse_severity(fail_on) if fail_on else cfg.publish_check.fail_on
    effective_ecosystem = ecosystem if ecosystem is not None else cfg.publish_check.ecosystem
    valid_ecosystems = {"auto", "npm", "python-sdist", "python-wheel"}
    if effective_ecosystem not in valid_ecosystems:
        err_console.print(
            f"[red]Invalid --ecosystem: {effective_ecosystem!r}. "
            f"Valid options: {', '.join(sorted(valid_ecosystems))}[/]"
        )
        raise typer.Exit(2)

    manifest, result = run_publish_check(path, cfg, ecosystem=effective_ecosystem)  # type: ignore[arg-type]

    # Apply severity overrides and policy suppressions (consistent with scan/gate)
    result = _apply_policy(result, cfg)

    if manifest_out is not None:
        manifest_out.parent.mkdir(parents=True, exist_ok=True)
        manifest_out.write_text(manifest.to_json(), encoding="utf-8")
        err_console.print(f"[green]✓[/] Wrote manifest to [bold]{manifest_out}[/]")

    if json_output:
        import json as _json

        payload = {
            "manifest": _json.loads(manifest.to_json()),
            "result": result.model_dump(mode="json"),
        }
        typer.echo(_json.dumps(payload, indent=2, sort_keys=True))
    elif markdown_output:
        typer.echo(render_markdown(result))
    else:
        err_console.print(
            f"[bold]publish-check[/] ecosystem=[cyan]{manifest.ecosystem}[/] "
            f"files=[bold]{len(manifest.files)}[/] "
            f"size=[bold]{manifest.total_bytes}[/]B"
        )
        render_findings(result, verbose=verbose)

    if result.errors:
        for err in result.errors:
            err_console.print(f"[yellow]⚠ {err}[/]")

    if result.has_blocking(threshold):
        err_console.print(
            f"\n[bold red]✗ publish-check failed:[/] findings at or above "
            f"[bold]{threshold.value}[/] severity detected.\n"
        )
        raise typer.Exit(1)
    err_console.print(
        f"\n[bold green]✓ publish-check passed:[/] no findings at or above "
        f"[bold]{threshold.value}[/] severity in the published file set.\n"
    )


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------

_UNKNOWN_FINDING_MESSAGE = (
    "Unknown rule or finding ID: {finding_id!r}. Run 'vibeguard rules list' to see available rules."
)


def _resolve_explain_adapter(name: str):
    """Construct the explain adapter named ``name`` or exit 2.

    Centralised so both ``explain`` and any future commands wanting an
    adapter (e.g. an ``explain`` JSON exporter) share the same error UX.
    """
    from vibeguard.explain import get_explain_adapter

    try:
        return get_explain_adapter(name)
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc


@app.command()
def explain(
    finding_id: Annotated[str, typer.Argument(help="Finding ID to explain, e.g. SEC-ENV")],
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Directory to load vibeguard.yaml from"),
    ] = Path("."),
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to vibeguard.yaml"),
    ] = None,
    adapter: Annotated[
        str | None,
        typer.Option(
            "--adapter",
            "--explain-adapter",
            help=(
                "Override the configured explain adapter. The built-in 'static' "
                "adapter is always available; install plugins for richer adapters."
            ),
        ),
    ] = None,
) -> None:
    """Print an explanation of a finding type and how to fix it."""
    from vibeguard.explain import StaticExplainAdapter
    from vibeguard.models import Confidence, Finding, Severity
    from vibeguard.rules.registry import RULE_REGISTRY

    _ensure_rules_loaded()

    c = Console()
    upper_id = finding_id.upper()

    # Resolve the adapter: CLI flag > config > "static". The legacy code path
    # printed the hand-written curated text directly without going through any
    # registry lookup, so we preserve that exact behaviour: when the chosen
    # adapter is the static one *and* a curated explanation exists for the
    # upper-cased ID, render the curated text verbatim.
    cfg = _load_config(config, path)
    # A whitespace-only `--adapter` override is treated as "no override" and
    # falls back to the configured adapter, mirroring the config validator's
    # rejection of blank names (config.py) and avoiding an opaque
    # "Unknown explain adapter '   '" error.
    adapter_name = (adapter or "").strip() or cfg.explain.adapter
    explainer = _resolve_explain_adapter(adapter_name)

    if isinstance(explainer, StaticExplainAdapter):
        curated = StaticExplainAdapter.explain_by_id(upper_id)
        if curated:
            c.print(curated)
            return

    # Find the parent rule so we can synthesise a Finding for the adapter.
    # We do this even for the static adapter so that non-curated IDs go
    # through one canonical code path.
    for metadata in RULE_REGISTRY.values():
        if upper_id in {fid.upper() for fid in metadata.finding_ids}:
            synthetic = Finding(
                id=upper_id,
                rule=metadata.rule_id,
                title=metadata.title,
                description=metadata.description,
                severity=Severity(metadata.default_severity),
                path="(explain)",
                recommendation="",
                tags=list(metadata.tags),
                confidence=Confidence(metadata.confidence),
            )
            c.print(explainer.explain(synthetic))
            return

    # Match the exit-code semantics of ``vibeguard rules explain``: an
    # unknown identifier is a hard error (exit 2) so a typo in CI doesn't
    # silently masquerade as a passed explain. See issue #90.
    err_console.print(f"[red]{_UNKNOWN_FINDING_MESSAGE.format(finding_id=finding_id)}[/]")
    raise typer.Exit(2)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_config(
    config_path: Path | None,
    scan_path: Path,
    *,
    policy_pack: str | None = None,
) -> VibeGuardConfig:
    """Load config, searching scan_path if no explicit config given.

    ``policy_pack`` is a CLI-level override for the optional ``policy_pack:``
    YAML key. When set, it wins over the file's setting and is propagated
    into :meth:`VibeGuardConfig.load` so its defaults merge in before
    validation.
    """
    if config_path:
        try:
            return VibeGuardConfig.load(config_path, policy_pack=policy_pack)
        except ValidationError as exc:
            err_console.print(f"[red]Invalid config {config_path}:[/]")
            for error in exc.errors():
                loc = " → ".join(str(p) for p in error["loc"])
                err_console.print(f"  [bold]{loc}[/]: {error['msg']}")
            raise typer.Exit(2) from exc
        except Exception as exc:
            err_console.print(f"[red]Error loading config {config_path}: {exc}[/]")
            raise typer.Exit(2) from exc

    # Auto-discover vibeguard.yaml in scan path
    candidate = scan_path / "vibeguard.yaml"
    if candidate.exists():
        try:
            return VibeGuardConfig.load(candidate, policy_pack=policy_pack)
        except ValidationError as exc:
            err_console.print(f"[red]Invalid config {candidate}:[/]")
            for error in exc.errors():
                loc = " → ".join(str(p) for p in error["loc"])
                err_console.print(f"  [bold]{loc}[/]: {error['msg']}")
            raise typer.Exit(2) from exc
        except Exception as exc:
            err_console.print(f"[yellow]⚠ Could not load {candidate}: {exc}. Using defaults.[/]")

    # No vibeguard.yaml in the scan path — still honour --policy-pack so
    # users can ship a pack-only invocation in CI without committing a
    # config file. Pass a path inside scan_path that definitely doesn't
    # exist so VibeGuardConfig.load doesn't fall through to the CWD's
    # ``vibeguard.yaml`` and silently apply it as user config.
    if policy_pack is not None:
        try:
            return VibeGuardConfig.load(candidate, policy_pack=policy_pack)
        except ValidationError as exc:
            err_console.print(f"[red]Invalid --policy-pack {policy_pack!r}:[/]")
            for error in exc.errors():
                loc = " → ".join(str(p) for p in error["loc"])
                err_console.print(f"  [bold]{loc}[/]: {error['msg']}")
            raise typer.Exit(2) from exc
    return VibeGuardConfig()


def _parse_severity(value: str) -> Severity:
    valid = [s.value for s in Severity]
    try:
        return Severity(value.lower())
    except ValueError:
        err_console.print(f"[red]Invalid severity: {value!r}. Valid options: {', '.join(valid)}[/]")
        raise typer.Exit(2) from None


def _apply_policy(result: ScanResult, cfg: VibeGuardConfig) -> ScanResult:
    """Apply severity overrides and policy suppressions to a scan result."""
    findings = result.findings

    # Apply severity overrides (#27)
    if cfg.severity_overrides:
        findings = apply_severity_overrides(findings, cfg.severity_overrides)

    # Apply policy suppressions (#28)
    warnings: list[Finding] = []
    if cfg.suppressions:
        findings, warnings = apply_policy_suppressions(findings, cfg.suppressions)

    # Use model_copy so we inherit any future ScanResult fields rather than
    # re-enumerating the schema each time a field is added.
    return result.model_copy(update={"findings": findings + warnings})


def _apply_baseline(
    result: ScanResult, baseline_path: Path | None, cfg: VibeGuardConfig
) -> ScanResult:
    """Apply baseline filtering to a scan result."""
    from vibeguard.baseline import Baseline, BaselineLoadError, filter_baselined

    bp = baseline_path
    if bp is None and cfg.baseline:
        bp = Path(cfg.baseline)

    if bp is None or not bp.exists():
        return result

    try:
        baseline = Baseline.load(bp)
    except BaselineLoadError as exc:
        err_console.print(f"[red]Error: {exc}[/]")
        raise typer.Exit(2) from exc
    filtered = filter_baselined(result.findings, baseline)
    return result.model_copy(update={"findings": filtered})


def _should_emit_annotations(
    annotations_flag: bool | None,
    json_output: bool,
    markdown_output: bool,
    sarif_output: bool,
    pr_comment_output: bool,
    diagnostics_output: bool = False,
) -> bool:
    """Determine whether to emit GitHub Actions annotations."""
    # Explicit flag takes precedence
    if annotations_flag is True:
        return True
    if annotations_flag is False:
        return False
    # Auto-enable in GitHub Actions unless another structured output is selected
    return is_github_actions() and not any(
        [json_output, markdown_output, sarif_output, pr_comment_output, diagnostics_output]
    )


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------

baseline_app = typer.Typer(name="baseline", help="Manage baseline files.", no_args_is_help=True)
app.add_typer(baseline_app)


@baseline_app.command("create")
def baseline_create(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Repository or directory to scan"),
    ] = Path("."),
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to vibeguard.yaml"),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output baseline file path"),
    ] = Path(".vibeguard-baseline.json"),
) -> None:
    """Create a baseline file from a full scan of the repository."""
    from vibeguard.baseline import create_baseline

    _validate_scan_path(path)
    cfg = _load_config(config, path)
    result = run_scan(path, cfg, diff_only=False)

    baseline = create_baseline(result.findings)
    baseline.save(output)

    err_console.print(
        f"[green]✓[/] Baseline created: [bold]{output}[/] "
        f"({len(baseline.entries)} finding(s) fingerprinted)"
    )


@baseline_app.command("update")
def baseline_update(
    path: Annotated[
        Path,
        typer.Option("--path", "-p", help="Repository or directory to scan"),
    ] = Path("."),
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to vibeguard.yaml"),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Baseline file path to update"),
    ] = Path(".vibeguard-baseline.json"),
) -> None:
    """Re-scan and update an existing baseline file."""
    from vibeguard.baseline import create_baseline

    _validate_scan_path(path)
    cfg = _load_config(config, path)
    result = run_scan(path, cfg, diff_only=False)

    baseline = create_baseline(result.findings)
    baseline.save(output)

    err_console.print(
        f"[green]✓[/] Baseline updated: [bold]{output}[/] "
        f"({len(baseline.entries)} finding(s) fingerprinted)"
    )


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

rules_app = typer.Typer(
    name="rules",
    help="Inspect available rules and their finding IDs.",
    no_args_is_help=True,
)
app.add_typer(rules_app)


def _ensure_rules_loaded() -> None:
    """Import every rule module so ``RULE_REGISTRY`` is populated.

    Delegates to the canonical ``vibeguard.rules.load_all_builtin_rules``
    so the module list is maintained in exactly one place.
    """
    from vibeguard.rules import load_all_builtin_rules

    load_all_builtin_rules()


@rules_app.command("list")
def rules_list(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output as JSON instead of a table"),
    ] = False,
    tag: Annotated[
        str | None,
        typer.Option("--tag", help="Filter by tag (case-insensitive)"),
    ] = None,
    list_plugins: Annotated[
        bool,
        typer.Option(
            "--list-plugins",
            help="Run plugin discovery and include loaded/failed plugins in the output",
        ),
    ] = False,
) -> None:
    """List all registered rules and their finding IDs."""
    import json as _json

    from rich.table import Table

    from vibeguard import __version__
    from vibeguard.rules.plugins import discover_plugin_rules
    from vibeguard.rules.registry import RULE_REGISTRY

    _ensure_rules_loaded()

    # Force-discover plugins so their rules are registered and listed.
    # We intentionally pass an empty disabled list here: ``rules list`` is a
    # discovery tool — users who want to hide a plugin can rely on
    # ``plugins.disabled`` for runtime behaviour, but the listing should
    # surface everything installed.
    plugin_summary: tuple[list, list] = ([], [])
    if list_plugins:
        plugin_summary = discover_plugin_rules()
        # Instantiating plugin rules already runs the rule's module import,
        # which (for well-behaved plugins) registers metadata. Nothing more
        # needed here.

    tag_filter = tag.lower() if tag else None

    rows: list[dict[str, object]] = []
    for rule_id in sorted(RULE_REGISTRY.keys()):
        meta = RULE_REGISTRY[rule_id]
        if tag_filter and tag_filter not in {t.lower() for t in meta.tags}:
            continue
        rows.append(
            {
                "rule_id": meta.rule_id,
                "title": meta.title,
                "default_severity": meta.default_severity,
                "confidence": meta.confidence,
                "tags": list(meta.tags),
                "finding_ids": list(meta.finding_ids),
                "applies_to": list(meta.applies_to),
                "config_key": meta.config_key or meta.rule_id,
            }
        )

    if json_output:
        payload: dict[str, object] = {"version": __version__, "rules": rows}
        if list_plugins:
            loaded, failures = plugin_summary
            payload["plugins"] = {
                "loaded": [
                    {"name": p.name, "distribution": p.distribution, "rule_id": p.rule.id}
                    for p in loaded
                ],
                "failed": [
                    {"name": f.name, "distribution": f.distribution, "reason": f.reason}
                    for f in failures
                ],
            }
        typer.echo(_json.dumps(payload, indent=2, sort_keys=False))
        return

    c = Console()
    table = Table(title=f"Rules available in vibeguard {__version__}")
    table.add_column("Rule", style="cyan", no_wrap=True)
    table.add_column("Title")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Confidence", no_wrap=True)
    table.add_column("Tags")
    for row in rows:
        table.add_row(
            str(row["rule_id"]),
            str(row["title"]),
            str(row["default_severity"]),
            str(row["confidence"]),
            ", ".join(row["tags"]),  # type: ignore[arg-type]
        )
    c.print(table)
    if not rows:
        err_console.print("[yellow]No rules matched the filter.[/]")

    if list_plugins:
        loaded, failures = plugin_summary
        plug_table = Table(title="Discovered plugins")
        plug_table.add_column("Status", style="cyan", no_wrap=True)
        plug_table.add_column("Name")
        plug_table.add_column("Distribution")
        plug_table.add_column("Detail")
        for p in loaded:
            plug_table.add_row(
                "[green]loaded[/]", p.name, p.distribution or "—", f"rule_id={p.rule.id}"
            )
        for f in failures:
            plug_table.add_row("[red]failed[/]", f.name, f.distribution or "—", f.reason)
        if not loaded and not failures:
            plug_table.add_row("—", "(none)", "—", "no entry points in 'vibeguard.rules'")
        c.print(plug_table)


@rules_app.command("explain")
def rules_explain(
    identifier: Annotated[
        str,
        typer.Argument(help="Rule ID (e.g. 'secrets') or finding ID (e.g. 'SEC-ENV')"),
    ],
) -> None:
    """Explain a rule or finding ID using metadata from the rule registry."""
    from rich.panel import Panel

    from vibeguard.rules.registry import RULE_REGISTRY

    _ensure_rules_loaded()

    c = Console()
    needle = identifier.strip()

    # Try exact rule_id first.
    meta = RULE_REGISTRY.get(needle) or RULE_REGISTRY.get(needle.lower())
    if meta is None:
        # Otherwise, treat as a finding ID and resolve to its rule.
        upper = needle.upper()
        for candidate in RULE_REGISTRY.values():
            if upper in {fid.upper() for fid in candidate.finding_ids}:
                meta = candidate
                # Print a thin header pointing at the finding ID's parent rule
                # before falling through to the full rule explanation below.
                c.print(f"[bold]{upper}[/] is produced by rule [cyan]{meta.rule_id}[/]\n")
                break

    if meta is None:
        err_console.print(f"[red]{_UNKNOWN_FINDING_MESSAGE.format(finding_id=identifier)}[/]")
        raise typer.Exit(2)

    finding_lines = [f"  • {fid}" for fid in meta.finding_ids] or ["  (none registered)"]
    body_lines = [
        f"[bold]{meta.title}[/] ({meta.rule_id})",
        "",
        meta.description,
        "",
        f"[dim]Default severity:[/] {meta.default_severity}",
        f"[dim]Confidence:[/]       {meta.confidence}",
        f"[dim]Tags:[/]             {', '.join(meta.tags) or '—'}",
        f"[dim]Applies to:[/]       {', '.join(meta.applies_to) or '*'}",
        # The config section is rule id by default, but the few mismatches
        # (e.g. ``risky_diff`` → ``risky_patterns``) used to be invisible
        # from this surface. Surfacing ``config_key`` here closes #89's UX
        # gap so a user knows exactly which YAML block tunes the rule.
        f"[dim]Config section:[/]   {meta.config_key or meta.rule_id} (in vibeguard.yaml)",
        "",
        "[bold]Finding IDs[/]",
        *finding_lines,
    ]
    if meta.docs_url:
        body_lines += ["", f"[dim]Docs:[/] {meta.docs_url}"]
    c.print(Panel.fit("\n".join(body_lines), title=meta.rule_id))
