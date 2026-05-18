"""VibeGuard CLI — entry point."""

from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console

from vibeguard import __version__
from vibeguard.config import DEFAULT_CONFIG_YAML, VibeGuardConfig
from vibeguard.git import get_git_metadata
from vibeguard.models import Severity
from vibeguard.reporters.console import render_findings
from vibeguard.reporters.json_reporter import print_json
from vibeguard.reporters.markdown import render_markdown
from vibeguard.scanner import run_scan

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
) -> None:
    """Create a default vibeguard.yaml configuration file."""
    config_path = path / "vibeguard.yaml"
    if config_path.exists():
        err_console.print(f"[yellow]vibeguard.yaml already exists at {config_path}. Skipping.[/]")
        raise typer.Exit(0)

    path.mkdir(parents=True, exist_ok=True)
    config_path.write_text(DEFAULT_CONFIG_YAML)
    err_console.print(f"[green]✓[/] Created [bold]{config_path}[/]")
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


def _validate_output_options(json_output: bool, markdown_output: bool) -> None:
    """Fail fast if mutually exclusive output options are both set."""
    if json_output and markdown_output:
        err_console.print(
            "[red]Error: --json and --markdown are mutually exclusive. Choose one.[/]"
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
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit non-zero if findings meet this severity [info|low|medium|high|critical]",
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show detailed finding descriptions"),
    ] = False,
) -> None:
    """Scan a repository for risky AI-generated code patterns."""
    _validate_output_options(json_output, markdown_output)
    cfg = _load_config(config, path)
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

    if json_output:
        print_json(result)
    elif markdown_output:
        typer.echo(render_markdown(result))
    else:
        render_findings(result, verbose=verbose)

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
    """Scan and exit non-zero if blocking findings are found (for CI gates)."""
    _validate_output_options(json_output, markdown_output)
    cfg = _load_config(config, path)
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

    if json_output:
        print_json(result)
    elif markdown_output:
        typer.echo(render_markdown(result))
    else:
        render_findings(result, verbose=verbose)

    if result.errors:
        for err in result.errors:
            err_console.print(f"[yellow]⚠ {err}[/]")

    threshold = cfg.fail_on
    if result.has_blocking(threshold):
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
# explain
# ---------------------------------------------------------------------------

_FINDING_EXPLANATIONS: dict[str, str] = {
    "SEC-AWSACCESSKEY": """
[bold]AWS Access Key (SEC-AWSACCESSKEY)[/]

AWS Access Key IDs (beginning AKIA…) are credentials for AWS services.
Committing them exposes your account to unauthorized access, data theft,
cryptomining charges, and data exfiltration.

[bold]Why it matters:[/]
Bots scan GitHub/GitLab continuously for leaked AWS keys. Exposure time can
be seconds before a key is exploited.

[bold]How to fix:[/]
1. Rotate the key immediately in the AWS IAM console.
2. Audit CloudTrail for unauthorized usage.
3. Remove the key from git history (git filter-repo or BFG).
4. Use IAM roles, environment variables, or AWS Secrets Manager instead.
""",
    "SEC-ENV": """
[bold]Sensitive .env file committed (SEC-ENV)[/]

.env files typically contain database passwords, API keys, JWT secrets, and
other credentials. They should never be committed.

[bold]How to fix:[/]
1. Add .env to .gitignore immediately.
2. Remove it from git history.
3. Rotate all credentials contained in the file.
4. Use environment variables in CI/CD instead.
""",
    "MAP-DIST": """
[bold]Source map in distribution directory (MAP-DIST)[/]

Source maps (.map files) reverse-engineer your minified/compiled code back to
the original source. Publishing them exposes your source code to anyone who
downloads your package or opens DevTools.

[bold]How to fix:[/]
Add *.map to .npmignore or remove .map patterns from your package.json `files`.
""",
    "TEST-MISSING": """
[bold]Source changes without tests (TEST-MISSING)[/]

AI coding tools generate code quickly but often skip tests. Untested
AI-generated code is a common source of regressions, edge-case bugs, and
security gaps that only show up in production.

[bold]How to fix:[/]
Write unit tests covering the changed logic before merging. Even basic
happy-path tests catch a large percentage of AI hallucination bugs.
""",
    "RISK-EVALEXEC": """
[bold]eval() / exec() usage (RISK-EVALEXEC)[/]

Dynamic code execution functions can run arbitrary code. If user input
reaches eval/exec, this is a critical Remote Code Execution (RCE) vulnerability.

[bold]How to fix:[/]
Eliminate eval/exec if possible. If not, ensure inputs are strictly validated
and whitelisted before execution.
""",
    "AI-DISABLESECURITY": """
[bold]Security disabled (AI-DISABLESECURITY)[/]

AI coding assistants sometimes comment out or disable security controls to
make code "work" without understanding the implications. This is a very
common source of vulnerabilities in AI-generated code.

[bold]How to fix:[/]
Re-enable the security control. If the bypass is intentional, document the
reason and get a security review.
""",
}

_DEFAULT_EXPLANATION = """
[bold]{finding_id}[/]

No detailed explanation is available for this finding ID.

Run [bold]vibeguard scan --verbose[/] for inline descriptions and recommendations.
For more information, see the VibeGuard documentation:
https://github.com/dgenio/vibeguard
"""


@app.command()
def explain(
    finding_id: Annotated[str, typer.Argument(help="Finding ID to explain, e.g. SEC-ENV")],
) -> None:
    """Print an explanation of a finding type and how to fix it."""
    c = Console()
    text = _FINDING_EXPLANATIONS.get(
        finding_id.upper(),
        _DEFAULT_EXPLANATION.format(finding_id=finding_id),
    )
    c.print(text)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_config(config_path: Path | None, scan_path: Path) -> VibeGuardConfig:
    """Load config, searching scan_path if no explicit config given."""
    if config_path:
        try:
            return VibeGuardConfig.load(config_path)
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
            return VibeGuardConfig.load(candidate)
        except ValidationError as exc:
            err_console.print(f"[red]Invalid config {candidate}:[/]")
            for error in exc.errors():
                loc = " → ".join(str(p) for p in error["loc"])
                err_console.print(f"  [bold]{loc}[/]: {error['msg']}")
            raise typer.Exit(2) from exc
        except Exception as exc:
            err_console.print(f"[yellow]⚠ Could not load {candidate}: {exc}. Using defaults.[/]")

    return VibeGuardConfig()


def _parse_severity(value: str) -> Severity:
    valid = [s.value for s in Severity]
    try:
        return Severity(value.lower())
    except ValueError:
        err_console.print(f"[red]Invalid severity: {value!r}. Valid options: {', '.join(valid)}[/]")
        raise typer.Exit(2) from None
