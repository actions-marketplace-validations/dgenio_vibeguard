"""Central format registry mapping a format name to a rendered string (#233).

The single-flag stdout dispatch in the CLI predates file output; this module is
the one place that turns a format *name* into report text, so ``--output`` and
the repeatable ``--report FORMAT=PATH`` option (and the embedding API, #192) can
emit any format to any destination without re-implementing the per-reporter
call conventions (``pr-comment`` and ``weaver`` need gate context; ``sarif``
takes the ingestion cap).

``console`` is intentionally absent: the Rich table is terminal-only and has no
string form suitable for a file.
"""

from __future__ import annotations

from vibeguard.models import ScanResult, Severity
from vibeguard.reporters.diagnostics import render_diagnostics
from vibeguard.reporters.json_reporter import render_json
from vibeguard.reporters.markdown import render_markdown, render_pr_comment
from vibeguard.reporters.rdjson import render_rdjson
from vibeguard.reporters.sarif import DEFAULT_SARIF_MAX_RESULTS, render_sarif
from vibeguard.reporters.sonar import render_sonar
from vibeguard.reporters.weaver import render_weaver

# Machine-readable formats that can be written to a file or stdout. Order is the
# documented precedence used in help text and error messages.
MACHINE_FORMATS: tuple[str, ...] = (
    "json",
    "sarif",
    "markdown",
    "pr-comment",
    "diagnostics",
    "weaver",
    "rdjson",
    "sonar",
)


def render_format(
    fmt: str,
    result: ScanResult,
    *,
    gate_passed: bool = True,
    threshold: Severity = Severity.HIGH,
    blocking: bool = False,
    sarif_max_results: int = DEFAULT_SARIF_MAX_RESULTS,
) -> str:
    """Render ``result`` as ``fmt`` and return the report text.

    ``gate_passed``/``threshold`` parameterise the PR-comment headline and the
    weaver report mode; ``blocking`` selects the weaver advisory/blocking mode;
    ``sarif_max_results`` is the SARIF ingestion cap. Raises ``ValueError`` for
    an unknown format name.
    """
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result, max_results=sarif_max_results)
    if fmt == "markdown":
        return render_markdown(result)
    if fmt == "pr-comment":
        return render_pr_comment(result, gate_passed=gate_passed, threshold=threshold)
    if fmt == "diagnostics":
        return render_diagnostics(result)
    if fmt == "weaver":
        return render_weaver(result, threshold=threshold, blocking=blocking)
    if fmt == "rdjson":
        return render_rdjson(result)
    if fmt == "sonar":
        return render_sonar(result)
    raise ValueError(f"Unknown output format: {fmt!r}. Valid formats: {', '.join(MACHINE_FORMATS)}")
