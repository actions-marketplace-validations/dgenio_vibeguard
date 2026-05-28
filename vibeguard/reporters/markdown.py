"""Markdown reporter — useful for PR comments."""

from __future__ import annotations

from vibeguard import __version__
from vibeguard.models import Finding, ScanResult, Severity

_SEV_EMOJI = {
    Severity.INFO: "ℹ️",
    Severity.LOW: "🔵",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🔴",
    Severity.CRITICAL: "💀",
}


def render_markdown(result: ScanResult) -> str:
    """Return a Markdown string of the scan result."""
    lines: list[str] = []
    lines.append("## VibeGuard Scan Results\n")

    counts = result.counts()
    total = len(result.findings)
    score = result.health_score
    lines.append(f"**Health score:** `{score.total}/100` ({score.grade})\n")

    if total == 0:
        lines.append("✅ **No findings** — scan passed.\n")
    else:
        badges = " | ".join(
            f"{_SEV_EMOJI.get(Severity(k), '')} **{k}**: {v}" for k, v in counts.items() if v > 0
        )
        lines.append(f"**{total} finding(s)** — {badges}\n")

        lines.append("| Severity | Rule | Path | Title |\n| --- | --- | --- | --- |")

        for finding in sorted(result.findings, key=lambda f: f.severity, reverse=True):
            emoji = _SEV_EMOJI.get(finding.severity, "")
            loc = finding.path + (f":{finding.line}" if finding.line else "")
            lines.append(
                f"| {emoji} {finding.severity.value} | `{finding.rule}` "
                f"| `{loc}` | {finding.title} |"
            )

        lines.append("")
        lines.append("### Details\n")
        for finding in sorted(result.findings, key=lambda f: f.severity, reverse=True):
            lines.extend(_finding_detail(finding))

    lines.append(f"\n---\n*Scanned {result.scanned_files} file(s) · policy: {result.policy}*")
    return "\n".join(lines)


def _finding_detail(finding: Finding) -> list[str]:
    emoji = _SEV_EMOJI.get(finding.severity, "")
    loc = finding.path + (f":{finding.line}" if finding.line else "")
    lines = [
        f"#### {emoji} `{finding.id}` — {finding.title}",
        "",
        f"**Path:** `{loc}`  ",
        f"**Severity:** {finding.severity.value}  ",
        f"**Confidence:** {finding.confidence.value}  ",
        f"**Fingerprint:** `{finding.fingerprint[:12]}`  ",
        "",
        finding.description,
        "",
    ]
    if finding.evidence:
        lines += ["```", finding.evidence, "```", ""]
    lines += [f"**Recommendation:** {finding.recommendation}", ""]
    return lines


# ---------------------------------------------------------------------------
# PR-comment mode (#21)
# ---------------------------------------------------------------------------

_MAX_PR_COMMENT_CHARS = 65536


def render_pr_comment(
    result: ScanResult,
    gate_passed: bool = True,
    threshold: Severity = Severity.HIGH,
) -> str:
    """Return a PR-optimized Markdown comment with collapsible sections.

    ``threshold`` is the effective ``--fail-on`` severity. Findings at or above
    it are shown under "Blocking Findings"; everything below is collapsed. The
    default of ``HIGH`` preserves the historical split for callers that don't
    pass a threshold.
    """
    lines: list[str] = []

    # Header with pass/fail
    status_emoji = "🟢" if gate_passed else "🔴"
    status_text = "PASS" if gate_passed else "FAIL"
    lines.append(f"## {status_emoji} VibeGuard Scan Results — {status_text}\n")

    counts = result.counts()
    total = len(result.findings)

    # Summary table
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in reversed(list(Severity)):
        count = counts.get(sev.value, 0)
        if count > 0:
            emoji = _SEV_EMOJI.get(sev, "")
            lines.append(f"| {emoji} {sev.value.capitalize()} | {count} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    if total == 0:
        lines.append("✅ No findings — all clear.\n")
    else:
        # Separate blocking from non-blocking by the effective fail-on threshold
        # so the comment matches the gate decision (e.g. --fail-on medium shows
        # medium findings as blocking, not tucked under "additional findings").
        blocking = [f for f in result.findings if f.severity >= threshold]
        non_blocking = [f for f in result.findings if f.severity < threshold]

        if blocking:
            lines.append("### Blocking Findings\n")
            for finding in sorted(blocking, key=lambda f: f.severity, reverse=True):
                lines.extend(_pr_finding_detail(finding))

        if non_blocking:
            lines.append(
                f"\n<details>\n<summary>{len(non_blocking)} additional findings "
                f"(below {threshold.value} threshold)...</summary>\n"
            )
            for finding in sorted(non_blocking, key=lambda f: f.severity, reverse=True):
                lines.extend(_pr_finding_detail(finding))
            lines.append("</details>\n")

    lines.append(
        f"\n---\n*Scanned {result.scanned_files} file(s) · "
        f"policy: {result.policy} · vibeguard {__version__}*"
    )

    output = "\n".join(lines)
    if len(output) > _MAX_PR_COMMENT_CHARS:
        truncation_notice = (
            f"\n\n---\n⚠️ *Output truncated — exceeded {_MAX_PR_COMMENT_CHARS} character limit.*"
        )
        budget = _MAX_PR_COMMENT_CHARS - len(truncation_notice)
        # Cut at the last newline within the budget so we don't slice mid-tag
        # (e.g. half of a `<details>` element) and ship broken HTML.
        cut_at = output.rfind("\n", 0, budget)
        if cut_at == -1:
            cut_at = budget
        output = output[:cut_at] + truncation_notice
    return output


def _pr_finding_detail(finding: Finding) -> list[str]:
    emoji = _SEV_EMOJI.get(finding.severity, "")
    loc = finding.path + (f":{finding.line}" if finding.line else "")
    lines = [
        "<details>",
        f"<summary>{emoji} <code>{finding.id}</code> — {finding.title} "
        f"(<code>{loc}</code>)</summary>",
        "",
        finding.description,
        "",
    ]
    if finding.evidence:
        lines += ["```", finding.evidence, "```", ""]
    if finding.recommendation:
        lines.append(f"**Recommendation:** {finding.recommendation}")
    lines += ["", "</details>", ""]
    return lines
