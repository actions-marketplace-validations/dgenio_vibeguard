"""Markdown reporter — useful for PR comments."""

from __future__ import annotations

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
        "",
        finding.description,
        "",
    ]
    if finding.evidence:
        lines += ["```", finding.evidence, "```", ""]
    lines += [f"**Recommendation:** {finding.recommendation}", ""]
    return lines
