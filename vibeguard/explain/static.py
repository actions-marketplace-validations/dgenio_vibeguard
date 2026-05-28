"""Default offline explanation adapter.

:class:`StaticExplainAdapter` is the always-available adapter that VibeGuard
ships with. It draws on two sources, in order:

1. A curated dictionary of hand-written, finding-specific explanations for a
   handful of "you really need to act on this" findings (AWS keys, .env
   commits, eval/exec, etc.). These come from the same text the CLI used
   before the adapter interface existed.
2. The rule metadata registry (:mod:`vibeguard.rules.registry`). For any
   finding that doesn't have a hand-written explanation, the adapter falls
   back to the parent rule's title, description, tags, and `applies_to` list.

The adapter never raises and never performs I/O — it is the safety net that
makes ``vibeguard explain`` work in air-gapped CI runners.
"""

from __future__ import annotations

from vibeguard.explain.base import ExplainAdapter
from vibeguard.models import Finding

# Curated, hand-written explanations for the highest-impact finding IDs.
# Sourced from the original ``_FINDING_EXPLANATIONS`` dict in ``vibeguard.cli``
# so that the CLI behaviour is unchanged for the IDs that were already
# covered before this interface existed.
_CURATED: dict[str, str] = {
    "SEC-AWSACCESSKEY": """\
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
    "SEC-ENV": """\
[bold]Sensitive .env file committed (SEC-ENV)[/]

.env files typically contain database passwords, API keys, JWT secrets, and
other credentials. They should never be committed.

[bold]How to fix:[/]
1. Add .env to .gitignore immediately.
2. Remove it from git history.
3. Rotate all credentials contained in the file.
4. Use environment variables in CI/CD instead.
""",
    "MAP-DIST": """\
[bold]Source map in distribution directory (MAP-DIST)[/]

Source maps (.map files) reverse-engineer your minified/compiled code back to
the original source. Publishing them exposes your source code to anyone who
downloads your package or opens DevTools.

[bold]How to fix:[/]
Add *.map to .npmignore or remove .map patterns from your package.json `files`.
""",
    "TEST-MISSING": """\
[bold]Source changes without tests (TEST-MISSING)[/]

AI coding tools generate code quickly but often skip tests. Untested
AI-generated code is a common source of regressions, edge-case bugs, and
security gaps that only show up in production.

[bold]How to fix:[/]
Write unit tests covering the changed logic before merging. Even basic
happy-path tests catch a large percentage of AI hallucination bugs.
""",
    "RISK-EVALEXEC": """\
[bold]eval() / exec() usage (RISK-EVALEXEC)[/]

Dynamic code execution functions can run arbitrary code. If user input
reaches eval/exec, this is a critical Remote Code Execution (RCE) vulnerability.

[bold]How to fix:[/]
Eliminate eval/exec if possible. If not, ensure inputs are strictly validated
and whitelisted before execution.
""",
    "AI-DISABLESECURITY": """\
[bold]Security disabled (AI-DISABLESECURITY)[/]

AI coding assistants sometimes comment out or disable security controls to
make code "work" without understanding the implications. This is a very
common source of vulnerabilities in AI-generated code.

[bold]How to fix:[/]
Re-enable the security control. If the bypass is intentional, document the
reason and get a security review.
""",
}


def _registry_fallback(finding: Finding) -> str:
    """Return rule-metadata-based text when no curated explanation exists."""
    # Imported lazily so that ``vibeguard.explain.static`` doesn't pull the
    # full registry at import time — important because the CLI sometimes
    # constructs adapters before all rule modules have been loaded.
    from vibeguard.rules.registry import RULE_REGISTRY

    rule_id = finding.rule
    meta = RULE_REGISTRY.get(rule_id) or RULE_REGISTRY.get(rule_id.lower())
    if meta is not None:
        lines = [
            f"[bold]{finding.id}[/] — from rule [cyan]{meta.title}[/]",
            "",
            meta.description,
            "",
            f"[dim]Rule ID:[/] {meta.rule_id}",
        ]
        if meta.applies_to:
            lines.append(f"[dim]Applies to:[/] {', '.join(meta.applies_to)}")
        if meta.tags:
            lines.append(f"[dim]Tags:[/] {', '.join(meta.tags)}")
        # Prefer the rule-registry's per-finding remediation over the
        # synthesised ``Finding.recommendation`` because (a) the registry text
        # is hand-tuned for ``explain`` UX and (b) ``vibeguard explain
        # <FINDING_ID>`` synthesises a Finding with an empty recommendation
        # — without this lookup, the "How to fix" section would never render
        # for that call path.
        remediation = meta.remediations.get(finding.id.upper())
        if remediation:
            lines += ["", "[bold]How to fix[/]", remediation]
        elif finding.recommendation:
            lines += ["", "[bold]Recommendation[/]", finding.recommendation]
        return "\n".join(lines) + "\n"

    # Last-resort fallback when the finding's parent rule isn't in the
    # registry (e.g. plugin rule that registered the Rule but not metadata).
    lines = [
        f"[bold]{finding.id}[/]",
        "",
        finding.description or "(no description available)",
    ]
    if finding.recommendation:
        lines += ["", "[bold]Recommendation[/]", finding.recommendation]
    return "\n".join(lines) + "\n"


class StaticExplainAdapter(ExplainAdapter):
    """Offline, deterministic adapter — always available, no config needed."""

    name = "static"

    def explain(self, finding: Finding, context: str | None = None) -> str:
        # ``context`` is intentionally unused — the static adapter is
        # context-insensitive by design. Third-party adapters can put it
        # to work for richer explanations.
        del context
        curated = _CURATED.get(finding.id.upper())
        if curated:
            return curated
        return _registry_fallback(finding)

    @classmethod
    def explain_by_id(cls, finding_id: str) -> str | None:
        """Return the curated explanation for ``finding_id``, if any.

        Used by the CLI to keep the legacy ``vibeguard explain <FINDING-ID>``
        invocation path working without constructing a synthetic
        :class:`Finding`. Returns ``None`` when no curated text exists so the
        caller can fall through to its existing registry-based rendering.
        """
        return _CURATED.get(finding_id.upper())
