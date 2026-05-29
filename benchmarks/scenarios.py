"""Scenario detection/false-positive evaluation harness (#97).

Where :mod:`benchmarks.run` measures scan *speed* on synthetic repos, this
harness measures *what VibeGuard detects* on the hand-written, realistic
AI-diff fixtures under ``benchmarks/scenarios/`` — plus a false-positive
baseline on deliberately clean fixtures.

It is deterministic and offline: findings do not vary between runs, so the
output is safe to diff or snapshot. (Only :mod:`benchmarks.run` timings vary
by hardware.)

Run it::

    python -m benchmarks.scenarios            # human-readable table
    python -m benchmarks.scenarios --json     # machine-readable

See ``docs/benchmark.md`` for the published report and methodology.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vibeguard.config import VibeGuardConfig
from vibeguard.models import Severity
from vibeguard.scanner import run_scan

SCENARIOS_DIR = Path(__file__).resolve().parent / "scenarios"

# A path that does not exist, so ``VibeGuardConfig.load`` starts from empty
# data and applies only the requested policy pack's defaults — never the
# repository's own ``vibeguard.yaml`` (which would happen with ``path=None``).
_NO_CONFIG = SCENARIOS_DIR / "__no_such_vibeguard_config__.yaml"

_BLOCKING = (Severity.HIGH, Severity.CRITICAL)


@dataclass(frozen=True)
class Scenario:
    """One evaluation fixture and what we expect VibeGuard to say about it."""

    name: str
    description: str
    kind: str  # "vulnerable" | "clean"
    policy_pack: str | None = None
    # Finding IDs that MUST appear (vulnerable scenarios only).
    expected_ids: frozenset[str] = field(default_factory=frozenset)


SCENARIOS: list[Scenario] = [
    Scenario(
        "node-web-app",
        "Node web app: CORS wildcard, auth bypass, .env, source maps, git-URL dep",
        "vulnerable",
        expected_ids=frozenset(
            {"SEC-ENV", "MAP-PKG", "PKG-NPMLEAK", "DEP-URLNODE", "RISK-CORSCONFIG"}
        ),
    ),
    Scenario(
        "python-api",
        "Python API: verify=False, shell exec, f-string SQL, hardcoded secret",
        "vulnerable",
        expected_ids=frozenset(
            {"AUTH-VERIFY-FALSE", "RISK-SUBPROCESSSHELL", "SQL-PY-FSTRING", "SEC-HARDCODEDPASSWORD"}
        ),
    ),
    Scenario(
        "go-service",
        "Go service: TLS bypass, shell exec, CORS wildcard",
        "vulnerable",
        expected_ids=frozenset({"GO-INSECURE-TLS", "GO-EXEC-SHELL", "GO-CORS-WILDCARD"}),
    ),
    Scenario(
        "iac-config",
        "Terraform: IAM wildcard, security group open to 0.0.0.0/0, public S3 ACL",
        "vulnerable",
        expected_ids=frozenset({"TF-IAM-WILDCARD", "TF-SG-OPEN", "TF-S3-PUBLIC"}),
    ),
    Scenario(
        "clean-library",
        "Clean single-package OSS library — false-positive baseline",
        "clean",
        policy_pack="oss-library",
    ),
    Scenario(
        "monorepo",
        "Clean multi-package monorepo with source/test layout — false-positive baseline",
        "clean",
        policy_pack="oss-library",
    ),
]


def _config_for(scenario: Scenario) -> VibeGuardConfig:
    if scenario.policy_pack:
        return VibeGuardConfig.load(path=_NO_CONFIG, policy_pack=scenario.policy_pack)
    return VibeGuardConfig()


def evaluate(scenario: Scenario) -> dict[str, Any]:
    """Scan one scenario and return a structured, deterministic report."""
    result = run_scan(SCENARIOS_DIR / scenario.name, _config_for(scenario))
    ids = {f.id for f in result.findings}
    blocking = sorted(f.id for f in result.findings if f.severity in _BLOCKING)
    return {
        "name": scenario.name,
        "kind": scenario.kind,
        "policy_pack": scenario.policy_pack,
        "total": len(result.findings),
        "by_severity": dict(Counter(f.severity.value for f in result.findings)),
        "by_rule": dict(Counter(f.rule for f in result.findings)),
        "blocking": blocking,
        "missing_expected": sorted(scenario.expected_ids - ids),
    }


def evaluate_all() -> list[dict[str, Any]]:
    return [evaluate(s) for s in SCENARIOS]


def _format_text(reports: list[dict[str, Any]]) -> str:
    lines = ["VibeGuard scenario evaluation", ""]
    lines.append(f"  {'scenario':<16} {'kind':<11} {'total':>5}  {'blocking':>8}  detail")
    lines.append(f"  {'-' * 16} {'-' * 11} {'-' * 5}  {'-' * 8}  {'-' * 6}")
    for r in reports:
        sev = ", ".join(f"{k}:{v}" for k, v in sorted(r["by_severity"].items()))
        detail = sev or "no findings"
        if r["missing_expected"]:
            detail += f"  !! MISSING {r['missing_expected']}"
        lines.append(
            f"  {r['name']:<16} {r['kind']:<11} {r['total']:>5}  {len(r['blocking']):>8}  {detail}"
        )
    clean = [r for r in reports if r["kind"] == "clean"]
    fp = sum(len(r["blocking"]) for r in clean)
    lines += ["", f"  false positives (blocking findings on clean fixtures): {fp}"]
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate VibeGuard against scenario fixtures.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    args = parser.parse_args(argv)

    reports = evaluate_all()
    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        print(_format_text(reports))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
