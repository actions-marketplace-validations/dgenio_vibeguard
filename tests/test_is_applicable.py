"""Tests that the scanner wires Rule.is_applicable into the scan loop (#193)."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import Finding, ScanContext
from vibeguard.rules.base import Rule
from vibeguard.rules.ci_docker import CiDockerRule
from vibeguard.rules.go_rules import GoRulesRule
from vibeguard.rules.iac import IaCRule
from vibeguard.scanner import _context_for_rule


def _ctx(files: list[str]) -> ScanContext:
    root = Path("/repo")
    paths = [root / f for f in files]
    return ScanContext(
        root=root,
        config=VibeGuardConfig(),
        files=paths,
        changed_files=paths,
        diff_only=False,
    )


class _GoOnlyRule(Rule):
    id = "go-only-test"
    name = "Go only"
    description = "Records the files it is handed."

    def __init__(self) -> None:
        self.seen: list[str] = []

    def is_applicable(self, path: Path) -> bool:
        return path.suffix == ".go"

    def scan(self, context: ScanContext) -> list[Finding]:
        self.seen = [p.name for p in context.files]
        return []


class _DefaultRule(Rule):
    id = "default-test"
    name = "Default"
    description = "Keeps the default is_applicable."

    def scan(self, context: ScanContext) -> list[Finding]:
        return []


def test_rejected_paths_never_reach_scan():
    rule = _GoOnlyRule()
    ctx = _ctx(["main.go", "app.py", "lib.go", "README.md"])
    filtered = _context_for_rule(rule, ctx)
    # Both files and changed_files are filtered to the applicable set.
    assert [p.name for p in filtered.files] == ["main.go", "lib.go"]
    assert [p.name for p in filtered.changed_files] == ["main.go", "lib.go"]
    # And the rule, when scanned with that context, only ever sees those files.
    rule.scan(filtered)
    assert rule.seen == ["main.go", "lib.go"]


def test_is_applicable_evaluated_once_per_unique_path():
    # A path present in both files and changed_files must be evaluated once
    # (the documented "once per candidate file per rule" contract).
    calls: list[str] = []

    class _CountingRule(Rule):
        id = "counting-test"
        name = "Counting"
        description = "Counts is_applicable calls."

        def is_applicable(self, path: Path) -> bool:
            calls.append(path.name)
            return path.suffix == ".go"

        def scan(self, context: ScanContext) -> list[Finding]:
            return []

    ctx = _ctx(["main.go", "app.py"])  # files and changed_files are identical
    _context_for_rule(_CountingRule(), ctx)
    assert sorted(calls) == ["app.py", "main.go"]  # each unique path once, not twice


def test_default_hook_returns_context_unchanged_and_uncopied():
    # Rules that don't override the hook pay no filtering cost — same object.
    ctx = _ctx(["a.py", "b.js"])
    assert _context_for_rule(_DefaultRule(), ctx) is ctx


def test_builtin_is_applicable_matches_scan_scope():
    assert GoRulesRule().is_applicable(Path("/r/x.go")) is True
    assert GoRulesRule().is_applicable(Path("/r/x.py")) is False

    assert IaCRule().is_applicable(Path("/r/main.tf")) is True
    assert IaCRule().is_applicable(Path("/r/deploy.yaml")) is True
    assert IaCRule().is_applicable(Path("/r/deploy.yml")) is True
    assert IaCRule().is_applicable(Path("/r/main.go")) is False

    assert CiDockerRule().is_applicable(Path("/r/Dockerfile")) is True
    assert CiDockerRule().is_applicable(Path("/r/api.dockerfile")) is True
    assert CiDockerRule().is_applicable(Path("/r/.github/workflows/ci.yml")) is True
    assert CiDockerRule().is_applicable(Path("/r/src/app.py")) is False
    # A plain YAML outside .github/workflows is not a CI/Docker file.
    assert CiDockerRule().is_applicable(Path("/r/config.yml")) is False
