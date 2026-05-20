"""VibeGuard configuration loading and Pydantic models."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from vibeguard.models import Severity

if TYPE_CHECKING:
    from vibeguard.models import Finding


class IgnoreConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    paths: list[str] = Field(
        default=[
            ".git/",
            "node_modules/",
            ".venv/",
            "venv/",
            "dist/",
            "build/",
            "*.egg-info/",
            ".tox/",
            "__pycache__/",
        ]
    )
    findings: list[str] = Field(default_factory=list)


class PackageAllowlistConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    files: list[str] = Field(
        default=[
            "README.md",
            "README.rst",
            "LICENSE",
            "pyproject.toml",
            "setup.cfg",
            "setup.py",
            "package.json",
            "CHANGELOG.md",
            "NOTICE",
        ]
    )


class SecretsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    min_entropy: float = 3.5


class SourcemapsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class PackagingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class DependenciesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class RiskyPatternsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    diff_size_threshold: int = Field(default=30, ge=1)
    diff_breadth_threshold: int = Field(default=5, ge=1)


class TestsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class AIFootprintsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class GoRulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class CiDockerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class IaCConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class AuthConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class SqlConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class AgentMemoryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class PublishCheckConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    ecosystem: Literal["auto", "npm", "python-sdist", "python-wheel"] = "auto"
    fail_on: Severity = Severity.HIGH


class SeverityOverride(BaseModel):
    """A severity override for a specific rule or finding ID.

    `finding_id` is matched exactly against ``Finding.id`` (e.g. ``"SEC-ENV"``).
    To override a whole family of findings, scope by `rule_id` instead — every
    finding produced by that rule will be remapped. `finding_id` always wins
    over `rule_id` when both apply.
    """

    model_config = ConfigDict(extra="forbid")

    rule_id: str | None = None
    finding_id: str | None = None
    severity: Severity

    @model_validator(mode="after")
    def _at_least_one_id(self) -> SeverityOverride:
        if not self.rule_id and not self.finding_id:
            raise ValueError("At least one of 'rule_id' or 'finding_id' must be provided")
        return self


class Suppression(BaseModel):
    """A policy suppression with required reason and optional expiry.

    `finding_id` is matched exactly against ``Finding.id`` (e.g. ``"SEC-ENV"``);
    `rule_id` matches every finding produced by that rule. When **both** are
    set on the same Suppression, the match is **OR**: a finding is suppressed
    if either identifier matches the configured `path_pattern`. Prefer scoping
    by `finding_id` alone for surgical suppressions and `rule_id` alone for
    family-wide ones — setting both is rarely what you want.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str | None = None
    rule_id: str | None = None
    path_pattern: str = "**"
    reason: str
    expires: str | None = None

    @model_validator(mode="after")
    def _at_least_one_id(self) -> Suppression:
        if not self.rule_id and not self.finding_id:
            raise ValueError("At least one of 'rule_id' or 'finding_id' must be provided")
        return self

    @model_validator(mode="after")
    def _reason_not_empty(self) -> Suppression:
        if not self.reason.strip():
            raise ValueError("'reason' must not be empty")
        return self

    @model_validator(mode="after")
    def _expires_is_iso_date(self) -> Suppression:
        if self.expires is None:
            return self
        try:
            date.fromisoformat(self.expires)
        except ValueError as exc:
            raise ValueError(
                f"'expires' must be an ISO date (YYYY-MM-DD), got {self.expires!r}"
            ) from exc
        return self


class ScannerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_file_size_kb: int = Field(default=1024, ge=1)


class VibeGuardConfig(BaseModel):
    """Root configuration model."""

    model_config = ConfigDict(extra="forbid")

    policy: Literal["relaxed", "balanced", "strict"] = "balanced"
    fail_on: Severity = Severity.HIGH
    baseline: str | None = Field(default=None, description="Path to baseline file")
    severity_overrides: list[SeverityOverride] = Field(default_factory=list)
    suppressions: list[Suppression] = Field(default_factory=list)
    ignore: IgnoreConfig = Field(default_factory=IgnoreConfig)
    package_allowlist: PackageAllowlistConfig = Field(default_factory=PackageAllowlistConfig)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    sourcemaps: SourcemapsConfig = Field(default_factory=SourcemapsConfig)
    packaging: PackagingConfig = Field(default_factory=PackagingConfig)
    dependencies: DependenciesConfig = Field(default_factory=DependenciesConfig)
    risky_patterns: RiskyPatternsConfig = Field(default_factory=RiskyPatternsConfig)
    tests: TestsConfig = Field(default_factory=TestsConfig)
    ai_footprints: AIFootprintsConfig = Field(default_factory=AIFootprintsConfig)
    go_rules: GoRulesConfig = Field(default_factory=GoRulesConfig)
    ci_docker: CiDockerConfig = Field(default_factory=CiDockerConfig)
    iac: IaCConfig = Field(default_factory=IaCConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    sql: SqlConfig = Field(default_factory=SqlConfig)
    agent_memory: AgentMemoryConfig = Field(default_factory=AgentMemoryConfig)
    publish_check: PublishCheckConfig = Field(default_factory=PublishCheckConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)

    @classmethod
    def load(cls, path: Path | str | None = None) -> VibeGuardConfig:
        """Load config from a YAML file, falling back to defaults."""
        if path is None:
            path = Path("vibeguard.yaml")

        config_path = Path(path)
        if not config_path.exists():
            return cls()

        with config_path.open() as f:
            data: dict[str, Any] = yaml.safe_load(f) or {}

        return cls.model_validate(data)

    def is_path_ignored(self, path: str | Path) -> bool:
        """Return True if the path matches any ignore pattern."""
        import fnmatch

        path_str = str(path).replace("\\", "/")
        parts = path_str.split("/")
        for pattern in self.ignore.paths:
            # Normalize pattern – strip trailing slash for directory matching
            clean = pattern.rstrip("/")
            # Check individual path components against the pattern
            for part in parts:
                if fnmatch.fnmatch(part, clean):
                    return True
        return False


def load_ignorefile(root: Path) -> list[str]:
    """Load .vibeguardignore patterns from the scan root using pathspec."""
    ignore_path = root / ".vibeguardignore"
    if not ignore_path.exists():
        return []
    return [
        line.strip()
        for line in ignore_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


DEFAULT_CONFIG_YAML = """\
# VibeGuard configuration
# https://github.com/dgenio/vibeguard

policy: balanced      # relaxed | balanced | strict
fail_on: high         # info | low | medium | high | critical

ignore:
  paths:
    - .git/
    - node_modules/
    - .venv/
    - venv/
    - dist/
    - build/
    - "*.egg-info/"
    - .tox/
    - __pycache__/
  findings: []        # list of finding IDs to suppress

package_allowlist:
  files:
    - README.md
    - README.rst
    - LICENSE
    - pyproject.toml
    - setup.cfg
    - setup.py
    - package.json
    - CHANGELOG.md
    - NOTICE

scanner:
  max_file_size_kb: 1024  # skip files larger than this (KB)

secrets:
  enabled: true
  min_entropy: 3.5

sourcemaps:
  enabled: true

packaging:
  enabled: true

dependencies:
  enabled: true

risky_patterns:
  enabled: true

tests:
  enabled: true

ai_footprints:
  enabled: true

publish_check:
  enabled: true
  ecosystem: auto     # auto | npm | python-sdist | python-wheel
  fail_on: high       # severity threshold when used as a gate

# severity_overrides:
#   - rule_id: "AI-FOOTPRINT"
#     severity: high
#   - finding_id: "SEC-ENV"
#     severity: critical

# suppressions:
#   - finding_id: "SEC-ENV"
#     path_pattern: "tests/fixtures/**"
#     reason: "Test fixture — intentional example"
#     expires: "2026-12-31"

# baseline: .vibeguard-baseline.json
"""


def apply_severity_overrides(
    findings: list[Finding], overrides: list[SeverityOverride]
) -> list[Finding]:
    """Apply severity overrides to findings, returning new Finding instances."""
    if not overrides:
        return findings

    result: list[Finding] = []
    for finding in findings:
        new_severity = finding.severity
        for override in overrides:
            if override.finding_id and finding.id == override.finding_id:
                new_severity = override.severity
                break
            if override.rule_id and finding.rule == override.rule_id:
                new_severity = override.severity
                # Don't break — a more specific finding_id override may follow
        if new_severity != finding.severity:
            result.append(finding.model_copy(update={"severity": new_severity}))
        else:
            result.append(finding)
    return result


def apply_policy_suppressions(
    findings: list[Finding], suppressions: list[Suppression]
) -> tuple[list[Finding], list[Finding]]:
    """Apply policy suppressions and return (active_findings, warning_findings).

    Expired suppressions emit a SUPPRESSION-EXPIRED warning instead of suppressing.
    """
    import fnmatch

    from vibeguard.models import Confidence, Finding, Severity

    if not suppressions:
        return findings, []

    active: list[Finding] = []
    warnings: list[Finding] = []

    # Pre-check for expired suppressions. `expires` is validated as an ISO
    # date at config load (see Suppression._expires_is_iso_date), so we can
    # parse it directly without a defensive try/except — a malformed value
    # would have failed at load time rather than silently never expiring.
    today = date.today()
    expired_suppressions: set[int] = set()
    for idx, supp in enumerate(suppressions):
        if supp.expires:
            expiry = date.fromisoformat(supp.expires)
            if expiry < today:
                expired_suppressions.add(idx)
                warnings.append(
                    Finding(
                        id="SUPPRESSION-EXPIRED",
                        rule="suppressions",
                        title="Policy suppression expired",
                        description=(
                            f"Suppression for {supp.finding_id or supp.rule_id} "
                            f"(path: {supp.path_pattern}) expired on {supp.expires}."
                        ),
                        severity=Severity.LOW,
                        path="vibeguard.yaml",
                        recommendation="Remove or renew the expired suppression.",
                        tags=["suppressions"],
                        confidence=Confidence.HIGH,
                    )
                )

    for finding in findings:
        suppressed = False
        for idx, supp in enumerate(suppressions):
            if idx in expired_suppressions:
                continue

            # Check if rule_id or finding_id matches
            id_match = False
            if (
                supp.finding_id
                and finding.id == supp.finding_id
                or supp.rule_id
                and finding.rule == supp.rule_id
            ):
                id_match = True

            if not id_match:
                continue

            # Check path pattern
            finding_path = finding.path.replace("\\", "/")
            if fnmatch.fnmatch(finding_path, supp.path_pattern):
                suppressed = True
                break

        if not suppressed:
            active.append(finding)

    return active, warnings
