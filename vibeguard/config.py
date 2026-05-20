"""VibeGuard configuration loading and Pydantic models."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from vibeguard.models import Severity


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


class ScannerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_file_size_kb: int = Field(default=1024, ge=1)


class VibeGuardConfig(BaseModel):
    """Root configuration model."""

    model_config = ConfigDict(extra="forbid")

    policy: Literal["relaxed", "balanced", "strict"] = "balanced"
    fail_on: Severity = Severity.HIGH
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
"""
