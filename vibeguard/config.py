"""VibeGuard configuration loading and Pydantic models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class IgnoreConfig(BaseModel):
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
    enabled: bool = True
    min_entropy: float = 3.5


class SourcemapsConfig(BaseModel):
    enabled: bool = True


class PackagingConfig(BaseModel):
    enabled: bool = True


class DependenciesConfig(BaseModel):
    enabled: bool = True


class RiskyPatternsConfig(BaseModel):
    enabled: bool = True


class TestsConfig(BaseModel):
    enabled: bool = True


class AIFootprintsConfig(BaseModel):
    enabled: bool = True


class VibeGuardConfig(BaseModel):
    """Root configuration model."""

    policy: str = "balanced"
    fail_on: str = "high"
    ignore: IgnoreConfig = Field(default_factory=IgnoreConfig)
    package_allowlist: PackageAllowlistConfig = Field(default_factory=PackageAllowlistConfig)
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    sourcemaps: SourcemapsConfig = Field(default_factory=SourcemapsConfig)
    packaging: PackagingConfig = Field(default_factory=PackagingConfig)
    dependencies: DependenciesConfig = Field(default_factory=DependenciesConfig)
    risky_patterns: RiskyPatternsConfig = Field(default_factory=RiskyPatternsConfig)
    tests: TestsConfig = Field(default_factory=TestsConfig)
    ai_footprints: AIFootprintsConfig = Field(default_factory=AIFootprintsConfig)

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

        path_str = str(path)
        for pattern in self.ignore.paths:
            # Normalize pattern – strip trailing slash for directory matching
            clean = pattern.rstrip("/")
            if fnmatch.fnmatch(path_str, f"*{clean}*") or fnmatch.fnmatch(
                path_str, f"{clean}*"
            ):
                return True
            # Also check individual path components
            parts = Path(path_str).parts
            for part in parts:
                if fnmatch.fnmatch(part, clean):
                    return True
        return False


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
"""
