"""VibeGuard configuration loading and Pydantic models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


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


class TestsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class AIFootprintsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class ScannerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_file_size_kb: int = 1024


class VibeGuardConfig(BaseModel):
    """Root configuration model."""

    model_config = ConfigDict(extra="forbid")

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
        line
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
"""
