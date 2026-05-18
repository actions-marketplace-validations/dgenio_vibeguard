"""Tests for configuration loading."""

from __future__ import annotations

import textwrap
from pathlib import Path

from vibeguard.config import VibeGuardConfig


def test_defaults():
    cfg = VibeGuardConfig()
    assert cfg.policy == "balanced"
    assert cfg.fail_on == "high"
    assert cfg.secrets.enabled is True
    assert cfg.sourcemaps.enabled is True
    assert cfg.packaging.enabled is True
    assert cfg.dependencies.enabled is True
    assert cfg.risky_patterns.enabled is True
    assert cfg.tests.enabled is True
    assert cfg.ai_footprints.enabled is True


def test_load_from_file(tmp_path: Path):
    yaml_content = textwrap.dedent("""
        policy: strict
        fail_on: medium
        secrets:
          enabled: false
        tests:
          enabled: false
    """)
    cfg_file = tmp_path / "vibeguard.yaml"
    cfg_file.write_text(yaml_content)

    cfg = VibeGuardConfig.load(cfg_file)
    assert cfg.policy == "strict"
    assert cfg.fail_on == "medium"
    assert cfg.secrets.enabled is False
    assert cfg.tests.enabled is False
    # Other rules still default to enabled
    assert cfg.sourcemaps.enabled is True


def test_load_nonexistent_returns_defaults(tmp_path: Path):
    cfg = VibeGuardConfig.load(tmp_path / "does_not_exist.yaml")
    assert cfg.policy == "balanced"


def test_load_empty_file(tmp_path: Path):
    cfg_file = tmp_path / "vibeguard.yaml"
    cfg_file.write_text("")
    cfg = VibeGuardConfig.load(cfg_file)
    assert cfg.policy == "balanced"


def test_ignore_paths_git(tmp_path: Path):
    cfg = VibeGuardConfig()
    assert cfg.is_path_ignored(".git/config")
    assert cfg.is_path_ignored("node_modules/lodash/index.js")
    assert cfg.is_path_ignored(".venv/lib/python3.11/site-packages/foo.py")


def test_ignore_paths_not_ignored():
    cfg = VibeGuardConfig()
    assert not cfg.is_path_ignored("src/main.py")
    assert not cfg.is_path_ignored("vibeguard/cli.py")
    assert not cfg.is_path_ignored("README.md")


def test_ignore_custom_path(tmp_path: Path):
    yaml_content = textwrap.dedent("""
        ignore:
          paths:
            - custom_dir/
    """)
    cfg_file = tmp_path / "vibeguard.yaml"
    cfg_file.write_text(yaml_content)
    cfg = VibeGuardConfig.load(cfg_file)
    assert cfg.is_path_ignored("custom_dir/something.py")


def test_policy_relaxed(tmp_path: Path):
    yaml_content = "policy: relaxed\n"
    cfg_file = tmp_path / "vibeguard.yaml"
    cfg_file.write_text(yaml_content)
    cfg = VibeGuardConfig.load(cfg_file)
    assert cfg.policy == "relaxed"
