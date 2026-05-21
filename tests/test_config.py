"""Tests for configuration loading."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from vibeguard.config import VibeGuardConfig, load_ignorefile


def test_defaults():
    cfg = VibeGuardConfig()
    assert cfg.policy == "balanced"
    assert cfg.fail_on == "high"
    assert cfg.policy_pack is None
    assert cfg.secrets.enabled is True
    assert cfg.sourcemaps.enabled is True
    assert cfg.packaging.enabled is True
    assert cfg.dependencies.enabled is True
    assert cfg.risky_patterns.enabled is True
    assert cfg.tests.enabled is True
    assert cfg.tests.mapping == []
    assert cfg.ai_footprints.enabled is True
    assert cfg.go_rules.enabled is True
    assert cfg.ci_docker.enabled is True
    assert cfg.iac.enabled is True
    assert cfg.auth.enabled is True
    assert cfg.sql.enabled is True
    assert cfg.agent_memory.enabled is True


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


class TestStrictValidation:
    """Tests for extra='forbid' config validation (#13)."""

    def test_unknown_root_key_rejected(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text("policy: balanced\nfail_oon: high\n")
        with pytest.raises(ValidationError) as exc_info:
            VibeGuardConfig.load(cfg_file)
        assert "fail_oon" in str(exc_info.value)

    def test_unknown_nested_key_rejected(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text("secrets:\n  enabeld: true\n")
        with pytest.raises(ValidationError) as exc_info:
            VibeGuardConfig.load(cfg_file)
        assert "enabeld" in str(exc_info.value)

    def test_valid_config_accepted(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text("policy: strict\nfail_on: medium\n")
        cfg = VibeGuardConfig.load(cfg_file)
        assert cfg.policy == "strict"


class TestScannerConfig:
    """Tests for scanner config (max_file_size_kb)."""

    def test_default_max_file_size(self):
        cfg = VibeGuardConfig()
        assert cfg.scanner.max_file_size_kb == 1024

    def test_custom_max_file_size(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text("scanner:\n  max_file_size_kb: 512\n")
        cfg = VibeGuardConfig.load(cfg_file)
        assert cfg.scanner.max_file_size_kb == 512

    def test_max_file_size_zero_rejected(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text("scanner:\n  max_file_size_kb: 0\n")
        with pytest.raises(ValidationError):
            VibeGuardConfig.load(cfg_file)

    def test_invalid_fail_on_rejected(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text("fail_on: disaster\n")
        with pytest.raises(ValidationError):
            VibeGuardConfig.load(cfg_file)

    def test_invalid_policy_rejected(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text("policy: aggressive\n")
        with pytest.raises(ValidationError):
            VibeGuardConfig.load(cfg_file)


class TestLoadIgnorefile:
    """Tests for .vibeguardignore loading (#26)."""

    def test_missing_file_returns_empty(self, tmp_path: Path):
        patterns = load_ignorefile(tmp_path)
        assert patterns == []

    def test_loads_patterns(self, tmp_path: Path):
        (tmp_path / ".vibeguardignore").write_text("*.log\nbuild/\n")
        patterns = load_ignorefile(tmp_path)
        assert "*.log" in patterns
        assert "build/" in patterns

    def test_ignores_comments_and_blanks(self, tmp_path: Path):
        (tmp_path / ".vibeguardignore").write_text("# comment\n\n*.tmp\n  \n")
        patterns = load_ignorefile(tmp_path)
        assert patterns == ["*.tmp"]
