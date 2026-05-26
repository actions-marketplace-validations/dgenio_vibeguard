"""Tests for built-in policy packs (#49)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from vibeguard.cli import app
from vibeguard.config import VibeGuardConfig
from vibeguard.models import Severity
from vibeguard.policies import (
    KNOWN_PACK_NAMES,
    UnknownPolicyPackError,
    available_packs,
    load_policy_pack,
    merge_policy_pack,
)


class TestPackRegistry:
    """The pack registry must match what ships on disk."""

    def test_known_pack_names_match_disk(self):
        # Both views of "what packs exist" must agree, otherwise users get
        # different errors from the CLI vs. the loader.
        assert set(KNOWN_PACK_NAMES) == set(available_packs())

    def test_all_three_packs_present(self):
        # Spec from #49 — these are the deliverable.
        assert set(KNOWN_PACK_NAMES) == {"oss-library", "web-app", "strict-ci"}

    def test_pack_yamls_exist_on_disk(self):
        for name in KNOWN_PACK_NAMES:
            data = load_policy_pack(name)
            assert isinstance(data, dict)
            # Every pack must declare a fail_on, otherwise it doesn't actually
            # change gating behaviour and would be pointless.
            assert "fail_on" in data


class TestPackContents:
    """Each pack's defaults match the spec in #49."""

    def test_oss_library_defaults(self):
        data = load_policy_pack("oss-library")
        assert data["fail_on"] == "high"
        # tests:enabled is the OSS-library headline (library test layouts vary)
        assert data["tests"]["enabled"] is False
        # Ignore list MUST include examples/ and docs/ per spec
        assert "examples/" in data["ignore"]["paths"]
        assert "docs/" in data["ignore"]["paths"]

    def test_web_app_defaults(self):
        data = load_policy_pack("web-app")
        assert data["fail_on"] == "medium"
        # Auth/SQL/risky_diff must be promoted to high
        overrides = data["severity_overrides"]
        promoted_rules = {o["rule_id"] for o in overrides if o["severity"] == "high"}
        assert {"auth", "sql", "risky_diff"} <= promoted_rules

    def test_strict_ci_defaults(self):
        data = load_policy_pack("strict-ci")
        assert data["fail_on"] == "low"
        assert data["policy"] == "strict"
        # Every rule family overridden to critical
        overrides = data["severity_overrides"]
        critical_rules = {o["rule_id"] for o in overrides if o["severity"] == "critical"}
        assert "secrets" in critical_rules
        assert "auth" in critical_rules
        assert "sql" in critical_rules


class TestLoadPolicyPackErrors:
    def test_unknown_pack_raises(self):
        with pytest.raises(UnknownPolicyPackError) as exc_info:
            load_policy_pack("totally-made-up")
        # Error message must list valid options so the user can recover.
        msg = str(exc_info.value)
        assert "oss-library" in msg
        assert "web-app" in msg


class TestMergePolicyPack:
    def test_pack_fills_in_missing_keys(self):
        user: dict = {}
        pack = {"fail_on": "high", "policy": "strict"}
        merged = merge_policy_pack(user, pack)
        assert merged["fail_on"] == "high"
        assert merged["policy"] == "strict"

    def test_user_scalar_overrides_pack_scalar(self):
        user = {"fail_on": "critical"}
        pack = {"fail_on": "high", "policy": "strict"}
        merged = merge_policy_pack(user, pack)
        assert merged["fail_on"] == "critical"
        assert merged["policy"] == "strict"

    def test_user_sub_section_merges_one_level(self):
        user = {"tests": {"enabled": True}}
        pack = {"tests": {"enabled": False, "mapping": []}}
        merged = merge_policy_pack(user, pack)
        assert merged["tests"]["enabled"] is True
        # The mapping key from the pack survives because user didn't set it.
        assert merged["tests"]["mapping"] == []

    def test_user_list_replaces_pack_list(self):
        # Lists never extend: user authority is total.
        user = {"severity_overrides": [{"rule_id": "secrets", "severity": "low"}]}
        pack = {
            "severity_overrides": [
                {"rule_id": "auth", "severity": "critical"},
                {"rule_id": "sql", "severity": "critical"},
            ]
        }
        merged = merge_policy_pack(user, pack)
        assert merged["severity_overrides"] == [{"rule_id": "secrets", "severity": "low"}]

    def test_inputs_not_mutated(self):
        user = {"fail_on": "critical"}
        pack = {"fail_on": "high", "tests": {"enabled": False}}
        merge_policy_pack(user, pack)
        assert user == {"fail_on": "critical"}
        assert pack == {"fail_on": "high", "tests": {"enabled": False}}


class TestVibeGuardConfigLoadWithPack:
    def test_pack_from_yaml_key_applies(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text("policy_pack: oss-library\n")
        cfg = VibeGuardConfig.load(cfg_file)
        assert cfg.policy_pack == "oss-library"
        assert cfg.fail_on == Severity.HIGH
        # Pack disables tests rule
        assert cfg.tests.enabled is False
        # Pack ignores examples/ and docs/
        assert "examples/" in cfg.ignore.paths
        assert "docs/" in cfg.ignore.paths

    def test_pack_from_kwarg_overrides_yaml_key(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text("policy_pack: oss-library\n")
        cfg = VibeGuardConfig.load(cfg_file, policy_pack="strict-ci")
        assert cfg.policy_pack == "strict-ci"
        assert cfg.fail_on == Severity.LOW
        assert cfg.policy == "strict"

    def test_user_fail_on_beats_pack_fail_on(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text(
            textwrap.dedent("""
                policy_pack: oss-library
                fail_on: critical
            """)
        )
        cfg = VibeGuardConfig.load(cfg_file)
        # User said critical; pack said high — user wins.
        assert cfg.fail_on == Severity.CRITICAL

    def test_user_rule_enabled_beats_pack(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text(
            textwrap.dedent("""
                policy_pack: oss-library
                tests:
                  enabled: true
            """)
        )
        cfg = VibeGuardConfig.load(cfg_file)
        # Pack disables tests, user re-enables them.
        assert cfg.tests.enabled is True

    def test_unknown_pack_in_yaml_raises_validation_error(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text("policy_pack: nonexistent\n")
        with pytest.raises(ValidationError) as exc_info:
            VibeGuardConfig.load(cfg_file)
        # The chained error path includes either "policy_pack" (literal check)
        # or the pack-name string itself (loader-level message).
        msg = str(exc_info.value)
        assert "policy_pack" in msg or "nonexistent" in msg

    def test_unknown_pack_via_kwarg_raises(self, tmp_path: Path):
        with pytest.raises(ValidationError):
            VibeGuardConfig.load(tmp_path / "missing.yaml", policy_pack="not-real")

    def test_pack_alone_without_yaml_file(self, tmp_path: Path):
        # No vibeguard.yaml on disk — pack should still apply.
        cfg = VibeGuardConfig.load(tmp_path / "absent.yaml", policy_pack="web-app")
        assert cfg.policy_pack == "web-app"
        assert cfg.fail_on == Severity.MEDIUM


class TestCliPolicyPack:
    runner = CliRunner()

    def test_init_with_policy_pack_creates_pack_config(self, tmp_path: Path):
        result = self.runner.invoke(
            app, ["init", "--path", str(tmp_path), "--policy-pack", "oss-library"]
        )
        assert result.exit_code == 0
        content = (tmp_path / "vibeguard.yaml").read_text()
        assert "policy_pack: oss-library" in content
        # Generated file must be loadable and apply pack defaults.
        cfg = VibeGuardConfig.load(tmp_path / "vibeguard.yaml")
        assert cfg.policy_pack == "oss-library"
        assert cfg.tests.enabled is False

    def test_init_unknown_pack_exits_nonzero(self, tmp_path: Path):
        result = self.runner.invoke(app, ["init", "--path", str(tmp_path), "--policy-pack", "nope"])
        assert result.exit_code == 2
        assert not (tmp_path / "vibeguard.yaml").exists()

    def test_scan_with_policy_pack_no_config(self, tmp_path: Path):
        # No config file on disk — just exercise that --policy-pack alone works.
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("print('hi')\n")
        result = self.runner.invoke(
            app, ["scan", "--path", str(tmp_path), "--policy-pack", "strict-ci"]
        )
        # scan always exits 0; we just want to confirm no crash.
        assert result.exit_code == 0

    def test_gate_unknown_policy_pack_exits_2(self, tmp_path: Path):
        result = self.runner.invoke(app, ["gate", "--path", str(tmp_path), "--policy-pack", "fake"])
        assert result.exit_code == 2

    def test_scan_pack_only_ignores_cwd_vibeguard_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Pack-only invocation must not pick up CWD's vibeguard.yaml.

        Regression guard for a leakage where ``_load_config`` fell through
        to ``Path("vibeguard.yaml")`` in the current working directory when
        the scan path had no config — silently merging two unrelated
        configs together.
        """
        import json

        cwd = tmp_path / "cwd_with_config"
        cwd.mkdir()
        (cwd / "vibeguard.yaml").write_text("policy: balanced\nfail_on: high\n")

        scan_root = tmp_path / "scan_target"
        scan_root.mkdir()
        (scan_root / "code.py").write_text("print('x')\n")

        monkeypatch.chdir(cwd)
        result = self.runner.invoke(
            app,
            [
                "scan",
                "--path",
                str(scan_root),
                "--policy-pack",
                "strict-ci",
                "--json",
            ],
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        # strict-ci sets policy: strict — the pack must win because there's
        # no config in the scan_root.
        assert payload["policy"] == "strict"
