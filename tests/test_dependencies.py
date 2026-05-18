"""Tests for dependency risk rule."""

from __future__ import annotations

import json
from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext
from vibeguard.rules.dependencies import DependenciesRule


def _ctx(tmp_path: Path, files: dict[str, str], policy: str = "balanced") -> ScanContext:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    cfg = VibeGuardConfig(policy=policy)
    return ScanContext(
        root=tmp_path,
        config=cfg,
        files=[tmp_path / n for n in files],
    )


class TestDependenciesRule:
    rule = DependenciesRule()

    def test_url_dep_flagged(self, tmp_path: Path):
        data = json.dumps(
            {"name": "app", "dependencies": {"mylib": "https://github.com/user/mylib"}}
        )
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        assert any(f.id == "DEP-URLNODE" for f in findings)

    def test_git_dep_flagged(self, tmp_path: Path):
        data = json.dumps(
            {"name": "app", "dependencies": {"mylib": "git+https://github.com/user/mylib.git"}}
        )
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        assert any(f.id == "DEP-URLNODE" for f in findings)

    def test_broad_version_strict_mode(self, tmp_path: Path):
        data = json.dumps({"name": "app", "dependencies": {"lodash": "*"}})
        ctx = _ctx(tmp_path, {"package.json": data}, policy="strict")
        findings = self.rule.scan(ctx)
        assert any(f.id == "DEP-BROADVER" for f in findings)

    def test_broad_version_balanced_mode_no_finding(self, tmp_path: Path):
        data = json.dumps({"name": "app", "dependencies": {"lodash": "*"}})
        ctx = _ctx(tmp_path, {"package.json": data}, policy="balanced")
        findings = self.rule.scan(ctx)
        assert not any(f.id == "DEP-BROADVER" for f in findings)

    def test_normal_dep_no_finding(self, tmp_path: Path):
        data = json.dumps(
            {"name": "app", "dependencies": {"express": "^4.18.2", "lodash": "^4.17.21"}}
        )
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        assert not any(f.id in ("DEP-URLNODE", "DEP-BROADVER") for f in findings)

    def test_python_url_dep_flagged(self, tmp_path: Path):
        toml = (
            "[project]\n"
            'name = "app"\n'
            'dependencies = ["mylib @ git+https://github.com/user/mylib.git"]\n'
        )
        ctx = _ctx(tmp_path, {"pyproject.toml": toml})
        findings = self.rule.scan(ctx)
        assert any(f.id == "DEP-URLPYTHON" for f in findings)

    def test_python_unpinned_strict(self, tmp_path: Path):
        toml = '[project]\nname = "app"\ndependencies = ["requests"]\n'
        ctx = _ctx(tmp_path, {"pyproject.toml": toml}, policy="strict")
        findings = self.rule.scan(ctx)
        assert any(f.id == "DEP-UNPINNEDPY" for f in findings)
