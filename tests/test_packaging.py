"""Tests for packaging hygiene rule."""

from __future__ import annotations

import json
from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext
from vibeguard.rules.packaging import PackagingRule


def _ctx(tmp_path: Path, files: dict[str, str]) -> ScanContext:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return ScanContext(
        root=tmp_path,
        config=VibeGuardConfig(),
        files=[tmp_path / n for n in files],
    )


class TestPackagingRule:
    rule = PackagingRule()

    def test_package_json_no_files_no_npmignore(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-NPMFILES" for f in findings)

    def test_package_json_with_npmignore_no_finding(self, tmp_path: Path):
        (tmp_path / ".npmignore").write_text("tests/\n")
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-NPMFILES" for f in findings)

    def test_package_json_broad_pattern(self, tmp_path: Path):
        data = json.dumps({"name": "foo", "files": ["**"]})
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-NPMBROAD" for f in findings)

    def test_package_json_env_pattern(self, tmp_path: Path):
        data = json.dumps({"name": "foo", "files": ["dist/", ".env"]})
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-NPMLEAK" for f in findings)

    def test_package_json_tests_pattern(self, tmp_path: Path):
        data = json.dumps({"name": "foo", "files": ["src/", "tests/"]})
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-NPMLEAK" for f in findings)

    def test_manifest_in_env_detected(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {"MANIFEST.in": "include .env\nrecursive-include src *\n"},
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-MANIFESTLEAK" for f in findings)

    def test_clean_package_json_no_findings(self, tmp_path: Path):
        data = json.dumps({"name": "foo", "version": "1.0.0", "files": ["dist/", "README.md"]})
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        # No dangerous patterns in the files list
        assert not any(f.id in ("PKG-NPMBROAD", "PKG-NPMLEAK") for f in findings)
