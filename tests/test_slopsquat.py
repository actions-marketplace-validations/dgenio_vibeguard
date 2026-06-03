"""Tests for the slopsquat (hallucinated-dependency) rule (#113)."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules import slopsquat as slop_mod
from vibeguard.rules.slopsquat import SlopsquatRule


def _ctx(tmp_path: Path, files: dict[str, str], *, registry_check: bool = False) -> ScanContext:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    config = VibeGuardConfig()
    config.slopsquat.registry_check = registry_check
    return ScanContext(
        root=tmp_path,
        config=config,
        files=[tmp_path / n for n in files],
    )


class TestOfflineHeuristic:
    rule = SlopsquatRule()

    def test_multi_token_name_absent_from_lockfile_is_flagged(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {
                "package.json": '{"dependencies": {"smart-data-pipeline-helper": "^1.0.0"}}',
                "package-lock.json": '{"packages": {"node_modules/express": {}}}',
            },
        )
        findings = self.rule.scan(ctx)
        assert [f.id for f in findings] == ["SLOP-HALLUCINATION-SHAPE"]
        assert findings[0].severity == Severity.HIGH
        assert "smart-data-pipeline-helper" in findings[0].evidence

    def test_name_present_in_lockfile_not_flagged(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {
                "package.json": '{"dependencies": {"smart-data-pipeline-helper": "^1.0.0"}}',
                "package-lock.json": (
                    '{"packages": {"node_modules/smart-data-pipeline-helper": {}}}'
                ),
            },
        )
        assert self.rule.scan(ctx) == []

    def test_no_lockfile_means_no_offline_finding(self, tmp_path: Path):
        # Without a lockfile the heuristic cannot tell "invented" from "not yet
        # installed", so it stays silent (conservative, prefer false negatives).
        ctx = _ctx(
            tmp_path,
            {"package.json": '{"dependencies": {"smart-data-pipeline-helper": "^1.0.0"}}'},
        )
        assert self.rule.scan(ctx) == []

    def test_short_name_not_flagged(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {
                "package.json": '{"dependencies": {"python-dateutil": "^2.0.0"}}',
                "package-lock.json": '{"packages": {"node_modules/express": {}}}',
            },
        )
        assert self.rule.scan(ctx) == []

    def test_pyproject_and_poetry_lock(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {
                "pyproject.toml": (
                    "[project]\n"
                    'dependencies = ["super-secure-auth-toolkit>=1.0", "requests>=2.0"]\n'
                ),
                "poetry.lock": '[[package]]\nname = "requests"\nversion = "2.31.0"\n',
            },
        )
        findings = self.rule.scan(ctx)
        assert [f.id for f in findings] == ["SLOP-HALLUCINATION-SHAPE"]
        assert findings[0].evidence == "super-secure-auth-toolkit"

    def test_requirements_txt(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {
                "requirements.txt": "ultra-fast-json-serializer==1.2.3\nrequests==2.31.0\n",
                "poetry.lock": '[[package]]\nname = "requests"\n',
            },
        )
        findings = self.rule.scan(ctx)
        assert [f.id for f in findings] == ["SLOP-HALLUCINATION-SHAPE"]

    def test_monorepo_sibling_lockfile_does_not_cover(self, tmp_path: Path):
        # A lockfile in packages/b must NOT vouch for a manifest in packages/a.
        # With no lockfile at or above packages/a, its manifest is left alone.
        ctx = _ctx(
            tmp_path,
            {
                "packages/a/package.json": '{"dependencies": {"fancy-multi-token-name": "1.0.0"}}',
                "packages/b/package-lock.json": '{"packages": {"node_modules/express": {}}}',
            },
        )
        assert self.rule.scan(ctx) == []

    def test_monorepo_root_lockfile_covers_subdir(self, tmp_path: Path):
        # A root lockfile is an ancestor of every workspace package, so a
        # subdir dependency absent from it is flagged.
        ctx = _ctx(
            tmp_path,
            {
                "package-lock.json": '{"packages": {"node_modules/express": {}}}',
                "packages/a/package.json": '{"dependencies": {"fancy-multi-token-name": "1.0.0"}}',
            },
        )
        findings = self.rule.scan(ctx)
        assert [f.id for f in findings] == ["SLOP-HALLUCINATION-SHAPE"]
        assert findings[0].path.replace("\\", "/") == "packages/a/package.json"


class TestRegistryCheck:
    rule = SlopsquatRule()

    def _pkg(self, tmp_path: Path, registry_check: bool) -> ScanContext:
        return _ctx(
            tmp_path,
            {"package.json": '{"dependencies": {"leftpad-ultimate": "^1.0.0"}}'},
            registry_check=registry_check,
        )

    def test_registry_check_off_by_default_does_no_network(self, tmp_path: Path, monkeypatch):
        def _boom(*_a, **_k):  # pragma: no cover — must never be called
            raise AssertionError("network lookup ran with registry_check disabled")

        monkeypatch.setattr(slop_mod, "_registry_lookup", _boom)
        assert self.rule.scan(self._pkg(tmp_path, registry_check=False)) == []

    def test_missing_package_flagged(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(slop_mod, "_registry_lookup", lambda *a, **k: (False, None))
        findings = self.rule.scan(self._pkg(tmp_path, registry_check=True))
        assert [f.id for f in findings] == ["SLOP-REGISTRY-MISSING"]
        assert findings[0].severity == Severity.HIGH

    def test_young_package_flagged(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(slop_mod, "_registry_lookup", lambda *a, **k: (True, 5))
        findings = self.rule.scan(self._pkg(tmp_path, registry_check=True))
        assert [f.id for f in findings] == ["SLOP-REGISTRY-YOUNG"]
        assert findings[0].severity == Severity.MEDIUM

    def test_established_package_not_flagged(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(slop_mod, "_registry_lookup", lambda *a, **k: (True, 900))
        assert self.rule.scan(self._pkg(tmp_path, registry_check=True)) == []

    def test_inconclusive_lookup_stays_silent(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(slop_mod, "_registry_lookup", lambda *a, **k: (None, None))
        assert self.rule.scan(self._pkg(tmp_path, registry_check=True)) == []


class TestLockNameExtraction:
    def test_extract_poetry_names(self):
        names = slop_mod._extract_lock_names(
            "poetry.lock", '[[package]]\nname = "Requests"\n[[package]]\nname = "flask"\n'
        )
        assert names == {"requests", "flask"}
