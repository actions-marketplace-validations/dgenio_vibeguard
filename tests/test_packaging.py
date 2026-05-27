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

    def test_manifest_in_graft_dot_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"MANIFEST.in": "graft .\n"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-MANIFEST-GRAFT" for f in findings)

    def test_manifest_in_graft_star_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"MANIFEST.in": "graft *\n"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-MANIFEST-GRAFT" for f in findings)

    def test_manifest_in_recursive_include_dot_star_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"MANIFEST.in": "recursive-include . *\n"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-MANIFEST-RECURSIVE" for f in findings)

    def test_manifest_in_global_include_star_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"MANIFEST.in": "global-include *\n"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-MANIFEST-RECURSIVE" for f in findings)

    def test_manifest_in_targeted_recursive_include_clean(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"MANIFEST.in": "recursive-include src/mypkg *.py\n"})
        findings = self.rule.scan(ctx)
        assert not any(f.id in ("PKG-MANIFEST-GRAFT", "PKG-MANIFEST-RECURSIVE") for f in findings)

    def test_npmignore_negate_env_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {".npmignore": "*.env\n!.env\n"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-NPMIGNORE-NEGATE" for f in findings)

    def test_npmignore_normal_lines_clean(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {".npmignore": "tests/\n*.log\n# comment\n"})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-NPMIGNORE-NEGATE" for f in findings)

    # ------------------------------------------------------------------
    # PKG-NPMIGNORE-BROAD — broad re-include negations (#34)
    # ------------------------------------------------------------------

    def test_npmignore_broad_negate_star_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {".npmignore": "*\n!*\n"})
        findings = self.rule.scan(ctx)
        broad = [f for f in findings if f.id == "PKG-NPMIGNORE-BROAD"]
        assert len(broad) == 1
        assert broad[0].severity.value == "medium"
        assert broad[0].line == 2

    def test_npmignore_broad_negate_doublestar_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {".npmignore": "*\n!**\n"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-NPMIGNORE-BROAD" for f in findings)

    def test_npmignore_broad_negate_root_slash_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {".npmignore": "*\n!/\n"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-NPMIGNORE-BROAD" for f in findings)

    def test_npmignore_targeted_negate_not_broad(self, tmp_path: Path):
        # `!.env` is a targeted, dangerous negation — caught by NPMIGNORE-NEGATE
        # but NOT by NPMIGNORE-BROAD. The two checks must not overlap on this
        # input or the dedicated -BROAD test below loses meaning.
        ctx = _ctx(tmp_path, {".npmignore": "*.env\n!.env\n"})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-NPMIGNORE-BROAD" for f in findings)
        assert any(f.id == "PKG-NPMIGNORE-NEGATE" for f in findings)

    def test_npmignore_comment_line_with_bang_not_flagged(self, tmp_path: Path):
        # `# !*` is a comment, not a negation.
        ctx = _ctx(tmp_path, {".npmignore": "tests/\n# !*\n"})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-NPMIGNORE-BROAD" for f in findings)

    # ------------------------------------------------------------------
    # PKG-PREPARE-SCRIPT — npm prepare/prepack lifecycle scripts (#34)
    # ------------------------------------------------------------------

    def test_prepare_script_flagged(self, tmp_path: Path):
        data = json.dumps(
            {
                "name": "foo",
                "version": "1.0.0",
                "files": ["dist/"],
                "scripts": {"prepare": "npm run build"},
            }
        )
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        prepare = [f for f in findings if f.id == "PKG-PREPARE-SCRIPT"]
        assert len(prepare) == 1
        assert prepare[0].severity.value == "low"
        assert "prepare" in prepare[0].title
        assert prepare[0].evidence == "prepare: npm run build"

    def test_prepack_script_flagged(self, tmp_path: Path):
        data = json.dumps(
            {
                "name": "foo",
                "version": "1.0.0",
                "files": ["dist/"],
                "scripts": {"prepack": "node build.js"},
            }
        )
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-PREPARE-SCRIPT" for f in findings)

    def test_both_prepare_and_prepack_each_flagged(self, tmp_path: Path):
        data = json.dumps(
            {
                "name": "foo",
                "version": "1.0.0",
                "files": ["dist/"],
                "scripts": {"prepare": "tsc", "prepack": "rollup -c"},
            }
        )
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        prepare = [f for f in findings if f.id == "PKG-PREPARE-SCRIPT"]
        assert len(prepare) == 2
        titles = {f.title for f in prepare}
        assert any("prepare" in t for t in titles)
        assert any("prepack" in t for t in titles)

    def test_other_scripts_not_flagged_as_prepare(self, tmp_path: Path):
        data = json.dumps(
            {
                "name": "foo",
                "version": "1.0.0",
                "files": ["dist/"],
                "scripts": {"test": "jest", "build": "tsc", "start": "node ."},
            }
        )
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-PREPARE-SCRIPT" for f in findings)

    # ------------------------------------------------------------------
    # PKG-COVERAGE-LEAK — coverage artifacts at the package root (#34)
    # ------------------------------------------------------------------

    def test_coverage_dir_with_no_npmignore_flagged(self, tmp_path: Path):
        (tmp_path / "coverage").mkdir()
        (tmp_path / "coverage" / "index.html").write_text("<html></html>")
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        leaks = [f for f in findings if f.id == "PKG-COVERAGE-LEAK"]
        assert len(leaks) == 1
        assert leaks[0].severity.value == "low"
        assert leaks[0].path == "coverage"

    def test_htmlcov_dir_flagged_for_python_package(self, tmp_path: Path):
        (tmp_path / "htmlcov").mkdir()
        ctx = _ctx(
            tmp_path,
            {"pyproject.toml": '[project]\nname = "foo"\nversion = "1.0.0"\n'},
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-COVERAGE-LEAK" and f.path == "htmlcov" for f in findings)

    def test_nyc_output_dir_flagged(self, tmp_path: Path):
        (tmp_path / ".nyc_output").mkdir()
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-COVERAGE-LEAK" and f.path == ".nyc_output" for f in findings)

    def test_coverage_excluded_by_npmignore_not_flagged(self, tmp_path: Path):
        (tmp_path / "coverage").mkdir()
        (tmp_path / ".npmignore").write_text("coverage\n")
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-COVERAGE-LEAK" for f in findings)

    def test_coverage_excluded_by_npmignore_trailing_slash(self, tmp_path: Path):
        (tmp_path / "coverage").mkdir()
        (tmp_path / ".npmignore").write_text("coverage/\n")
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-COVERAGE-LEAK" for f in findings)

    def test_coverage_excluded_by_npm_files_allowlist(self, tmp_path: Path):
        (tmp_path / "coverage").mkdir()
        (tmp_path / "dist").mkdir()
        data = json.dumps({"name": "foo", "version": "1.0.0", "files": ["dist/"]})
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        # A `files` allowlist that doesn't list `coverage` excludes it from publish.
        assert not any(f.id == "PKG-COVERAGE-LEAK" for f in findings)

    def test_coverage_excluded_by_manifest_in_prune(self, tmp_path: Path):
        (tmp_path / "htmlcov").mkdir()
        ctx = _ctx(
            tmp_path,
            {
                "pyproject.toml": '[project]\nname = "foo"\nversion = "1.0.0"\n',
                "MANIFEST.in": "prune htmlcov\n",
            },
        )
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-COVERAGE-LEAK" for f in findings)

    def test_no_coverage_dir_no_leak(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-COVERAGE-LEAK" for f in findings)

    # ------------------------------------------------------------------
    # PKG-CI-LEAK — CI config at the package root (#34)
    # ------------------------------------------------------------------

    def test_github_dir_at_root_flagged_for_npm(self, tmp_path: Path):
        (tmp_path / ".github").mkdir()
        (tmp_path / ".github" / "workflows").mkdir()
        (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI\n")
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        leaks = [f for f in findings if f.id == "PKG-CI-LEAK"]
        assert len(leaks) == 1
        assert leaks[0].path == ".github"
        assert leaks[0].severity.value == "low"

    def test_travis_yml_at_root_flagged(self, tmp_path: Path):
        (tmp_path / ".travis.yml").write_text("language: python\n")
        ctx = _ctx(
            tmp_path,
            {"pyproject.toml": '[project]\nname = "foo"\nversion = "1.0.0"\n'},
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-CI-LEAK" and f.path == ".travis.yml" for f in findings)

    def test_gitlab_ci_at_root_flagged(self, tmp_path: Path):
        (tmp_path / ".gitlab-ci.yml").write_text("stages: [test]\n")
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-CI-LEAK" and f.path == ".gitlab-ci.yml" for f in findings)

    def test_circleci_dir_flagged(self, tmp_path: Path):
        (tmp_path / ".circleci").mkdir()
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "PKG-CI-LEAK" and f.path == ".circleci" for f in findings)

    def test_ci_excluded_by_npmignore_not_flagged(self, tmp_path: Path):
        (tmp_path / ".github").mkdir()
        (tmp_path / ".npmignore").write_text(".github\n")
        ctx = _ctx(tmp_path, {"package.json": '{"name":"foo","version":"1.0.0"}'})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-CI-LEAK" for f in findings)

    def test_ci_excluded_by_files_allowlist(self, tmp_path: Path):
        (tmp_path / ".github").mkdir()
        (tmp_path / "dist").mkdir()
        data = json.dumps({"name": "foo", "version": "1.0.0", "files": ["dist/"]})
        ctx = _ctx(tmp_path, {"package.json": data})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-CI-LEAK" for f in findings)

    def test_ci_excluded_by_manifest_prune(self, tmp_path: Path):
        (tmp_path / ".github").mkdir()
        ctx = _ctx(
            tmp_path,
            {
                "pyproject.toml": '[project]\nname = "foo"\nversion = "1.0.0"\n',
                "MANIFEST.in": "prune .github\n",
            },
        )
        findings = self.rule.scan(ctx)
        assert not any(f.id == "PKG-CI-LEAK" for f in findings)

    def test_root_artifact_audit_runs_once_per_root(self, tmp_path: Path):
        # Audit must not double-fire when `package.json` is encountered before
        # `pyproject.toml` in the same directory — pick the manifest order.
        (tmp_path / "coverage").mkdir()
        ctx = _ctx(
            tmp_path,
            {
                "package.json": '{"name":"foo","version":"1.0.0"}',
                "pyproject.toml": '[project]\nname = "foo"\nversion = "1.0.0"\n',
            },
        )
        findings = self.rule.scan(ctx)
        leaks = [f for f in findings if f.id == "PKG-COVERAGE-LEAK"]
        # Each ecosystem manifest opens a fresh audit at its own root, but the
        # audited_roots guard makes sure each root is only audited once even
        # when both an npm and a Python manifest sit in it.
        assert len(leaks) == 1
