"""End-to-end tests for the `vibeguard publish-check` CLI command."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from vibeguard.cli import app

runner = CliRunner()
EXAMPLES = Path(__file__).parent.parent / "examples"


class TestPublishCheckCLI:
    def test_publish_check_on_vulnerable_node_package_fails(self):
        pkg = EXAMPLES / "vulnerable-node-package"
        if not pkg.exists():
            return
        result = runner.invoke(app, ["publish-check", "--path", str(pkg), "--fail-on", "high"])
        # Fixture lists .env and *.map in files — must trip publish-check.
        assert result.exit_code == 1

    def test_publish_check_json_emits_manifest_and_result(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]})
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.js").write_text("console.log('hi')\n")
        result = runner.invoke(app, ["publish-check", "--path", str(tmp_path), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert "manifest" in payload
        assert "result" in payload
        assert payload["manifest"]["ecosystem"] == "npm"
        assert any(f["path"] == "package.json" for f in payload["manifest"]["files"])

    def test_publish_check_manifest_out_writes_file(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]})
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.js").write_text("console.log('hi')\n")
        out = tmp_path / "out" / "manifest.json"
        result = runner.invoke(
            app,
            ["publish-check", "--path", str(tmp_path), "--manifest-out", str(out)],
        )
        assert result.exit_code == 0
        assert out.is_file()
        data = json.loads(out.read_text())
        assert data["ecosystem"] == "npm"
        assert any(f["path"] == "package.json" for f in data["files"])

    def test_publish_check_clean_npm_package_passes(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]})
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "index.js").write_text("export const x = 1\n")
        (tmp_path / "README.md").write_text("# demo\n")
        result = runner.invoke(app, ["publish-check", "--path", str(tmp_path), "--fail-on", "high"])
        assert result.exit_code == 0
        assert "publish-check passed" in (result.stderr or result.stdout)

    def test_publish_check_invalid_ecosystem_exits_two(self, tmp_path: Path):
        (tmp_path / "package.json").write_text("{}")
        result = runner.invoke(
            app, ["publish-check", "--path", str(tmp_path), "--ecosystem", "rubygems"]
        )
        assert result.exit_code == 2

    def test_publish_check_mutual_exclusion_json_markdown(self, tmp_path: Path):
        (tmp_path / "package.json").write_text("{}")
        result = runner.invoke(
            app, ["publish-check", "--path", str(tmp_path), "--json", "--markdown"]
        )
        assert result.exit_code == 2

    def test_publish_check_explicit_python_sdist(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            "[build-system]\n"
            'requires = ["hatchling"]\n'
            'build-backend = "hatchling.build"\n'
            "[project]\n"
            'name = "demo"\n'
            'version = "1.0.0"\n'
            "[tool.hatch.build.targets.sdist]\n"
            'include = ["src/", ".env"]\n'
        )
        (tmp_path / "src" / "demo").mkdir(parents=True)
        (tmp_path / "src" / "demo" / "__init__.py").write_text("")
        (tmp_path / ".env").write_text("API_KEY=AKIAIOSFODNN7EXAMPLE\n")
        result = runner.invoke(
            app,
            [
                "publish-check",
                "--path",
                str(tmp_path),
                "--ecosystem",
                "python-sdist",
                "--fail-on",
                "high",
            ],
        )
        # .env is in the include list → publish-check must fail.
        assert result.exit_code == 1

    def test_publish_check_unknown_root_emits_warning(self, tmp_path: Path):
        # No package.json, no pyproject.toml → auto detection returns None.
        (tmp_path / "src.txt").write_text("hi\n")
        result = runner.invoke(app, ["publish-check", "--path", str(tmp_path), "--json"])
        assert result.exit_code == 0  # no findings beat threshold
        payload = json.loads(result.stdout)
        assert any("Could not detect ecosystem" in w for w in payload["manifest"]["warnings"])

    def test_publish_check_explicit_npm_without_package_json_is_structured(self, tmp_path: Path):
        """Explicit --ecosystem with missing manifest should return a manifest+error, not crash."""
        result = runner.invoke(
            app,
            [
                "publish-check",
                "--path",
                str(tmp_path),
                "--ecosystem",
                "npm",
                "--json",
            ],
        )
        assert result.exit_code == 0  # no blocking findings — only the warning
        payload = json.loads(result.stdout)
        assert any("not found" in w for w in payload["manifest"]["warnings"])
        assert any("not found" in e for e in payload["result"]["errors"])

    def test_publish_check_explicit_python_sdist_without_pyproject_is_structured(
        self, tmp_path: Path
    ):
        result = runner.invoke(
            app,
            [
                "publish-check",
                "--path",
                str(tmp_path),
                "--ecosystem",
                "python-sdist",
                "--json",
            ],
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert any(
            "pyproject.toml" in w and "not found" in w for w in payload["manifest"]["warnings"]
        )

    def test_publish_check_disabled_in_config_short_circuits(self, tmp_path: Path):
        (tmp_path / "vibeguard.yaml").write_text(
            "publish_check:\n  enabled: false\n  ecosystem: auto\n  fail_on: high\n"
        )
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]})
        )
        result = runner.invoke(app, ["publish-check", "--path", str(tmp_path)])
        assert result.exit_code == 0
        assert "disabled" in (result.stderr or "") or "disabled" in result.stdout

    def test_publish_check_ecosystem_falls_back_to_config(self, tmp_path: Path):
        (tmp_path / "vibeguard.yaml").write_text(
            "publish_check:\n  ecosystem: python-sdist\n  fail_on: high\n"
        )
        # Both package.json AND pyproject.toml exist; auto would pick npm, but config says python-sdist.
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]})
        )
        (tmp_path / "pyproject.toml").write_text(
            "[build-system]\n"
            'requires = ["hatchling"]\n'
            'build-backend = "hatchling.build"\n'
            "[project]\n"
            'name = "demo"\n'
            'version = "1.0.0"\n'
            "[tool.hatch.build.targets.sdist]\n"
            'include = ["src/"]\n'
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "demo.py").write_text("x = 1\n")
        result = runner.invoke(app, ["publish-check", "--path", str(tmp_path), "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["manifest"]["ecosystem"] == "python-sdist"

    def test_publish_check_flags_npmignore_negate(self, tmp_path: Path):
        """PKG-NPMIGNORE-NEGATE must fire even though .npmignore never ships."""
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]})
        )
        (tmp_path / ".npmignore").write_text("*.env\n!.env\n")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "demo.js").write_text("export const x = 1\n")
        result = runner.invoke(app, ["publish-check", "--path", str(tmp_path), "--json"])
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        ids = {f["id"] for f in payload["result"]["findings"]}
        assert "PKG-NPMIGNORE-NEGATE" in ids

    def test_publish_check_respects_suppressions(self, tmp_path: Path):
        """Suppressions from config must apply to publish-check findings."""
        (tmp_path / "package.json").write_text(
            json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]})
        )
        (tmp_path / ".npmignore").write_text("*.env\n!.env\n")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "demo.js").write_text("export const x = 1\n")
        # Config that suppresses the npmignore negate finding
        (tmp_path / "vibeguard.yaml").write_text(
            "suppressions:\n"
            '  - finding_id: "PKG-NPMIGNORE-NEGATE"\n'
            '    reason: "Intentional for testing"\n'
        )
        result = runner.invoke(
            app,
            ["publish-check", "--path", str(tmp_path), "--config", str(tmp_path / "vibeguard.yaml"), "--json"],
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        ids = {f["id"] for f in payload["result"]["findings"]}
        assert "PKG-NPMIGNORE-NEGATE" not in ids
