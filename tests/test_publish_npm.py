"""Tests for the npm pack simulator."""

from __future__ import annotations

import json
from pathlib import Path

from vibeguard.publish.npm import simulate_npm_pack


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)


class TestNpmSimulator:
    def test_files_allowlist_includes_only_matched_paths(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "package.json": json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]}),
                "src/index.js": "console.log('hi')\n",
                "src/util.js": "module.exports = 1\n",
                "tests/test_index.js": "// tests\n",
                "README.md": "# demo\n",
            },
        )
        m = simulate_npm_pack(tmp_path)
        paths = m.included_paths()
        assert "src/index.js" in paths
        assert "src/util.js" in paths
        assert "package.json" in paths  # always-included
        assert "README.md" in paths  # always-included
        assert "tests/test_index.js" not in paths
        assert "tests/test_index.js" in m.excluded

    def test_no_files_no_npmignore_walks_everything_and_warns(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "package.json": json.dumps({"name": "demo", "version": "1.0.0"}),
                "src/index.js": "console.log(1)\n",
                ".env": "SECRET=x\n",
            },
        )
        m = simulate_npm_pack(tmp_path)
        paths = m.included_paths()
        assert "package.json" in paths
        assert "src/index.js" in paths
        assert ".env" in paths
        assert any("no .npmignore" in w for w in m.warnings)

    def test_npmignore_fallback_excludes_listed_paths(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "package.json": json.dumps({"name": "demo", "version": "1.0.0"}),
                ".npmignore": "tests/\n.env\n",
                "src/index.js": "console.log(1)\n",
                ".env": "SECRET=x\n",
                "tests/test_index.js": "// tests\n",
            },
        )
        m = simulate_npm_pack(tmp_path)
        paths = m.included_paths()
        assert "src/index.js" in paths
        assert "tests/test_index.js" not in paths
        assert ".env" not in paths
        assert "tests/test_index.js" in m.excluded
        assert ".env" in m.excluded

    def test_gitignore_used_when_npmignore_missing(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "package.json": json.dumps({"name": "demo", "version": "1.0.0"}),
                ".gitignore": "tests/\n",
                "src/index.js": "console.log(1)\n",
                "tests/test_index.js": "// tests\n",
            },
        )
        m = simulate_npm_pack(tmp_path)
        paths = m.included_paths()
        assert "tests/test_index.js" not in paths

    def test_node_modules_and_git_always_excluded(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "package.json": json.dumps({"name": "demo", "version": "1.0.0", "files": ["**"]}),
                "node_modules/lodash/index.js": "module.exports = 1\n",
                ".git/HEAD": "ref: refs/heads/main\n",
                "src/app.js": "console.log(1)\n",
            },
        )
        m = simulate_npm_pack(tmp_path)
        paths = m.included_paths()
        assert "src/app.js" in paths
        assert not any(p.startswith("node_modules/") for p in paths)
        assert not any(p.startswith(".git/") for p in paths)

    def test_always_included_at_root_only(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "package.json": json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]}),
                "README.md": "# top\n",
                "src/README.md": "# nested\n",  # NOT auto-included
                "src/index.js": "console.log(1)\n",
            },
        )
        m = simulate_npm_pack(tmp_path)
        paths = m.included_paths()
        assert "README.md" in paths
        assert "src/README.md" in paths  # included via files-allowlist "src/", not always-included
        # Confirm reason classification
        readme = next(f for f in m.files if f.path == "README.md")
        assert readme.included_by == "always-included"
        nested = next(f for f in m.files if f.path == "src/README.md")
        assert nested.included_by == "files-allowlist"

    def test_missing_package_json_raises(self, tmp_path: Path):
        try:
            simulate_npm_pack(tmp_path)
        except FileNotFoundError:
            return
        raise AssertionError("expected FileNotFoundError when package.json is missing")

    def test_invalid_package_json_returns_warning(self, tmp_path: Path):
        (tmp_path / "package.json").write_text("{not valid json")
        m = simulate_npm_pack(tmp_path)
        assert m.files == []
        assert any("not valid JSON" in w for w in m.warnings)

    def test_manifest_total_bytes_sums_included(self, tmp_path: Path):
        body = "x" * 100
        _write(
            tmp_path,
            {
                "package.json": json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]}),
                "src/a.js": body,
                "src/b.js": body,
                "tests/t.js": "ignored\n",
            },
        )
        m = simulate_npm_pack(tmp_path)
        included_sizes = sum(f.size_bytes for f in m.files)
        assert m.total_bytes == included_sizes
        # 2 src files (100 each) + package.json
        assert m.total_bytes >= 200

    def test_excluded_lists_always_excluded_root_files(self, tmp_path: Path):
        """Always-excluded files on disk must appear in the manifest's `excluded` list."""
        _write(
            tmp_path,
            {
                "package.json": json.dumps({"name": "demo", "version": "1.0.0", "files": ["src/"]}),
                ".gitignore": "node_modules/\n",
                ".npmignore": "tests/\n",
                ".npmrc": "registry=https://my-registry.example.com\n",
                "src/index.js": "console.log(1)\n",
                "node_modules/lodash/index.js": "module.exports = 1\n",
            },
        )
        m = simulate_npm_pack(tmp_path)
        # Always-excluded root files exist on disk → must be reported as excluded.
        assert ".gitignore" in m.excluded
        assert ".npmignore" in m.excluded
        assert ".npmrc" in m.excluded
        # And the node_modules directory marker.
        assert "node_modules/" in m.excluded
        # They must NOT appear in the included file list.
        paths = m.included_paths()
        assert ".gitignore" not in paths
        assert ".npmignore" not in paths
        assert ".npmrc" not in paths

    def test_vulnerable_node_example_reproduces_known_leaks(self, tmp_path: Path):
        """Smoke test against the bundled vulnerable-node-package fixture."""
        examples = Path(__file__).parent.parent / "examples" / "vulnerable-node-package"
        if not (examples / "package.json").exists():
            return  # fixture missing; skip in environments without examples/
        m = simulate_npm_pack(examples)
        paths = m.included_paths()
        # The fixture's package.json lists files: ["src/", "dist/", ".env", "**/*.map"]
        assert any(p == ".env" for p in paths)
        assert any(p.endswith(".map") for p in paths)
