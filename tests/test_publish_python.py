"""Tests for the Python sdist/wheel simulator."""

from __future__ import annotations

from pathlib import Path

from vibeguard.publish.python import simulate_python


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for name, content in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)


HATCH_PYPROJECT = """\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "demo"
version = "1.0.0"

[tool.hatch.build.targets.sdist]
include = ["src/", ".env"]

[tool.hatch.build.targets.wheel]
packages = ["src/demo"]
"""


SETUPTOOLS_PYPROJECT = """\
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "demo"
version = "1.0.0"

[tool.setuptools.packages.find]
where = ["src"]
"""


class TestHatchSdist:
    def test_include_globs_match(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "pyproject.toml": HATCH_PYPROJECT,
                "src/demo/__init__.py": "",
                "src/demo/core.py": "x = 1\n",
                ".env": "SECRET=x\n",
                "tests/test_demo.py": "# tests\n",
            },
        )
        m = simulate_python(tmp_path, target="python-sdist")
        paths = m.included_paths()
        assert "src/demo/core.py" in paths
        assert "src/demo/__init__.py" in paths
        assert ".env" in paths
        assert "tests/test_demo.py" not in paths
        assert "pyproject.toml" in paths  # always-included

    def test_excluded_root_files_left_out(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "pyproject.toml": HATCH_PYPROJECT,
                "src/demo/__init__.py": "",
                "Makefile": "all:\n\t@echo build\n",
                "tox.ini": "[tox]\nenvlist = py310\n",
            },
        )
        m = simulate_python(tmp_path, target="python-sdist")
        paths = m.included_paths()
        assert "Makefile" not in paths
        assert "tox.ini" not in paths

    def test_excluded_directories_skipped(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "pyproject.toml": HATCH_PYPROJECT,
                "src/demo/__init__.py": "",
                ".git/HEAD": "ref\n",
                "__pycache__/foo.pyc": b"\x00\x00",
                ".venv/lib/python.py": "x = 1\n",
            },
        )
        m = simulate_python(tmp_path, target="python-sdist")
        paths = m.included_paths()
        assert not any(p.startswith(".git/") for p in paths)
        assert not any(p.startswith("__pycache__/") for p in paths)
        assert not any(p.startswith(".venv/") for p in paths)


class TestHatchWheel:
    def test_wheel_includes_only_package_dirs(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "pyproject.toml": HATCH_PYPROJECT,
                "src/demo/__init__.py": "",
                "src/demo/core.py": "x = 1\n",
                ".env": "SECRET=x\n",
                "README.md": "# demo\n",
            },
        )
        m = simulate_python(tmp_path, target="python-wheel")
        paths = m.included_paths()
        assert "src/demo/__init__.py" in paths
        assert "src/demo/core.py" in paths
        # Wheel does NOT include sdist metadata files or .env
        assert ".env" not in paths
        assert "README.md" not in paths


class TestSetuptoolsSdist:
    def test_packages_find_walks_src(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "pyproject.toml": SETUPTOOLS_PYPROJECT,
                "src/demo/__init__.py": "",
                "src/demo/core.py": "x = 1\n",
                "tests/test_demo.py": "# tests\n",
            },
        )
        m = simulate_python(tmp_path, target="python-sdist")
        paths = m.included_paths()
        assert "src/demo/__init__.py" in paths
        assert "src/demo/core.py" in paths
        assert "tests/test_demo.py" not in paths

    def test_manifest_in_graft_and_recursive_include(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "pyproject.toml": SETUPTOOLS_PYPROJECT,
                "src/demo/__init__.py": "",
                "src/demo/data/big.csv": "1,2,3\n",
                "MANIFEST.in": (
                    "graft src/demo/data\n"
                    "recursive-include src/demo *.py\n"
                    "exclude src/demo/secret.py\n"
                ),
            },
        )
        m = simulate_python(tmp_path, target="python-sdist")
        paths = m.included_paths()
        assert "src/demo/data/big.csv" in paths
        assert "src/demo/__init__.py" in paths

    def test_manifest_in_prune_drops_directory(self, tmp_path: Path):
        _write(
            tmp_path,
            {
                "pyproject.toml": SETUPTOOLS_PYPROJECT,
                "src/demo/__init__.py": "",
                "src/demo/secrets/key.pem": "PRIVATE KEY\n",
                "MANIFEST.in": "graft src/demo\nprune src/demo/secrets\n",
            },
        )
        m = simulate_python(tmp_path, target="python-sdist")
        paths = m.included_paths()
        assert "src/demo/__init__.py" in paths
        assert "src/demo/secrets/key.pem" not in paths


class TestErrors:
    def test_missing_pyproject_raises(self, tmp_path: Path):
        try:
            simulate_python(tmp_path, target="python-sdist")
        except FileNotFoundError:
            return
        raise AssertionError("expected FileNotFoundError")

    def test_invalid_toml_returns_warning(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[broken[[")
        m = simulate_python(tmp_path, target="python-sdist")
        assert m.files == []
        assert any("not valid TOML" in w for w in m.warnings)

    def test_unknown_backend_falls_back(self, tmp_path: Path):
        # No build-system block at all.
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "1.0.0"\n')
        (tmp_path / "README.md").write_text("# demo\n")
        m = simulate_python(tmp_path, target="python-sdist")
        # README and pyproject still always-included
        paths = m.included_paths()
        assert "pyproject.toml" in paths
        assert "README.md" in paths


class TestVulnerablePythonExample:
    """Smoke test against the bundled fixture."""

    def test_sdist_includes_known_leaks(self):
        examples = Path(__file__).parent.parent / "examples" / "vulnerable-python-package"
        if not (examples / "pyproject.toml").exists():
            return  # skip if fixture missing
        m = simulate_python(examples, target="python-sdist")
        paths = m.included_paths()
        # The fixture's pyproject.toml lists include = ["src/", ".env", "tests/", "**/*.map"].
        # `tests/` and `**/*.map` are listed but no matching files exist on disk;
        # the leaked file actually shipped is `.env` plus the source under `src/`.
        assert ".env" in paths
        assert "src/main.py" in paths
        assert "pyproject.toml" in paths  # always-included
