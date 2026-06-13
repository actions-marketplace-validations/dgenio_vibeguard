"""Tests for the consolidated manifest/lockfile parser (#179).

Each supported format has a happy-path case and a malformed-input case; the
latter must degrade to empty data, never raise.
"""

from __future__ import annotations

import pytest

from vibeguard.manifests import (
    LOCKFILE_TO_MANIFEST,
    NODE_LOCKFILES,
    PY_LOCKFILES,
    lock_package_names,
    node_dependency_names,
    node_dependency_versions,
    pyproject_dependency_names,
    pyproject_dependency_specifiers,
    requirements_dependency_names,
    split_python_name,
)

# ---------------------------------------------------------------------------
# package.json
# ---------------------------------------------------------------------------


def test_node_dependency_versions_merges_groups():
    text = """
    {
      "dependencies": {"left-pad": "^1.0.0"},
      "devDependencies": {"jest": "29.0.0"},
      "optionalDependencies": {"fsevents": "2.3.0"}
    }
    """
    assert node_dependency_versions(text) == {
        "left-pad": "^1.0.0",
        "jest": "29.0.0",
        "fsevents": "2.3.0",
    }


def test_node_dependency_names_lists_all_groups():
    text = '{"dependencies": {"a": "1"}, "devDependencies": {"b": "2"}}'
    assert node_dependency_names(text) == ["a", "b"]


@pytest.mark.parametrize("bad", ["", "not json", "[1, 2, 3]", "{"])
def test_node_malformed_returns_empty(bad: str):
    assert node_dependency_versions(bad) == {}
    assert node_dependency_names(bad) == []


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------


def test_pyproject_specifiers_and_names():
    text = """
    [project]
    name = "demo"
    dependencies = ["requests>=2,<3", "rich[all]", "typer ; python_version>='3.10'"]
    """
    assert pyproject_dependency_specifiers(text) == [
        "requests>=2,<3",
        "rich[all]",
        "typer ; python_version>='3.10'",
    ]
    assert pyproject_dependency_names(text) == ["requests", "rich", "typer"]


@pytest.mark.parametrize("bad", ["", "= = =", "[project"])
def test_pyproject_malformed_returns_empty(bad: str):
    assert pyproject_dependency_specifiers(bad) == []
    assert pyproject_dependency_names(bad) == []


def test_split_python_name():
    assert split_python_name("requests>=2.0") == "requests"
    assert split_python_name("django-stubs[compatible-mypy]") == "django-stubs"


# ---------------------------------------------------------------------------
# requirements*.txt
# ---------------------------------------------------------------------------


def test_requirements_names_skip_comments_and_flags():
    text = "# comment\nrequests==2.0\n-r other.txt\n\nflask>=2\n--index-url https://x\n"
    assert requirements_dependency_names(text) == ["requests", "flask"]


# ---------------------------------------------------------------------------
# lockfiles
# ---------------------------------------------------------------------------


def test_package_lock_json_structured():
    text = """
    {"packages": {"node_modules/left-pad": {}, "node_modules/@scope/util": {}}}
    """
    assert lock_package_names("package-lock.json", text) == {"left-pad", "@scope/util"}


def test_yarn_lock_regex():
    text = 'left-pad@^1.0.0:\n  version "1.0.0"\n"@scope/util@^2":\n  version "2.0.0"\n'
    names = lock_package_names("yarn.lock", text)
    assert "left-pad" in names
    assert "@scope/util" in names


def test_poetry_lock_lowercased():
    text = '[[package]]\nname = "Requests"\n[[package]]\nname = "flask"\n'
    assert lock_package_names("poetry.lock", text) == {"requests", "flask"}


def test_pipfile_lock_sections():
    text = '{"default": {"requests": {}}, "develop": {"pytest": {}}}'
    assert lock_package_names("Pipfile.lock", text) == {"requests", "pytest"}


@pytest.mark.parametrize("name", ["package-lock.json", "Pipfile.lock"])
def test_lock_malformed_json_returns_empty(name: str):
    assert lock_package_names(name, "{ not json") == set()


def test_lock_unknown_filename_returns_empty():
    assert lock_package_names("Cargo.lock", "anything") == set()


# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------


def test_lockfile_to_manifest_covers_all_known_lockfiles():
    # Every npm/py lockfile name has a manifest mapping for the drift check.
    for lf in NODE_LOCKFILES | PY_LOCKFILES:
        assert lf in LOCKFILE_TO_MANIFEST
