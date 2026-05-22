"""Tests for the developer-workflow integration artifacts.

Pins ``.pre-commit-hooks.yaml``, ``Dockerfile``, ``.dockerignore``, the
``.github/workflows/docker.yml`` workflow, and the matching docs pages to
the shape contributors and downstream users depend on. Closes #45 (pre-
commit hook support) and #48 (Docker image for CI usage).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

PRE_COMMIT_HOOKS = REPO_ROOT / ".pre-commit-hooks.yaml"
DOCKERFILE = REPO_ROOT / "Dockerfile"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
DOCKER_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "docker.yml"
DOCS_PRE_COMMIT = REPO_ROOT / "docs" / "pre-commit.md"
DOCS_DOCKER = REPO_ROOT / "docs" / "docker.md"


# --------------------------------------------------------------------------- #
# Pre-commit hooks manifest (#45)
# --------------------------------------------------------------------------- #


class TestPreCommitHooksManifest:
    @pytest.fixture(scope="class")
    def hooks(self) -> list[dict]:
        assert PRE_COMMIT_HOOKS.exists(), (
            ".pre-commit-hooks.yaml is required at the repository root so "
            "users can install VibeGuard with two lines in their "
            ".pre-commit-config.yaml."
        )
        data = yaml.safe_load(PRE_COMMIT_HOOKS.read_text(encoding="utf-8"))
        assert isinstance(data, list), "pre-commit manifest must be a YAML list of hooks"
        return data

    def test_ships_expected_hook_ids(self, hooks: list[dict]):
        ids = {h.get("id") for h in hooks}
        assert ids == {"vibeguard-gate", "vibeguard-scan", "vibeguard-validate-config"}, (
            f"Unexpected hook id set: {sorted(ids)}"
        )

    def test_every_hook_has_required_fields(self, hooks: list[dict]):
        required = {"id", "name", "description", "entry", "language"}
        for hook in hooks:
            missing = required - hook.keys()
            assert not missing, f"Hook {hook.get('id')} missing fields: {sorted(missing)}"

    def test_every_hook_uses_language_python(self, hooks: list[dict]):
        # `language: python` lets pre-commit install vibeguard into its own
        # isolated virtualenv, so the host shell doesn't need vibeguard on
        # $PATH. Anything else would defeat the point of shipping the manifest.
        for hook in hooks:
            assert hook["language"] == "python", (
                f"Hook {hook['id']} must use language: python (got {hook['language']!r})"
            )

    def test_every_hook_calls_the_vibeguard_cli(self, hooks: list[dict]):
        for hook in hooks:
            assert hook["entry"].startswith("vibeguard "), (
                f"Hook {hook['id']} entry must invoke the vibeguard CLI (got {hook['entry']!r})"
            )

    def test_gate_hook_defaults_to_fail_on_high(self, hooks: list[dict]):
        gate = next(h for h in hooks if h["id"] == "vibeguard-gate")
        assert gate["entry"] == "vibeguard gate"
        assert gate["args"] == ["--fail-on", "high"]
        assert gate["pass_filenames"] is False
        assert gate["always_run"] is True

    def test_scan_hook_is_informational(self, hooks: list[dict]):
        # The scan hook must NOT carry --fail-on; `vibeguard scan` always
        # exits 0, which is the contract this hook documents.
        scan = next(h for h in hooks if h["id"] == "vibeguard-scan")
        assert scan["entry"] == "vibeguard scan"
        assert "args" not in scan or scan["args"] == []
        assert scan["pass_filenames"] is False
        assert scan["always_run"] is True

    def test_validate_hook_targets_only_vibeguard_yaml(self, hooks: list[dict]):
        validate = next(h for h in hooks if h["id"] == "vibeguard-validate-config")
        assert validate["entry"] == "vibeguard validate"
        # The filter must match vibeguard.yaml (and nothing else) so the hook
        # only fires when the config file itself changes.
        assert validate["files"] == r"^vibeguard\.yaml$"
        assert validate["pass_filenames"] is False


# --------------------------------------------------------------------------- #
# Dockerfile (#48)
# --------------------------------------------------------------------------- #


class TestDockerfile:
    @pytest.fixture(scope="class")
    def dockerfile(self) -> str:
        assert DOCKERFILE.exists(), "Dockerfile is required at the repository root"
        return DOCKERFILE.read_text(encoding="utf-8")

    def test_uses_python_slim_base(self, dockerfile: str):
        # python:*-slim is the only base allowed — debian/ubuntu would bloat
        # the runtime layer; alpine breaks pydantic-core wheels.
        assert "FROM python:3.12-slim" in dockerfile, (
            "Dockerfile must use python:3.12-slim as the base image"
        )

    def test_has_two_stage_build(self, dockerfile: str):
        # Two-stage build keeps `build` and any compile-time deps out of the
        # published runtime image. Drop this assertion only if you switch
        # back to a single-stage layout intentionally.
        assert dockerfile.count("FROM python:3.12-slim") >= 2, (
            "Dockerfile should be a multi-stage build (build + runtime)"
        )
        assert "AS build" in dockerfile
        assert "AS runtime" in dockerfile

    def test_runs_as_non_root_user(self, dockerfile: str):
        assert "useradd" in dockerfile and "vibeguard" in dockerfile, (
            "Dockerfile must create a non-root vibeguard user"
        )
        assert "USER vibeguard" in dockerfile, "Dockerfile must drop to USER vibeguard"

    def test_workdir_is_scan(self, dockerfile: str):
        assert "WORKDIR /scan" in dockerfile, (
            "Dockerfile must set WORKDIR /scan so a single bind-mount lands at the documented path"
        )

    def test_entrypoint_is_vibeguard_cli(self, dockerfile: str):
        assert 'ENTRYPOINT ["vibeguard"]' in dockerfile, (
            "Dockerfile must set ENTRYPOINT to the vibeguard CLI"
        )

    def test_carries_oci_labels(self, dockerfile: str):
        for label in (
            "org.opencontainers.image.title",
            "org.opencontainers.image.description",
            "org.opencontainers.image.source",
            "org.opencontainers.image.licenses",
            "org.opencontainers.image.version",
        ):
            assert label in dockerfile, f"Dockerfile is missing OCI label {label!r}"

    def test_installs_from_local_source(self, dockerfile: str):
        # The image must match the source tree exactly. Pulling from PyPI
        # here would let the image float independently of the repo SHA.
        assert "python -m build" in dockerfile, (
            "Dockerfile must build the wheel from the local source tree"
        )


# --------------------------------------------------------------------------- #
# .dockerignore (#48)
# --------------------------------------------------------------------------- #


class TestDockerignore:
    @pytest.fixture(scope="class")
    def patterns(self) -> set[str]:
        assert DOCKERIGNORE.exists(), ".dockerignore is required to keep the build context slim"
        return {
            line.strip()
            for line in DOCKERIGNORE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

    @pytest.mark.parametrize(
        "pattern",
        [
            ".git/",
            ".github/",
            ".venv/",
            "tests/",
            "examples/",
            "docs/",
            "**/__pycache__/",
        ],
    )
    def test_excludes_pattern(self, patterns: set[str], pattern: str):
        assert pattern in patterns, f".dockerignore is missing required pattern {pattern!r}"


# --------------------------------------------------------------------------- #
# Docker CI workflow (#48)
# --------------------------------------------------------------------------- #


class TestDockerWorkflow:
    @pytest.fixture(scope="class")
    def workflow(self) -> dict:
        assert DOCKER_WORKFLOW.exists(), "Docker CI workflow is required"
        # `on:` is parsed by PyYAML as the Python boolean True (YAML 1.1
        # legacy). We don't introspect that key, so this is fine.
        return yaml.safe_load(DOCKER_WORKFLOW.read_text(encoding="utf-8"))

    def test_has_a_build_job(self, workflow: dict):
        assert "jobs" in workflow
        assert "build" in workflow["jobs"], "Docker workflow must define a `build` job"

    def test_does_not_push_to_any_registry(self, workflow: dict):
        # Issue #48 explicitly defers the registry-push decision to
        # maintainers. The smoke-test workflow must never push.
        flat = yaml.safe_dump(workflow)
        assert "docker/login-action" not in flat, (
            "Docker workflow must not log in to any container registry"
        )
        assert "push: true" not in flat, "Docker workflow must not push images"

    def test_smoke_tests_a_scan_invocation(self, workflow: dict):
        flat = yaml.safe_dump(workflow)
        # The workflow must actually exercise the CLI inside the container,
        # not just verify the image builds.
        assert "docker run" in flat
        assert "vibeguard:ci scan" in flat

    def test_smoke_tests_non_root_user(self, workflow: dict):
        # Issue #48 acceptance criterion: container runs as a non-root user.
        flat = yaml.safe_dump(workflow)
        assert "UID_RUN" in flat, (
            "Docker workflow must capture the container UID in a variable"
        )
        assert "-ne 0" in flat, (
            "Docker workflow must assert the UID is non-zero"
        )


# --------------------------------------------------------------------------- #
# Docs (#45 + #48)
# --------------------------------------------------------------------------- #


class TestIntegrationDocs:
    @pytest.fixture(scope="class")
    def pre_commit_doc(self) -> str:
        assert DOCS_PRE_COMMIT.exists(), "docs/pre-commit.md is required"
        return DOCS_PRE_COMMIT.read_text(encoding="utf-8")

    @pytest.fixture(scope="class")
    def docker_doc(self) -> str:
        assert DOCS_DOCKER.exists(), "docs/docker.md is required"
        return DOCS_DOCKER.read_text(encoding="utf-8")

    def test_pre_commit_doc_covers_required_sections(self, pre_commit_doc: str):
        # Issue #45 enumerates the sections this guide must contain.
        for needle in (
            "pre-commit install",
            ".pre-commit-config.yaml",
            "vibeguard-gate",
            "vibeguard-scan",
            "vibeguard-validate-config",
            "SKIP=",
            "rev:",
        ):
            assert needle in pre_commit_doc, (
                f"docs/pre-commit.md is missing required content {needle!r}"
            )

    def test_docker_doc_covers_required_sections(self, docker_doc: str):
        # Issue #48 enumerates the sections this guide must contain.
        for needle in (
            "docker build",
            "docker run",
            "ENTRYPOINT",
            "non-root",
            "GitHub Actions",
        ):
            assert needle in docker_doc, f"docs/docker.md is missing required content {needle!r}"
