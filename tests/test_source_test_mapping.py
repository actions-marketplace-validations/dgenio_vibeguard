"""Tests for source-test mapping in monorepos (#69)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from vibeguard.config import SourceTestMapping, VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.tests import MissingTestsRule


def _make_ctx(
    tmp_path: Path,
    files: list[str],
    cfg: VibeGuardConfig | None = None,
) -> ScanContext:
    for name in files:
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# content\n")

    changed = [tmp_path / n for n in files]
    return ScanContext(
        root=tmp_path,
        config=cfg or VibeGuardConfig(),
        files=changed,
        changed_files=changed,
        diff_only=True,
    )


class TestSourceTestMappingValidation:
    def test_default_is_empty_list(self):
        cfg = VibeGuardConfig()
        assert cfg.tests.mapping == []

    def test_valid_mapping_accepted(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text(
            textwrap.dedent("""
                tests:
                  enabled: true
                  mapping:
                    - source: "packages/api/src/**"
                      tests:
                        - "packages/api/tests/**"
            """)
        )
        cfg = VibeGuardConfig.load(cfg_file)
        assert len(cfg.tests.mapping) == 1
        assert cfg.tests.mapping[0].source == "packages/api/src/**"
        assert cfg.tests.mapping[0].tests == ["packages/api/tests/**"]

    def test_empty_tests_list_rejected(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text(
            textwrap.dedent("""
                tests:
                  mapping:
                    - source: "src/**"
                      tests: []
            """)
        )
        with pytest.raises(ValidationError):
            VibeGuardConfig.load(cfg_file)

    def test_empty_source_pattern_rejected(self, tmp_path: Path):
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text(
            textwrap.dedent("""
                tests:
                  mapping:
                    - source: "   "
                      tests:
                        - "tests/**"
            """)
        )
        with pytest.raises(ValidationError):
            VibeGuardConfig.load(cfg_file)

    def test_empty_string_test_pattern_rejected(self):
        with pytest.raises(ValidationError):
            SourceTestMapping(source="src/**", tests=[""])

    def test_unknown_mapping_key_rejected(self, tmp_path: Path):
        # Extra fields under tests.mapping items must fail loudly (extra=forbid).
        cfg_file = tmp_path / "vibeguard.yaml"
        cfg_file.write_text(
            textwrap.dedent("""
                tests:
                  mapping:
                    - source: "src/**"
                      tests: ["tests/**"]
                      whoops: true
            """)
        )
        with pytest.raises(ValidationError) as exc_info:
            VibeGuardConfig.load(cfg_file)
        assert "whoops" in str(exc_info.value)


class TestDefaultBehaviorPreserved:
    """With no mapping, behavior must be byte-identical to today."""

    rule = MissingTestsRule()

    def test_source_only_still_flags(self, tmp_path: Path):
        ctx = _make_ctx(tmp_path, ["src/auth.py"])
        findings = self.rule.scan(ctx)
        assert any(f.id == "TEST-MISSING" for f in findings)

    def test_source_with_test_still_passes(self, tmp_path: Path):
        ctx = _make_ctx(tmp_path, ["src/auth.py", "tests/test_auth.py"])
        findings = self.rule.scan(ctx)
        assert not any(f.id == "TEST-MISSING" for f in findings)


class TestMonorepoMapping:
    rule = MissingTestsRule()

    def _ctx_with_mapping(
        self,
        tmp_path: Path,
        files: list[str],
        mappings: list[SourceTestMapping],
        policy: str = "balanced",
    ) -> ScanContext:
        cfg = VibeGuardConfig(policy=policy)
        cfg.tests.mapping = mappings
        return _make_ctx(tmp_path, files, cfg=cfg)

    def test_monorepo_mapped_test_satisfies(self, tmp_path: Path):
        # api package: src + sibling tests directory inside the same package
        ctx = self._ctx_with_mapping(
            tmp_path,
            files=[
                "packages/api/src/handler.py",
                "packages/api/tests/test_handler.py",
            ],
            mappings=[
                SourceTestMapping(
                    source="packages/api/src/**",
                    tests=["packages/api/tests/**"],
                ),
            ],
        )
        findings = self.rule.scan(ctx)
        # Sibling-package test layout — would have been an FP under the
        # default heuristic if tests/ wasn't in the change. With the mapping,
        # the matching test in the same package satisfies the requirement.
        assert not any(f.id == "TEST-MISSING" for f in findings)

    def test_monorepo_missing_mapped_test_flags(self, tmp_path: Path):
        # Source change in api package, but tests changed in a DIFFERENT
        # package — mapping must not be fooled.
        ctx = self._ctx_with_mapping(
            tmp_path,
            files=[
                "packages/api/src/handler.py",
                "packages/web/tests/test_other.py",
            ],
            mappings=[
                SourceTestMapping(
                    source="packages/api/src/**",
                    tests=["packages/api/tests/**"],
                ),
                SourceTestMapping(
                    source="packages/web/src/**",
                    tests=["packages/web/tests/**"],
                ),
            ],
        )
        findings = self.rule.scan(ctx)
        offenders = [f for f in findings if f.id == "TEST-MISSING"]
        assert offenders
        # The finding description should name the api file specifically.
        assert "handler.py" in offenders[0].description

    def test_file_outside_any_mapping_falls_back_to_heuristic(self, tmp_path: Path):
        # src/cli.py matches no mapping — heuristic decides. Tests dir is
        # untouched, so it should still flag.
        ctx = self._ctx_with_mapping(
            tmp_path,
            files=["src/cli.py"],
            mappings=[
                SourceTestMapping(
                    source="packages/api/src/**",
                    tests=["packages/api/tests/**"],
                ),
            ],
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "TEST-MISSING" for f in findings)

    def test_file_outside_mapping_covered_by_legacy_tests(self, tmp_path: Path):
        # Same as above but with a heuristic-recognised test in the change.
        ctx = self._ctx_with_mapping(
            tmp_path,
            files=["src/cli.py", "tests/test_cli.py"],
            mappings=[
                SourceTestMapping(
                    source="packages/api/src/**",
                    tests=["packages/api/tests/**"],
                ),
            ],
        )
        findings = self.rule.scan(ctx)
        assert not any(f.id == "TEST-MISSING" for f in findings)

    def test_multiple_mappings_each_evaluated_independently(self, tmp_path: Path):
        # Both packages change; only one has its tests touched. The other
        # must still flag.
        ctx = self._ctx_with_mapping(
            tmp_path,
            files=[
                "packages/api/src/a.py",
                "packages/api/tests/test_a.py",
                "packages/web/src/b.py",
            ],
            mappings=[
                SourceTestMapping(
                    source="packages/api/src/**",
                    tests=["packages/api/tests/**"],
                ),
                SourceTestMapping(
                    source="packages/web/src/**",
                    tests=["packages/web/tests/**"],
                ),
            ],
        )
        findings = self.rule.scan(ctx)
        offenders = [f for f in findings if f.id == "TEST-MISSING"]
        assert offenders
        assert "b.py" in offenders[0].description
        assert "a.py" not in offenders[0].description

    def test_mapping_supports_multiple_test_globs(self, tmp_path: Path):
        ctx = self._ctx_with_mapping(
            tmp_path,
            files=[
                "packages/api/src/h.py",
                "packages/api/spec/api_spec.py",  # matches second test glob
            ],
            mappings=[
                SourceTestMapping(
                    source="packages/api/src/**",
                    tests=[
                        "packages/api/tests/**",
                        "packages/api/spec/**",
                    ],
                ),
            ],
        )
        findings = self.rule.scan(ctx)
        assert not any(f.id == "TEST-MISSING" for f in findings)

    def test_strict_policy_under_mapping(self, tmp_path: Path):
        ctx = self._ctx_with_mapping(
            tmp_path,
            files=["packages/api/src/h.py"],
            mappings=[
                SourceTestMapping(
                    source="packages/api/src/**",
                    tests=["packages/api/tests/**"],
                ),
            ],
            policy="strict",
        )
        findings = self.rule.scan(ctx)
        offenders = [f for f in findings if f.id == "TEST-MISSING"]
        assert offenders
        # Strict policy promotes from low to medium — same as legacy path.
        assert offenders[0].severity == Severity.MEDIUM
