"""Tests for the rule scaffolder (#100)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from vibeguard.scaffold import (
    ScaffoldError,
    class_name,
    render_rule_module,
    render_test_module,
    scaffold_rule,
)


class TestValidation:
    def test_rejects_non_snake_case_rule_id(self, tmp_path: Path):
        with pytest.raises(ScaffoldError, match="rule id"):
            scaffold_rule("BadRuleID", "SEC-X", root=tmp_path)

    def test_rejects_bad_finding_prefix(self, tmp_path: Path):
        with pytest.raises(ScaffoldError, match="finding prefix"):
            scaffold_rule("good_rule", "lowercase", root=tmp_path)

    def test_class_name_camel_cases(self):
        assert class_name("exposed_supabase_key") == "ExposedSupabaseKeyRule"


class TestGeneration:
    def test_creates_module_and_test(self, tmp_path: Path):
        result = scaffold_rule("supabase_key", "SEC-SUPABASE", root=tmp_path)
        module = tmp_path / "vibeguard" / "rules" / "supabase_key.py"
        test = tmp_path / "tests" / "test_supabase_key.py"
        assert module.exists() and test.exists()
        assert set(result.created) == {module, test}
        assert result.checklist  # non-empty manual-steps list

    def test_generated_files_are_valid_python(self, tmp_path: Path):
        scaffold_rule("supabase_key", "SEC-SUPABASE", root=tmp_path)
        for rel in ("vibeguard/rules/supabase_key.py", "tests/test_supabase_key.py"):
            src = (tmp_path / rel).read_text(encoding="utf-8")
            ast.parse(src)  # raises SyntaxError if the template is malformed

    def test_draft_templates_are_valid_python(self):
        # Draft mode injects an extra comment line into scan(); make sure both
        # the rule and test modules still parse and the comment sits at the
        # function-body indent.
        module = render_rule_module("supabase_key", "SEC-SUPABASE", draft=True)
        ast.parse(module)
        ast.parse(render_test_module("supabase_key", "SEC-SUPABASE", draft=True))
        assert "\n        # NOTE: scaffolded draft" in module

    def test_module_contains_identifiers(self, tmp_path: Path):
        module = render_rule_module("supabase_key", "SEC-SUPABASE", draft=False)
        assert 'id = "supabase_key"' in module
        assert "class SupabaseKeyRule(Rule)" in module
        assert "SEC-SUPABASE-PLACEHOLDER" in module
        assert "register_rule(" in module

    def test_test_module_has_positive_and_negative(self, tmp_path: Path):
        test = render_test_module("supabase_key", "SEC-SUPABASE", draft=False)
        assert "test_positive_case_is_flagged" in test
        assert "test_clean_input_not_flagged" in test


class TestOverwriteAndModes:
    def test_refuses_overwrite_without_force(self, tmp_path: Path):
        scaffold_rule("supabase_key", "SEC-SUPABASE", root=tmp_path)
        with pytest.raises(ScaffoldError, match="Refusing to overwrite"):
            scaffold_rule("supabase_key", "SEC-SUPABASE", root=tmp_path)

    def test_force_overwrites(self, tmp_path: Path):
        scaffold_rule("supabase_key", "SEC-SUPABASE", root=tmp_path)
        result = scaffold_rule("supabase_key", "SEC-SUPABASE", root=tmp_path, force=True)
        assert len(result.created) == 2

    def test_dry_run_writes_nothing(self, tmp_path: Path):
        result = scaffold_rule("supabase_key", "SEC-SUPABASE", root=tmp_path, dry_run=True)
        assert result.created == []
        assert result.rendered  # content is still produced for display
        assert not (tmp_path / "vibeguard" / "rules" / "supabase_key.py").exists()

    def test_draft_marks_test_skipped(self, tmp_path: Path):
        test = render_test_module("supabase_key", "SEC-SUPABASE", draft=True)
        assert "pytest.mark.skip" in test
