"""Tests for the findings → lessons interop example (#103, #120).

Guards the runnable example in ``examples/interop/`` and the LessonCard shape it
produces against the vendored weaver-spec ``LessonCard`` schema.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import jsonschema

REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE = REPO_ROOT / "examples" / "interop" / "findings_to_lessons.py"
_LESSON_SCHEMA_PATH = REPO_ROOT / "docs" / "weaver" / "lesson_card.schema.json"
_FIXED_TS = "2026-06-04T00:00:00+00:00"


def _load_example():
    spec = importlib.util.spec_from_file_location("interop_example", _EXAMPLE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_example_module_imports():
    mod = _load_example()
    assert hasattr(mod, "build_lesson_cards")
    assert hasattr(mod, "scan_scenarios")


def test_distinguishes_repeated_from_one_off():
    mod = _load_example()
    results = mod.scan_scenarios()
    lessons = mod.build_lesson_cards(results, created_at=_FIXED_TS)
    lesson_rules = {lesson["applicability"][0] for lesson in lessons}

    # ai_footprints and auth recur across scenarios 01 + 02 -> repeated.
    assert "ai_footprints" in lesson_rules
    assert "auth" in lesson_rules
    # A category that appears in only one scenario must NOT mint a lesson.
    assert "slopsquat" not in lesson_rules


def test_lessons_are_in_review_not_active():
    mod = _load_example()
    results = mod.scan_scenarios()
    lessons = mod.build_lesson_cards(results, created_at=_FIXED_TS)
    assert lessons, "expected at least one repeated-pattern lesson"
    for lesson in lessons:
        # Lessons are proposed, never auto-activated — a human reviews first.
        assert lesson["lifecycle_state"] == "in_review"


def test_lessons_name_specific_findings():
    """A useful lesson is specific: it cites the finding IDs it generalises."""
    mod = _load_example()
    results = mod.scan_scenarios()
    lessons = mod.build_lesson_cards(results, created_at=_FIXED_TS)
    ai = next(lesson for lesson in lessons if lesson["applicability"][0] == "ai_footprints")
    assert "AI-TRUSTALLCERTS" in ai["applicability"]
    assert "AI-TEMPBYPASS" in ai["applicability"]
    assert ai["source_refs"], "lesson must carry provenance source_refs"


def test_source_refs_are_deduplicated():
    """source_refs is fingerprint-keyed; repeated detections must not duplicate
    a ref. Guards the list->set aggregation fix."""
    mod = _load_example()
    results = mod.scan_scenarios()
    lessons = mod.build_lesson_cards(results, created_at=_FIXED_TS)
    for lesson in lessons:
        refs = lesson["source_refs"]
        assert len(refs) == len(set(refs)), f"duplicate source_refs in {lesson['lesson_id']}"


def test_lessons_validate_against_vendored_lesson_schema():
    mod = _load_example()
    results = mod.scan_scenarios()
    lessons = mod.build_lesson_cards(results, created_at=_FIXED_TS)
    schema = json.loads(_LESSON_SCHEMA_PATH.read_text())
    for lesson in lessons:
        jsonschema.validate(instance=lesson, schema=schema)


def test_example_runs_as_script():
    mod = _load_example()
    assert mod.main() == 0
