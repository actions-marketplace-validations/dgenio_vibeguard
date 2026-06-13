"""Completeness tests for the shared severity-presentation table (#194).

These guard the single source of truth in ``vibeguard.reporters._format``: if a
new ``Severity`` member is added without a presentation entry — or a field is
left blank — these fail fast instead of letting one reporter silently ship a
missing icon/emoji/level.
"""

from __future__ import annotations

from dataclasses import fields

import pytest

from vibeguard.models import Severity
from vibeguard.reporters._format import (
    SEVERITY_PRESENTATION,
    SeverityPresentation,
    presentation_for,
)


def test_every_severity_has_a_presentation_entry():
    assert set(SEVERITY_PRESENTATION) == set(Severity)


@pytest.mark.parametrize("severity", list(Severity))
def test_presentation_fields_are_populated(severity: Severity):
    pres = SEVERITY_PRESENTATION[severity]
    # String fields must be non-empty; diagnostic_code is an int (0 is valid).
    assert pres.color.strip()
    assert pres.icon.strip()
    assert pres.emoji.strip()
    assert pres.sarif_level in {"error", "warning", "note"}
    assert isinstance(pres.diagnostic_code, int)
    assert 0 <= pres.diagnostic_code <= 3
    assert pres.annotation_command in {"error", "warning", "notice"}


def test_presentation_for_matches_table():
    for severity in Severity:
        assert presentation_for(severity) is SEVERITY_PRESENTATION[severity]


def test_presentation_is_frozen():
    # Frozen dataclass — accidental mutation by a reporter must raise.
    pres = SEVERITY_PRESENTATION[Severity.HIGH]
    with pytest.raises(AttributeError):
        pres.color = "blue"  # type: ignore[misc]


def test_no_field_left_unset():
    # Every declared field is part of the contract every reporter relies on.
    declared = {f.name for f in fields(SeverityPresentation)}
    assert declared == {
        "color",
        "icon",
        "emoji",
        "sarif_level",
        "diagnostic_code",
        "annotation_command",
    }
