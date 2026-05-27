"""Baseline file support for suppressing existing findings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from vibeguard.models import Finding


class BaselineLoadError(Exception):
    """Raised when a baseline file cannot be parsed or validated."""


class BaselineEntry(BaseModel):
    """A single entry in the baseline file."""

    rule_id: str
    path: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Baseline(BaseModel):
    """The complete baseline: a mapping of fingerprint -> entry metadata."""

    version: int = 1
    entries: dict[str, BaselineEntry] = Field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> Baseline:
        """Load a baseline from a JSON file.

        Raises ``BaselineLoadError`` if the file is malformed or fails schema
        validation. A missing file is not an error — an empty baseline is
        returned so callers can treat "no baseline" and "empty baseline" the
        same way.
        """
        if not path.exists():
            return cls()
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BaselineLoadError(f"Baseline file {path} is not valid JSON: {exc}") from exc
        try:
            return cls.model_validate(data)
        except Exception as exc:
            raise BaselineLoadError(
                f"Baseline file {path} does not match the expected schema: {exc}"
            ) from exc

    def save(self, path: Path) -> None:
        """Save the baseline to a JSON file."""
        path.write_text(
            json.dumps(self.model_dump(mode="json"), indent=2, default=str) + "\n",
            encoding="utf-8",
        )

    def contains(self, fingerprint: str) -> bool:
        """Check if a fingerprint is in the baseline."""
        return fingerprint in self.entries


def compute_fingerprint(finding: Finding) -> str:
    """Compute a stable fingerprint for a finding.

    Thin wrapper around ``Finding.fingerprint`` (the same algorithm) so the
    baseline file, SARIF ``partialFingerprints``, the diagnostics reporter,
    and ``model_dump`` JSON all share one identity definition. See
    ``Finding.fingerprint`` for the algorithm.
    """
    return finding.fingerprint


def create_baseline(findings: list[Finding]) -> Baseline:
    """Create a baseline from a list of findings."""
    entries: dict[str, BaselineEntry] = {}
    for finding in findings:
        fp = compute_fingerprint(finding)
        if fp not in entries:
            entries[fp] = BaselineEntry(
                rule_id=finding.id,
                path=finding.path.replace("\\", "/"),
            )
    return Baseline(entries=entries)


def filter_baselined(findings: list[Finding], baseline: Baseline) -> list[Finding]:
    """Remove findings that are present in the baseline."""
    return [f for f in findings if not baseline.contains(compute_fingerprint(f))]
