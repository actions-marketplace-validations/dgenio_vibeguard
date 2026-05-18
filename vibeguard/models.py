"""Pydantic models for VibeGuard findings and scan context."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: Severity) -> bool:  # type: ignore[override]
        return _SEVERITY_ORDER[self] < _SEVERITY_ORDER[other]

    def __le__(self, other: Severity) -> bool:  # type: ignore[override]
        return _SEVERITY_ORDER[self] <= _SEVERITY_ORDER[other]

    def __gt__(self, other: Severity) -> bool:  # type: ignore[override]
        return _SEVERITY_ORDER[self] > _SEVERITY_ORDER[other]

    def __ge__(self, other: Severity) -> bool:  # type: ignore[override]
        return _SEVERITY_ORDER[self] >= _SEVERITY_ORDER[other]


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Finding(BaseModel):
    """A single finding produced by a VibeGuard rule."""

    id: str = Field(description="Unique finding identifier, e.g. SEC001")
    rule: str = Field(description="Rule name that produced this finding")
    title: str = Field(description="Short human-readable title")
    description: str = Field(description="Detailed description of the issue")
    severity: Severity
    path: str = Field(description="Relative file path")
    line: int | None = Field(default=None, description="Line number if available")
    evidence: str | None = Field(default=None, description="Snippet of offending content")
    recommendation: str = Field(description="How to fix or address this finding")
    tags: list[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.MEDIUM

    @field_validator("evidence", mode="before")
    @classmethod
    def _truncate_evidence(cls, v: Any) -> Any:
        # Limit evidence length to avoid inadvertently storing long secrets
        if isinstance(v, str) and len(v) > 200:
            return v[:200] + "…"
        return v


class ScanResult(BaseModel):
    """Aggregated results from a full scan."""

    findings: list[Finding] = Field(default_factory=list)
    scanned_files: int = 0
    changed_files: int = 0
    scan_path: str = "."
    policy: str = "balanced"
    errors: list[str] = Field(default_factory=list)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def has_blocking(self, threshold: Severity) -> bool:
        return any(f.severity >= threshold for f in self.findings)

    def counts(self) -> dict[str, int]:
        return {s.value: len(self.by_severity(s)) for s in Severity}


class GitMetadata(BaseModel):
    """Git context for a scan."""

    branch: str | None = None
    base_branch: str | None = None
    commit: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    is_available: bool = False
    error: str | None = None


class ScanContext(BaseModel):
    """Everything a rule needs to perform a scan."""

    model_config = {"arbitrary_types_allowed": True}

    root: Path
    config: Any  # VibeGuardConfig — forward ref to avoid circular import
    files: list[Path] = Field(default_factory=list)
    changed_files: list[Path] = Field(default_factory=list)
    git: GitMetadata = Field(default_factory=GitMetadata)
    diff_only: bool = False
