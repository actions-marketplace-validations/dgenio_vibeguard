"""Pydantic models for VibeGuard findings and scan context."""

from __future__ import annotations

import hashlib
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field, field_validator


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
        # Limit evidence length to avoid inadvertently storing long secrets.
        # Documented in ``docs/output-schemas.md``: the fingerprint hashes the
        # stored (post-truncation) evidence, so two findings whose evidence
        # shares the first 200 chars and matches on id+path collide. The
        # ``id`` + ``path`` discriminators keep this narrow in practice.
        if isinstance(v, str) and len(v) > 200:
            return v[:200] + "…"
        return v

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """Deterministic identity for this finding across runs.

        Algorithm (``vibeguard/v1``):
        ``sha256(finding_id + ":" + normalized_path + ":" + sha256(evidence)[:16])``

        ``evidence`` here is the **stored** evidence — i.e. the 200-char
        snippet after ``_truncate_evidence`` runs. Two findings whose evidence
        shares the same first 200 chars and matches on ``id`` and ``path``
        will collide; in practice the discriminator strength of
        ``id`` + ``path`` keeps that boundary narrow. Line numbers are
        intentionally excluded so a finding's identity is stable when
        surrounding code shifts. See ``docs/output-schemas.md``.
        """
        evidence_part = ""
        if self.evidence:
            evidence_part = hashlib.sha256(self.evidence.encode("utf-8")).hexdigest()[:16]
        raw = f"{self.id}:{self.path.replace(chr(92), '/')}:{evidence_part}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class HealthScore(BaseModel):
    """Deterministic repository health score derived from scan findings.

    The score starts at ``100`` and is reduced by a fixed integer penalty per
    finding based on its severity. The formula and weights are intentionally
    simple and documented in ``docs/output-schemas.md`` so consumers can
    explain the number to their teams without inspecting code.
    """

    total: int = Field(description="Score from 0 (worst) to 100 (best)", ge=0, le=100)
    grade: Literal["A", "B", "C", "D", "F"] = Field(description="Letter grade derived from total")
    penalty: int = Field(description="Sum of severity weights subtracted from 100", ge=0)
    by_severity: dict[str, int] = Field(
        default_factory=dict, description="Finding count per severity level"
    )
    by_category: dict[str, int] = Field(
        default_factory=dict, description="Finding count per rule (category)"
    )
    weights: dict[str, int] = Field(
        default_factory=dict, description="Severity → penalty weight used for this score"
    )


class ScanResult(BaseModel):
    """Aggregated results from a full scan."""

    findings: list[Finding] = Field(default_factory=list)
    scanned_files: int = 0
    changed_files: int = 0
    scan_path: str = "."
    policy: Literal["relaxed", "balanced", "strict"] = "balanced"
    errors: list[str] = Field(default_factory=list)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def has_blocking(self, threshold: Severity) -> bool:
        return any(f.severity >= threshold for f in self.findings)

    def counts(self) -> dict[str, int]:
        return {s.value: len(self.by_severity(s)) for s in Severity}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def health_score(self) -> HealthScore:
        """Repo health score derived from the current findings list."""
        # Imported here to avoid a circular import via the reporters/scoring chain.
        from vibeguard.scoring import compute_health_score

        return compute_health_score(self.findings)


class GitMetadata(BaseModel):
    """Git context for a scan."""

    branch: str | None = None
    base_branch: str | None = None
    commit: str | None = None
    changed_files: list[str] = Field(default_factory=list)
    is_available: bool = False
    error: str | None = None
    #: How the changed-file/diff set was resolved in ``--diff`` mode.
    #: ``"merge-base"`` means a base branch was found and the diff is
    #: ``base...HEAD``; ``"head-only"`` means base detection failed and the
    #: diff degraded to ``git diff HEAD`` (uncommitted/staged changes only) —
    #: a narrower scope the scanner surfaces as a diagnostic (#182).
    diff_strategy: Literal["merge-base", "head-only"] | None = None
    #: True when the working copy is a shallow clone (``fetch-depth: 1``),
    #: which commonly breaks base-branch detection in CI (#182).
    is_shallow: bool = False
    #: Non-fatal git-context warnings (e.g. an explicit ``--base`` ref that
    #: could not be verified). Surfaced by the scanner alongside scan errors.
    warnings: list[str] = Field(default_factory=list)


class ScanContext(BaseModel):
    """Everything a rule needs to perform a scan."""

    model_config = {"arbitrary_types_allowed": True}

    root: Path
    config: Any  # VibeGuardConfig — forward ref to avoid circular import
    files: list[Path] = Field(default_factory=list)
    changed_files: list[Path] = Field(default_factory=list)
    git: GitMetadata = Field(default_factory=GitMetadata)
    diff_only: bool = False
    #: Raw unified-diff text for the change set, populated by the scanner in
    #: ``--diff`` mode (empty in full-scan mode). Rules that need before/after
    #: information a single file snapshot cannot provide — e.g. detecting a
    #: *lowered* coverage threshold or a *deleted* test file — read it here.
    #: Line-scoped findings do not need it: the scanner already restricts them
    #: to changed lines via the diff.
    diff_text: str = ""
