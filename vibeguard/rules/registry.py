"""Rule metadata registry for VibeGuard."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata for a single VibeGuard rule."""

    rule_id: str
    title: str
    description: str
    finding_ids: list[str] = field(default_factory=list)
    default_severity: str = "medium"
    confidence: str = "medium"
    tags: list[str] = field(default_factory=list)
    docs_url: str | None = None
    applies_to: list[str] = field(default_factory=list)
    examples: list[dict[str, str]] = field(default_factory=list)


RULE_REGISTRY: dict[str, RuleMetadata] = {}


def register_rule(metadata: RuleMetadata) -> None:
    """Register a rule's metadata in the global registry."""
    RULE_REGISTRY[metadata.rule_id] = metadata
