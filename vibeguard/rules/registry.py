"""Rule metadata registry for VibeGuard."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata for a single VibeGuard rule."""

    rule_id: str
    title: str
    description: str
    finding_ids: tuple[str, ...] = field(default_factory=tuple)
    default_severity: str = "medium"
    confidence: str = "medium"
    tags: tuple[str, ...] = field(default_factory=tuple)
    docs_url: str | None = None
    applies_to: tuple[str, ...] = field(default_factory=tuple)
    examples: tuple[dict[str, str], ...] = field(default_factory=tuple)


RULE_REGISTRY: dict[str, RuleMetadata] = {}


def register_rule(metadata: RuleMetadata) -> None:
    """Register a rule's metadata in the global registry.

    Raises ValueError on duplicate rule_id registration.
    Normalizes mutable sequence fields to tuples for immutability.
    """
    if metadata.rule_id in RULE_REGISTRY:
        raise ValueError(f"Duplicate rule registration: '{metadata.rule_id}' is already registered")
    # Normalize list fields to tuples (callers may pass lists)
    if isinstance(metadata.finding_ids, list):
        object.__setattr__(metadata, "finding_ids", tuple(metadata.finding_ids))
    if isinstance(metadata.tags, list):
        object.__setattr__(metadata, "tags", tuple(metadata.tags))
    if isinstance(metadata.applies_to, list):
        object.__setattr__(metadata, "applies_to", tuple(metadata.applies_to))
    if isinstance(metadata.examples, list):
        object.__setattr__(metadata, "examples", tuple(metadata.examples))
    RULE_REGISTRY[metadata.rule_id] = metadata
