"""Rule metadata registry for VibeGuard."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata for a single VibeGuard rule.

    ``config_key`` is the top-level ``vibeguard.yaml`` section that controls
    this rule (e.g. ``risky_patterns`` for ``rule_id="risky_diff"``). When
    omitted, the registry registration step fills it in with ``rule_id`` —
    the common case where rule id and config section match. The CLI surfaces
    this in ``vibeguard rules explain`` so a user who knows the rule id can
    always find the corresponding YAML section.

    ``remediations`` maps finding IDs to a one-paragraph "how to fix"
    instruction. ``vibeguard explain <FINDING_ID>`` renders the remediation
    underneath the rule context. Finding IDs missing from this mapping fall
    back to the rule's generic ``description``.
    """

    rule_id: str
    title: str
    description: str
    finding_ids: Sequence[str] = field(default_factory=tuple)
    default_severity: str = "medium"
    confidence: str = "medium"
    tags: Sequence[str] = field(default_factory=tuple)
    docs_url: str | None = None
    applies_to: Sequence[str] = field(default_factory=tuple)
    examples: Sequence[dict[str, str]] = field(default_factory=tuple)
    config_key: str | None = None
    remediations: Mapping[str, str] = field(default_factory=dict)


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
    if metadata.config_key is None:
        # The rule id is the configuration section name in the common case
        # (one rule, one config block named after it). Rules that need a
        # different section pass ``config_key=...`` explicitly.
        object.__setattr__(metadata, "config_key", metadata.rule_id)
    # Freeze the remediation mapping so registry consumers cannot accidentally
    # mutate the dict that lives inside the (otherwise immutable) metadata.
    if not isinstance(metadata.remediations, MappingProxyType):
        # Normalise finding IDs to upper-case so lookups are case-insensitive.
        normalised = {str(k).upper(): str(v) for k, v in dict(metadata.remediations).items()}
        object.__setattr__(metadata, "remediations", MappingProxyType(normalised))
    RULE_REGISTRY[metadata.rule_id] = metadata
