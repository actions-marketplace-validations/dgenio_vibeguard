"""Base rule interface for VibeGuard."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from vibeguard.models import Finding, ScanContext


class Rule(ABC):
    """Abstract base class for all VibeGuard rules."""

    id: str
    name: str
    description: str

    @abstractmethod
    def scan(self, context: ScanContext) -> list[Finding]:
        """Run the rule against the given scan context."""
        ...

    def _rel(self, context: ScanContext, path: Path) -> str:
        """Return a path relative to the scan root."""
        try:
            return str(path.relative_to(context.root))
        except ValueError:
            return str(path)
