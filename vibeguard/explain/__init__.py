"""Pluggable finding-explanation adapters for VibeGuard.

VibeGuard's :command:`vibeguard explain` command surfaces remediation guidance
for a finding ID. The default :class:`StaticExplainAdapter` answers from the
in-repo rule metadata registry and a small set of curated hand-written
explanations — no network, no API key, no third-party dependency required.

Third-party packages can ship richer adapters (for example, a local LLM via
Ollama, or an Anthropic / OpenAI-backed adapter) by:

1. Declaring an entry point in the ``vibeguard.explain_adapters`` group, e.g.
   ``ollama = "my_pkg.adapter:OllamaAdapter"``; or
2. Calling :func:`register_explain_adapter` at import time.

The public surface re-exported here is the **only** stable contract for
adapter authors. See ``docs/explain-adapters.md`` for the full how-to and
``docs/plugin-api.md`` for the wider plugin policy.
"""

from __future__ import annotations

from vibeguard.explain.base import ExplainAdapter
from vibeguard.explain.registry import (
    discover_adapter_plugins,
    get_explain_adapter,
    register_explain_adapter,
    registered_adapter_names,
)
from vibeguard.explain.static import StaticExplainAdapter

__all__ = [
    "ExplainAdapter",
    "StaticExplainAdapter",
    "discover_adapter_plugins",
    "get_explain_adapter",
    "register_explain_adapter",
    "registered_adapter_names",
]
