"""Abstract base class for explanation adapters.

Adapter authors should subclass :class:`ExplainAdapter`, set the ``name`` class
attribute to the identifier users will pass via ``--adapter`` or the
``explain.adapter`` config key, and implement :meth:`explain`.

The interface is intentionally minimal: a single method that turns a
:class:`vibeguard.models.Finding` (plus an optional free-form context string)
into a Markdown / Rich-formatted explanation. Anything fancier — streaming,
function calling, RAG — belongs inside an adapter implementation, not in this
interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from vibeguard.models import Finding


class ExplainAdapter(ABC):
    """Abstract interface for finding-explanation providers.

    Implementations MUST:

    * Be safe to construct with no arguments (the registry instantiates them
      via ``cls()``). Adapters that need credentials or runtime configuration
      should read from environment variables in their constructor — never
      from a config file the adapter doesn't own.
    * Return a non-empty string from :meth:`explain` for every Finding. If the
      adapter cannot answer (network down, model missing, API key absent),
      return the static fallback rather than raising — VibeGuard's CLI does
      not retry, and an exception will surface as a generic CLI error.
    * Be deterministic *or* document non-determinism. The static adapter is
      deterministic by construction; LLM-backed adapters are inherently not.
    """

    #: Stable identifier for this adapter — used in ``vibeguard.yaml``
    #: (``explain.adapter: ollama``) and on the ``--adapter`` CLI flag.
    #: Subclasses MUST override this with a unique, lowercase, hyphen-or-
    #: underscore-separated string.
    name: str = ""

    @abstractmethod
    def explain(self, finding: Finding, context: str | None = None) -> str:
        """Return a detailed explanation and remediation for ``finding``.

        Parameters
        ----------
        finding:
            The :class:`vibeguard.models.Finding` to explain. Adapters can use
            any of its fields — ``id``, ``rule``, ``severity``, ``path``,
            ``line``, ``evidence``, ``description``, ``recommendation`` — to
            build the response.
        context:
            Optional free-form context the caller wants the adapter to take
            into account (e.g. the surrounding source code, the PR
            description). Adapters MAY ignore it; the static adapter does.

        Returns
        -------
        str
            A non-empty Markdown / Rich-formatted string. The CLI prints this
            verbatim, so authors should not include trailing whitespace
            indents that would clash with terminal width.
        """
