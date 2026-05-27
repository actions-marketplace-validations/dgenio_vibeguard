"""Adapter registry and entry-point discovery for explanation providers.

This module mirrors the rule-plugin registry (:mod:`vibeguard.rules.plugins`)
in shape and conventions: a flat name → class mapping, a no-raise discovery
function that surfaces failures as structured records, and a single
:func:`get_explain_adapter` factory the CLI consumes.

Built-in adapters
-----------------

The registry is pre-populated with the always-available
:class:`~vibeguard.explain.static.StaticExplainAdapter` under the name
``"static"``. Importing :mod:`vibeguard.explain` is enough to make it
available; users do not need to install or configure anything.

Third-party adapters
--------------------

Plugins register themselves either:

* declaratively, via an entry point in the ``vibeguard.explain_adapters``
  group, or
* imperatively, by calling :func:`register_explain_adapter` at import time.

Entry-point discovery is **lazy** and **opt-in** — it runs only when
:func:`discover_adapter_plugins` (or :func:`get_explain_adapter`) is invoked.
That keeps ``vibeguard scan`` fast: rule plugins matter for every scan, but
explain adapters only matter when the user runs ``vibeguard explain``.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata as importlib_metadata

from vibeguard.explain.base import ExplainAdapter
from vibeguard.explain.static import StaticExplainAdapter

ENTRY_POINT_GROUP = "vibeguard.explain_adapters"

_REGISTRY: dict[str, type[ExplainAdapter]] = {}

# The static adapter is the always-on baseline.
_REGISTRY["static"] = StaticExplainAdapter


@dataclass(frozen=True)
class LoadedAdapter:
    """A successfully discovered third-party adapter."""

    name: str
    distribution: str | None
    cls: type[ExplainAdapter]


@dataclass(frozen=True)
class AdapterLoadFailure:
    """A third-party adapter that failed to load."""

    name: str
    distribution: str | None
    reason: str


def register_explain_adapter(name: str, cls: type[ExplainAdapter]) -> None:
    """Register an adapter class under ``name``.

    Raises
    ------
    TypeError
        When ``cls`` is not a subclass of :class:`ExplainAdapter`.
    ValueError
        When ``name`` is empty, or already registered to a different class.
    """
    if not name:
        raise ValueError("Adapter name must be non-empty")
    if not isinstance(cls, type) or not issubclass(cls, ExplainAdapter):
        raise TypeError(f"Adapter for {name!r} must be a subclass of ExplainAdapter, got {cls!r}")
    existing = _REGISTRY.get(name)
    if existing is not None and existing is not cls:
        raise ValueError(
            f"Adapter {name!r} is already registered to a different class "
            f"({existing.__module__}.{existing.__name__})"
        )
    _REGISTRY[name] = cls


def registered_adapter_names() -> tuple[str, ...]:
    """Return the sorted tuple of currently registered adapter names."""
    return tuple(sorted(_REGISTRY))


def get_explain_adapter(name: str = "static") -> ExplainAdapter:
    """Construct and return an adapter instance by name.

    Discovery from the ``vibeguard.explain_adapters`` entry-point group runs
    lazily here when ``name`` is not already registered. Built-in names
    (currently just ``static``) resolve without touching entry points.

    Raises
    ------
    ValueError
        When no adapter with the given name is registered, even after
        entry-point discovery. The error message lists the available names.
    """
    if name in _REGISTRY:
        return _REGISTRY[name]()

    # Cold cache — try entry-point discovery before giving up. We pass
    # ``register=True`` so any successful loads land in ``_REGISTRY`` and the
    # next lookup is a cache hit.
    discover_adapter_plugins(register=True)
    if name in _REGISTRY:
        return _REGISTRY[name]()

    available = ", ".join(sorted(_REGISTRY))
    raise ValueError(
        f"Unknown explain adapter {name!r}. Registered adapters: {available}. "
        "Install a plugin that registers this adapter, or use a built-in name."
    )


def _entry_points() -> Iterable[importlib_metadata.EntryPoint]:
    eps = importlib_metadata.entry_points()
    try:
        return eps.select(group=ENTRY_POINT_GROUP)
    except AttributeError:  # pragma: no cover — defensive only
        return eps.get(ENTRY_POINT_GROUP, [])  # type: ignore[attr-defined]


def _distribution_name(entry: importlib_metadata.EntryPoint) -> str | None:
    dist = getattr(entry, "dist", None)
    if dist is None:
        return None
    return getattr(dist, "name", None) or getattr(dist, "metadata", {}).get("Name")


def _warn(message: str) -> None:
    """Discovery warnings mirror the rule-plugin format for grep-ability."""
    print(f"[vibeguard] explain-adapter warning: {message}", file=sys.stderr)


def discover_adapter_plugins(
    *,
    register: bool = False,
) -> tuple[list[LoadedAdapter], list[AdapterLoadFailure]]:
    """Discover adapters declared in the ``vibeguard.explain_adapters`` group.

    Parameters
    ----------
    register:
        When ``True``, successfully loaded adapter classes are added to the
        in-process registry so subsequent ``get_explain_adapter`` calls
        resolve them. When ``False`` (the default for callers like
        ``vibeguard rules list``), discovery is purely informational.

    Returns
    -------
    tuple[list[LoadedAdapter], list[AdapterLoadFailure]]
        Successfully loaded adapters and a parallel list of failures.
        Discovery is best-effort: a broken plugin never raises out of this
        function, never crashes the CLI, and never aborts scanning.
    """
    loaded: list[LoadedAdapter] = []
    failures: list[AdapterLoadFailure] = []

    for entry in _entry_points():
        dist = _distribution_name(entry)
        try:
            obj = entry.load()
        except Exception as exc:  # noqa: BLE001
            reason = f"{type(exc).__name__}: {exc}"
            failures.append(AdapterLoadFailure(name=entry.name, distribution=dist, reason=reason))
            _warn(f"failed to import '{entry.name}' ({dist or 'unknown dist'}): {reason}")
            continue
        if not isinstance(obj, type) or not issubclass(obj, ExplainAdapter):
            reason = f"{obj!r} is not a subclass of vibeguard.explain.base.ExplainAdapter"
            failures.append(AdapterLoadFailure(name=entry.name, distribution=dist, reason=reason))
            _warn(f"rejected '{entry.name}': {reason}")
            continue
        if register:
            try:
                register_explain_adapter(entry.name, obj)
            except ValueError as exc:
                # Already registered (same class) is harmless; conflicts are
                # surfaced as failures so the user can pick one.
                if "already registered" in str(exc):
                    failures.append(
                        AdapterLoadFailure(name=entry.name, distribution=dist, reason=str(exc))
                    )
                    continue
                raise
        loaded.append(LoadedAdapter(name=entry.name, distribution=dist, cls=obj))

    return loaded, failures
