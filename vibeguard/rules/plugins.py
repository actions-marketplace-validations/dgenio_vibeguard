"""Entry-point discovery for third-party VibeGuard rules.

Plugins declare themselves in their own ``pyproject.toml``::

    [project.entry-points."vibeguard.rules"]
    my-rule = "my_package.rules:MyRule"

At scanner startup we enumerate the ``vibeguard.rules`` entry-point group
and try to load each declared class. Discovery is best-effort:

* Import errors, missing attributes and incompatible types are caught,
  logged to stderr, and the offending entry point is skipped — a broken
  plugin must never crash the host scanner.
* Plugins listed in ``plugins.disabled`` in ``vibeguard.yaml`` are skipped
  silently after discovery.

See ``docs/plugin-api.md`` for the public-API contract and versioning
policy.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata as importlib_metadata

from vibeguard.rules.base import Rule

ENTRY_POINT_GROUP = "vibeguard.rules"


@dataclass(frozen=True)
class LoadedPlugin:
    """A successfully loaded plugin rule.

    The dataclass is the single record passed back to the scanner: it owns
    the entry-point name, the source distribution name (for ``--list-plugins``
    UX), and an *instance* of the rule class. We instantiate eagerly so any
    constructor-time errors surface during discovery, not in the middle of a
    scan.
    """

    name: str
    distribution: str | None
    rule: Rule


@dataclass(frozen=True)
class PluginLoadFailure:
    """Information about a plugin that failed to load.

    Returned alongside successfully loaded plugins so that ``rules list
    --list-plugins`` can surface broken plugins to the user even when the
    scan itself continues. We do not raise — keeping discovery best-effort
    is a hard requirement, see ``docs/plugin-api.md``.
    """

    name: str
    distribution: str | None
    reason: str


def _entry_points() -> Iterable[importlib_metadata.EntryPoint]:
    """Yield entry points for the ``vibeguard.rules`` group.

    ``importlib.metadata.entry_points`` is the public API as of Python 3.10
    (the form supported by our minimum). We call it once per discovery so
    that test environments which install plugins mid-process pick them up.
    """
    eps = importlib_metadata.entry_points()
    # Python 3.10+ ``EntryPoints`` exposes ``.select``; older fallback would
    # use ``eps.get(group, [])`` but we require 3.10 in pyproject.toml.
    try:
        return eps.select(group=ENTRY_POINT_GROUP)
    except AttributeError:  # pragma: no cover — defensive only
        return eps.get(ENTRY_POINT_GROUP, [])  # type: ignore[attr-defined]


def _warn(message: str) -> None:
    """Emit a discovery warning to stderr.

    We intentionally do not use :mod:`logging` because VibeGuard's CLI does
    not configure handlers and we want the message to surface in CI logs
    without extra setup. The prefix mirrors other CLI warnings so users can
    grep for ``[vibeguard]``.
    """
    print(f"[vibeguard] plugin warning: {message}", file=sys.stderr)


def _instantiate(entry: importlib_metadata.EntryPoint) -> Rule:
    """Resolve an entry point and return an instantiated rule.

    Raises whichever error the entry point produces; the caller wraps the
    call in a try/except to guarantee discovery never raises.
    """
    obj = entry.load()
    if isinstance(obj, type):
        if not issubclass(obj, Rule):
            raise TypeError(
                f"entry point '{entry.name}' resolved to {obj!r}, which is not a subclass "
                "of vibeguard.api.BaseRule"
            )
        instance = obj()
    else:
        # Allow factories that return an instance directly. This matches
        # pytest's plugin pattern and keeps the door open for future
        # PLUGIN_API_VERSION-aware factories without breaking the contract.
        instance = obj() if callable(obj) else obj
        if not isinstance(instance, Rule):
            raise TypeError(
                f"entry point '{entry.name}' did not produce a Rule instance "
                f"(got {type(instance).__name__})"
            )
    return instance


def _distribution_name(entry: importlib_metadata.EntryPoint) -> str | None:
    """Best-effort source-distribution name for ``rules list --list-plugins``.

    ``EntryPoint.dist`` is populated by ``importlib.metadata`` when the
    entry point was discovered from an installed distribution; in test
    fixtures that synthesise entry points by hand it can be ``None``.
    """
    dist = getattr(entry, "dist", None)
    if dist is None:
        return None
    return getattr(dist, "name", None) or getattr(dist, "metadata", {}).get("Name")


def discover_plugin_rules(
    *,
    disabled: Iterable[str] = (),
) -> tuple[list[LoadedPlugin], list[PluginLoadFailure]]:
    """Discover and instantiate every registered plugin rule.

    Parameters
    ----------
    disabled:
        Names of entry points to skip (the left-hand side of the entry
        point declaration, e.g. ``my-rule`` in
        ``my-rule = "my_pkg.rules:MyRule"``).

    Returns
    -------
    tuple[list[LoadedPlugin], list[PluginLoadFailure]]
        Successfully loaded plugins and a parallel list of failures. The
        scanner consumes ``loaded`` and ``rules list --list-plugins``
        renders both.
    """
    disabled_set = {name for name in disabled if name}
    loaded: list[LoadedPlugin] = []
    failures: list[PluginLoadFailure] = []

    for entry in _entry_points():
        if entry.name in disabled_set:
            continue
        dist_name = _distribution_name(entry)
        try:
            rule = _instantiate(entry)
        except Exception as exc:  # noqa: BLE001 — discovery must never raise
            reason = f"{type(exc).__name__}: {exc}"
            failures.append(
                PluginLoadFailure(name=entry.name, distribution=dist_name, reason=reason)
            )
            _warn(f"failed to load '{entry.name}' ({dist_name or 'unknown dist'}): {reason}")
            continue
        loaded.append(LoadedPlugin(name=entry.name, distribution=dist_name, rule=rule))

    return loaded, failures
