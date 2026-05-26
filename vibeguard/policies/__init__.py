"""Built-in policy packs.

A policy pack is a small YAML file shipped next to this module. Its contents
are merged into the user's ``vibeguard.yaml`` as **defaults** — every key the
user has explicitly set wins over the pack. This makes packs opinionated
starting points without locking users in.

The public surface is intentionally tiny:

* :data:`KNOWN_PACK_NAMES` — list of built-in pack names.
* :func:`load_policy_pack` — read a pack's YAML into a plain ``dict``.
* :func:`merge_policy_pack` — combine pack defaults under a user data dict.
* :func:`available_packs` — discovered from disk (useful for tooling).

Adding a new built-in pack requires three updates: drop the YAML here, add
the name to :data:`KNOWN_PACK_NAMES`, and update the ``PolicyPackName``
Literal in ``vibeguard/config.py``. A test guards this invariant.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_POLICIES_DIR = Path(__file__).resolve().parent

# Hard-coded order is the order shown to users (rules CLI, error messages,
# docs); discovery on disk is the source of truth for what's installable.
KNOWN_PACK_NAMES: tuple[str, ...] = ("oss-library", "web-app", "strict-ci")


class UnknownPolicyPackError(ValueError):
    """Raised when a policy pack name is not recognised.

    The CLI surfaces this as a clear "valid options are…" message; config
    loading converts it into a ``ValidationError`` so it shows up alongside
    other config issues.
    """


def available_packs() -> list[str]:
    """Return policy pack names discovered from disk, sorted alphabetically."""
    return sorted(p.stem for p in _POLICIES_DIR.glob("*.yaml"))


def _pack_path(name: str) -> Path:
    return _POLICIES_DIR / f"{name}.yaml"


def load_policy_pack(name: str) -> dict[str, Any]:
    """Load the named pack and return its YAML contents as a dict.

    Raises :class:`UnknownPolicyPackError` if no pack file exists for the
    given name. Empty YAML files load as ``{}``.
    """
    path = _pack_path(name)
    if not path.exists():
        valid = ", ".join(available_packs()) or "(none installed)"
        raise UnknownPolicyPackError(f"Unknown policy pack {name!r}. Valid options: {valid}.")

    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise UnknownPolicyPackError(
            f"Policy pack {name!r} is malformed — expected a mapping at the top level."
        )
    return data


def merge_policy_pack(user_data: dict[str, Any], pack_data: dict[str, Any]) -> dict[str, Any]:
    """Return ``user_data`` filled in with pack defaults, user keys winning.

    Merge semantics are explicitly **shallow with one nested level**:

    * For sub-config sections (dict values) we merge keys — pack-only keys
      are added, user-only keys are kept, conflicts go to the user.
    * For list values (e.g. ``ignore.paths``, ``severity_overrides``,
      ``suppressions``) we never extend: the user's list replaces the
      pack's list entirely when present. This avoids surprising duplicate
      entries and matches how every other config tool handles array
      precedence.
    * For scalars at the root (e.g. ``fail_on``), the user value wins if
      it is set.

    The returned dict is a new shallow copy; the inputs are not mutated.
    """
    merged: dict[str, Any] = dict(pack_data)
    for key, user_value in user_data.items():
        pack_value = merged.get(key)
        if isinstance(user_value, dict) and isinstance(pack_value, dict):
            sub: dict[str, Any] = dict(pack_value)
            sub.update(user_value)
            merged[key] = sub
        else:
            merged[key] = user_value
    return merged
