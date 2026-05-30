"""VibeGuard — Guardrails for vibe-coded software."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

# Single source of truth: the version declared in pyproject.toml and recorded
# in the installed distribution metadata. Never hardcode a literal here — a
# hardcoded value silently drifts from pyproject.toml (see
# docs/release-checklist.md and the guard in tests/test_docs_references.py).
try:
    __version__ = _version("vibeguard-gate")
except PackageNotFoundError:  # pragma: no cover — running from a source tree without install
    __version__ = "0.0.0+unknown"

# Public plugin API version. Increment the major component on any
# backwards-incompatible change to vibeguard.api or vibeguard.rules.base.
# See docs/plugin-api.md for the versioning policy.
PLUGIN_API_VERSION = "1.0"
