"""Pre-publish safety simulation for npm and Python packages.

This package implements deterministic, pure-Python simulation of what
`npm pack` and `python -m build` would include when publishing, without
shelling out to the package managers themselves. The simulated file set
is then fed through the standard VibeGuard rule engine so the same
secrets, sourcemaps, and packaging rules apply to the publish view.
"""

from vibeguard.publish.manifest import PublishedFile, PublishManifest
from vibeguard.publish.runner import detect_ecosystem, run_publish_check

__all__ = [
    "PublishManifest",
    "PublishedFile",
    "detect_ecosystem",
    "run_publish_check",
]
