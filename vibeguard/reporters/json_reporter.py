"""JSON reporter."""

from __future__ import annotations

import json

from vibeguard.models import ScanResult


def render_json(result: ScanResult) -> str:
    """Return a JSON string of the scan result."""
    data = result.model_dump(mode="json")
    return json.dumps(data, indent=2, default=str)


def print_json(result: ScanResult) -> None:
    """Print JSON output to stdout."""
    print(render_json(result))
