"""Clean API handler — monorepo benchmark fixture."""

from __future__ import annotations


def add_item(store: dict, key: str, value: int) -> dict:
    store[key] = value
    return store
