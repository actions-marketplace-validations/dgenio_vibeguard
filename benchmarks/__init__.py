"""Deterministic benchmark suite for VibeGuard scanner speed (#52).

This package is **not** shipped — it's a developer tool. See ``run.py`` for
the entry point and ``README.md`` in the same directory for usage notes.

The benchmark is informational only: it is intentionally **not** wired into
``make ci``, because CI runners have noisy performance characteristics and a
hard regression threshold would produce false alarms. Use it to compare
before/after on a single machine when working on rule performance.
"""
