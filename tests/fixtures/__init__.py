"""Test fixtures for VibeGuard.

This package contains:
- ``corpus/`` — paired true-positive / false-positive code samples per rule (#53).
- ``mutations/`` — realistic AI-introduced regressions (#59).
- ``golden/`` — frozen reporter outputs for snapshot tests (#54).
- ``canonical_scan_result`` — deterministic ScanResult used by golden tests.

Contents are intentionally vulnerable-looking; ``vibeguard.yaml`` adds
``tests/`` (and these subtrees) to its ignore list so the self-scan job
does not treat fixtures as real findings.
"""
