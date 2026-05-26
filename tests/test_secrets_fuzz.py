"""Hypothesis-driven fuzz tests for the secrets scanner (#55).

Goal: ``SecretsRule.scan`` must NEVER raise on unusual file contents.
Regex catastrophic-backtracking, decode failures on non-UTF-8 bytes,
zero-length files, files containing only null bytes or newlines, and
absurdly long lines must all be tolerated — the rule's job is to scan,
not crash the scanner.
"""

from __future__ import annotations

import os
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from vibeguard.config import VibeGuardConfig
from vibeguard.models import Finding, ScanContext
from vibeguard.rules.secrets import SecretsRule

# Override with HYPOTHESIS_MAX_EXAMPLES for deeper local exploration.
_DEFAULT_SETTINGS = settings(
    max_examples=int(os.environ.get("HYPOTHESIS_MAX_EXAMPLES", "75")),
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture],
)


def _scan_with_content(tmp_path: Path, name: str, content: bytes) -> list[Finding]:
    file_path = tmp_path / name
    file_path.write_bytes(content)
    ctx = ScanContext(root=tmp_path, config=VibeGuardConfig(), files=[file_path])
    return SecretsRule().scan(ctx)


@given(
    content=st.binary(max_size=4096),
    suffix=st.sampled_from([".py", ".js", ".ts", ".env", ".yaml", ".txt", ".json", ".md"]),
)
@_DEFAULT_SETTINGS
def test_secrets_scan_never_raises_on_arbitrary_bytes(
    content: bytes, suffix: str, tmp_path: Path
) -> None:
    findings = _scan_with_content(tmp_path, f"fuzz{suffix}", content)
    assert isinstance(findings, list)
    for f in findings:
        assert isinstance(f, Finding)


@given(
    line_length=st.integers(min_value=0, max_value=20_000),
    char=st.sampled_from(["a", "0", "/", "+", "=", "_", "\x00", "\xff"]),
)
@_DEFAULT_SETTINGS
def test_secrets_scan_on_pathological_long_lines(
    line_length: int, char: str, tmp_path: Path
) -> None:
    """A single very long line — common in minified JS — must not stall or crash."""
    line = (char * line_length).encode("utf-8", errors="replace")
    _scan_with_content(tmp_path, "minified.js", line)


@given(
    n_lines=st.integers(min_value=0, max_value=2000),
    line_pattern=st.text(min_size=0, max_size=200),
)
@_DEFAULT_SETTINGS
def test_secrets_scan_on_many_repeated_lines(
    n_lines: int, line_pattern: str, tmp_path: Path
) -> None:
    """Many repeated lines should not exhaust memory or hang."""
    content = ("\n".join([line_pattern] * n_lines)).encode("utf-8", errors="replace")
    _scan_with_content(tmp_path, "many.py", content)


def test_secrets_scan_handles_only_null_bytes(tmp_path: Path) -> None:
    findings = _scan_with_content(tmp_path, "nulls.py", b"\x00" * 1024)
    assert isinstance(findings, list)


def test_secrets_scan_handles_only_newlines(tmp_path: Path) -> None:
    findings = _scan_with_content(tmp_path, "lines.py", b"\n" * 5000)
    assert findings == []


def test_secrets_scan_handles_invalid_utf8(tmp_path: Path) -> None:
    """Decode errors should be replaced, not raised — scanner uses errors='replace'."""
    findings = _scan_with_content(tmp_path, "binary.py", b"\xff\xfe\x00\x01\x02 plain text")
    assert isinstance(findings, list)
