"""Scan/gate behavioural-parity regression test (#188).

The documented contract (``docs/stability-contract.md``) is that ``gate`` is
``scan`` *plus enforcement*: the two commands run identical analysis and differ
only in exit code (and the human-facing verdict line). Because they are
implemented as parallel code paths in ``vibeguard/cli.py``, that equivalence is
maintained by discipline today; this test makes it executable and will be the
safety net for the planned shared-pipeline refactor.

The comparison is on ``--json`` output, whose payload is the serialized
``ScanResult`` — the analysis result itself, with no command-specific framing.
Any divergence in findings, diagnostics, counts, or health score fails here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vibeguard.cli import EXIT_BLOCKED, EXIT_OK, app

runner = CliRunner()
EXAMPLES = Path(__file__).parent.parent / "examples"


def _json(argv: list[str]) -> dict:
    result = runner.invoke(app, argv)
    assert result.exit_code in (EXIT_OK, EXIT_BLOCKED), (
        f"{argv} exited {result.exit_code}\n{result.stdout}"
    )
    return json.loads(result.stdout)


class TestScanGateParity:
    """`scan --json` and `gate --json` must produce identical analysis payloads
    for the same inputs (#188)."""

    def _assert_parity(self, target_args: list[str]) -> None:
        scan_payload = _json(["scan", *target_args, "--json"])
        # `gate` needs a threshold; use the lowest so it exercises the full
        # analysis path. The JSON payload is the ScanResult and must match scan.
        gate_payload = _json(["gate", *target_args, "--json", "--fail-on", "info"])
        assert scan_payload == gate_payload

    def test_parity_on_finding_rich_fixture(self):
        self._assert_parity(["--path", str(EXAMPLES / "vulnerable-python-package")])

    def test_parity_on_clean_fixture(self, tmp_path: Path):
        (tmp_path / "hello.py").write_text("print('hello, world')\n")
        self._assert_parity(["--path", str(tmp_path)])

    def test_parity_with_policy_pack(self):
        self._assert_parity(
            ["--path", str(EXAMPLES / "vulnerable-python-package"), "--policy-pack", "strict-ci"]
        )


class TestScanGateExitCodeContract:
    """The commands differ where the contract says they should: exit code.
    `scan` is always 0 on findings; `gate` is 0/1 by whether findings meet the
    threshold — including the exact-at-threshold boundary (#188)."""

    def _find_a_severity(self, target: str) -> str:
        # Pull a real severity present in the fixture so we can probe the
        # at-threshold boundary rather than guessing.
        payload = _json(["scan", "--path", target, "--json"])
        severities = {f["severity"] for f in payload["findings"]}
        assert severities, "fixture produced no findings"
        # Prefer the highest present so `--fail-on <it>` has findings at exactly
        # that level.
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in severities:
                return sev
        raise AssertionError("unreachable")

    def test_scan_always_zero_gate_blocks_at_threshold(self):
        target = str(EXAMPLES / "vulnerable-python-package")
        sev = self._find_a_severity(target)

        scan_result = runner.invoke(app, ["scan", "--path", target, "--fail-on", sev])
        assert scan_result.exit_code == EXIT_OK  # scan never fails on findings

        gate_result = runner.invoke(app, ["gate", "--path", target, "--fail-on", sev])
        # Findings exist at exactly `sev`, so the gate blocks.
        assert gate_result.exit_code == EXIT_BLOCKED

    def test_gate_passes_above_all_findings(self, tmp_path: Path):
        (tmp_path / "hello.py").write_text("print('clean')\n")
        result = runner.invoke(app, ["gate", "--path", str(tmp_path), "--fail-on", "critical"])
        assert result.exit_code == EXIT_OK


@pytest.mark.parametrize("fail_on", ["info", "low", "medium", "high", "critical"])
def test_parity_holds_across_thresholds(fail_on: str):
    """The analysis payload is threshold-independent: `--fail-on` changes the
    gate verdict, never the findings. scan and gate agree at every threshold."""
    target = str(EXAMPLES / "vulnerable-python-package")
    scan_payload = _json(["scan", "--path", target, "--json", "--fail-on", fail_on])
    gate_payload = _json(["gate", "--path", target, "--json", "--fail-on", fail_on])
    assert scan_payload == gate_payload
