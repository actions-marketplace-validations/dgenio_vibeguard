"""Executable stability contract (#197).

Each class maps to a clause in ``docs/stability-contract.md`` and pins it so the
document and the binary cannot silently disagree. A change that intentionally
alters a contractual surface must update the doc *and* the matching test here in
the same PR — that friction is the point.

Scope note: this suite pins the *contract*, not every behaviour. Detailed
per-command behaviour lives in ``test_cli.py`` / ``test_cli_e2e.py``; the golden
reporter output lives in ``test_reporters_golden.py`` / ``test_sarif.py``. Here
we assert the promises the contract document actually makes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from vibeguard.cli import EXIT_BLOCKED, EXIT_OK, EXIT_USAGE, app
from vibeguard.config import VibeGuardConfig
from vibeguard.models import Finding, ScanContext, Severity
from vibeguard.reporters.json_reporter import render_json
from vibeguard.reporters.sarif import render_sarif
from vibeguard.rules import load_all_builtin_rules
from vibeguard.rules.registry import RULE_REGISTRY
from vibeguard.scanner import run_scan

runner = CliRunner()


class TestExitCodeConstants:
    """Contract: exit codes 0/1/2 have fixed meanings (docs: Exit codes)."""

    def test_named_constants_match_contract(self):
        assert EXIT_OK == 0
        assert EXIT_BLOCKED == 1
        assert EXIT_USAGE == 2


class TestScanGateSplit:
    """Contract: `scan` is informational (always 0 on findings); `gate` fails
    closed with exit 1 at/above `--fail-on` (docs: CLI command stability)."""

    def _repo_with_blocking_finding(self, tmp_path: Path) -> Path:
        # A committed .env is a HIGH-severity SEC-ENV finding — blocking at the
        # default gate threshold.
        (tmp_path / ".env").write_text("AWS_SECRET_ACCESS_KEY=abc123\n")
        return tmp_path

    def test_scan_exits_zero_on_findings(self, tmp_path: Path):
        self._repo_with_blocking_finding(tmp_path)
        result = runner.invoke(app, ["scan", "--path", str(tmp_path)])
        assert result.exit_code == EXIT_OK

    def test_gate_exits_blocked_on_blocking_findings(self, tmp_path: Path):
        self._repo_with_blocking_finding(tmp_path)
        result = runner.invoke(app, ["gate", "--path", str(tmp_path), "--fail-on", "high"])
        assert result.exit_code == EXIT_BLOCKED

    def test_gate_exits_zero_when_nothing_meets_threshold(self, tmp_path: Path):
        (tmp_path / "hello.py").write_text("print('hi')\n")
        result = runner.invoke(app, ["gate", "--path", str(tmp_path), "--fail-on", "critical"])
        assert result.exit_code == EXIT_OK


class TestFailClosed:
    """Contract: the gate fails closed (exit 2) rather than reporting success
    when it cannot run as asked (docs: Operational behaviour)."""

    def test_nonexistent_path_exits_usage(self, tmp_path: Path):
        missing = tmp_path / "does-not-exist"
        result = runner.invoke(app, ["gate", "--path", str(missing)])
        assert result.exit_code == EXIT_USAGE

    def test_malformed_config_exits_usage(self, tmp_path: Path):
        (tmp_path / "hello.py").write_text("print('hi')\n")
        (tmp_path / "vibeguard.yaml").write_text("fail_on: not-a-severity\n")
        result = runner.invoke(app, ["gate", "--path", str(tmp_path)])
        assert result.exit_code == EXIT_USAGE

    def test_explain_unknown_id_exits_usage(self):
        result = runner.invoke(app, ["explain", "NOPE-NOTREAL"])
        assert result.exit_code == EXIT_USAGE


class TestDocumentedFlagsParse:
    """Contract: the documented commands remain present and parse (docs: CLI
    command stability). ``--help`` exercises each command's option wiring."""

    @pytest.mark.parametrize(
        "argv",
        [
            ["--help"],
            ["init", "--help"],
            ["scan", "--help"],
            ["gate", "--help"],
            ["explain", "--help"],
            ["rules", "--help"],
            ["rules", "list", "--help"],
            ["rules", "explain", "--help"],
            ["publish-check", "--help"],
            ["baseline", "--help"],
            ["baseline", "create", "--help"],
            ["baseline", "update", "--help"],
            ["version", "--help"],
            ["validate", "--help"],
        ],
    )
    def test_command_help_parses(self, argv: list[str]):
        result = runner.invoke(app, argv)
        assert result.exit_code == EXIT_OK, f"{argv} exited {result.exit_code}"


class TestJsonSchemaKeys:
    """Contract: the JSON output's top-level shape is stable (docs: Output
    schema stability; output-schemas.md)."""

    def test_top_level_keys_present(self, tmp_path: Path):
        (tmp_path / "hello.py").write_text("print('hi')\n")
        result = runner.invoke(app, ["scan", "--path", str(tmp_path), "--json"])
        assert result.exit_code == EXIT_OK
        data = json.loads(result.stdout)
        expected = {
            "findings",
            "scanned_files",
            "changed_files",
            "scan_path",
            "policy",
            "diagnostics",
            "errors",
            "health_score",
        }
        assert expected <= set(data), f"missing keys: {expected - set(data)}"


class TestSarifSchema:
    """Contract: SARIF output is a stable integration surface (docs: Output
    schema stability). The full SARIF 2.1.0 schema is not vendored (the gate is
    offline), so we validate the SARIF envelope structure the contract relies
    on, using ``jsonschema`` (already a dev dependency)."""

    _SARIF_ENVELOPE = {
        "type": "object",
        "required": ["$schema", "version", "runs"],
        "properties": {
            "version": {"const": "2.1.0"},
            "runs": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "required": ["tool", "results"],
                    "properties": {
                        "tool": {
                            "type": "object",
                            "required": ["driver"],
                            "properties": {
                                "driver": {
                                    "type": "object",
                                    "required": ["name", "rules"],
                                }
                            },
                        },
                        "results": {"type": "array"},
                    },
                },
            },
        },
    }

    def test_sarif_envelope_validates(self, tmp_path: Path):
        (tmp_path / ".env").write_text("AWS_SECRET_ACCESS_KEY=abc123\n")
        result = run_scan(tmp_path, VibeGuardConfig())
        sarif = json.loads(render_sarif(result))
        # Raises jsonschema.ValidationError if the envelope drifts.
        jsonschema.validate(sarif, self._SARIF_ENVELOPE)


class TestFindingIdSnapshot:
    """Contract: finding IDs are stable identifiers — once shipped, an ID is not
    renamed or removed without a major bump (docs: Finding ID stability). New
    IDs are *additive*, so this is a subset check: every baseline ID must still
    be registered. Adding an ID is fine; removing/renaming one fails here.

    To retire an ID intentionally, bump the major version, document the
    deprecation, and remove it from ``BASELINE_FINDING_IDS`` in the same PR.
    """

    # Snapshot of finding IDs shipped as of this suite's introduction.
    BASELINE_FINDING_IDS = frozenset(
        {
            "AGENT-MEMORY-DB",
            "AGENT-MEMORY-DIR",
            "AGENT-MEMORY-LOG",
            "AGENT-TOOL-TRACE",
            "AGENT-TRANSCRIPT",
            "AI-AIGENERATED",
            "AI-CORSWILDCARD",
            "AI-DISABLESECURITY",
            "AI-HALLUCINATEDTODO",
            "AI-PLACEHOLDERCRED",
            "AI-SKIPVALIDATION",
            "AI-TEMPBYPASS",
            "AI-TRUSTALLCERTS",
            "AUTH-ALLOW-ALL",
            "AUTH-BYPASS-COMMENT",
            "AUTH-COMMENTED-AUTH",
            "AUTH-DISABLED-MIDDLEWARE",
            "AUTH-HARDCODED-ADMIN",
            "AUTH-JWT-NONE",
            "AUTH-RETURN-NIL-AUTH",
            "AUTH-VERIFY-FALSE",
            "DEP-BROADVER",
            "DEP-LOCKFILE-MISMATCH",
            "DEP-MANIFEST-NO-LOCK",
            "DEP-REGISTRY-CHANGE",
            "DEP-TYPOSQUATNPM",
            "DEP-TYPOSQUATPY",
            "DEP-UNPINNEDPY",
            "DEP-URLNODE",
            "DEP-URLPYTHON",
            "DIFF-BREADTH",
            "DIFF-RISK-FILES",
            "DIFF-SIZE",
            "DOCKER-ADD-URL",
            "DOCKER-BROAD-CHMOD",
            "DOCKER-CURL-BASH",
            "DOCKER-LATEST-TAG",
            "DOCKER-PRIVILEGED",
            "DOCKER-SECRET-ENV",
            "ERR-BARE-EXCEPT-PASS",
            "ERR-DISCARDED-GO",
            "ERR-EMPTY-CATCH",
            "GHA-BROAD-PERMISSIONS",
            "GHA-DISABLE-CHECK",
            "GHA-PULL-REQUEST-TARGET",
            "GHA-SECRET-ECHO",
            "GHA-UNVERSIONED-ACTION",
            "GO-AUTH-BYPASS",
            "GO-CORS-WILDCARD",
            "GO-EXEC-SHELL",
            "GO-HARDCODED-TOKEN",
            "GO-INSECURE-TLS",
            "GO-SQL-SPRINTF",
            "GO-UNSAFE-DELETE",
            "K8S-ALLOW-ALL",
            "K8S-HOST-PATH",
            "K8S-NO-TLS",
            "K8S-PRIVILEGED",
            "K8S-ROOT-CONTAINER",
            "MAP-DIST",
            "MAP-FILE",
            "MAP-PKG",
            "MAP-URL",
            "PI-EXFIL",
            "PI-HIDDEN-UNICODE",
            "PI-OBFUSCATED",
            "PI-OVERRIDE",
            "PKG-CI-LEAK",
            "PKG-COVERAGE-LEAK",
            "PKG-MANIFEST-GRAFT",
            "PKG-MANIFEST-RECURSIVE",
            "PKG-MANIFESTLEAK",
            "PKG-NPMBROAD",
            "PKG-NPMFILES",
            "PKG-NPMIGNORE-BROAD",
            "PKG-NPMIGNORE-NEGATE",
            "PKG-NPMLEAK",
            "PKG-PREPARE-SCRIPT",
            "PKG-PYBROAD",
            "PKG-PYLEAK",
            "PKG-SETUPPYLEAK",
            "RISK-ALLOWEDHOSTSWILDCARD",
            "RISK-AUTHBYPASS",
            "RISK-AUTHZCHECK",
            "RISK-CORSCONFIG",
            "RISK-CRYPTOUSAGE",
            "RISK-DBWRITE",
            "RISK-DEBUGMODE",
            "RISK-DESERIALIZATION",
            "RISK-ENVACCESS",
            "RISK-EVALEXEC",
            "RISK-FILEDELETE",
            "RISK-JWTHANDLING",
            "RISK-NETWORKCALL",
            "RISK-PAYMENTLOGIC",
            "RISK-PERMCHANGE",
            "RISK-SUBPROCESSSHELL",
            "RISK-TRUSTCERTS",
            "SEC-AWSACCESSKEY",
            "SEC-AWSSECRETKEY",
            "SEC-BEARERTOKEN",
            "SEC-DATABASEURL",
            "SEC-ENV",
            "SEC-GENERICAPIKEY",
            "SEC-GITHUBTOKEN",
            "SEC-HARDCODEDPASSWORD",
            "SEC-OPENAIKEY",
            "SEC-PRIVATEKEY",
            "SEC-SLACKTOKEN",
            "SEC-STRIPEKEY",
            "SLOP-HALLUCINATION-SHAPE",
            "SLOP-REGISTRY-MISSING",
            "SLOP-REGISTRY-YOUNG",
            "SQL-GO-SPRINTF",
            "SQL-JS-CONCAT",
            "SQL-JS-TEMPLATE",
            "SQL-PY-CONCAT",
            "SQL-PY-FORMAT",
            "SQL-PY-FSTRING",
            "SUPPRESS-BARE-NOQA",
            "SUPPRESS-ESLINT-FILE",
            "SUPPRESS-NOLINT-BARE",
            "SUPPRESS-NOSEC-BARE",
            "SUPPRESS-TS-NOCHECK",
            "SUPPRESS-TYPE-IGNORE",
            "TEST-COVERAGE-LOWERED",
            "TEST-DELETED",
            "TEST-MISSING",
            "TEST-ONLY-ADDED",
            "TEST-SKIP-ADDED",
            "TF-IAM-WILDCARD",
            "TF-NO-VERSION-PIN",
            "TF-S3-PUBLIC",
            "TF-SG-OPEN",
            "TF-UNENCRYPTED",
        }
    )

    def _registered_finding_ids(self) -> set[str]:
        load_all_builtin_rules()
        ids: set[str] = set()
        for meta in RULE_REGISTRY.values():
            ids.update(meta.finding_ids)
        return ids

    def test_no_baseline_id_disappeared(self):
        registered = self._registered_finding_ids()
        removed = self.BASELINE_FINDING_IDS - registered
        assert not removed, (
            f"Finding IDs removed/renamed without a major bump: {sorted(removed)}. "
            "IDs are a stable identifier surface (docs/stability-contract.md)."
        )


class TestFingerprintVectors:
    """Contract: the ``vibeguard/v1`` fingerprint algorithm is byte-stable
    (docs: output-schemas.md). Fixed inputs must map to fixed hashes, and the
    hash must be line-independent so identity survives surrounding edits."""

    def test_fingerprint_vector_with_evidence(self):
        f = Finding(
            id="SEC-ENV",
            rule="secrets",
            title="t",
            description="d",
            severity=Severity.HIGH,
            path="src/config.py",
            line=9,
            evidence="AKIAIOSFODNN7EXAMPLE",
            recommendation="r",
        )
        assert f.fingerprint == ("a59b7840dfe62c9126714135bb84656fb3f1d127ce2e7ce1dd1c2c00e790dc30")

    def test_fingerprint_is_line_independent(self):
        common = {
            "id": "SEC-ENV",
            "rule": "secrets",
            "title": "t",
            "description": "d",
            "severity": Severity.HIGH,
            "path": "src/config.py",
            "evidence": "AKIAIOSFODNN7EXAMPLE",
            "recommendation": "r",
        }
        assert Finding(line=9, **common).fingerprint == Finding(line=99, **common).fingerprint

    def test_fingerprint_vector_without_evidence_or_line(self):
        f = Finding(
            id="MAP-DIST",
            rule="sourcemaps",
            title="t",
            description="d",
            severity=Severity.LOW,
            path="dist/app.js.map",
            recommendation="r",
        )
        assert f.fingerprint == ("e377a5a0489abd8b8c869e9f66a56620f34542c97551401638606194ebecf7e4")


class TestOutputOrdering:
    """Contract: findings are emitted in canonical ``(path, line, id)`` order,
    identical across repeated runs (docs: Output ordering, #222)."""

    def _multi_finding_repo(self, root: Path) -> None:
        # Several files across rules and paths, deliberately not in sorted order
        # by creation, so a stable output order must come from the sort — not
        # from filesystem or rule-registration order.
        (root / "z_app.py").write_text("import os\npassword = 'hunter2haslength'\n")
        (root / "a_server.js").write_text("eval(userInput)\n")
        (root / ".env").write_text("AWS_SECRET_ACCESS_KEY=abc123\n")
        (root / "m_utils.py").write_text("import pickle\npickle.loads(data)\n")

    def test_findings_sorted_by_path_line_id(self, tmp_path: Path):
        self._multi_finding_repo(tmp_path)
        result = run_scan(tmp_path, VibeGuardConfig())
        assert len(result.findings) > 1
        keys = [(f.path, f.line or 0, f.id) for f in result.findings]
        assert keys == sorted(keys)

    def test_repeated_scans_are_byte_identical(self, tmp_path: Path):
        self._multi_finding_repo(tmp_path)
        first = render_json(run_scan(tmp_path, VibeGuardConfig()))
        second = render_json(run_scan(tmp_path, VibeGuardConfig()))
        assert first == second


class TestScanContextConfigTyped:
    """Contract/regression (#217): ``ScanContext.config`` is typed as
    ``VibeGuardConfig``, not ``Any`` — so rule/plugin config access is
    statically checked. This guards against the ``Any`` hole reappearing."""

    def test_config_field_is_vibeguardconfig(self):
        # The field must be typed as VibeGuardConfig, not Any. Across pydantic
        # versions the stored annotation is either the resolved class (newer) or
        # a ForwardRef('VibeGuardConfig') (the 2.0 floor, where model_rebuild
        # does not eagerly resolve the introspection view) — both are correct;
        # what matters is that it is not Any and names VibeGuardConfig. Runtime
        # enforcement is proven separately by test_wrong_config_type_is_rejected.
        annotation = ScanContext.model_fields["config"].annotation
        assert annotation is not Any
        resolved = annotation is VibeGuardConfig
        named = getattr(annotation, "__forward_arg__", None) == "VibeGuardConfig"
        assert resolved or named, f"unexpected config annotation: {annotation!r}"

    def test_wrong_config_type_is_rejected(self, tmp_path: Path):
        with pytest.raises(ValidationError):
            ScanContext(root=tmp_path, config="not-a-config")  # type: ignore[arg-type]
