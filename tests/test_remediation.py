"""Structured remediation metadata model + rule integration (#238)."""

from __future__ import annotations

import json
from pathlib import Path

from vibeguard.models import Confidence, Finding, Remediation, RemediationKind, Severity


class TestRemediationModel:
    def test_optional_and_absent_by_default(self) -> None:
        f = Finding(
            id="X",
            rule="r",
            title="t",
            description="d",
            severity=Severity.LOW,
            path="a.py",
            recommendation="fix",
        )
        assert f.remediation is None
        # Serialized JSON carries the field as null (additive, ignorable).
        assert json.loads(f.model_dump_json())["remediation"] is None

    def test_round_trips_through_json(self) -> None:
        rem = Remediation(
            kind=RemediationKind.ADD_IGNORE_ENTRY,
            target=".gitignore",
            content=".env",
            description="Add .env to .gitignore.",
            confidence=Confidence.HIGH,
        )
        f = Finding(
            id="SEC-ENV",
            rule="secrets",
            title="t",
            description="d",
            severity=Severity.HIGH,
            path=".env",
            recommendation="fix",
            remediation=rem,
        )
        data = json.loads(f.model_dump_json())["remediation"]
        assert data["kind"] == "add-ignore-entry"
        assert data["target"] == ".gitignore"
        assert data["content"] == ".env"

    def test_remediation_does_not_change_fingerprint(self) -> None:
        base = {
            "id": "SEC-ENV",
            "rule": "secrets",
            "title": "t",
            "description": "d",
            "severity": Severity.HIGH,
            "path": ".env",
            "recommendation": "fix",
        }
        without = Finding(**base)
        with_rem = Finding(
            **base,
            remediation=Remediation(kind=RemediationKind.DELETE_FILE, description="x"),
        )
        assert without.fingerprint == with_rem.fingerprint


class TestRuleRemediationIntegration:
    """Real rules attach structured remediation to mechanically-fixable findings.

    Exercised at the rule level so the scanner's default ignore set (which
    excludes ``dist/``) doesn't hide the publish-directory source maps.
    """

    def _ctx(self, root: Path, files: list[Path]):
        from vibeguard.config import VibeGuardConfig
        from vibeguard.models import ScanContext

        return ScanContext(root=root, config=VibeGuardConfig(), files=files)

    def test_committed_env_carries_add_ignore_entry(self, tmp_path: Path) -> None:
        from vibeguard.rules.secrets import SecretsRule

        env = tmp_path / ".env"
        env.write_text("API_KEY=supersecretvalue123456\n")
        findings = SecretsRule().scan(self._ctx(tmp_path, [env]))
        sec = [f for f in findings if f.id == "SEC-ENV"]
        assert sec, "expected a SEC-ENV finding"
        rem = sec[0].remediation
        assert rem is not None
        assert rem.kind is RemediationKind.ADD_IGNORE_ENTRY
        assert rem.target == ".gitignore"
        assert rem.content == ".env"

    def test_sourcemap_in_dist_carries_remediation(self, tmp_path: Path) -> None:
        from vibeguard.rules.sourcemaps import SourceMapsRule

        dist = tmp_path / "dist"
        dist.mkdir()
        mp = dist / "app.js.map"
        mp.write_text('{"version":3}\n')
        findings = SourceMapsRule().scan(self._ctx(tmp_path, [mp]))
        maps = [f for f in findings if f.id == "MAP-DIST"]
        assert maps, "expected a MAP-DIST finding"
        rem = maps[0].remediation
        assert rem is not None
        assert rem.kind is RemediationKind.ADD_IGNORE_ENTRY
        assert rem.content == "*.map"

    def test_at_least_three_finding_families_emit_remediation(self, tmp_path: Path) -> None:
        # Acceptance criterion: >=3 finding families carry structured remediation.
        from vibeguard.rules.secrets import SecretsRule
        from vibeguard.rules.sourcemaps import SourceMapsRule

        env = tmp_path / ".env"
        env.write_text("API_KEY=supersecretvalue123456\n")
        dist = tmp_path / "dist"
        dist.mkdir()
        mp = dist / "app.js.map"
        mp.write_text('{"version":3}\n')
        bundle = dist / "bundle.js"
        bundle.write_text("console.log(1);\n//# sourceMappingURL=bundle.js.map\n")

        findings = SecretsRule().scan(self._ctx(tmp_path, [env]))
        findings += SourceMapsRule().scan(self._ctx(tmp_path, [mp, bundle]))
        ids_with_remediation = {f.id for f in findings if f.remediation is not None}
        assert len(ids_with_remediation) >= 3, ids_with_remediation
        # One is the precise replace-span fix that maps to a SARIF fix.
        assert "MAP-URL" in ids_with_remediation
