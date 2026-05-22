"""Tests for the ``Finding.fingerprint`` computed field (issue #68)."""

from __future__ import annotations

import hashlib
import json

from vibeguard.baseline import compute_fingerprint
from vibeguard.models import Confidence, Finding, Severity


def _make_finding(
    finding_id: str = "SEC-ENV",
    path: str = "src/config.py",
    line: int | None = 5,
    evidence: str | None = "SECRET_KEY=abc123",
) -> Finding:
    return Finding(
        id=finding_id,
        rule="secrets",
        title="Test finding",
        description="Test description.",
        severity=Severity.HIGH,
        path=path,
        line=line,
        evidence=evidence,
        recommendation="Fix it.",
        tags=["test"],
        confidence=Confidence.HIGH,
    )


class TestFingerprintProperty:
    def test_property_matches_helper(self):
        f = _make_finding()
        assert f.fingerprint == compute_fingerprint(f)

    def test_same_inputs_same_fingerprint(self):
        a = _make_finding()
        b = _make_finding()
        assert a.fingerprint == b.fingerprint

    def test_line_excluded_from_fingerprint(self):
        a = _make_finding(line=5)
        b = _make_finding(line=999)
        assert a.fingerprint == b.fingerprint

    def test_path_changes_fingerprint(self):
        a = _make_finding(path="src/a.py")
        b = _make_finding(path="src/b.py")
        assert a.fingerprint != b.fingerprint

    def test_evidence_changes_fingerprint(self):
        a = _make_finding(evidence="key1")
        b = _make_finding(evidence="key2")
        assert a.fingerprint != b.fingerprint

    def test_id_changes_fingerprint(self):
        a = _make_finding(finding_id="SEC-ENV")
        b = _make_finding(finding_id="SEC-AWSACCESSKEY")
        assert a.fingerprint != b.fingerprint

    def test_no_evidence_still_stable(self):
        a = _make_finding(evidence=None)
        b = _make_finding(evidence=None)
        assert a.fingerprint == b.fingerprint
        # And distinct from the same finding with evidence
        assert a.fingerprint != _make_finding().fingerprint

    def test_fingerprint_is_64_char_hex(self):
        fp = _make_finding().fingerprint
        assert len(fp) == 64
        # All hex
        int(fp, 16)

    def test_backslash_path_normalized_to_forward_slash(self):
        # Windows-style path must hash to the same value as POSIX-style
        win = _make_finding(path="src\\windows\\file.py")
        posix = _make_finding(path="src/windows/file.py")
        assert win.fingerprint == posix.fingerprint

    def test_algorithm_is_documented_v1(self):
        """Recompute the exact documented formula and assert equality.

        The pinned value here protects the documented contract: anyone
        changing the algorithm will fail this test, not just the integration
        tests, making the intent explicit.
        """
        f = _make_finding()
        evidence_hash = hashlib.sha256(f.evidence.encode("utf-8")).hexdigest()[:16]  # type: ignore[union-attr]
        raw = f"{f.id}:{f.path}:{evidence_hash}"
        expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        assert f.fingerprint == expected


class TestFingerprintInJsonOutput:
    def test_fingerprint_present_in_model_dump(self):
        f = _make_finding()
        dumped = f.model_dump(mode="json")
        assert "fingerprint" in dumped
        assert dumped["fingerprint"] == f.fingerprint

    def test_fingerprint_present_in_json_string(self):
        f = _make_finding()
        as_json = json.loads(f.model_dump_json())
        assert as_json["fingerprint"] == f.fingerprint
