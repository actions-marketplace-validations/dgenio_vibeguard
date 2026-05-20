"""Tests for the PublishManifest model and JSON serializer."""

from __future__ import annotations

import json

from vibeguard.publish.manifest import PublishedFile, PublishManifest


class TestPublishManifest:
    def test_to_json_is_sorted_and_deterministic(self):
        m = PublishManifest(
            ecosystem="npm",
            package_root="/x",
            package_name="demo",
            package_version="1.0.0",
            files=[
                PublishedFile(path="src/z.js", size_bytes=10, included_by="files-allowlist"),
                PublishedFile(path="src/a.js", size_bytes=20, included_by="files-allowlist"),
                PublishedFile(path="package.json", size_bytes=5, included_by="always-included"),
            ],
            excluded=["tests/zz.js", "tests/aa.js"],
            total_bytes=35,
        )
        out = m.to_json()
        data = json.loads(out)
        # Files sorted by path
        assert [f["path"] for f in data["files"]] == ["package.json", "src/a.js", "src/z.js"]
        # Excluded sorted
        assert data["excluded"] == ["tests/aa.js", "tests/zz.js"]
        # Determinism: serialize twice → identical
        assert m.to_json() == out

    def test_to_json_uses_sorted_keys_at_top_level(self):
        m = PublishManifest(ecosystem="npm", package_root="/x")
        out = m.to_json()
        # Keys appear in alphabetical order in the output
        lines = [ln for ln in out.splitlines() if ln.strip().startswith('"')]
        keys = [ln.split('":', 1)[0].strip().lstrip('"') for ln in lines]
        # Top-level keys should include these — and 'ecosystem' should appear before 'files'
        e_idx = keys.index("ecosystem")
        f_idx = keys.index("files")
        assert e_idx < f_idx

    def test_included_paths_returns_sorted_list(self):
        m = PublishManifest(
            ecosystem="npm",
            package_root="/x",
            files=[
                PublishedFile(path="b", size_bytes=1, included_by="x"),
                PublishedFile(path="a", size_bytes=1, included_by="x"),
            ],
        )
        assert m.included_paths() == ["a", "b"]

    def test_extra_fields_forbidden(self):
        try:
            PublishedFile(path="x", size_bytes=1, included_by="x", extra="boom")  # type: ignore[call-arg]
        except Exception as exc:
            assert "Extra inputs are not permitted" in str(exc) or "extra_forbidden" in str(exc)
            return
        raise AssertionError("expected PublishedFile to reject extra fields")

    def test_size_bytes_must_be_non_negative(self):
        try:
            PublishedFile(path="x", size_bytes=-1, included_by="x")
        except Exception:
            return
        raise AssertionError("expected PublishedFile to reject negative size_bytes")
