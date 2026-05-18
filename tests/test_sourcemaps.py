"""Tests for source maps rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.sourcemaps import SourceMapsRule


def _ctx(tmp_path: Path, files: dict[str, str]) -> ScanContext:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return ScanContext(
        root=tmp_path,
        config=VibeGuardConfig(),
        files=[tmp_path / n for n in files],
    )


class TestSourceMapsRule:
    rule = SourceMapsRule()

    def test_map_file_in_dist_is_high(self, tmp_path: Path):
        (tmp_path / "dist").mkdir()
        map_file = tmp_path / "dist" / "app.js.map"
        map_file.write_text('{"version":3}')
        ctx = ScanContext(
            root=tmp_path,
            config=VibeGuardConfig(),
            files=[map_file],
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "MAP-DIST" and f.severity == Severity.HIGH for f in findings)

    def test_map_file_outside_dist_is_low(self, tmp_path: Path):
        map_file = tmp_path / "app.js.map"
        map_file.write_text('{"version":3}')
        ctx = ScanContext(
            root=tmp_path,
            config=VibeGuardConfig(),
            files=[map_file],
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "MAP-FILE" and f.severity == Severity.LOW for f in findings)

    def test_sourcemapping_url_in_js(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {"bundle.js": "var x=1;\n//# sourceMappingURL=bundle.js.map\n"},
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "MAP-URL" for f in findings)

    def test_sourcemapping_url_inline_data_ignored(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {"bundle.js": "var x=1;\n//# sourceMappingURL=data:application/json;base64,abc\n"},
        )
        findings = self.rule.scan(ctx)
        assert not any(f.id == "MAP-URL" for f in findings)

    def test_package_json_with_map_files(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {"package.json": '{"name":"foo","files":["dist/*.js","dist/*.js.map"]}'},
        )
        findings = self.rule.scan(ctx)
        assert any(f.id == "MAP-PKG" for f in findings)

    def test_clean_js_no_findings(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.js": "console.log('hello');\n"})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_sourcemapping_in_dist_is_high(self, tmp_path: Path):
        (tmp_path / "dist").mkdir()
        js_file = tmp_path / "dist" / "bundle.js"
        js_file.write_text("var x=1;\n//# sourceMappingURL=bundle.js.map\n")
        ctx = ScanContext(
            root=tmp_path,
            config=VibeGuardConfig(),
            files=[js_file],
        )
        findings = self.rule.scan(ctx)
        url_findings = [f for f in findings if f.id == "MAP-URL"]
        assert url_findings
        assert url_findings[0].severity == Severity.HIGH
