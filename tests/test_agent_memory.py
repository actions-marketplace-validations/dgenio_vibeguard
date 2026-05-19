"""Tests for agent memory artifact detection rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.agent_memory import AgentMemoryRule


def _ctx(tmp_path: Path, files: dict[str, str]) -> ScanContext:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    all_files = [tmp_path / n for n in files]
    return ScanContext(
        root=tmp_path,
        config=VibeGuardConfig(),
        files=all_files,
    )


class TestAgentMemoryRule:
    rule = AgentMemoryRule()

    def test_memory_sqlite_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"agent_cache.sqlite": "fake db content"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AGENT-MEMORY-DB" for f in findings)

    def test_session_db_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"sessions.db": "fake db"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AGENT-MEMORY-DB" for f in findings)

    def test_memory_jsonl_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"memories.jsonl": '{"note": "test"}'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AGENT-MEMORY-LOG" for f in findings)

    def test_transcript_txt_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"transcript.txt": "User: hello\nAssistant: hi"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AGENT-TRANSCRIPT" for f in findings)

    def test_tool_trace_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"tool_trace.jsonl": '{"tool": "read_file"}'})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AGENT-TOOL-TRACE" for f in findings)

    def test_memory_dir_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {".agent_memory/notes.md": "# Notes"})
        findings = self.rule.scan(ctx)
        assert any(f.id == "AGENT-MEMORY-DIR" for f in findings)

    # Negative tests
    def test_regular_sqlite_not_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.sqlite": "normal app db"})
        findings = self.rule.scan(ctx)
        assert not any(f.id == "AGENT-MEMORY-DB" for f in findings)

    def test_test_fixture_not_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"test_fixtures/memories.sqlite": "fixture data"})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_regular_log_not_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.jsonl": '{"event": "startup"}'})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    def test_severity_is_correct(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"agent_cache.sqlite": "data"})
        findings = self.rule.scan(ctx)
        db_findings = [f for f in findings if f.id == "AGENT-MEMORY-DB"]
        assert db_findings[0].severity == Severity.HIGH
