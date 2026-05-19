"""Agent memory artifact detection rule."""

from __future__ import annotations

import re

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# Patterns that strongly indicate agent memory artifacts when found in repos
_MEMORY_PATH_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    (
        "AGENT-MEMORY-DB",
        "Agent memory database",
        re.compile(
            r"(?i)(memories?|sessions?|transcripts?|agent[_\-]?cache|copilot[_\-]?memory"
            r"|claude[_\-]?memory|cursor[_\-]?memory)\.(sqlite3?|db)$"
        ),
        Severity.HIGH,
    ),
    (
        "AGENT-MEMORY-LOG",
        "Agent memory/transcript JSONL log",
        re.compile(
            r"(?i)(memories?|sessions?|transcripts?|agent[_\-]?log"
            r"|chat[_\-]?history|conversation[_\-]?log)\.(jsonl|ndjson)$"
        ),
        Severity.HIGH,
    ),
    (
        "AGENT-TRANSCRIPT",
        "Agent conversation transcript",
        re.compile(
            r"(?i)(transcript|conversation|chat[_\-]?log|session[_\-]?log"
            r"|agent[_\-]?transcript)\.(txt|md|log)$"
        ),
        Severity.MEDIUM,
    ),
    (
        "AGENT-TOOL-TRACE",
        "Agent tool execution trace",
        re.compile(
            r"(?i)(tool[_\-]?trace|tool[_\-]?calls?|mcp[_\-]?log|function[_\-]?calls?)"
            r"\.(jsonl|json|log|ndjson)$"
        ),
        Severity.MEDIUM,
    ),
]

# Directory patterns that indicate agent memory storage
_MEMORY_DIR_PATTERNS: list[tuple[str, str, re.Pattern[str], Severity]] = [
    (
        "AGENT-MEMORY-DIR",
        "Agent memory directory",
        re.compile(
            r"(?i)(\.agent[_\-]?memory|\.copilot[_\-]?memory|\.claude[_\-]?memory"
            r"|\.cursor[_\-]?memory|\.ai[_\-]?memory|memories/session"
            r"|\.windsurf[_\-]?memory)"
        ),
        Severity.HIGH,
    ),
]

# Filename patterns that are NOT agent memory (false-positive exclusions)
_SAFE_PATTERNS = re.compile(
    r"(?i)(test[_\-]?fixtures?|fixtures?/|__tests__|spec/|examples?/|migrations?/|"
    r"seeds?/|demo)"
)


class AgentMemoryRule(Rule):
    id = "agent_memory"
    name = "Agent Memory Artifacts"
    description = "Detects accidentally committed agent memory databases, logs, and transcripts"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        for path in files_to_check:
            rel = self._rel(context, path)
            rel_posix = rel.replace("\\", "/")

            # Skip files in test/fixture/example directories
            if _SAFE_PATTERNS.search(rel_posix):
                continue

            # Check file path against memory patterns
            for finding_id, label, pattern, severity in _MEMORY_PATH_PATTERNS:
                if pattern.search(path.name):
                    findings.append(
                        Finding(
                            id=finding_id,
                            rule=self.id,
                            title=f"Agent artifact: {label}",
                            description=(
                                f"`{rel}` matches a known agent memory artifact pattern. "
                                "These files may contain architecture notes, user preferences, "
                                "task history, credentials, or personal data."
                            ),
                            severity=severity,
                            path=rel,
                            recommendation=(
                                "Add this file to .gitignore and remove it from the repository. "
                                "Agent memory artifacts should remain local."
                            ),
                            tags=["agent-memory", finding_id.lower()],
                            confidence=Confidence.MEDIUM,
                        )
                    )
                    break  # One finding per file

            # Check directory patterns
            for finding_id, label, pattern, severity in _MEMORY_DIR_PATTERNS:
                if pattern.search(rel_posix):
                    findings.append(
                        Finding(
                            id=finding_id,
                            rule=self.id,
                            title=f"Agent artifact: {label}",
                            description=(
                                f"`{rel}` is inside a directory that looks like an agent "
                                "memory storage location. These directories typically contain "
                                "session data, transcripts, and tool traces."
                            ),
                            severity=severity,
                            path=rel,
                            recommendation=(
                                "Add this directory to .gitignore. Agent memory directories "
                                "should not be committed to version control."
                            ),
                            tags=["agent-memory", finding_id.lower()],
                            confidence=Confidence.MEDIUM,
                        )
                    )
                    break

        return findings


register_rule(
    RuleMetadata(
        rule_id="agent_memory",
        title="Agent Memory Artifacts",
        description=(
            "Detects accidentally committed agent memory artifacts: SQLite databases, "
            "JSONL logs, transcripts, tool traces, and hidden memory directories."
        ),
        finding_ids=[
            "AGENT-MEMORY-DB",
            "AGENT-MEMORY-LOG",
            "AGENT-TRANSCRIPT",
            "AGENT-TOOL-TRACE",
            "AGENT-MEMORY-DIR",
        ],
        default_severity="high",
        confidence="medium",
        tags=["security", "agent-memory", "data-leak"],
        applies_to=["*.sqlite", "*.sqlite3", "*.db", "*.jsonl", "*.ndjson"],
    )
)
