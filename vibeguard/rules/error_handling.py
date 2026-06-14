"""Swallowed-error rule (#205).

Detects newly introduced error-swallowing constructs — the canonical
"wrap it in try/except so it stops crashing" AI fix that turns loud failures
into silent data corruption:

* ``ERR-BARE-EXCEPT-PASS`` — Python ``except:`` / ``except Exception:`` whose
  body is only ``pass`` / ``...``.
* ``ERR-EMPTY-CATCH`` — JavaScript/TypeScript ``catch`` with an empty body or a
  body that only logs.
* ``ERR-DISCARDED-GO`` — Go ``if err != nil { }`` with an empty body, or an
  ``_ = err`` discard.

Detection needs a tiny stateful look at the lines *following* the handler, so
this is the rule set's first capped-lookahead scan (max three physical lines).
It deliberately stays line-oriented rather than parsing an AST — see the
roadmap's "fast, pattern-level" criteria. ``contextlib.suppress(...)`` is an
*explicit* idiom and is never matched. Findings are line-based (reported on the
handler line), so the scanner scopes them to changed lines in ``--diff`` mode.
"""

from __future__ import annotations

import re

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules._util import is_comment_line, is_test_file
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

_PY_EXTENSIONS = {".py", ".pyi"}
_JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
_GO_EXTENSIONS = {".go"}
_CODE_EXTENSIONS = _PY_EXTENSIONS | _JS_EXTENSIONS | _GO_EXTENSIONS

_MAX_LOOKAHEAD = 3

# A broad/bare Python except header (bare ``except:`` or ``except Exception``/
# ``BaseException``). Specific excepts like ``except ValueError:`` are NOT
# matched — narrowing the catch is the recommended fix, not a finding.
_PY_BROAD_EXCEPT = re.compile(r"^except\b(?:\s+(?:Exception|BaseException)\b[^:]*)?:\s*(.*)$")
# The handler body is *only* ``pass`` / ``...`` (plus an optional trailing
# comment) — i.e. the error is discarded.
_PY_EMPTY_BODY = re.compile(r"^(?:pass|\.\.\.)\s*(?:#.*)?$")

# JS catch: opening of a catch block. Group 1 captures anything after ``{`` on
# the same line so an inline ``catch (e) {}`` can be judged without lookahead.
_JS_CATCH = re.compile(r"\bcatch\b\s*(?:\([^)]*\))?\s*\{(.*)$")
_JS_ONLY_LOG = re.compile(r"^console\.(?:log|error|warn|info|debug)\s*\(")

# Go: empty error-check body, or an explicit discard of the error value.
_GO_ERR_CHECK = re.compile(r"\bif\s+err\s*!=\s*nil\s*\{\s*(.*)$")
_GO_DISCARD = re.compile(r"^_\s*[,]?\s*=\s*.*\berr\b|^_\s*=\s*err\b")


class ErrorHandlingRule(Rule):
    id = "error_handling"
    name = "Swallowed Errors"
    description = (
        "Flags newly introduced error-swallowing (bare except: pass, empty "
        "catch blocks, discarded Go errors). A risk signal, not a vulnerability "
        "claim."
    )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        for path in files_to_check:
            ext = path.suffix.lower()
            if ext not in _CODE_EXTENSIONS:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = self._rel(context, path)
            is_test = is_test_file(path)
            base = Severity.MEDIUM if context.diff_only else Severity.LOW
            severity = Severity.LOW if is_test else base
            lines = content.splitlines()

            if ext in _PY_EXTENSIONS:
                findings.extend(self._scan_python(lines, rel, severity))
            elif ext in _JS_EXTENSIONS:
                findings.extend(self._scan_js(lines, rel, severity))
            elif ext in _GO_EXTENSIONS:
                findings.extend(self._scan_go(lines, rel, severity))

        return findings

    def _scan_python(self, lines: list[str], rel: str, severity: Severity) -> list[Finding]:
        findings: list[Finding] = []
        for i, raw in enumerate(lines):
            stripped = raw.strip()
            if is_comment_line(stripped):
                continue
            match = _PY_BROAD_EXCEPT.match(stripped)
            if not match:
                continue
            inline = match.group(1).strip()
            # An inline part that is empty *or* only a trailing comment
            # (``except Exception:  # explain``) carries no body — look ahead to
            # the real first statement instead of treating the comment as one.
            has_inline_body = bool(inline) and not inline.startswith("#")
            body = inline if has_inline_body else (_first_body(lines, i) or "")
            if _PY_EMPTY_BODY.match(body):
                findings.append(
                    self._finding(
                        "ERR-BARE-EXCEPT-PASS",
                        "Swallowed exception (except: pass)",
                        rel,
                        i + 1,
                        stripped,
                        (
                            f"`{rel}` line {i + 1} catches a broad exception and "
                            "discards it (`pass`/`...`). Silently swallowing errors "
                            "hides failures and can corrupt data."
                        ),
                        severity,
                    )
                )
        return findings

    def _scan_js(self, lines: list[str], rel: str, severity: Severity) -> list[Finding]:
        findings: list[Finding] = []
        for i, raw in enumerate(lines):
            stripped = raw.strip()
            if is_comment_line(stripped):
                continue
            match = _JS_CATCH.search(stripped)
            if not match:
                continue
            statements, closed = _js_catch_body(lines, i, match.group(1))
            if not closed:
                # Block doesn't close within the lookahead window — it may rethrow
                # or handle further down, so don't risk a false positive.
                continue
            # Flag only a truly empty body or one that *only* logs. A catch that
            # logs and then rethrows/handles (`console.error(e); throw e`) has a
            # non-log statement and is left alone (see #205).
            if not statements or all(_JS_ONLY_LOG.match(s) for s in statements):
                findings.append(self._js_finding(rel, i, stripped, severity))
        return findings

    def _scan_go(self, lines: list[str], rel: str, severity: Severity) -> list[Finding]:
        findings: list[Finding] = []
        for i, raw in enumerate(lines):
            stripped = raw.strip()
            if is_comment_line(stripped):
                continue
            if _GO_DISCARD.search(stripped):
                findings.append(
                    self._finding(
                        "ERR-DISCARDED-GO",
                        "Discarded Go error",
                        rel,
                        i + 1,
                        stripped,
                        (
                            f"`{rel}` line {i + 1} discards an error value (`_ = err`). "
                            "Handle or propagate the error instead of dropping it."
                        ),
                        severity,
                    )
                )
                continue
            match = _GO_ERR_CHECK.search(stripped)
            if not match:
                continue
            after = match.group(1).strip()
            body = after if after else (_first_body(lines, i) or "")
            if body in ("", "}"):
                findings.append(
                    self._finding(
                        "ERR-DISCARDED-GO",
                        "Empty Go error-check body",
                        rel,
                        i + 1,
                        stripped,
                        (
                            f"`{rel}` line {i + 1} checks `if err != nil` but the body "
                            "is empty, so the error is silently ignored."
                        ),
                        severity,
                    )
                )
        return findings

    def _js_finding(self, rel: str, i: int, evidence: str, severity: Severity) -> Finding:
        return self._finding(
            "ERR-EMPTY-CATCH",
            "Empty catch block",
            rel,
            i + 1,
            evidence,
            (
                f"`{rel}` line {i + 1} has a catch block that is empty or only logs. "
                "Swallowing the error hides failures from callers."
            ),
            severity,
        )

    def _finding(
        self,
        fid: str,
        title: str,
        rel: str,
        line: int,
        evidence: str,
        description: str,
        severity: Severity,
    ) -> Finding:
        return Finding(
            id=fid,
            rule=self.id,
            title=title,
            description=description,
            severity=severity,
            path=rel,
            line=line,
            evidence=evidence[:120],
            recommendation=_REMEDIATIONS[fid],
            tags=["error-handling", fid.lower()],
            confidence=Confidence.MEDIUM,
        )


def _first_body(lines: list[str], i: int, max_ahead: int = _MAX_LOOKAHEAD) -> str | None:
    """Return the first meaningful (non-blank, non-comment) line after ``i``.

    Capped at ``max_ahead`` physical lines so the scan stays cheap and never
    walks an entire function body.
    """
    for j in range(i + 1, min(i + 1 + max_ahead, len(lines))):
        stripped = lines[j].strip()
        if stripped and not is_comment_line(stripped):
            return stripped
    return None


def _split_stmts(text: str) -> list[str]:
    """Split a snippet into individual statements on ``;``, dropping blanks."""
    return [part.strip() for part in text.split(";") if part.strip()]


def _js_catch_body(
    lines: list[str], i: int, after_brace: str, max_ahead: int = _MAX_LOOKAHEAD
) -> tuple[list[str], bool]:
    """Return ``(statements, closed)`` for a JS/TS catch block opened on line ``i``.

    ``after_brace`` is the text following the catch's ``{`` on the same line.
    ``statements`` are the body statements up to the closing ``}`` (excluding
    braces); ``closed`` is True once the closing ``}`` is seen within the
    lookahead window. When the block does not close within ``max_ahead`` lines,
    ``closed`` is False and the caller should not flag it (it may rethrow or
    handle the error further down).
    """
    statements: list[str] = []

    inline = after_brace.strip()
    if inline:
        brace = inline.find("}")
        if brace != -1:
            return _split_stmts(inline[:brace]), True
        statements.extend(_split_stmts(inline))

    for j in range(i + 1, min(i + 1 + max_ahead, len(lines))):
        stripped = lines[j].strip()
        if not stripped or is_comment_line(stripped):
            continue
        brace = stripped.find("}")
        if brace != -1:
            statements.extend(_split_stmts(stripped[:brace]))
            return statements, True
        statements.extend(_split_stmts(stripped))
    return statements, False


_REMEDIATIONS: dict[str, str] = {
    "ERR-BARE-EXCEPT-PASS": (
        "Handle the error (log it with context, retry, or re-raise) or narrow the "
        "except to the specific exception you expect. If suppression is genuinely "
        "intended, use `contextlib.suppress(SpecificError)` so the intent is "
        "explicit."
    ),
    "ERR-EMPTY-CATCH": (
        "Do something with the caught error: log it with context, surface it to "
        "the caller, or rethrow. An empty (or log-only) catch hides failures."
    ),
    "ERR-DISCARDED-GO": (
        "Check and handle the returned error rather than discarding it. Return it, "
        'wrap it with context (`fmt.Errorf("...: %w", err)`), or log it — do not '
        "drop it with `_ = err` or an empty `if err != nil {}` body."
    ),
}

# ``RuleMetadata`` exists at import time so the variable above must be defined
# first; the registration below wires it into the registry.
register_rule(
    RuleMetadata(
        rule_id="error_handling",
        title="Swallowed Errors",
        description=(
            "Flags newly introduced error-swallowing (bare except: pass, empty "
            "catch blocks, discarded Go errors)."
        ),
        finding_ids=list(_REMEDIATIONS.keys()),
        default_severity="medium",
        confidence="medium",
        tags=["reliability", "ai", "error-handling"],
        applies_to=["*.py", "*.js", "*.ts", "*.go"],
        remediations=_REMEDIATIONS,
    )
)
