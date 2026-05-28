"""Tests guarding against stale documentation references.

These are mechanical "did the docs drift again?" checks that catch the exact
paper-cut patterns called out in the v1 newcomer-audit issues:

- #86: `docs/plugin-api.md` had a `vibeguard-gate>=0.6,<0.7` pin that
  excluded the current release.
- #87: `docs/github-action-reference.md` / `docs/github-actions.md` referenced
  `dgenio/vibeguard@v0.2`, a tag that never existed.
- #91: `CONTRIBUTING.md` told contributors to wait for PR #74 to land — but
  PR #74 had been merged for weeks.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"

# Tags published by the project, drawn from `git tag` at the time of writing.
# Treat this list as the source of truth for "does this action ref exist".
KNOWN_TAGS = {"v0.1.1", "v0.4.0", "v0.5.0", "v0.6.0", "v0.7.0", "v0.8.0"}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class TestPluginApiDocs:
    """Issue #86: plugin pin must include the current release."""

    def test_pin_does_not_exclude_current_release(self):
        text = _read(DOCS_DIR / "plugin-api.md")
        # The historical broken pin must be gone.
        assert ">=0.6,<0.7" not in text, (
            "docs/plugin-api.md still pins vibeguard-gate>=0.6,<0.7 — "
            "that range excludes the current release. See #86."
        )

    def test_pin_mentions_plugin_api_version(self):
        """The replacement prose must teach plugin authors to track
        PLUGIN_API_VERSION (the contract that's stable) rather than the
        release version (which moves every few weeks)."""
        text = _read(DOCS_DIR / "plugin-api.md")
        assert "PLUGIN_API_VERSION" in text


class TestGitHubActionDocs:
    """Issue #87: every `dgenio/vibeguard@<ref>` in docs must resolve."""

    _ACTION_REF = re.compile(r"dgenio/vibeguard@(v[\w.]+)")

    def test_all_action_refs_are_real_tags(self):
        offenders: list[tuple[Path, str]] = []
        # Sweep docs (.md) and the top-level action manifest (action.yml)
        # together — both surface the same `dgenio/vibeguard@<tag>` ref to
        # newcomers and both have shipped with stale references before.
        candidate_paths: list[Path] = list(DOCS_DIR.rglob("*.md"))
        candidate_paths.append(REPO_ROOT / "action.yml")
        candidate_paths.append(REPO_ROOT / "README.md")
        for path in candidate_paths:
            if not path.exists():
                continue
            for ref in self._ACTION_REF.findall(_read(path)):
                if ref not in KNOWN_TAGS:
                    offenders.append((path.relative_to(REPO_ROOT), ref))
        assert not offenders, (
            "Files reference dgenio/vibeguard@<tag> for tag(s) that do not "
            f"exist: {offenders}. Update the file to a real tag or add the "
            f"new tag to KNOWN_TAGS in this test. See #87."
        )


class TestContributingNoStaleIssueRefs:
    """Issue #91: CONTRIBUTING.md must not tell readers to wait for a PR
    that has long since merged."""

    def test_no_pending_pr_references_in_contributing(self):
        text = _read(REPO_ROOT / "CONTRIBUTING.md")
        # The exact patterns the audit flagged. Both must be gone.
        assert "once PR #74 lands" not in text
        assert "until PR #" not in text.lower()

    def test_contributing_points_at_how_to_add_a_rule(self):
        """The doc that PR #74 shipped — make sure CONTRIBUTING actually
        sends people to it now."""
        text = _read(REPO_ROOT / "CONTRIBUTING.md")
        assert "docs/how-to-add-a-rule.md" in text

    def test_rule_wiring_mentions_both_locations(self):
        """The Adding-a-new-rule section must mention both wiring sites,
        not just `vibeguard/scanner.py` — see #91's second paragraph."""
        text = _read(REPO_ROOT / "CONTRIBUTING.md")
        assert "vibeguard/scanner.py" in text
        assert "load_all_builtin_rules" in text
