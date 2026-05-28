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
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
README = REPO_ROOT / "README.md"
COMPARISON = DOCS_DIR / "comparison.md"

# Snapshot of published tags as a fallback when the test runs outside a git
# checkout (e.g. an installed sdist). The live source of truth — used when
# available — is ``git tag -l`` in the working tree; see ``_known_tags``.
_FALLBACK_TAGS = frozenset({"v0.1.1", "v0.4.0", "v0.5.0", "v0.6.0", "v0.7.0", "v0.8.0"})


def _known_tags() -> frozenset[str]:
    """Return the set of tags that GitHub will resolve for ``dgenio/vibeguard@<ref>``.

    Prefer ``git tag -l`` so the set tracks the repo on every release without
    a manual list update — that hand-maintained list was the same staleness
    class issue #87 was filed to prevent. Fall back to a snapshot when git is
    not available (e.g. installed sdist).
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "tag", "-l"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return _FALLBACK_TAGS
    tags = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    return frozenset(tags) if tags else _FALLBACK_TAGS


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
        known_tags = _known_tags()
        for path in candidate_paths:
            if not path.exists():
                continue
            for ref in self._ACTION_REF.findall(_read(path)):
                if ref not in known_tags:
                    offenders.append((path.relative_to(REPO_ROOT), ref))
        assert not offenders, (
            "Files reference dgenio/vibeguard@<tag> for tag(s) that do not "
            f"exist: {offenders}. Update the file to a real tag, or cut the "
            f"tag before merging. See #87."
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


class TestComparisonGuide:
    """Issue #96: a dedicated comparison guide must exist, be linked from the
    README, frame VibeGuard as complementary (not a replacement), and cover
    each tool category the issue calls out."""

    def test_comparison_guide_exists(self):
        assert COMPARISON.exists(), "docs/comparison.md is missing — see #96."

    def test_readme_links_to_comparison_guide(self):
        assert "docs/comparison.md" in _read(README), (
            "README must link to docs/comparison.md so readers can find the "
            "per-tool breakdown. See #96."
        )

    def test_guide_covers_every_tool_category(self):
        assert COMPARISON.exists(), "docs/comparison.md is missing — see #96."
        text = _read(COMPARISON)
        # The five categories the issue enumerates must each be present.
        for tool in ("CodeQL", "Semgrep", "gitleaks", "Dependabot", "eslint"):
            assert tool in text, f"docs/comparison.md does not mention {tool!r} — see #96."

    def test_guide_frames_vibeguard_as_complementary(self):
        """The guide must say VibeGuard complements rather than replaces, and
        must keep the explicit 'do not use as' boundary the issue asks for."""
        assert COMPARISON.exists(), "docs/comparison.md is missing — see #96."
        text = _read(COMPARISON)
        assert "complement" in text.lower()
        assert "Use VibeGuard when" in text
        assert "Do not use VibeGuard as" in text


class TestAdoptionReadme:
    """Issue #95: the README must surface an adoption-first path — a one-line
    positioning statement plus a GitHub Actions PR-gate snippet — near the top,
    above the deep CLI reference."""

    def test_readme_has_positioning_statement(self):
        assert "deterministic pre-merge safety gate for AI-generated diffs" in _read(README), (
            "README is missing the one-line positioning statement. See #95."
        )

    def test_action_snippet_appears_before_cli_reference(self):
        """The copy-paste GitHub Actions gate must be above the fold — i.e.
        before the deep `## CLI Reference` section — so a reader sees the
        adoption path without scrolling the whole README."""
        text = _read(README)
        gate_idx = text.find("dgenio/vibeguard@")
        cli_idx = text.find("## CLI Reference")
        assert gate_idx != -1, "README has no GitHub Action snippet — see #95."
        assert cli_idx != -1, "README is missing its CLI Reference section."
        assert gate_idx < cli_idx, (
            "The GitHub Actions gate snippet must appear before the CLI "
            "reference so the adoption path is above the fold. See #95."
        )


class TestEcosystemNote:
    """Issue #104: the README must explain where VibeGuard fits in a broader
    ecosystem while making clear it remains fully standalone."""

    def test_readme_has_ecosystem_section(self):
        assert "## Ecosystem" in _read(README), "README is missing the ## Ecosystem note. See #104."

    def test_ecosystem_note_states_standalone(self):
        text = _read(README)
        _, sep, ecosystem = text.partition("## Ecosystem")
        assert sep, "README is missing the ## Ecosystem note. See #104."
        assert "standalone" in ecosystem.lower(), (
            "The ecosystem note must state that VibeGuard is fully standalone. See #104."
        )
