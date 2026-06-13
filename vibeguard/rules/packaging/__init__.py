"""Packaging hygiene rule — detect publish leaks (#201).

Historically a single 914-line module, ``packaging`` audits two largely
independent ecosystems: npm publish semantics and Python sdist/wheel packaging.
The checks are now split by ecosystem into :mod:`._npm` and :mod:`._python`,
with the shared dangerous-pattern catalogue and root-artifact leak detector in
:mod:`._common`. The public surface is unchanged — ``PackagingRule``, the
``packaging`` rule id, every finding id, all severities, and the ``packaging:``
config section are byte-identical to the pre-split module, and
``from vibeguard.rules.packaging import PackagingRule`` still works.
"""

from __future__ import annotations

from pathlib import Path

from vibeguard.models import Finding, ScanContext
from vibeguard.rules.base import Rule
from vibeguard.rules.packaging import _npm, _python
from vibeguard.rules.packaging._common import RULE_ID, check_root_artifacts
from vibeguard.rules.registry import RuleMetadata, register_rule

__all__ = ["PackagingRule"]


class PackagingRule(Rule):
    id = RULE_ID
    name = "Packaging Hygiene"
    description = "Detects files that should not be published in Python or Node packages"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        # `package.json` / `pyproject.toml` are the publish-entry manifests we
        # use to anchor leakage checks. Track which package roots we've already
        # audited so a monorepo with multiple manifests still produces one set
        # of root-level findings per package (not N copies).
        audited_roots: set[Path] = set()

        for path in files_to_check:
            rel = self._rel(context, path)

            if path.name == "package.json":
                findings.extend(_npm.check_package_json(path, rel, context))
                pkg_root = path.parent
                if pkg_root not in audited_roots:
                    audited_roots.add(pkg_root)
                    findings.extend(check_root_artifacts(pkg_root, context, ecosystem="npm"))

            elif path.name == "pyproject.toml":
                findings.extend(_python.check_pyproject(path, rel, context))
                pkg_root = path.parent
                if pkg_root not in audited_roots:
                    audited_roots.add(pkg_root)
                    findings.extend(check_root_artifacts(pkg_root, context, ecosystem="python"))

            elif path.name == "MANIFEST.in":
                findings.extend(_python.check_manifest_in(path, rel))

            elif path.name == "setup.cfg":
                findings.extend(_python.check_setup_cfg(path, rel))

            elif path.name == ".npmignore":
                findings.extend(_npm.check_npmignore(path, rel))

        return findings


register_rule(
    RuleMetadata(
        rule_id="packaging",
        title="Packaging Hygiene",
        description=(
            "Detects files that should not be published in npm/PyPI packages: "
            "secrets, test data, build configs, source maps."
        ),
        finding_ids=[
            "PKG-NPMFILES",
            "PKG-NPMBROAD",
            "PKG-NPMLEAK",
            "PKG-PYBROAD",
            "PKG-PYLEAK",
            "PKG-MANIFESTLEAK",
            "PKG-MANIFEST-GRAFT",
            "PKG-MANIFEST-RECURSIVE",
            "PKG-NPMIGNORE-NEGATE",
            "PKG-NPMIGNORE-BROAD",
            "PKG-COVERAGE-LEAK",
            "PKG-CI-LEAK",
            "PKG-PREPARE-SCRIPT",
            "PKG-SETUPPYLEAK",
        ],
        default_severity="medium",
        confidence="high",
        tags=["packaging", "supply-chain"],
        applies_to=["package.json", "pyproject.toml", "MANIFEST.in", "setup.cfg", ".npmignore"],
        remediations={
            "PKG-NPMFILES": (
                "Trim the `files` array in `package.json` to only the runtime "
                "artifacts. Move tests, fixtures, and dev configs outside the "
                "published tree."
            ),
            "PKG-NPMBROAD": (
                "Replace broad `files` patterns (`./`, `*`, `**`) with a "
                "curated allow-list. The default whole-directory publish "
                "leaks tests, .env, and tooling configs."
            ),
            "PKG-NPMLEAK": (
                "Remove the leaking entry (`.env`, secrets, fixtures) from "
                "the npm `files` list. Rotate any credential that may have "
                "been packaged in a prior release."
            ),
            "PKG-PYBROAD": (
                "Replace `include = ['*']` or `packages = find_packages()` "
                "with an explicit list of importable modules so internal "
                "tooling is excluded from the wheel."
            ),
            "PKG-PYLEAK": (
                "Remove the sensitive file from the sdist/wheel by tightening "
                "`MANIFEST.in`, `tool.hatch.build.include`, or your build "
                "backend's package list. Rotate any leaked credential."
            ),
            "PKG-MANIFESTLEAK": (
                "Edit `MANIFEST.in` to remove the entry that pulls in "
                "sensitive files. Run `python -m build` and inspect the sdist "
                "to confirm the file is gone."
            ),
            "PKG-MANIFEST-GRAFT": (
                "Replace `graft` with a narrow `include` directive scoped to "
                "the specific files you need. `graft` recursively pulls in "
                "every file under a tree and is prone to leaks."
            ),
            "PKG-MANIFEST-RECURSIVE": (
                "Replace recursive globs (e.g. `recursive-include * *`) with "
                "explicit, scoped include rules so you can see what ships."
            ),
            "PKG-NPMIGNORE-NEGATE": (
                "Avoid `!`-prefixed re-includes in `.npmignore`. They are "
                "easy to misread and tend to re-add the very files you "
                "intended to exclude."
            ),
            "PKG-NPMIGNORE-BROAD": (
                "Tighten the `.npmignore` rule. Broad patterns like `*` "
                "without matching re-includes can silently include or "
                "exclude entire directories."
            ),
            "PKG-COVERAGE-LEAK": (
                "Add coverage artefacts (`.coverage`, `coverage.xml`, "
                "`htmlcov/`) to `.npmignore`/`MANIFEST.in` exclusions so "
                "they never ship to a registry."
            ),
            "PKG-CI-LEAK": (
                "Exclude `.github/`, `.gitlab-ci.yml`, and similar CI "
                "configuration from the published package. They reveal your "
                "internal pipeline and can leak secret-injection hints."
            ),
            "PKG-PREPARE-SCRIPT": (
                "Review the `prepare`/`postinstall` script for side effects. "
                "Lifecycle scripts run automatically on every install and "
                "are a common supply-chain attack vector."
            ),
            "PKG-SETUPPYLEAK": (
                "Remove the leaking entry from `setup.py`/`setup.cfg`. Inspect "
                "the built sdist (`tar tf dist/*.tar.gz`) to confirm only the "
                "intended files ship."
            ),
        },
    )
)
