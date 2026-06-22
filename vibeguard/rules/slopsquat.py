"""Slopsquatting / AI-hallucinated-dependency detection.

LLMs routinely *hallucinate* dependency names — packages that do not exist.
Attackers register those hallucinated names ("slopsquatting") so the next
AI-generated ``pip install`` / ``npm install`` pulls malicious code. This is a
novel, AI-specific supply-chain risk that generic dependency scanners do not
check for.

Detection runs in two tiers:

**Offline (default, no network).** For each dependency declared in a manifest
that is *absent from the project's lockfile* (i.e. it was added but never
resolved/installed), flag names whose shape matches common hallucination
patterns — long, descriptive, multi-token names an agent tends to invent. The
lockfile-absence gate keeps this conservative: a real dependency the developer
installed is already pinned in the lockfile and is never flagged.

**Registry check (opt-in, network).** When ``slopsquat.registry_check`` is
enabled, the rule additionally asks the package registry whether each declared
dependency actually exists, and how old it is.

.. warning::

   Enabling ``registry_check`` makes this rule perform **network I/O** and
   become **non-deterministic**, which deviates from the
   :class:`vibeguard.rules.base.Rule` contract (rules are normally pure,
   offline and deterministic). This is a deliberate, opt-in exception: the
   default offline path honours the contract, the network lookups are isolated
   in :func:`_registry_lookup`, bounded by a timeout, and never raise. Leave
   ``registry_check`` off to keep scans fully offline.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from vibeguard.manifests import NODE_LOCKFILES as _NODE_LOCKFILES
from vibeguard.manifests import NODE_MANIFEST as _NODE_MANIFEST
from vibeguard.manifests import PY_LOCKFILES as _PY_LOCKFILES
from vibeguard.manifests import PY_MANIFEST as _PY_MANIFEST
from vibeguard.manifests import PY_REQUIREMENTS_RE as _PY_REQUIREMENTS_RE
from vibeguard.manifests import (
    lock_package_names,
    node_dependency_names,
    pyproject_dependency_names,
    requirements_dependency_names,
)
from vibeguard.models import Confidence, Finding, ScanContext, ScanDiagnostic, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule

# Manifest/lockfile parsing and the name constants above now live in
# vibeguard.manifests (#179); they are aliased here so the rule body and the
# existing tests keep their local names.

# ``_extract_lock_names`` is re-exported for the dedicated parser test and any
# caller that imported it from this module before the consolidation.
_extract_lock_names = lock_package_names

# Minimum hyphen/underscore-separated token count for a name to read as a
# "descriptive, invented" hallucination shape (e.g. ``smart-data-pipeline``).
# Two-token ecosystem names (``python-dateutil``, ``opentelemetry-api``) stay
# below the threshold so they are never flagged.
_HALLUCINATION_MIN_TOKENS = 3

# Names that pass the token gate but are common, legitimate multi-token
# packages. Keeping this allowlist tiny is fine — the lockfile-absence gate is
# the primary FP guard; this just covers very common deps added before a lock
# refresh.
_KNOWN_MULTI_TOKEN = {
    "django-rest-framework",
    "aws-cdk-lib",
    "babel-plugin-macros",
    "eslint-config-prettier",
    "types-python-dateutil",
}

_NAME_SPLIT_RE = re.compile(r"[-_.]")


def _token_count(name: str) -> int:
    """Count descriptive tokens in a package name, ignoring any scope prefix."""
    base = name.rsplit("/", 1)[-1].lstrip("@")
    return len([t for t in _NAME_SPLIT_RE.split(base) if t])


def _looks_hallucinated(name: str) -> bool:
    """Conservative name-shape heuristic for AI-invented package names."""
    if name.lower() in _KNOWN_MULTI_TOKEN:
        return False
    return _token_count(name) >= _HALLUCINATION_MIN_TOKENS


def _lockfile_covers(lock_dir: Path, manifest_dir: Path) -> bool:
    """True if a lockfile in ``lock_dir`` governs a manifest in ``manifest_dir``.

    A lockfile applies to its own directory and to any directory nested below it
    (the workspace-root case), but never to a sibling or parent package.
    """
    return lock_dir == manifest_dir or lock_dir in manifest_dir.parents


class SlopsquatRule(Rule):
    id = "slopsquat"
    name = "Slopsquatting / Hallucinated Dependency"
    description = (
        "Flags likely AI-hallucinated dependencies: descriptive multi-token "
        "names added without a lockfile entry, plus an opt-in registry "
        "existence/age check."
    )

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        files_to_check = context.changed_files if context.diff_only else context.files

        # Index every lockfile in the tree. The offline heuristic associates a
        # manifest with lockfiles in its **own directory or any ancestor** —
        # mirroring how package managers resolve a workspace (a per-package
        # lockfile, or a single lockfile at the monorepo root). A manifest in a
        # subdirectory with no lockfile at or above it is left alone rather than
        # borrowing an unrelated sibling package's lockfile, which avoids the
        # monorepo false-positives/negatives a global lockfile set would cause.
        lockfiles = [
            p for p in context.files if p.name in _NODE_LOCKFILES or p.name in _PY_LOCKFILES
        ]
        name_cache: dict[Path, set[str]] = {}

        registry_check = bool(getattr(context.config.slopsquat, "registry_check", False))
        # Cache registry lookups for the whole scan so a dependency declared in
        # several manifests (or repeated within one) costs at most one network
        # call. Keyed by (ecosystem, lower-cased name); value is the lookup's
        # ``(exists, age_days, failure)`` outcome. The ``failure`` element lets
        # the scan aggregate network degradation into one diagnostic (#191).
        registry_cache: dict[tuple[str, str], tuple[bool | None, int | None, str | None]] = {}

        for path in files_to_check:
            if path.name == _NODE_MANIFEST:
                ecosystem, lockset, deps = "npm", _NODE_LOCKFILES, self._node_deps(path)
            elif path.name == _PY_MANIFEST:
                ecosystem, lockset, deps = "pypi", _PY_LOCKFILES, self._pyproject_deps(path)
            elif _PY_REQUIREMENTS_RE.search(path.name):
                ecosystem, lockset, deps = "pypi", _PY_LOCKFILES, self._requirements_deps(path)
            else:
                continue

            applicable = [lf for lf in lockfiles if _lockfile_covers(lf.parent, path.parent)]
            has_lock = any(lf.name in lockset for lf in applicable)
            locked_names: set[str] = set()
            for lf in applicable:
                if lf not in name_cache:
                    name_cache[lf] = self._lock_names(lf)
                locked_names |= name_cache[lf]

            findings.extend(
                self._check_deps(
                    deps,
                    self._rel(context, path),
                    ecosystem,
                    has_lock,
                    locked_names,
                    registry_check,
                    context,
                    registry_cache,
                )
            )

        # Registry verification is the only networked feature; when enabled in a
        # restricted network it can fail on every lookup and otherwise look
        # identical to "ran and found nothing". Surface that degradation as a
        # single aggregated diagnostic so users know verification was skipped
        # and findings reflect offline heuristics only (#191).
        if registry_check and registry_cache:
            self._record_registry_failures(context, registry_cache)

        return findings

    @staticmethod
    def _record_registry_failures(
        context: ScanContext,
        registry_cache: dict[tuple[str, str], tuple[bool | None, int | None, str | None]],
    ) -> None:
        """Emit one aggregated diagnostic if any registry lookup failed (#191)."""
        categories = [outcome[2] for outcome in registry_cache.values() if outcome[2]]
        if not categories:
            return
        attempted = len(registry_cache)
        failed = len(categories)
        kinds = ", ".join(sorted(set(categories)))
        context.diagnostics.append(
            ScanDiagnostic(
                category="network",
                severity="warning",
                rule="slopsquat",
                message=(
                    f"slopsquat registry check: {failed}/{attempted} lookup(s) failed "
                    f"({kinds}) — registry verification was skipped for those; "
                    "findings reflect offline heuristics only."
                ),
                detail=kinds,
            )
        )

    # ------------------------------------------------------------------
    # Per-dependency evaluation
    # ------------------------------------------------------------------

    def _check_deps(
        self,
        deps: list[str],
        rel: str,
        ecosystem: str,
        has_lock: bool,
        locked_names: set[str],
        registry_check: bool,
        context: ScanContext,
        registry_cache: dict[tuple[str, str], tuple[bool | None, int | None, str | None]],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for name in deps:
            normalized = name.lower()
            in_lock = normalized in locked_names

            # Offline heuristic: descriptive multi-token name that the lockfile
            # does not vouch for. Only meaningful when a lockfile exists at all.
            if has_lock and not in_lock and _looks_hallucinated(name):
                findings.append(
                    Finding(
                        id="SLOP-HALLUCINATION-SHAPE",
                        rule=self.id,
                        title=f"Possibly hallucinated dependency: {name}",
                        description=(
                            f"`{rel}`: `{name}` has a descriptive, multi-token name typical of "
                            "AI-invented packages and is not present in any lockfile. It may be a "
                            "hallucinated dependency that an attacker has slopsquatted."
                        ),
                        severity=Severity.HIGH,
                        path=rel,
                        evidence=name,
                        recommendation=(
                            f"Confirm `{name}` is a real, intended package before installing. "
                            "Check the registry listing, ownership, and download counts."
                        ),
                        tags=["dependencies", ecosystem, "slopsquatting", "supply-chain"],
                        confidence=Confidence.LOW,
                    )
                )

            # Opt-in registry verification (network).
            if registry_check:
                findings.extend(
                    self._registry_findings(name, rel, ecosystem, context, registry_cache)
                )

        return findings

    def _registry_findings(
        self,
        name: str,
        rel: str,
        ecosystem: str,
        context: ScanContext,
        registry_cache: dict[tuple[str, str], tuple[bool | None, int | None, str | None]],
    ) -> list[Finding]:
        timeout = float(getattr(context.config.slopsquat, "registry_timeout_seconds", 3.0))
        max_age_days = int(getattr(context.config.slopsquat, "registry_max_age_days", 30))

        cache_key = (ecosystem, name.lower())
        if cache_key in registry_cache:
            exists, age_days, _failure = registry_cache[cache_key]
        else:
            exists, age_days, failure = _registry_lookup(name, ecosystem, timeout)
            registry_cache[cache_key] = (exists, age_days, failure)
        if exists is None:
            # Network failed/inconclusive — stay silent here rather than guess;
            # the failure is aggregated into one scan diagnostic later (#191).
            return []
        if not exists:
            return [
                Finding(
                    id="SLOP-REGISTRY-MISSING",
                    rule=self.id,
                    title=f"Dependency not found on registry: {name}",
                    description=(
                        f"`{rel}`: `{name}` does not exist on the {ecosystem} registry. "
                        "A non-existent dependency is a hallmark of an AI hallucination — and "
                        "the exact name an attacker would slopsquat next."
                    ),
                    severity=Severity.HIGH,
                    path=rel,
                    evidence=name,
                    recommendation=(
                        f"Remove or correct `{name}`. If you expected it to exist, the AI tool "
                        "likely hallucinated the name."
                    ),
                    tags=["dependencies", ecosystem, "slopsquatting", "supply-chain"],
                    confidence=Confidence.HIGH,
                )
            ]
        if age_days is not None and age_days <= max_age_days:
            return [
                Finding(
                    id="SLOP-REGISTRY-YOUNG",
                    rule=self.id,
                    title=f"Suspiciously new dependency: {name}",
                    description=(
                        f"`{rel}`: `{name}` was first published {age_days} day(s) ago "
                        f"(threshold: {max_age_days}). Freshly-registered packages are how "
                        "slopsquatters capture hallucinated names."
                    ),
                    severity=Severity.MEDIUM,
                    path=rel,
                    evidence=name,
                    recommendation=(
                        f"Verify `{name}` is published by a trusted maintainer before relying "
                        "on it. Brand-new packages matching a hallucinated name are high-risk."
                    ),
                    tags=["dependencies", ecosystem, "slopsquatting", "supply-chain"],
                    confidence=Confidence.MEDIUM,
                )
            ]
        return []

    # ------------------------------------------------------------------
    # Manifest / lockfile parsing
    # ------------------------------------------------------------------

    def _node_deps(self, path: Path) -> list[str]:
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:  # noqa: BLE001 — unreadable manifest yields no deps
            return []
        return node_dependency_names(text)

    def _pyproject_deps(self, path: Path) -> list[str]:
        return pyproject_dependency_names(path.read_text(encoding="utf-8", errors="replace"))

    def _requirements_deps(self, path: Path) -> list[str]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return requirements_dependency_names(text)

    def _lock_names(self, path: Path) -> set[str]:
        """Best-effort set of lower-cased package names declared in one lockfile."""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return set()
        return lock_package_names(path.name, text)

    # ``is_applicable`` left as default (True). The scan loop already filters
    # by file name, mirroring ``DependenciesRule``.


def _registry_lookup(
    name: str, ecosystem: str, timeout: float
) -> tuple[bool | None, int | None, str | None]:
    """Return ``(exists, age_days, failure)`` for a package.

    Isolated network access. Never raises. ``failure`` is ``None`` on a
    conclusive answer (the package exists, or a ``404`` proves it does not);
    otherwise it is a short category naming why the lookup could not complete —
    ``"timeout"``, ``"network"`` (DNS/connection), ``"http"`` (a non-404 status),
    or ``"error"`` (an unexpected/parse failure). ``exists`` is ``None`` whenever
    ``failure`` is set so the rule stays silent rather than guessing; the scan
    aggregates these failures into one diagnostic (#191).
    """
    import urllib.error
    import urllib.parse
    import urllib.request
    from datetime import datetime, timezone

    if ecosystem == "npm":
        # Encode each path segment fully. A scoped name (`@scope/name`) keeps its
        # single separating slash; any other slash in the name is percent-encoded
        # so it cannot alter the URL path (the host is always the fixed registry).
        if name.startswith("@") and name.count("/") == 1:
            scope, _, pkg = name[1:].partition("/")
            encoded = f"@{urllib.parse.quote(scope, safe='')}/{urllib.parse.quote(pkg, safe='')}"
        else:
            encoded = urllib.parse.quote(name, safe="")
        url = f"https://registry.npmjs.org/{encoded}"
    else:
        url = f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vibeguard-slopsquat"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https host
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        # A 404 is a conclusive "this package does not exist" — not a failure.
        if exc.code == 404:
            return False, None, None
        return None, None, "http"
    except TimeoutError:
        # socket.timeout is an alias of TimeoutError since Python 3.10.
        return None, None, "timeout"
    except urllib.error.URLError as exc:
        # URLError wraps the lower-level cause; a wrapped timeout still reads as
        # a timeout, everything else (DNS, refused connection) as a network fault.
        if isinstance(getattr(exc, "reason", None), TimeoutError):
            return None, None, "timeout"
        return None, None, "network"
    except Exception:  # noqa: BLE001 — unexpected/parse failure is inconclusive
        return None, None, "error"

    created: str | None = None
    if ecosystem == "npm":
        created = (payload.get("time") or {}).get("created")
    else:
        # Earliest upload time across all releases.
        uploads = [
            f.get("upload_time_iso_8601") or f.get("upload_time")
            for files in (payload.get("releases") or {}).values()
            for f in (files or [])
        ]
        uploads = [u for u in uploads if u]
        created = min(uploads) if uploads else None

    if not created:
        return True, None, None
    try:
        ts = created.replace("Z", "+00:00")
        published = datetime.fromisoformat(ts)
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - published).days
        return True, max(age, 0), None
    except ValueError:
        return True, None, None


register_rule(
    RuleMetadata(
        rule_id="slopsquat",
        title="Slopsquatting / Hallucinated Dependency",
        description=(
            "Flags likely AI-hallucinated dependencies. Offline by default: "
            "descriptive multi-token names added without a lockfile entry. With "
            "the opt-in `registry_check`, also verifies each dependency exists "
            "on the registry and is not suspiciously new."
        ),
        finding_ids=[
            "SLOP-HALLUCINATION-SHAPE",
            "SLOP-REGISTRY-MISSING",
            "SLOP-REGISTRY-YOUNG",
        ],
        default_severity="high",
        confidence="low",
        tags=["security", "supply-chain", "dependencies", "slopsquatting"],
        applies_to=["package.json", "pyproject.toml", "requirements*.txt"],
        remediations={
            "SLOP-HALLUCINATION-SHAPE": (
                "Confirm the package is real and intended before installing it. "
                "AI assistants invent plausible-looking package names; attackers "
                "register those names so the next install pulls malicious code. "
                "Check the registry listing, ownership, and download counts, and "
                "make sure the dependency appears in your committed lockfile."
            ),
            "SLOP-REGISTRY-MISSING": (
                "The package does not exist on the registry — the AI tool almost "
                "certainly hallucinated the name. Remove it or replace it with the "
                "real package. Do not run the install until the name is corrected, "
                "or a slopsquatter may register it first."
            ),
            "SLOP-REGISTRY-YOUNG": (
                "The package exists but was published very recently. Brand-new "
                "packages matching a hallucinated name are a classic slopsquat. "
                "Verify the maintainer and provenance before depending on it."
            ),
        },
    )
)
