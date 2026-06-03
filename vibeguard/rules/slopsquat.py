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
from typing import Any

from vibeguard.models import Confidence, Finding, ScanContext, Severity
from vibeguard.rules.base import Rule
from vibeguard.rules.registry import RuleMetadata, register_rule


def _load_toml(text: str) -> dict[str, Any] | None:
    """Parse TOML text, returning None if no parser is available or it is malformed."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return None
    try:
        return tomllib.loads(text)
    except Exception:  # noqa: BLE001 — malformed TOML
        return None


# Manifest files we read declared dependencies from, keyed by ecosystem.
_NODE_MANIFEST = "package.json"
_PY_MANIFEST = "pyproject.toml"
_PY_REQUIREMENTS_RE = re.compile(r"requirements.*\.txt$")

# Lockfiles whose presence means a declared dependency has been resolved. A
# dependency *absent* from these is "added but never installed" — the shape an
# AI hallucination takes before anyone runs the package manager.
_NODE_LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
_PY_LOCKFILES = {"poetry.lock", "uv.lock", "Pipfile.lock"}

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
                )
            )

        return findings

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
                findings.extend(self._registry_findings(name, rel, ecosystem, context))

        return findings

    def _registry_findings(
        self, name: str, rel: str, ecosystem: str, context: ScanContext
    ) -> list[Finding]:
        timeout = float(getattr(context.config.slopsquat, "registry_timeout_seconds", 3.0))
        max_age_days = int(getattr(context.config.slopsquat, "registry_max_age_days", 30))

        exists, age_days = _registry_lookup(name, ecosystem, timeout)
        if exists is None:
            # Network failed/inconclusive — stay silent rather than guess.
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
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return []
        names: list[str] = []
        for group in ("dependencies", "devDependencies", "optionalDependencies"):
            block = data.get(group)
            if isinstance(block, dict):
                names.extend(str(k) for k in block)
        return names

    def _pyproject_deps(self, path: Path) -> list[str]:
        data = _load_toml(path.read_text(encoding="utf-8", errors="replace"))
        if data is None:
            return []
        raw = data.get("project", {}).get("dependencies", [])
        names: list[str] = []
        for dep in raw:
            name = _PY_NAME_RE.split(str(dep))[0].strip()
            if name:
                names.append(name)
        return names

    def _requirements_deps(self, path: Path) -> list[str]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        names: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            name = _PY_NAME_RE.split(line)[0].strip()
            if name:
                names.append(name)
        return names

    def _lock_names(self, path: Path) -> set[str]:
        """Best-effort set of lower-cased package names declared in one lockfile."""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return set()
        return _extract_lock_names(path.name, text)

    # ``is_applicable`` left as default (True). The scan loop already filters
    # by file name, mirroring ``DependenciesRule``.


# Package-name boundary for Python specifiers (e.g. ``requests>=2,<3 ; extra``).
_PY_NAME_RE = re.compile(r"[>=<!~;\s\[\]()]")

# Loose name extractors for lockfiles. These are intentionally permissive — a
# false *inclusion* only suppresses a heuristic finding, which is the safe
# direction.
_PKG_LOCK_NAME_RE = re.compile(r'"node_modules/((?:@[^/"]+/)?[^/"]+)"')
_YARN_NAME_RE = re.compile(r'^"?((?:@[^/@\s]+/)?[^@\s"]+)@', re.MULTILINE)
_POETRY_NAME_RE = re.compile(r'^name\s*=\s*"([^"]+)"', re.MULTILINE)


def _extract_lock_names(filename: str, text: str) -> set[str]:
    names: set[str] = set()
    if filename == "package-lock.json":
        try:
            data = json.loads(text)
        except Exception:  # noqa: BLE001
            data = None
        if isinstance(data, dict):
            for key in ("packages", "dependencies"):
                block = data.get(key)
                if isinstance(block, dict):
                    for raw in block:
                        leaf = str(raw).rsplit("node_modules/", 1)[-1]
                        if leaf:
                            names.add(leaf.lower())
        names.update(m.group(1).lower() for m in _PKG_LOCK_NAME_RE.finditer(text))
    elif filename in {"yarn.lock", "pnpm-lock.yaml"}:
        names.update(m.group(1).lower() for m in _YARN_NAME_RE.finditer(text))
    elif filename in {"poetry.lock", "uv.lock"}:
        names.update(m.group(1).lower() for m in _POETRY_NAME_RE.finditer(text))
    elif filename == "Pipfile.lock":
        try:
            data = json.loads(text)
        except Exception:  # noqa: BLE001
            data = None
        if isinstance(data, dict):
            for section in ("default", "develop"):
                block = data.get(section)
                if isinstance(block, dict):
                    names.update(str(k).lower() for k in block)
    return names


def _registry_lookup(name: str, ecosystem: str, timeout: float) -> tuple[bool | None, int | None]:
    """Return ``(exists, age_days)`` for a package, or ``(None, None)`` on error.

    Isolated network access. Never raises — any failure returns an inconclusive
    ``(None, None)`` so the rule stays silent rather than emitting a guess.
    """
    import urllib.error
    import urllib.parse
    import urllib.request
    from datetime import datetime, timezone

    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}"
    else:
        url = f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vibeguard-slopsquat"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https host
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False, None
        return None, None
    except Exception:  # noqa: BLE001 — network/parse failure is inconclusive
        return None, None

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
        return True, None
    try:
        ts = created.replace("Z", "+00:00")
        published = datetime.fromisoformat(ts)
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - published).days
        return True, max(age, 0)
    except ValueError:
        return True, None


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
