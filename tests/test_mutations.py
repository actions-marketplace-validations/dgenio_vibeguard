"""Tests that mutation-style fixtures still trigger their expected findings (#59).

AI coding agents produce characteristic failure patterns: auth commented out,
CORS opened to ``*``, SSL verification disabled, JWT alg=none, hardcoded
admin credentials, stub secrets, package include lists widened, and so on.
These tests guard those patterns explicitly so a future rule refactor that
silently misses a category fails CI here.

The fixtures live in ``tests/fixtures/mutations/``. Each test copies the
fixture into a tmp directory and runs the full scanner so the assertion
exercises rules + scanner orchestration.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from vibeguard.config import VibeGuardConfig
from vibeguard.models import Severity
from vibeguard.scanner import run_scan

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "mutations"


# (fixture filename, acceptable finding IDs, minimum severity, optional
# staged filename override). Override is used for rules that key on an
# exact filename (e.g. PackagingRule only acts on a file literally named
# ``package.json``; ``SecretsRule`` only emits SEC-ENV for ``.env``).
#
# Multiple acceptable IDs are listed where more than one rule legitimately
# covers the mutation (e.g. ssl_verify_disabled.py is caught by both
# AUTH-VERIFY-FALSE and AI-TRUSTALLCERTS / RISK-TRUSTCERTS).
_MUTATIONS: list[tuple[str, list[str], Severity, str | None]] = [
    (
        "auth_commented_out.py",
        ["AUTH-COMMENTED-AUTH", "AUTH-DISABLED-MIDDLEWARE", "AUTH-BYPASS-COMMENT"],
        Severity.MEDIUM,
        None,
    ),
    (
        "cors_opened.js",
        ["RISK-CORSCONFIG", "AI-CORSWILDCARD"],
        Severity.MEDIUM,
        None,
    ),
    (
        "ssl_verify_disabled.py",
        ["AUTH-VERIFY-FALSE", "AI-TRUSTALLCERTS", "RISK-TRUSTCERTS"],
        Severity.MEDIUM,
        None,
    ),
    (
        "jwt_none.py",
        ["AUTH-JWT-NONE"],
        Severity.HIGH,
        None,
    ),
    (
        "stub_credentials.env",
        # Staged as `.env` so the SEC-ENV file-level finding triggers in
        # addition to the per-line secret detections.
        ["SEC-ENV", "SEC-AWSACCESSKEY", "SEC-GITHUBTOKEN", "SEC-DATABASEURL"],
        Severity.HIGH,
        ".env",
    ),
    (
        "eval_with_input.py",
        ["RISK-EVALEXEC"],
        Severity.MEDIUM,
        None,
    ),
    (
        "disable_security.py",
        ["AI-DISABLESECURITY"],
        Severity.MEDIUM,
        None,
    ),
    (
        "trust_all_certs.py",
        ["AI-TRUSTALLCERTS", "AUTH-VERIFY-FALSE", "RISK-TRUSTCERTS"],
        Severity.MEDIUM,
        None,
    ),
    (
        "hardcoded_admin.py",
        ["AUTH-HARDCODED-ADMIN", "AI-PLACEHOLDERCRED"],
        Severity.MEDIUM,
        None,
    ),
    (
        "package_files_widened.json",
        ["PKG-NPMBROAD", "PKG-NPMLEAK"],
        Severity.MEDIUM,
        "package.json",
    ),
]


def _stage_fixture(fixture_name: str, dest: Path, staged_name: str | None) -> Path:
    """Copy a mutation fixture into a fresh tmp tree and return its path."""
    src = FIXTURES_DIR / fixture_name
    if not src.exists():
        pytest.fail(f"Missing mutation fixture: {src}")
    # Use a neutral ``src/`` layout so the scanner does not classify the
    # file as a test fixture and downgrade severities. ``staged_name``
    # lets specific cases land at a path that the rule cares about
    # (e.g. ``.env`` for SEC-ENV, ``package.json`` for PKG-* rules).
    target = dest / "src" / (staged_name or fixture_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(src, target)
    return target


@pytest.mark.parametrize(
    "fixture_name,expected_ids,min_severity,staged_name",
    _MUTATIONS,
    ids=[m[0] for m in _MUTATIONS],
)
def test_mutation_is_detected(
    fixture_name: str,
    expected_ids: list[str],
    min_severity: Severity,
    staged_name: str | None,
    tmp_path: Path,
) -> None:
    """Each mutation fixture must trigger one of its expected finding IDs."""
    _stage_fixture(fixture_name, tmp_path, staged_name)
    cfg = VibeGuardConfig()
    result = run_scan(tmp_path, cfg)
    finding_ids = {f.id for f in result.findings}

    hit_ids = finding_ids & set(expected_ids)
    assert hit_ids, (
        f"Mutation `{fixture_name}` produced no expected finding. "
        f"Expected one of {expected_ids}. Got: {sorted(finding_ids)}"
    )

    # At least one of the hit findings should meet the minimum severity.
    severities = [f.severity for f in result.findings if f.id in hit_ids]
    assert any(s >= min_severity for s in severities), (
        f"Mutation `{fixture_name}` hit {sorted(hit_ids)} but at severities "
        f"{[s.value for s in severities]}, none meeting min={min_severity.value}."
    )


def test_every_mutation_fixture_is_covered() -> None:
    """Guard against fixtures being added without test coverage."""
    covered = {name for name, _ids, _sev, _staged in _MUTATIONS}
    actual = {p.name for p in FIXTURES_DIR.iterdir() if p.is_file() and p.name != "__init__.py"}
    missing_in_test = actual - covered
    missing_on_disk = covered - actual
    assert not missing_in_test, (
        f"Mutation fixtures exist on disk but no test covers them: {sorted(missing_in_test)}. "
        "Add an entry to _MUTATIONS."
    )
    assert not missing_on_disk, (
        f"_MUTATIONS lists fixtures that do not exist on disk: {sorted(missing_on_disk)}."
    )
