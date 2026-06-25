"""Tests for risky diff rule."""

from __future__ import annotations

from pathlib import Path

from vibeguard.config import VibeGuardConfig
from vibeguard.models import ScanContext, Severity
from vibeguard.rules.risky_diff import RiskyDiffRule


def _ctx(tmp_path: Path, files: dict[str, str], diff_only: bool = False) -> ScanContext:
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    all_files = [tmp_path / n for n in files]
    return ScanContext(
        root=tmp_path,
        config=VibeGuardConfig(),
        files=all_files,
        changed_files=all_files if diff_only else [],
        diff_only=diff_only,
    )


class TestRiskyDiffRule:
    rule = RiskyDiffRule()

    def test_eval_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.py": "result = eval(user_input)\n"})
        findings = self.rule.scan(ctx)
        assert any("EVALEXEC" in f.id for f in findings)

    def test_subprocess_shell_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"deploy.py": "subprocess.run(cmd, shell=True)\n"})
        findings = self.rule.scan(ctx)
        assert any("SUBPROCESSSHELL" in f.id for f in findings)

    def test_auth_bypass_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"auth.py": "skip_auth = True\n"})
        findings = self.rule.scan(ctx)
        assert any("AUTHBYPASS" in f.id for f in findings)

    def test_jwt_verify_false(self, tmp_path: Path):
        ctx = _ctx(
            tmp_path,
            {"auth.js": 'jwt.decode(token, secret, { algorithms: ["none"] })\n'},
        )
        findings = self.rule.scan(ctx)
        assert any("JWT" in f.id for f in findings)

    def test_deserialization_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"loader.py": "data = pickle.loads(raw_data)\n"})
        findings = self.rule.scan(ctx)
        assert any("DESERIALIZATION" in f.id for f in findings)

    def test_comment_line_skipped(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.py": "# result = eval(user_input)\n"})
        findings = self.rule.scan(ctx)
        assert not any("EVALEXEC" in f.id for f in findings)

    def test_test_file_lower_severity(self, tmp_path: Path):
        (tmp_path / "tests").mkdir()
        test_file = tmp_path / "tests" / "test_app.py"
        test_file.write_text("result = eval(user_input)\n")
        ctx = ScanContext(
            root=tmp_path,
            config=VibeGuardConfig(),
            files=[test_file],
        )
        findings = self.rule.scan(ctx)
        eval_findings = [f for f in findings if "EVALEXEC" in f.id]
        assert eval_findings
        assert eval_findings[0].severity == Severity.LOW

    def test_non_code_file_skipped(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"data.csv": "eval,exec,subprocess\n"})
        findings = self.rule.scan(ctx)
        assert len(findings) == 0

    # #138: keywords inside Python docstrings are prose, not code, and must not
    # be mistaken for risk-sensitive logic.
    def test_docstring_keyword_not_flagged(self, tmp_path: Path):
        content = '''"""Maintenance helper.

This script processes a refund and reconciles billing records.
"""


def cleanup() -> None:
    return None
'''
        ctx = _ctx(tmp_path, {"maintenance.py": content})
        findings = self.rule.scan(ctx)
        assert not any("PAYMENTLOGIC" in f.id for f in findings)

    def test_docstring_does_not_mask_following_code(self, tmp_path: Path):
        # The docstring must be skipped without swallowing real code beneath it.
        content = '''"""Charges customers."""


def charge():
    stripe.charge(amount)
'''
        ctx = _ctx(tmp_path, {"billing.py": content})
        findings = self.rule.scan(ctx)
        assert any("PAYMENTLOGIC" in f.id for f in findings)

    def test_code_sharing_line_with_triple_quote_still_flagged(self, tmp_path: Path):
        # Recall guard (#268 review): a real risky call must still flag even when
        # its arguments are a triple-quoted literal on the same line.
        ctx = _ctx(tmp_path, {"app.py": 'os.system("""rm -rf /tmp/build""")\n'})
        findings = self.rule.scan(ctx)
        assert any("SUBPROCESSSHELL" in f.id for f in findings)

    def test_cors_wildcard_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"server.js": "app.use(cors({ origins: '*' }))\n"})
        findings = self.rule.scan(ctx)
        assert any("CORS" in f.id for f in findings)

    def test_findings_not_duplicated_per_file(self, tmp_path: Path):
        """Same pattern appearing multiple times in a file should only produce one finding."""
        content = "eval(a)\neval(b)\neval(c)\n"
        ctx = _ctx(tmp_path, {"app.py": content})
        findings = self.rule.scan(ctx)
        eval_findings = [f for f in findings if "EVALEXEC" in f.id and f.path == "app.py"]
        assert len(eval_findings) == 1


class TestDebugArtifacts:
    """#206: framework debug artifacts left enabled."""

    rule = RiskyDiffRule()

    def test_django_debug_true_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.py": "DEBUG = True\n"})
        assert any(f.id == "RISK-DEBUGMODE" for f in self.rule.scan(ctx))

    def test_flask_app_run_debug_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.py": "app.run(debug=True)\n"})
        assert any(f.id == "RISK-DEBUGMODE" for f in self.rule.scan(ctx))

    def test_allowed_hosts_wildcard_detected(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.py": "ALLOWED_HOSTS = ['*']\n"})
        assert any(f.id == "RISK-ALLOWEDHOSTSWILDCARD" for f in self.rule.scan(ctx))

    def test_env_driven_debug_not_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.py": "DEBUG = os.environ.get('DEBUG') == '1'\n"})
        assert not any(f.id == "RISK-DEBUGMODE" for f in self.rule.scan(ctx))

    def test_commented_debug_not_flagged(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.py": "# DEBUG = True\n"})
        assert not any(f.id == "RISK-DEBUGMODE" for f in self.rule.scan(ctx))

    def test_settings_file_boosted_to_high(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"settings.py": "DEBUG = True\n"})
        debug = [f for f in self.rule.scan(ctx) if f.id == "RISK-DEBUGMODE"]
        assert debug and debug[0].severity == Severity.HIGH

    def test_non_settings_file_is_medium(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"app.py": "DEBUG = True\n"})
        debug = [f for f in self.rule.scan(ctx) if f.id == "RISK-DEBUGMODE"]
        assert debug and debug[0].severity == Severity.MEDIUM

    def test_config_module_boosted_to_high(self, tmp_path: Path):
        # `config.py` is a framework settings file too — boosted like settings.py.
        ctx = _ctx(tmp_path, {"config.py": "DEBUG = True\n"})
        debug = [f for f in self.rule.scan(ctx) if f.id == "RISK-DEBUGMODE"]
        assert debug and debug[0].severity == Severity.HIGH

    def test_config_directory_boosted_to_high(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"config/app.py": "DEBUG = True\n"})
        debug = [f for f in self.rule.scan(ctx) if f.id == "RISK-DEBUGMODE"]
        assert debug and debug[0].severity == Severity.HIGH
