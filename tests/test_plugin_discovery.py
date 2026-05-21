"""Tests for ``vibeguard.rules.plugins`` entry-point discovery."""

from __future__ import annotations

from importlib import metadata as importlib_metadata

import pytest

from vibeguard.api import BaseRule, Finding, ScanContext
from vibeguard.rules import plugins as plugins_module
from vibeguard.rules.plugins import (
    ENTRY_POINT_GROUP,
    LoadedPlugin,
    PluginLoadFailure,
    discover_plugin_rules,
)


class _OkRule(BaseRule):
    id = "test-plugin-ok"
    name = "OK Plugin"
    description = "Always returns no findings."

    def scan(self, context: ScanContext) -> list[Finding]:
        del context
        return []


class _BadInitRule(BaseRule):
    id = "test-plugin-bad-init"
    name = "Bad init"
    description = "Raises in __init__."

    def __init__(self) -> None:
        raise RuntimeError("intentionally broken at construction time")

    def scan(self, context: ScanContext) -> list[Finding]:  # pragma: no cover
        del context
        return []


class _NotARule:
    """Resolved by an entry point but not a Rule subclass."""

    def __init__(self) -> None:
        self.flavour = "definitely not a rule"


class _FakeEntryPoint:
    """A stand-in for ``importlib.metadata.EntryPoint``.

    ``EntryPoint.load()`` is what the discovery layer ultimately calls;
    overriding it here lets us drive every code path without writing an
    installable package.
    """

    def __init__(
        self,
        name: str,
        value: object,
        dist_name: str | None = "test-dist",
        *,
        load_error: Exception | None = None,
    ) -> None:
        self.name = name
        self.group = ENTRY_POINT_GROUP
        self.value = value
        self._payload = value
        self._load_error = load_error

        class _Dist:
            name = dist_name

        self.dist = _Dist() if dist_name else None

    def load(self):  # mirrors EntryPoint.load
        if self._load_error is not None:
            raise self._load_error
        return self._payload


def _install_entry_points(monkeypatch: pytest.MonkeyPatch, entries: list[_FakeEntryPoint]) -> None:
    """Make ``importlib.metadata.entry_points`` return our fake set.

    ``entry_points()`` returns an ``EntryPoints`` object on 3.10+ that
    supports ``.select(group=...)``. We mimic just enough of that surface
    to keep the discovery code path unchanged.
    """

    class _EntryPoints:
        def __init__(self, items: list[_FakeEntryPoint]) -> None:
            self._items = items

        def select(self, *, group: str):
            return [e for e in self._items if e.group == group]

    monkeypatch.setattr(
        importlib_metadata,
        "entry_points",
        lambda: _EntryPoints(entries),
    )


class TestDiscoverPluginRules:
    def test_no_entry_points_returns_empty(self, monkeypatch: pytest.MonkeyPatch):
        _install_entry_points(monkeypatch, [])
        loaded, failures = discover_plugin_rules()
        assert loaded == []
        assert failures == []

    def test_successful_plugin_loaded(self, monkeypatch: pytest.MonkeyPatch):
        _install_entry_points(monkeypatch, [_FakeEntryPoint("ok", _OkRule)])
        loaded, failures = discover_plugin_rules()
        assert failures == []
        assert len(loaded) == 1
        assert isinstance(loaded[0], LoadedPlugin)
        assert loaded[0].name == "ok"
        assert loaded[0].rule.id == "test-plugin-ok"
        assert loaded[0].distribution == "test-dist"

    def test_constructor_failure_is_isolated(self, monkeypatch: pytest.MonkeyPatch, capsys):
        _install_entry_points(
            monkeypatch,
            [_FakeEntryPoint("bad", _BadInitRule), _FakeEntryPoint("ok", _OkRule)],
        )
        loaded, failures = discover_plugin_rules()
        assert [p.name for p in loaded] == ["ok"]
        assert len(failures) == 1
        assert isinstance(failures[0], PluginLoadFailure)
        assert failures[0].name == "bad"
        assert "intentionally broken" in failures[0].reason
        # Stderr warning emitted so CI logs show the failure
        err = capsys.readouterr().err
        assert "[vibeguard] plugin warning" in err
        assert "'bad'" in err

    def test_non_rule_subclass_is_rejected(self, monkeypatch: pytest.MonkeyPatch):
        _install_entry_points(monkeypatch, [_FakeEntryPoint("nope", _NotARule)])
        loaded, failures = discover_plugin_rules()
        assert loaded == []
        assert len(failures) == 1
        assert "not a subclass" in failures[0].reason or "did not produce" in failures[0].reason

    def test_disabled_plugin_is_skipped(self, monkeypatch: pytest.MonkeyPatch):
        _install_entry_points(monkeypatch, [_FakeEntryPoint("ok", _OkRule)])
        loaded, failures = discover_plugin_rules(disabled=["ok"])
        assert loaded == []
        assert failures == []

    def test_disabled_does_not_touch_other_plugins(self, monkeypatch: pytest.MonkeyPatch):
        class _Other(_OkRule):
            id = "test-plugin-other"

        _install_entry_points(
            monkeypatch,
            [_FakeEntryPoint("ok", _OkRule), _FakeEntryPoint("other", _Other)],
        )
        loaded, _failures = discover_plugin_rules(disabled=["ok"])
        assert [p.name for p in loaded] == ["other"]

    def test_import_error_during_load_is_isolated(self, monkeypatch: pytest.MonkeyPatch, capsys):
        """The most common real-world failure: broken import chain at load time."""
        _install_entry_points(
            monkeypatch,
            [
                _FakeEntryPoint(
                    "broken-import",
                    _OkRule,  # value is irrelevant — load raises before using it
                    load_error=ImportError("No module named 'nonexistent'"),
                ),
                _FakeEntryPoint("ok", _OkRule),
            ],
        )
        loaded, failures = discover_plugin_rules()
        assert [p.name for p in loaded] == ["ok"]
        assert len(failures) == 1
        assert failures[0].name == "broken-import"
        assert "ImportError" in failures[0].reason
        assert "nonexistent" in failures[0].reason
        err = capsys.readouterr().err
        assert "[vibeguard] plugin warning" in err
        assert "'broken-import'" in err


class TestPluginsModuleSanity:
    def test_entry_point_group_constant(self):
        assert plugins_module.ENTRY_POINT_GROUP == "vibeguard.rules"


class TestScannerPluginIntegration:
    """Verify that the scanner wires plugin discovery into run_scan correctly."""

    def test_plugin_findings_appear_in_scan_result(self, monkeypatch: pytest.MonkeyPatch, tmp_path):
        """A loaded plugin's findings should appear in the ScanResult."""
        from vibeguard.config import VibeGuardConfig
        from vibeguard.models import Confidence, Finding, Severity
        from vibeguard.rules import plugins as scanner_plugins_ref
        from vibeguard.scanner import run_scan

        # Create a minimal file so the scanner has something to scan
        (tmp_path / "dummy.py").write_text("# hello\n")

        expected_finding = Finding(
            id="PLUG-TEST",
            rule="test-scanner-plugin",
            title="Plugin finding",
            description="Found by plugin",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            path="dummy.py",
            recommendation="No action needed.",
        )

        class _PluginRule(BaseRule):
            id = "test-scanner-plugin"
            name = "Test Scanner Plugin"
            description = "Plugin for scanner integration test."

            def scan(self, context: ScanContext) -> list[Finding]:
                return [expected_finding]

        fake_loaded = [
            LoadedPlugin(name="test-plugin", distribution="test-dist", rule=_PluginRule())
        ]

        monkeypatch.setattr(
            scanner_plugins_ref,
            "discover_plugin_rules",
            lambda disabled=(): (fake_loaded, []),
        )
        # Also monkeypatch at the scanner module level since it imports directly
        import vibeguard.scanner as scanner_mod

        monkeypatch.setattr(
            scanner_mod, "discover_plugin_rules", lambda disabled=(): (fake_loaded, [])
        )

        config = VibeGuardConfig()
        result = run_scan(tmp_path, config)
        plugin_findings = [f for f in result.findings if f.rule == "test-scanner-plugin"]
        assert len(plugin_findings) == 1
        assert plugin_findings[0].id == "PLUG-TEST"

    def test_plugin_failures_surface_as_errors(self, monkeypatch: pytest.MonkeyPatch, tmp_path):
        """A plugin load failure should appear in scan errors."""
        from vibeguard.config import VibeGuardConfig
        from vibeguard.scanner import run_scan

        (tmp_path / "dummy.py").write_text("# hello\n")

        fake_failure = PluginLoadFailure(
            name="broken-plugin", distribution="broken-dist", reason="ImportError: no module"
        )

        import vibeguard.scanner as scanner_mod

        monkeypatch.setattr(
            scanner_mod, "discover_plugin_rules", lambda disabled=(): ([], [fake_failure])
        )

        config = VibeGuardConfig()
        result = run_scan(tmp_path, config)
        error_msgs = [e for e in result.errors if "broken-plugin" in e]
        assert len(error_msgs) == 1
        assert "failed to load" in error_msgs[0]
