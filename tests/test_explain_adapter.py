"""Tests for the explanation adapter interface (#61)."""

from __future__ import annotations

import importlib

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from vibeguard import api as vibeguard_api
from vibeguard.cli import app
from vibeguard.config import ExplainConfig, VibeGuardConfig
from vibeguard.explain import (
    ExplainAdapter,
    StaticExplainAdapter,
    get_explain_adapter,
    register_explain_adapter,
    registered_adapter_names,
)
from vibeguard.explain import registry as registry_module
from vibeguard.models import Confidence, Finding, Severity

runner = CliRunner()


def _sample_finding(finding_id: str = "SEC-ENV", rule: str = "secrets") -> Finding:
    return Finding(
        id=finding_id,
        rule=rule,
        title="sample",
        description="sample description",
        severity=Severity.HIGH,
        path="sample.py",
        recommendation="fix it",
        tags=["sample"],
        confidence=Confidence.HIGH,
    )


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------


class TestPublicApi:
    def test_explain_adapter_exported_from_api(self):
        assert hasattr(vibeguard_api, "ExplainAdapter")
        assert vibeguard_api.ExplainAdapter is ExplainAdapter
        assert "ExplainAdapter" in vibeguard_api.__all__

    def test_register_explain_adapter_exported_from_api(self):
        assert hasattr(vibeguard_api, "register_explain_adapter")
        assert vibeguard_api.register_explain_adapter is register_explain_adapter
        assert "register_explain_adapter" in vibeguard_api.__all__

    def test_explain_adapter_is_abstract(self):
        with pytest.raises(TypeError):
            ExplainAdapter()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# Static adapter behaviour
# ---------------------------------------------------------------------------


class TestStaticAdapter:
    def test_static_adapter_has_static_name(self):
        assert StaticExplainAdapter.name == "static"

    def test_curated_finding_returns_hand_written_text(self):
        adapter = StaticExplainAdapter()
        out = adapter.explain(_sample_finding(finding_id="SEC-ENV"))
        assert "Sensitive .env file" in out
        assert "git history" in out

    def test_curated_lookup_is_case_insensitive(self):
        adapter = StaticExplainAdapter()
        out = adapter.explain(_sample_finding(finding_id="sec-env"))
        assert "Sensitive .env file" in out

    def test_non_curated_falls_back_to_registry(self):
        # PKG-NPMFILES is not in the curated set, so the adapter should
        # render the parent rule's metadata.
        importlib.import_module("vibeguard.rules.packaging")
        adapter = StaticExplainAdapter()
        out = adapter.explain(_sample_finding(finding_id="PKG-NPMFILES", rule="packaging"))
        assert "Packaging Hygiene" in out
        assert "packaging" in out

    def test_unknown_rule_uses_last_resort_fallback(self):
        # A finding from an unregistered rule still produces non-empty text.
        adapter = StaticExplainAdapter()
        out = adapter.explain(_sample_finding(finding_id="UNK-XYZ", rule="not-a-real-rule"))
        assert "UNK-XYZ" in out
        assert "sample description" in out

    def test_explain_by_id_returns_none_for_uncurated(self):
        assert StaticExplainAdapter.explain_by_id("PKG-NPMFILES") is None

    def test_explain_by_id_returns_text_for_curated(self):
        out = StaticExplainAdapter.explain_by_id("SEC-ENV")
        assert out is not None
        assert "Sensitive .env file" in out

    def test_context_argument_is_ignored_by_static_adapter(self):
        adapter = StaticExplainAdapter()
        with_ctx = adapter.explain(_sample_finding("SEC-ENV"), context="surrounding code")
        without_ctx = adapter.explain(_sample_finding("SEC-ENV"))
        assert with_ctx == without_ctx


# ---------------------------------------------------------------------------
# Registry / get_explain_adapter
# ---------------------------------------------------------------------------


class _OkAdapter(ExplainAdapter):
    name = "test-ok"

    def explain(self, finding: Finding, context: str | None = None) -> str:
        del context
        return f"ok:{finding.id}"


class _NotAnAdapter:
    """Resolved by an entry point but not a subclass of ExplainAdapter."""


class TestRegistry:
    def setup_method(self):
        # Save a snapshot so each test can mutate the registry in isolation.
        self._snapshot = dict(registry_module._REGISTRY)

    def teardown_method(self):
        registry_module._REGISTRY.clear()
        registry_module._REGISTRY.update(self._snapshot)

    def test_static_is_pre_registered(self):
        assert "static" in registered_adapter_names()
        instance = get_explain_adapter("static")
        assert isinstance(instance, StaticExplainAdapter)

    def test_register_then_resolve(self):
        register_explain_adapter("test-ok", _OkAdapter)
        instance = get_explain_adapter("test-ok")
        assert isinstance(instance, _OkAdapter)
        out = instance.explain(_sample_finding("X"))
        assert out == "ok:X"

    def test_register_rejects_non_adapter_class(self):
        with pytest.raises(TypeError):
            register_explain_adapter("bad", _NotAnAdapter)  # type: ignore[arg-type]

    def test_register_rejects_empty_name(self):
        with pytest.raises(ValueError):
            register_explain_adapter("", _OkAdapter)

    def test_register_same_class_twice_is_noop(self):
        register_explain_adapter("test-ok", _OkAdapter)
        # No exception when re-registering the *same* class.
        register_explain_adapter("test-ok", _OkAdapter)

    def test_register_conflict_raises(self):
        class _OtherAdapter(ExplainAdapter):
            name = "test-ok"

            def explain(self, finding: Finding, context: str | None = None) -> str:
                del context
                return finding.id

        register_explain_adapter("test-ok", _OkAdapter)
        with pytest.raises(ValueError, match="already registered"):
            register_explain_adapter("test-ok", _OtherAdapter)

    def test_unknown_adapter_raises_with_listing(self):
        with pytest.raises(ValueError) as exc:
            get_explain_adapter("does-not-exist")
        assert "does-not-exist" in str(exc.value)
        assert "static" in str(exc.value)


# ---------------------------------------------------------------------------
# Entry-point discovery
# ---------------------------------------------------------------------------


class _FakeEntryPoint:
    """Stand-in for ``importlib.metadata.EntryPoint`` used in tests."""

    def __init__(self, name: str, obj):
        self.name = name
        self._obj = obj
        self.dist = None

    def load(self):
        if isinstance(self._obj, Exception):
            raise self._obj
        return self._obj


class TestDiscovery:
    def setup_method(self):
        self._snapshot = dict(registry_module._REGISTRY)

    def teardown_method(self):
        registry_module._REGISTRY.clear()
        registry_module._REGISTRY.update(self._snapshot)

    def test_discovery_registers_valid_adapters(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            registry_module,
            "_entry_points",
            lambda: [_FakeEntryPoint("test-ok", _OkAdapter)],
        )
        loaded, failures = registry_module.discover_adapter_plugins(register=True)
        assert [p.name for p in loaded] == ["test-ok"]
        assert failures == []
        assert "test-ok" in registered_adapter_names()

    def test_discovery_skips_non_adapter_objects(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            registry_module,
            "_entry_points",
            lambda: [_FakeEntryPoint("bogus", _NotAnAdapter)],
        )
        loaded, failures = registry_module.discover_adapter_plugins(register=True)
        assert loaded == []
        assert len(failures) == 1
        assert failures[0].name == "bogus"
        assert "ExplainAdapter" in failures[0].reason
        assert "bogus" not in registered_adapter_names()

    def test_discovery_isolates_import_failures(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(
            registry_module,
            "_entry_points",
            lambda: [_FakeEntryPoint("broken", ImportError("boom"))],
        )
        loaded, failures = registry_module.discover_adapter_plugins(register=True)
        assert loaded == []
        assert len(failures) == 1
        assert failures[0].name == "broken"
        assert "ImportError" in failures[0].reason
        # The function MUST NOT raise out — that's the whole point of the
        # best-effort discovery contract.

    def test_get_explain_adapter_lazily_runs_discovery(self, monkeypatch: pytest.MonkeyPatch):
        # The "lazy-discovery" adapter is not registered up front; we expect
        # get_explain_adapter("lazy-disc") to trigger entry-point discovery
        # and resolve it on first call.
        monkeypatch.setattr(
            registry_module,
            "_entry_points",
            lambda: [_FakeEntryPoint("lazy-disc", _OkAdapter)],
        )
        instance = get_explain_adapter("lazy-disc")
        assert isinstance(instance, _OkAdapter)

    def test_real_entry_points_function_returns_iterable(self):
        # Smoke test against the real importlib.metadata so we know the
        # private helper hasn't drifted from the CPython API.
        result = registry_module._entry_points()
        # An EntryPoints selection is iterable even when no plugins are
        # installed; we only assert iterability so the test doesn't break
        # when someone wires a real adapter entry point into this repo.
        assert list(result) is not None


# ---------------------------------------------------------------------------
# Config integration
# ---------------------------------------------------------------------------


class TestConfig:
    def test_default_explain_adapter_is_static(self):
        cfg = VibeGuardConfig()
        assert cfg.explain.adapter == "static"

    def test_custom_adapter_name_accepted(self):
        cfg = VibeGuardConfig.model_validate({"explain": {"adapter": "ollama"}})
        assert cfg.explain.adapter == "ollama"

    def test_empty_adapter_rejected(self):
        with pytest.raises(ValidationError):
            VibeGuardConfig.model_validate({"explain": {"adapter": ""}})

    def test_whitespace_only_adapter_rejected(self):
        with pytest.raises(ValidationError):
            VibeGuardConfig.model_validate({"explain": {"adapter": "   "}})

    def test_extra_keys_in_explain_rejected(self):
        with pytest.raises(ValidationError):
            VibeGuardConfig.model_validate({"explain": {"adapter": "static", "rogue": 1}})

    def test_explain_config_is_optional(self):
        # Existing configs without an `explain` block must still load cleanly.
        cfg = VibeGuardConfig.model_validate({})
        assert isinstance(cfg.explain, ExplainConfig)
        assert cfg.explain.adapter == "static"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCli:
    @pytest.fixture(autouse=True)
    def _isolate_registry(self):
        # The explain CLI resolves adapters via get_explain_adapter, which runs
        # entry-point discovery (register=True) on a cache miss and mutates the
        # module-global _REGISTRY. Snapshot/restore so a stray real adapter
        # entry point can't leak across tests and cause order-dependent flakes.
        snapshot = dict(registry_module._REGISTRY)
        yield
        registry_module._REGISTRY.clear()
        registry_module._REGISTRY.update(snapshot)

    def test_explain_default_adapter_renders_curated_text(self, tmp_path):
        result = runner.invoke(app, ["explain", "SEC-ENV", "--path", str(tmp_path)])
        assert result.exit_code == 0, result.stdout
        assert "Sensitive .env file" in result.stdout

    def test_explain_uses_static_adapter_for_uncurated_id(self, tmp_path):
        result = runner.invoke(app, ["explain", "PKG-NPMFILES", "--path", str(tmp_path)])
        assert result.exit_code == 0, result.stdout
        # Falls back to rule metadata
        assert "Packaging Hygiene" in result.stdout
        assert "packaging" in result.stdout

    def test_explain_unknown_adapter_exits_two(self, tmp_path):
        result = runner.invoke(
            app,
            [
                "explain",
                "SEC-ENV",
                "--adapter",
                "definitely-not-installed",
                "--path",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 2

    def test_explain_unknown_adapter_lists_registered(self, tmp_path):
        result = runner.invoke(
            app,
            [
                "explain",
                "SEC-ENV",
                "--adapter",
                "definitely-not-installed",
                "--path",
                str(tmp_path),
            ],
        )
        combined = result.stdout + (result.stderr or "")
        assert "static" in combined
        assert "definitely-not-installed" in combined

    def test_explain_adapter_alias_works(self, tmp_path):
        # --explain-adapter is the documented long alias for --adapter.
        result = runner.invoke(
            app,
            ["explain", "SEC-ENV", "--explain-adapter", "static", "--path", str(tmp_path)],
        )
        assert result.exit_code == 0, result.stdout
        assert "Sensitive .env file" in result.stdout

    def test_explain_uses_config_adapter_when_no_flag(self, tmp_path):
        # Write a vibeguard.yaml selecting the static adapter explicitly.
        (tmp_path / "vibeguard.yaml").write_text("explain:\n  adapter: static\n", encoding="utf-8")
        result = runner.invoke(app, ["explain", "SEC-ENV", "--path", str(tmp_path)])
        assert result.exit_code == 0, result.stdout
        assert "Sensitive .env file" in result.stdout

    def test_explain_rejects_unknown_adapter_from_config(self, tmp_path):
        (tmp_path / "vibeguard.yaml").write_text(
            "explain:\n  adapter: bogus-from-config\n", encoding="utf-8"
        )
        result = runner.invoke(app, ["explain", "SEC-ENV", "--path", str(tmp_path)])
        assert result.exit_code == 2
        combined = result.stdout + (result.stderr or "")
        assert "bogus-from-config" in combined
