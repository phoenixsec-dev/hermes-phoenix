from __future__ import annotations

from types import SimpleNamespace

from hermes_phoenix import plugin


class FakeContext:
    profile_name = "test-profile"

    def __init__(self):
        self.tools = []
        self.cli = []
        self.commands = []
        self.hooks = []

    def register_tool(self, **kwargs):
        self.tools.append(kwargs)

    def register_cli_command(self, **kwargs):
        self.cli.append(kwargs)

    def register_command(self, **kwargs):
        self.commands.append(kwargs)

    def register_hook(self, name, callback):
        self.hooks.append((name, callback))


def _registration_config(*, enable_resolve=False, warnings=()):
    return SimpleNamespace(
        enable_resolve=enable_resolve,
        configuration_warnings=warnings,
    )


def test_register_omits_plaintext_resolve_by_default_and_does_no_network(monkeypatch):
    monkeypatch.setattr(plugin, "load_plugin_config", lambda **_kwargs: _registration_config())

    def unexpected_preflight(*_args, **_kwargs):
        raise AssertionError("register() must not perform network preflight")

    monkeypatch.setattr(plugin, "status_payload", unexpected_preflight)
    ctx = FakeContext()
    plugin.register(ctx)
    assert [item["name"] for item in ctx.tools] == ["phoenix_status", "phoenix_list"]
    assert [item["toolset"] for item in ctx.tools] == ["phoenix", "phoenix_list"]
    assert [item["name"] for item in ctx.cli] == ["phoenix"]
    assert [item["name"] for item in ctx.commands] == ["phoenix"]
    assert [name for name, _callback in ctx.hooks] == ["on_session_start"]


def test_register_logs_inactive_configuration_warnings(monkeypatch, caplog):
    monkeypatch.setattr(
        plugin,
        "load_plugin_config",
        lambda **_kwargs: _registration_config(warnings=("synthetic inactive option",)),
    )
    plugin.register(FakeContext())
    assert "Phoenix configuration warning: synthetic inactive option" in caplog.text


def test_register_exposes_plaintext_resolve_only_when_explicitly_enabled(monkeypatch):
    monkeypatch.setattr(
        plugin,
        "load_plugin_config",
        lambda **_kwargs: _registration_config(enable_resolve=True),
    )
    ctx = FakeContext()
    plugin.register(ctx)
    assert [item["name"] for item in ctx.tools] == [
        "phoenix_status",
        "phoenix_list",
        "phoenix_resolve",
    ]


def test_register_fails_closed_when_config_cannot_load(monkeypatch):
    def broken_config(**_kwargs):
        raise RuntimeError("synthetic config failure")

    monkeypatch.setattr(plugin, "load_plugin_config", broken_config)
    ctx = FakeContext()
    plugin.register(ctx)
    assert [item["name"] for item in ctx.tools] == ["phoenix_status", "phoenix_list"]


def test_session_preflight_has_short_timeout_and_real_channel(monkeypatch):
    monkeypatch.setattr(plugin, "load_plugin_config", lambda **_kwargs: _registration_config())
    calls = []

    def fake_status_payload(*_args, **kwargs):
        calls.append(kwargs)
        return {"ok": True}

    monkeypatch.setattr(plugin, "status_payload", fake_status_payload)
    ctx = FakeContext()
    plugin.register(ctx)
    callback = ctx.hooks[0][1]
    callback(session_id="session-1", platform="telegram")
    callback(session_id="session-1", platform="telegram")
    assert len(calls) == 1
    assert calls[0]["channel"] == "telegram"
    assert calls[0]["timeout_cap"] == 2.0


def test_session_preflight_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(plugin, "load_plugin_config", lambda **_kwargs: _registration_config())
    calls = []
    monkeypatch.setattr(
        plugin,
        "status_payload",
        lambda *_args, **kwargs: calls.append(kwargs) or {"ok": True},
    )
    ctx = FakeContext()
    plugin.register(ctx)
    callback = ctx.hooks[0][1]
    for index in range(257):
        callback(session_id=f"session-{index}")
    callback(session_id="session-256")
    assert len(calls) == 257
    callback(session_id="session-0")
    assert len(calls) == 258
