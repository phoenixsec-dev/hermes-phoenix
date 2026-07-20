from __future__ import annotations

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


def test_register_exposes_path_b_runtime_surfaces(monkeypatch):
    monkeypatch.setattr(plugin, "status_payload", lambda *_args, **_kwargs: {"ok": True})
    ctx = FakeContext()
    plugin.register(ctx)
    assert [item["name"] for item in ctx.tools] == [
        "phoenix_status",
        "phoenix_list",
        "phoenix_resolve",
    ]
    assert [item["toolset"] for item in ctx.tools] == [
        "phoenix",
        "phoenix_list",
        "phoenix_resolve",
    ]
    assert [item["name"] for item in ctx.cli] == ["phoenix"]
    assert [item["name"] for item in ctx.commands] == ["phoenix"]
    assert [name for name, _callback in ctx.hooks] == ["on_session_start"]
