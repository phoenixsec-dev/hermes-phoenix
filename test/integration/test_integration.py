from __future__ import annotations

import json

import pytest

from hermes_phoenix.client import CallerContext, PhoenixClient
from hermes_phoenix.config import load_plugin_config
from hermes_phoenix.errors import IdentityError
from hermes_phoenix import plugin
from .harness import PhoenixServer, detect_availability, ensure_binaries

pytestmark = pytest.mark.integration


class HookContext:
    profile_name = "integration"

    def __init__(self) -> None:
        self.hooks = []

    def register_tool(self, **_kwargs):
        return None

    def register_cli_command(self, **_kwargs):
        return None

    def register_command(self, **_kwargs):
        return None

    def register_hook(self, name, callback):
        self.hooks.append((name, callback))


def test_real_phoenix_sealed_resolve_and_scrub_hooks(monkeypatch, tmp_path):
    availability = detect_availability()
    if not availability.available:
        if __import__("os").environ.get("PHOENIX_INTEGRATION_REQUIRED"):
            pytest.fail(availability.reason)
        pytest.skip(availability.reason)

    binaries = ensure_binaries(availability)
    server = PhoenixServer(binaries)
    try:
        server.init()
        server.start()
        server.cli(["set", "hermes-int/key", "-v", "synthetic-hermes-integration-value"])
        server.cli(
            [
                "agent",
                "create",
                "hermes-int",
                "-t",
                "synthetic-hermes-integration-token",
                "--acl",
                "hermes-int/*:read",
            ]
        )
        seal_key = server.run_dir / "hermes-int.seal.key"
        server.cli(["keypair", "generate", "hermes-int", "-o", str(seal_key)])
        token_file = server.run_dir / "hermes-int.token"
        token_file.write_text("synthetic-hermes-integration-token")
        token_file.chmod(0o600)

        config = load_plugin_config(
            raw={
                "server": server.url,
                "token_file": str(token_file),
                "default_namespace": "hermes-int",
                "enable_resolve": True,
                "seal_mode": True,
                "seal_key_file": str(seal_key),
            },
            environ={},
            profile_name="integration",
        )
        sealed = PhoenixClient(config).resolve(
            ["key"],
            caller=CallerContext(profile="integration", tool="phoenix_resolve"),
        )
        serialized = json.dumps(sealed, sort_keys=True)
        assert sealed["mode"] == "sealed"
        assert sealed["values"]["phoenix://hermes-int/key"].startswith("PHOENIX_SEALED:")
        assert "synthetic-hermes-integration-value" not in serialized

        # An explicitly plaintext fetch registers the synthetic value. The real
        # Hermes callbacks then scrub subsequent terminal/tool output strings.
        plain = PhoenixClient(config).resolve(
            ["key"],
            caller=CallerContext(profile="integration", tool="secret-source"),
            sealed=False,
        )
        assert plain["values"]["phoenix://hermes-int/key"] == "synthetic-hermes-integration-value"
        monkeypatch.setattr(plugin, "load_plugin_config", lambda **_kwargs: config)
        context = HookContext()
        plugin.register(context)
        hooks = dict(context.hooks)
        transformed = hooks["transform_terminal_output"](
            command="printf",
            output="synthetic-hermes-integration-value",
            returncode=0,
            task_id="integration-task",
            env_type="local",
        )
        assert transformed == "[PHOENIX-SCRUBBED:key]"
        tool_transformed = hooks["transform_tool_result"](
            tool_name="other_tool",
            args={},
            result='{"value":"synthetic-hermes-integration-value"}',
        )
        assert "synthetic-hermes-integration-value" not in tool_transformed

        missing_key_config = load_plugin_config(
            raw={
                "server": server.url,
                "token_file": str(token_file),
                "default_namespace": "hermes-int",
                "seal_mode": True,
                "seal_key_file": str(server.run_dir / "missing.seal.key"),
            },
            environ={},
            profile_name="integration",
        )
        with pytest.raises(IdentityError) as caught:
            PhoenixClient(missing_key_config).resolve(
                ["key"],
                caller=CallerContext(profile="integration"),
            )
        failure = json.dumps(caught.value.to_payload().as_dict(), sort_keys=True)
        assert "synthetic-hermes-integration-value" not in failure
        assert "synthetic-hermes-integration-token" not in failure
    finally:
        server.dispose()
        binaries.cleanup()
