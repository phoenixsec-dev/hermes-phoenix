from __future__ import annotations

import pytest

from hermes_phoenix.config import load_plugin_config
from hermes_phoenix.errors import ConfigurationError


def test_config_uses_profile_namespace_and_never_env_bearer(tmp_path):
    token_file = tmp_path / "token"
    config = load_plugin_config(
        raw={"server": "https://phoenix.example:9090", "token_file": str(token_file)},
        environ={"PHOENIX_TOKEN": "must-not-be-read"},
        profile_name="kit-main",
    )
    assert config.default_namespace == "services/hermes/kit-main"
    assert config.token_file == token_file
    assert not hasattr(config, "token")


def test_config_supports_mtls_without_bearer(tmp_path):
    config = load_plugin_config(
        raw={
            "server": "https://phoenix.example:9090/",
            "client_cert": str(tmp_path / "client.crt"),
            "client_key": str(tmp_path / "client.key"),
        },
        environ={},
    )
    assert config.auth_mode == "mtls"
    assert config.server == "https://phoenix.example:9090"


@pytest.mark.parametrize(
    "raw, message",
    [
        ({"server": "file:///tmp/socket", "token_file": "/tmp/token"}, "http:// or https://"),
        ({"server": "http://phoenix.example:9090", "token_file": "/tmp/token"}, "must use https://"),
        ({"server": "https://phoenix.example/api", "token_file": "/tmp/token"}, "must not contain a path"),
        ({"server": "https://phoenix.example", "token_file": "/tmp/token", "unknown": True}, "Unknown"),
        ({"server": "https://phoenix.example", "token_file": "relative/token"}, "absolute path"),
        ({"server": "https://phoenix.example", "token_file": "/tmp/token", "default_namespace": "../escape"}, "invalid path segment"),
        ({"server": "https://phoenix.example", "token_file": "/tmp/token", "seal_mode": True}, "seal_key_file"),
    ],
)
def test_config_rejects_unsafe_values(raw, message):
    with pytest.raises(ConfigurationError, match=message):
        load_plugin_config(raw=raw, environ={})
