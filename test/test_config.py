from __future__ import annotations

import pytest

from hermes_phoenix.config import load_plugin_config
from hermes_phoenix.errors import ConfigurationError


def test_config_uses_profile_namespace_and_never_env_bearer(tmp_path):
    token_file = tmp_path / "token"
    config = load_plugin_config(
        raw={"server": "https://phoenix.example:9090", "token_file": str(token_file)},
        environ={"PHOENIX_TOKEN": "must-not-be-read"},
        profile_name="example-main",
    )
    assert config.default_namespace == "services/hermes/example-main"
    assert config.token_file == token_file
    assert config.enable_resolve is False
    assert not hasattr(config, "token")


def test_config_accepts_enable_resolve_and_custom_ca_file(tmp_path):
    ca_file = tmp_path / "phoenix-ca.pem"
    config = load_plugin_config(
        raw={
            "server": "https://phoenix.example:9090",
            "token_file": str(tmp_path / "token"),
            "ca_file": str(ca_file),
            "enable_resolve": True,
        },
        environ={},
    )
    assert config.ca_file == ca_file
    assert config.enable_resolve is True


def test_config_expands_home_in_ca_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    config = load_plugin_config(
        raw={
            "server": "https://phoenix.example:9090",
            "token_file": str(tmp_path / "token"),
            "ca_file": "~/.config/phoenix/ca.pem",
        },
        environ={},
    )
    assert config.ca_file == tmp_path / ".config/phoenix/ca.pem"


def test_config_treats_b4_and_b5_role_options_as_functional(tmp_path):
    config = load_plugin_config(
        raw={
            "server": "https://phoenix.example:9090",
            "token_file": str(tmp_path / "token"),
            "role": "example-runtime",
            "seal_mode": True,
            "seal_key_file": str(tmp_path / "seal.key"),
            "spec_path": str(tmp_path / "env-spec"),
            "scrub": {"enabled": True},
        },
        environ={},
    )
    rendered = " ".join(config.configuration_warnings)
    assert "B4" not in rendered
    assert "spec_path" not in rendered
    assert "role" not in rendered


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
        (
            {
                "server": "https://phoenix.example",
                "token_file": "/tmp/token",
                "ca_file": "/tmp/ca.pem",
                "ca_cert": "/tmp/legacy-ca.pem",
            },
            "only ca_file",
        ),
        ({"server": "https://phoenix.example", "token_file": "/tmp/token", "enable_resolve": "yes"}, "true or false"),
        (
            {
                "server": "https://phoenix.example",
                "token_file": "/tmp/token",
                "scrub": {"placeholder": "{name}-{unexpected}"},
            },
            "exactly one",
        ),
        (
            {
                "server": "https://phoenix.example",
                "token_file": "/tmp/token",
                "scrub": {"placeholder": "{name}"},
            },
            "literal delimiter",
        ),
    ],
)
def test_config_rejects_unsafe_values(raw, message):
    with pytest.raises(ConfigurationError, match=message):
        load_plugin_config(raw=raw, environ={})
