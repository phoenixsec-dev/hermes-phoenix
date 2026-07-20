from __future__ import annotations

import pytest

from hermes_phoenix.client import CallerContext, PhoenixClient
from hermes_phoenix.config import load_plugin_config
from hermes_phoenix.errors import ApiError, ConfigurationError


def _config(stub_phoenix, tmp_path, **extra):
    token = tmp_path / "token"
    token.write_text("test-bootstrap-token")
    token.chmod(0o600)
    return load_plugin_config(
        raw={"server": stub_phoenix.url, "token_file": str(token), **extra},
        environ={},
        profile_name="kit-main",
    )


def test_status_authenticates_and_sends_sanitized_audit_headers(stub_phoenix, tmp_path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    result = client.status(
        caller=CallerContext(
            profile="kit-main\nforged",
            session_id="session-1",
            channel="telegram",
            tool="phoenix_status",
            task_id="task-1",
        )
    )
    assert result["ok"] is True
    assert result["health"] == {"status": "ok"}
    assert "secret-looking" not in str(result)
    policy_request = next(item for item in stub_phoenix.requests if item["path"].startswith("/v1/policy/check"))
    assert policy_request["headers"]["Authorization"] == "Bearer test-bootstrap-token"
    assert policy_request["headers"]["X-Hermes-Profile"] == "kit-main forged"
    assert policy_request["headers"]["X-Hermes-Tool"] == "phoenix_status"
    assert policy_request["headers"]["X-Hermes-Task-Id"] == "task-1"


def test_status_treats_non_string_health_status_as_reachable(stub_phoenix, tmp_path, monkeypatch):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "health", lambda **_kwargs: {"status": []})
    monkeypatch.setattr(client, "check_auth", lambda **_kwargs: None)
    result = client.status(caller=CallerContext(profile="default"))
    assert result["health"] == {"status": "reachable"}


def test_non_json_error_does_not_include_response_body(stub_phoenix, tmp_path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    with pytest.raises(ApiError) as caught:
        client._request_json("GET", "/non-json", caller=CallerContext(profile="default"))
    assert "secret-looking" not in str(caught.value)
    assert caught.value.code == "PHOENIX_NON_JSON_RESPONSE"


def test_http_error_does_not_include_server_controlled_fields(stub_phoenix, tmp_path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    with pytest.raises(ApiError) as caught:
        client._request_json("GET", "/secret-error", caller=CallerContext(profile="default"))
    rendered = str(caught.value.to_payload().as_dict())
    assert "secret-looking" not in rendered
    assert caught.value.code == "PHOENIX_AUTH_REJECTED"


def test_large_http_error_is_bounded(stub_phoenix, tmp_path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    with pytest.raises(ApiError) as caught:
        client._request_json("GET", "/large-error", caller=CallerContext(profile="default"))
    assert caught.value.code == "PHOENIX_RESPONSE_TOO_LARGE"


def test_redirects_are_not_followed(stub_phoenix, tmp_path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    with pytest.raises(ApiError) as caught:
        client._request_json("GET", "/redirect", caller=CallerContext(profile="default"))
    assert caught.value.status == 302
    assert not any(item["path"].startswith("/redirect-target") for item in stub_phoenix.requests)


def test_role_config_fails_closed(stub_phoenix, tmp_path):
    config = _config(stub_phoenix, tmp_path, role="kit-runtime")
    with pytest.raises(ConfigurationError, match="not implemented"):
        PhoenixClient(config)
