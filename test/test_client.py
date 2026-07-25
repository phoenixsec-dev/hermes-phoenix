from __future__ import annotations

import pytest

from hermes_phoenix.client import CallerContext, PhoenixClient
from hermes_phoenix.config import load_plugin_config
from hermes_phoenix.errors import ApiError, ConfigurationError, IdentityError, SealedResponseError
from hermes_phoenix.scrub import get_scrub_registry

SEAL_PRIVATE_KEY = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="


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
    assert policy_request["headers"]["X-Phoenix-Tool"] == "phoenix_status"
    assert policy_request["headers"]["X-Hermes-Task-Id"] == "task-1"


def test_client_registers_runtime_bearer_with_scrubber(stub_phoenix, tmp_path):
    PhoenixClient(_config(stub_phoenix, tmp_path))
    assert get_scrub_registry().scrub("leak test-bootstrap-token now") == (
        "leak [PHOENIX-SCRUBBED:kit-main-phoenix-token] now"
    )


def test_custom_ca_file_builds_tls_12_context(stub_phoenix, tmp_path, monkeypatch):
    captured = {}

    class FakeSSLContext:
        minimum_version = None

        def load_cert_chain(self, _cert, _key):
            raise AssertionError("client certificates were not configured")

    context = FakeSSLContext()

    def fake_create_default_context(*, cafile=None):
        captured["cafile"] = cafile
        return context

    monkeypatch.setattr("hermes_phoenix.client.ssl.create_default_context", fake_create_default_context)
    ca_file = tmp_path / "phoenix-ca.pem"
    PhoenixClient(_config(stub_phoenix, tmp_path, ca_file=str(ca_file)))
    assert captured["cafile"] == str(ca_file)
    assert context.minimum_version.name == "TLSv1_2"


def test_invalid_ca_file_fails_with_safe_configuration_error(stub_phoenix, tmp_path):
    with pytest.raises(ConfigurationError) as caught:
        PhoenixClient(_config(stub_phoenix, tmp_path, ca_file=str(tmp_path / "missing-ca.pem")))
    assert caught.value.code == "PHOENIX_CA_FILE_INVALID"
    assert "missing-ca.pem" not in str(caught.value)


def test_status_remains_available_and_reports_invalid_seal_configuration_safely(stub_phoenix, tmp_path, monkeypatch):
    client = PhoenixClient(
        _config(
            stub_phoenix,
            tmp_path,
            seal_mode=True,
            seal_key_file=str(tmp_path / "missing-seal.key"),
        )
    )
    monkeypatch.setattr(client, "health", lambda **_kwargs: {"status": "ok"})
    monkeypatch.setattr(client, "check_auth", lambda **_kwargs: None)
    result = client.status(caller=CallerContext(profile="default"))
    assert result["ok"] is True
    assert result["seal_configuration"] == {"key": "invalid"}
    rendered = str(result)
    assert "missing-seal.key" not in rendered
    assert any("fails closed" in note for note in result["notes"])


def test_status_treats_non_string_health_status_as_reachable(stub_phoenix, tmp_path, monkeypatch):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "health", lambda **_kwargs: {"status": []})
    monkeypatch.setattr(client, "check_auth", lambda **_kwargs: None)
    result = client.status(caller=CallerContext(profile="default"))
    assert result["health"] == {"status": "reachable"}


def test_list_returns_only_paths_under_normalized_prefix(stub_phoenix, tmp_path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    result = client.list(caller=CallerContext(profile="kit-main", tool="phoenix_list"))
    assert result == {
        "prefix": "services/hermes/kit-main/",
        "paths": [
            "services/hermes/kit-main/calendar/password",
            "services/hermes/kit-main/storage/token",
        ],
    }
    request = next(item for item in stub_phoenix.requests if item["path"].startswith("/v1/secrets/"))
    assert request["headers"]["X-Hermes-Tool"] == "phoenix_list"


def test_resolve_normalizes_refs_and_hides_server_error_text(stub_phoenix, tmp_path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    result = client.resolve(
        ["calendar/password", "missing"],
        caller=CallerContext(profile="kit-main", tool="phoenix_resolve"),
    )
    assert result["mode"] == "plaintext"
    assert result["values"] == {
        "phoenix://services/hermes/kit-main/calendar/password": "synthetic-secret-value"
    }
    assert result["errors"] == {
        "phoenix://services/hermes/kit-main/missing": "Phoenix did not resolve this ref."
    }
    assert "secret-looking" not in str(result)
    request = next(item for item in stub_phoenix.requests if item["path"] == "/v1/resolve")
    assert request["body"]["refs"] == [
        "phoenix://services/hermes/kit-main/calendar/password",
        "phoenix://services/hermes/kit-main/missing",
    ]
    assert request["headers"]["X-Hermes-Tool"] == "phoenix_resolve"


def test_resolve_rejects_response_refs_that_were_not_requested(stub_phoenix, tmp_path, monkeypatch):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(
        client,
        "_request_json",
        lambda *_args, **_kwargs: {
            "values": {"phoenix://services/hermes/kit-main/other": "must-not-escape"},
            "errors": {},
        },
    )
    with pytest.raises(ApiError) as caught:
        client.resolve(["calendar/password"], caller=CallerContext(profile="kit-main"))
    assert caught.value.code == "PHOENIX_RESPONSE_INVALID"
    assert "must-not-escape" not in str(caught.value)


@pytest.mark.parametrize("payload", [{"paths": None}, {}])
def test_list_treats_null_or_absent_paths_as_empty(stub_phoenix, tmp_path, monkeypatch, payload):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: payload)
    assert client.list(caller=CallerContext(profile="kit-main")) == {
        "prefix": "services/hermes/kit-main/",
        "paths": [],
    }


def test_list_preserves_legal_server_path_characters(stub_phoenix, tmp_path, monkeypatch):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    path = "services/hermes/kit-main/calendar/2026 summer+east:token"
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: {"paths": [path]})
    assert client.list(caller=CallerContext(profile="kit-main"))["paths"] == [path]


@pytest.mark.parametrize("paths", ["not-a-list", [123]])
def test_list_rejects_malformed_paths(stub_phoenix, tmp_path, monkeypatch, paths):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: {"paths": paths})
    with pytest.raises(ApiError) as caught:
        client.list(caller=CallerContext(profile="kit-main"))
    assert caught.value.code == "PHOENIX_RESPONSE_INVALID"


@pytest.mark.parametrize(
    "path",
    [
        "other/key",
        "services/hermes/kit-main/../other/secret",
        "services/hermes/kit-main/./secret",
        "services/hermes/kit-main/forged\npath",
        "services/hermes/kit-main/forged\x85path",
    ],
)
def test_list_rejects_path_outside_requested_prefix(stub_phoenix, tmp_path, monkeypatch, path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: {"paths": [path]})
    with pytest.raises(ApiError) as caught:
        client.list(caller=CallerContext(profile="kit-main"))
    assert caught.value.code == "PHOENIX_RESPONSE_INVALID"


@pytest.mark.parametrize(
    "payload",
    [
        {"values": [], "errors": {}},
        {"values": {"phoenix://services/hermes/kit-main/calendar/password": 123}, "errors": {}},
        {"values": {}, "errors": []},
        {"values": {}, "errors": {"phoenix://services/hermes/kit-main/calendar/password": 123}},
    ],
)
def test_resolve_rejects_malformed_value_and_error_maps(stub_phoenix, tmp_path, monkeypatch, payload):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: payload)
    with pytest.raises(ApiError) as caught:
        client.resolve(["calendar/password"], caller=CallerContext(profile="kit-main"))
    assert caught.value.code == "PHOENIX_RESPONSE_INVALID"


def test_sealed_resolve_sends_public_key_and_returns_only_opaque_tokens(stub_phoenix, tmp_path):
    seal_key = tmp_path / "seal.key"
    seal_key.write_text(SEAL_PRIVATE_KEY)
    seal_key.chmod(0o600)
    client = PhoenixClient(
        _config(stub_phoenix, tmp_path, seal_mode=True, seal_key_file=str(seal_key))
    )
    result = client.resolve(["calendar/password"], caller=CallerContext(profile="kit-main"))
    assert result["mode"] == "sealed"
    token = result["values"]["phoenix://services/hermes/kit-main/calendar/password"]
    assert token.startswith("PHOENIX_SEALED:")
    assert "synthetic-secret-value" not in str(result)
    request = next(item for item in stub_phoenix.requests if item["path"] == "/v1/resolve")
    assert request["headers"]["X-Phoenix-Seal-Key"] == "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="


def test_sealed_resolve_rejects_plaintext_only_http_200_without_leaking_it(stub_phoenix, tmp_path, monkeypatch):
    seal_key = tmp_path / "seal.key"
    seal_key.write_text(SEAL_PRIVATE_KEY)
    seal_key.chmod(0o600)
    client = PhoenixClient(
        _config(stub_phoenix, tmp_path, seal_mode=True, seal_key_file=str(seal_key))
    )
    monkeypatch.setattr(
        client,
        "_request_json",
        lambda *_args, **_kwargs: {
            "values": {"phoenix://services/hermes/kit-main/calendar/password": "must-not-escape"},
            "errors": {},
        },
    )
    with pytest.raises(SealedResponseError) as caught:
        client.resolve(["calendar/password"], caller=CallerContext(profile="kit-main"))
    assert caught.value.code == "PHOENIX_SEALED_VALUES_MISSING"
    assert "must-not-escape" not in str(caught.value.to_payload().as_dict())


@pytest.mark.parametrize(
    "payload",
    [
        {"sealed_values": []},
        {
            "sealed_values": {
                "phoenix://services/hermes/kit-main/calendar/password": {
                    "version": 1,
                    "algorithm": "wrong",
                    "path": "services/hermes/kit-main/calendar/password",
                    "ref": "phoenix://services/hermes/kit-main/calendar/password",
                    "ephemeral_key": "must-not-escape",
                    "nonce": "must-not-escape",
                    "ciphertext": "must-not-escape",
                }
            }
        },
        {
            "sealed_values": {
                "phoenix://services/hermes/kit-main/other": {
                    "version": 1,
                    "algorithm": "x25519-xsalsa20-poly1305",
                    "path": "services/hermes/kit-main/other",
                    "ref": "phoenix://services/hermes/kit-main/other",
                    "ephemeral_key": "must-not-escape",
                    "nonce": "must-not-escape",
                    "ciphertext": "must-not-escape",
                }
            }
        },
    ],
)
def test_sealed_resolve_rejects_malformed_or_mismatched_envelopes(stub_phoenix, tmp_path, monkeypatch, payload):
    seal_key = tmp_path / "seal.key"
    seal_key.write_text(SEAL_PRIVATE_KEY)
    seal_key.chmod(0o600)
    client = PhoenixClient(
        _config(stub_phoenix, tmp_path, seal_mode=True, seal_key_file=str(seal_key))
    )
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: payload)
    with pytest.raises(SealedResponseError) as caught:
        client.resolve(["calendar/password"], caller=CallerContext(profile="kit-main"))
    assert caught.value.code == "PHOENIX_SEALED_VALUES_INVALID"
    assert "must-not-escape" not in str(caught.value.to_payload().as_dict())


def test_sealed_dry_run_sends_handshake_but_accepts_plaintext_ok_status(stub_phoenix, tmp_path):
    seal_key = tmp_path / "seal.key"
    seal_key.write_text(SEAL_PRIVATE_KEY)
    seal_key.chmod(0o600)
    client = PhoenixClient(
        _config(stub_phoenix, tmp_path, seal_mode=True, seal_key_file=str(seal_key))
    )
    result = client.resolve(
        ["calendar/password"],
        caller=CallerContext(profile="kit-main"),
        dry_run=True,
    )
    assert result == {
        "mode": "dry_run",
        "values": {"phoenix://services/hermes/kit-main/calendar/password": "ok"},
        "errors": {},
    }
    request = next(item for item in stub_phoenix.requests if item["path"] == "/v1/resolve?dry_run=true")
    assert "X-Phoenix-Seal-Key" in request["headers"]


def test_missing_or_malformed_seal_key_fails_resolve_before_network(stub_phoenix, tmp_path):
    seal_key = tmp_path / "seal.key"
    seal_key.write_text("not-base64")
    seal_key.chmod(0o600)
    client = PhoenixClient(
        _config(stub_phoenix, tmp_path, seal_mode=True, seal_key_file=str(seal_key))
    )
    with pytest.raises(IdentityError) as caught:
        client.resolve(["calendar/password"], caller=CallerContext(profile="kit-main"))
    assert caught.value.code == "PHOENIX_SEAL_KEY_INVALID"
    assert not any(item["path"].startswith("/v1/resolve") for item in stub_phoenix.requests)


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
