from __future__ import annotations

from datetime import UTC, datetime, timedelta
import urllib.request

import pytest

from hermes_phoenix.client import CallerContext, PhoenixClient
from hermes_phoenix.config import load_plugin_config
from hermes_phoenix.errors import (
    ApiError,
    ApprovalRequiredError,
    ConfigurationError,
    IdentityError,
    SealedResponseError,
)
from hermes_phoenix.scrub import get_scrub_registry

SEAL_PRIVATE_KEY = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="


def _config(stub_phoenix, tmp_path, **extra):
    token = tmp_path / "token"
    token.write_text("test-bootstrap-token")
    token.chmod(0o600)
    return load_plugin_config(
        raw={"server": stub_phoenix.url, "token_file": str(token), **extra},
        environ={},
        profile_name="example-main",
    )


def test_status_authenticates_and_sends_sanitized_audit_headers(stub_phoenix, tmp_path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    result = client.status(
        caller=CallerContext(
            profile="example-main\nforged",
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
    assert policy_request["headers"]["X-Hermes-Profile"] == "example-main forged"
    assert policy_request["headers"]["X-Hermes-Tool"] == "phoenix_status"
    assert policy_request["headers"]["X-Phoenix-Tool"] == "phoenix_status"
    assert policy_request["headers"]["X-Hermes-Task-Id"] == "task-1"


def test_client_registers_runtime_bearer_with_scrubber(stub_phoenix, tmp_path):
    PhoenixClient(_config(stub_phoenix, tmp_path))
    assert get_scrub_registry().scrub("leak test-bootstrap-token now") == (
        "leak [PHOENIX-SCRUBBED:example-main-phoenix-token] now"
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


def test_status_with_role_and_invalid_seal_key_uses_bootstrap_and_remains_available(stub_phoenix, tmp_path):
    client = PhoenixClient(
        _config(
            stub_phoenix,
            tmp_path,
            role="example-runtime",
            seal_mode=True,
            seal_key_file=str(tmp_path / "missing-seal.key"),
        )
    )
    result = client.status(caller=CallerContext(profile="example-main", tool="phoenix_status"))
    assert result["ok"] is True
    assert result["seal_configuration"] == {"key": "invalid"}
    assert stub_phoenix.session_mint_count == 0
    policy = next(item for item in stub_phoenix.requests if item["path"].startswith("/v1/policy/check"))
    assert policy["headers"]["Authorization"] == "Bearer test-bootstrap-token"


def test_status_treats_non_string_health_status_as_reachable(stub_phoenix, tmp_path, monkeypatch):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "health", lambda **_kwargs: {"status": []})
    monkeypatch.setattr(client, "check_auth", lambda **_kwargs: None)
    result = client.status(caller=CallerContext(profile="default"))
    assert result["health"] == {"status": "reachable"}


def test_list_returns_paths_and_descriptions_only(stub_phoenix, tmp_path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    result = client.list(caller=CallerContext(profile="example-main", tool="phoenix_list"))
    assert result == {
        "prefix": "services/hermes/example-main/",
        "descriptions": True,
        "secrets": [
            {"path": "services/hermes/example-main/calendar/password", "description": "Calendar login"},
            {"path": "services/hermes/example-main/storage/token", "description": ""},
        ],
    }
    assert [item["path"] for item in stub_phoenix.requests] == ["/v1/metadata/services/hermes/example-main/"]
    assert stub_phoenix.requests[0]["headers"]["X-Hermes-Tool"] == "phoenix_list"


def test_list_falls_back_to_bare_paths_on_old_server(stub_phoenix, tmp_path):
    stub_phoenix.old_server = True
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    result = client.list(caller=CallerContext(profile="example-main"))
    assert result == {
        "prefix": "services/hermes/example-main/",
        "descriptions": False,
        "secrets": [
            {"path": "services/hermes/example-main/calendar/password", "description": ""},
            {"path": "services/hermes/example-main/storage/token", "description": ""},
        ],
    }
    assert [item["path"] for item in stub_phoenix.requests] == [
        "/v1/metadata/services/hermes/example-main/",
        "/v1/secrets/services/hermes/example-main/",
    ]


def test_list_does_not_fall_back_on_json_404(stub_phoenix, tmp_path, monkeypatch):
    # A JSON 404 comes from a handler on a current server, not a missing route.
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    with pytest.raises(ApiError) as caught:
        client.list("phoenix://services/hermes/other", caller=CallerContext(profile="example-main"))
    assert caught.value.code == "PHOENIX_HTTP_ERROR"
    assert not any(item["path"].startswith("/v1/secrets/") for item in stub_phoenix.requests)


@pytest.mark.parametrize("prefix", ["calendar", "calendar/", "calendar/*", "phoenix://services/hermes/example-main/calendar/*"])
def test_list_folder_forms_request_the_same_folder(stub_phoenix, tmp_path, prefix):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    with pytest.raises(ApiError):
        client.list(prefix, caller=CallerContext(profile="example-main"))  # stub has no such folder
    assert stub_phoenix.requests[-1]["path"] == "/v1/metadata/services/hermes/example-main/calendar/"


def test_resolve_normalizes_refs_and_hides_server_error_text(stub_phoenix, tmp_path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    result = client.resolve(
        ["calendar/password", "missing"],
        caller=CallerContext(profile="example-main", tool="phoenix_resolve"),
    )
    assert result["mode"] == "plaintext"
    assert result["values"] == {
        "phoenix://services/hermes/example-main/calendar/password": "synthetic-secret-value"
    }
    assert result["errors"] == {
        "phoenix://services/hermes/example-main/missing": "Phoenix did not resolve this ref."
    }
    assert "secret-looking" not in str(result)
    request = next(item for item in stub_phoenix.requests if item["path"] == "/v1/resolve")
    assert request["body"]["refs"] == [
        "phoenix://services/hermes/example-main/calendar/password",
        "phoenix://services/hermes/example-main/missing",
    ]
    assert request["headers"]["X-Hermes-Tool"] == "phoenix_resolve"


def test_resolve_rejects_response_refs_that_were_not_requested(stub_phoenix, tmp_path, monkeypatch):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(
        client,
        "_request_json",
        lambda *_args, **_kwargs: {
            "values": {"phoenix://services/hermes/example-main/other": "must-not-escape"},
            "errors": {},
        },
    )
    with pytest.raises(ApiError) as caught:
        client.resolve(["calendar/password"], caller=CallerContext(profile="example-main"))
    assert caught.value.code == "PHOENIX_RESPONSE_INVALID"
    assert "must-not-escape" not in str(caught.value)


@pytest.mark.parametrize("payload", [{"secrets": None}, {}])
def test_list_treats_null_or_absent_secrets_as_empty(stub_phoenix, tmp_path, monkeypatch, payload):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: payload)
    assert client.list(caller=CallerContext(profile="example-main")) == {
        "prefix": "services/hermes/example-main/",
        "descriptions": True,
        "secrets": [],
    }


def test_list_preserves_legal_server_path_characters(stub_phoenix, tmp_path, monkeypatch):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    path = "services/hermes/example-main/calendar/2026 summer+east:token"
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: {"secrets": [{"path": path}]})
    assert client.list(caller=CallerContext(profile="example-main"))["secrets"] == [{"path": path, "description": ""}]


@pytest.mark.parametrize(
    "secrets",
    ["not-a-list", [123], [{"path": 123}], [{"path": "services/hermes/example-main/x", "description": 1}]],
)
def test_list_rejects_malformed_entries(stub_phoenix, tmp_path, monkeypatch, secrets):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: {"secrets": secrets})
    with pytest.raises(ApiError) as caught:
        client.list(caller=CallerContext(profile="example-main"))
    assert caught.value.code == "PHOENIX_RESPONSE_INVALID"


@pytest.mark.parametrize(
    "path",
    [
        "other/key",
        "services/hermes/example-main/../other/secret",
        "services/hermes/example-main/./secret",
        "services/hermes/example-main/forged\npath",
        "services/hermes/example-main/forged\x85path",
    ],
)
def test_list_rejects_path_outside_requested_prefix(stub_phoenix, tmp_path, monkeypatch, path):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: {"secrets": [{"path": path}]})
    with pytest.raises(ApiError) as caught:
        client.list(caller=CallerContext(profile="example-main"))
    assert caught.value.code == "PHOENIX_RESPONSE_INVALID"


@pytest.mark.parametrize(
    "payload",
    [
        {"values": [], "errors": {}},
        {"values": {"phoenix://services/hermes/example-main/calendar/password": 123}, "errors": {}},
        {"values": {}, "errors": []},
        {"values": {}, "errors": {"phoenix://services/hermes/example-main/calendar/password": 123}},
    ],
)
def test_resolve_rejects_malformed_value_and_error_maps(stub_phoenix, tmp_path, monkeypatch, payload):
    client = PhoenixClient(_config(stub_phoenix, tmp_path))
    monkeypatch.setattr(client, "_request_json", lambda *_args, **_kwargs: payload)
    with pytest.raises(ApiError) as caught:
        client.resolve(["calendar/password"], caller=CallerContext(profile="example-main"))
    assert caught.value.code == "PHOENIX_RESPONSE_INVALID"


def test_sealed_resolve_sends_public_key_and_returns_only_opaque_tokens(stub_phoenix, tmp_path):
    seal_key = tmp_path / "seal.key"
    seal_key.write_text(SEAL_PRIVATE_KEY)
    seal_key.chmod(0o600)
    client = PhoenixClient(
        _config(stub_phoenix, tmp_path, seal_mode=True, seal_key_file=str(seal_key))
    )
    result = client.resolve(["calendar/password"], caller=CallerContext(profile="example-main"))
    assert result["mode"] == "sealed"
    token = result["values"]["phoenix://services/hermes/example-main/calendar/password"]
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
            "values": {"phoenix://services/hermes/example-main/calendar/password": "must-not-escape"},
            "errors": {},
        },
    )
    with pytest.raises(SealedResponseError) as caught:
        client.resolve(["calendar/password"], caller=CallerContext(profile="example-main"))
    assert caught.value.code == "PHOENIX_SEALED_VALUES_MISSING"
    assert "must-not-escape" not in str(caught.value.to_payload().as_dict())


@pytest.mark.parametrize(
    "payload",
    [
        {"sealed_values": []},
        {
            "sealed_values": {
                "phoenix://services/hermes/example-main/calendar/password": {
                    "version": 1,
                    "algorithm": "wrong",
                    "path": "services/hermes/example-main/calendar/password",
                    "ref": "phoenix://services/hermes/example-main/calendar/password",
                    "ephemeral_key": "must-not-escape",
                    "nonce": "must-not-escape",
                    "ciphertext": "must-not-escape",
                }
            }
        },
        {
            "sealed_values": {
                "phoenix://services/hermes/example-main/other": {
                    "version": 1,
                    "algorithm": "x25519-xsalsa20-poly1305",
                    "path": "services/hermes/example-main/other",
                    "ref": "phoenix://services/hermes/example-main/other",
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
        client.resolve(["calendar/password"], caller=CallerContext(profile="example-main"))
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
        caller=CallerContext(profile="example-main"),
        dry_run=True,
    )
    assert result == {
        "mode": "dry_run",
        "values": {"phoenix://services/hermes/example-main/calendar/password": "ok"},
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
        client.resolve(["calendar/password"], caller=CallerContext(profile="example-main"))
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


def test_role_session_mints_once_and_reuses_in_memory_token(stub_phoenix, tmp_path):
    config = _config(stub_phoenix, tmp_path, role="example-runtime")
    PhoenixClient(config).list(caller=CallerContext(profile="example-main", tool="phoenix_list"))
    PhoenixClient(config).list(caller=CallerContext(profile="example-main", tool="phoenix_list"))
    assert stub_phoenix.session_mint_count == 1
    assert stub_phoenix.session_renew_count == 0
    list_requests = [item for item in stub_phoenix.requests if item["path"].startswith("/v1/metadata/")]
    assert [item["headers"]["Authorization"] for item in list_requests] == [
        "Bearer phxs_synthetic-1",
        "Bearer phxs_synthetic-1",
    ]


def test_sealed_role_session_binds_and_reuses_public_key(stub_phoenix, tmp_path):
    seal_key = tmp_path / "seal.key"
    seal_key.write_text(SEAL_PRIVATE_KEY)
    seal_key.chmod(0o600)
    config = _config(
        stub_phoenix,
        tmp_path,
        role="example-runtime",
        seal_mode=True,
        seal_key_file=str(seal_key),
    )
    result = PhoenixClient(config).resolve(
        ["calendar/password"],
        caller=CallerContext(profile="example-main", tool="phoenix_resolve"),
    )
    assert result["mode"] == "sealed"
    mint = next(item for item in stub_phoenix.requests if item["path"] == "/v1/session/mint")
    resolve = next(item for item in stub_phoenix.requests if item["path"] == "/v1/resolve")
    expected = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
    assert mint["body"]["seal_public_key"] == expected
    assert resolve["headers"]["X-Phoenix-Seal-Key"] == expected
    assert resolve["headers"]["Authorization"] == "Bearer phxs_synthetic-1"


def test_role_session_renews_near_expiry_and_registers_token_scrubbing(stub_phoenix, tmp_path):
    stub_phoenix.session_ttl_seconds = 60
    config = _config(stub_phoenix, tmp_path, role="example-runtime")
    PhoenixClient(config).list(caller=CallerContext(profile="example-main", tool="phoenix_list"))
    PhoenixClient(config).list(caller=CallerContext(profile="example-main", tool="phoenix_list"))
    assert stub_phoenix.session_mint_count == 1
    assert stub_phoenix.session_renew_count == 1
    assert get_scrub_registry().scrub("phxs_renewed-1") == (
        "[PHOENIX-SCRUBBED:example-main-phoenix-session]"
    )


def test_expired_role_session_is_reminted(stub_phoenix, tmp_path, monkeypatch):
    import hermes_phoenix.session as session_module

    now = [datetime.now(UTC)]
    monkeypatch.setattr(session_module, "_utcnow", lambda: now[0])
    config = _config(stub_phoenix, tmp_path, role="example-runtime")
    PhoenixClient(config).list(caller=CallerContext(profile="example-main"))
    now[0] += timedelta(hours=2)
    PhoenixClient(config).list(caller=CallerContext(profile="example-main"))
    assert stub_phoenix.session_mint_count == 2
    assert stub_phoenix.session_renew_count == 0


def test_mtls_identity_rotation_at_same_paths_forces_fresh_role_mint(stub_phoenix, tmp_path, monkeypatch):
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    cert.write_text("synthetic-certificate-version-one")
    key.write_text("synthetic-private-key")
    key.chmod(0o600)
    config = load_plugin_config(
        raw={
            "server": stub_phoenix.url,
            "client_cert": str(cert),
            "client_key": str(key),
            "role": "example-runtime",
            "default_namespace": "services/hermes/example-main",
        },
        environ={},
        profile_name="example-main",
    )
    monkeypatch.setattr(
        PhoenixClient,
        "_build_opener",
        lambda _self: urllib.request.build_opener(urllib.request.ProxyHandler({})),
    )
    PhoenixClient(config).list(caller=CallerContext(profile="example-main"))
    cert.write_text("synthetic-certificate-version-two")
    PhoenixClient(config).list(caller=CallerContext(profile="example-main"))
    assert stub_phoenix.session_mint_count == 2


def test_role_session_approval_required_fails_closed_without_polling(stub_phoenix, tmp_path):
    config = _config(stub_phoenix, tmp_path, role="approval-role")
    with pytest.raises(ApprovalRequiredError) as caught:
        PhoenixClient(config).list(caller=CallerContext(profile="example-main"))
    payload = caught.value.to_payload().as_dict()
    assert payload["type"] == "approval_required"
    assert payload["code"] == "PHOENIX_APPROVAL_REQUIRED"
    assert payload["approval_id"] == "apr_synthetic"
    assert "does not poll" in payload["remediation"]
    assert not any(item["path"].startswith("/v1/approval/") for item in stub_phoenix.requests)


def test_role_session_mint_and_renewal_denials_do_not_leak_tokens_or_server_text(stub_phoenix, tmp_path):
    denied_config = _config(stub_phoenix, tmp_path, role="denied-role")
    with pytest.raises(ApiError) as mint_caught:
        PhoenixClient(denied_config).list(caller=CallerContext(profile="example-main"))
    mint_payload = str(mint_caught.value.to_payload().as_dict())
    assert mint_caught.value.code == "PHOENIX_SESSION_MINT_DENIED"
    assert "secret-looking" not in mint_payload
    assert "test-bootstrap-token" not in mint_payload

    stub_phoenix.session_ttl_seconds = 60
    config = _config(stub_phoenix, tmp_path, role="renew-denied-role")
    PhoenixClient(config).list(caller=CallerContext(profile="example-main"))
    stub_phoenix.deny_session_renewal = True
    with pytest.raises(ApiError) as renew_caught:
        PhoenixClient(config).list(caller=CallerContext(profile="example-main"))
    renew_payload = str(renew_caught.value.to_payload().as_dict())
    assert renew_caught.value.code == "PHOENIX_SESSION_RENEW_DENIED"
    assert "secret-looking" not in renew_payload
    assert "phxs_" not in renew_payload
