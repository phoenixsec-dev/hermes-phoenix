from __future__ import annotations

import json

from hermes_phoenix.config import load_plugin_config
from hermes_phoenix.scrub import get_scrub_registry
from hermes_phoenix.tools import make_list_handler, make_resolve_handler, status_payload

SEAL_PRIVATE_KEY = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="


def _loader(stub_phoenix, tmp_path, *, enable_resolve=False, **extra):
    token = tmp_path / "token"
    token.write_text("test-bootstrap-token")
    token.chmod(0o600)
    config = load_plugin_config(
        raw={
            "server": stub_phoenix.url,
            "token_file": str(token),
            "default_namespace": "services/hermes/example-main",
            "enable_resolve": enable_resolve,
            **extra,
        },
        environ={},
        profile_name="example-main",
    )
    return lambda: config


def test_list_handler_returns_paths_without_values(stub_phoenix, tmp_path):
    payload = json.loads(
        make_list_handler(_loader(stub_phoenix, tmp_path))(
            {},
            session_id="session-1",
            platform="telegram",
        )
    )
    assert payload["ok"] is True
    assert payload["count"] == 2
    assert payload["prefix"] == "services/hermes/example-main/"
    assert "synthetic-secret-value" not in str(payload)
    request = next(item for item in stub_phoenix.requests if item["path"].startswith("/v1/secrets/"))
    assert "X-Hermes-Channel" not in request["headers"]
    assert request["headers"]["X-Phoenix-Tool"] == "phoenix_list"


def test_list_handler_treats_null_paths_as_successful_empty_result(stub_phoenix, tmp_path):
    stub_phoenix.list_payload = {"paths": None}
    payload = json.loads(make_list_handler(_loader(stub_phoenix, tmp_path))({}))
    assert payload == {
        "count": 0,
        "ok": True,
        "paths": [],
        "prefix": "services/hermes/example-main/",
    }


def test_resolve_handler_reports_partial_plaintext_result(stub_phoenix, tmp_path):
    payload = json.loads(
        make_resolve_handler(_loader(stub_phoenix, tmp_path, enable_resolve=True))(
            {"refs": ["calendar/password", "missing"]},
            task_id="task-1",
        )
    )
    assert payload["ok"] is False
    assert payload["partial"] is True
    assert payload["mode"] == "plaintext"
    assert payload["requested"] == 2
    assert payload["resolved"] == 1
    assert payload["values"] == {
        "phoenix://services/hermes/example-main/calendar/password": "synthetic-secret-value"
    }
    assert "secret-looking" not in str(payload)


def test_direct_unsealed_resolve_remains_plaintext_but_registers_subsequent_scrubbing(stub_phoenix, tmp_path):
    payload = json.loads(
        make_resolve_handler(_loader(stub_phoenix, tmp_path, enable_resolve=True))(
            {"refs": ["calendar/password"]}
        )
    )
    assert payload["values"]["phoenix://services/hermes/example-main/calendar/password"] == "synthetic-secret-value"
    assert get_scrub_registry().scrub("later synthetic-secret-value output") == (
        "later [PHOENIX-SCRUBBED:password] output"
    )


def test_sealed_resolve_handler_returns_no_plaintext(stub_phoenix, tmp_path):
    seal_key = tmp_path / "seal.key"
    seal_key.write_text(SEAL_PRIVATE_KEY)
    seal_key.chmod(0o600)
    payload = json.loads(
        make_resolve_handler(
            _loader(
                stub_phoenix,
                tmp_path,
                enable_resolve=True,
                seal_mode=True,
                seal_key_file=str(seal_key),
            )
        )({"refs": ["calendar/password"]})
    )
    assert payload["ok"] is True
    assert payload["mode"] == "sealed"
    assert payload["values"]["phoenix://services/hermes/example-main/calendar/password"].startswith(
        "PHOENIX_SEALED:"
    )
    assert "synthetic-secret-value" not in str(payload)


def test_resolve_handler_rechecks_plugin_gate_at_call_time(stub_phoenix, tmp_path):
    payload = json.loads(
        make_resolve_handler(_loader(stub_phoenix, tmp_path))({"refs": ["calendar/password"]})
    )
    assert payload["ok"] is False
    assert payload["error"]["code"] == "PHOENIX_RESOLVE_DISABLED"
    assert not any(item["path"] == "/v1/resolve" for item in stub_phoenix.requests)


def test_resolve_handler_rejects_empty_or_extra_arguments(stub_phoenix, tmp_path):
    handler = make_resolve_handler(_loader(stub_phoenix, tmp_path, enable_resolve=True))
    for args in ({"refs": []}, {"refs": ["calendar/password"], "extra": True}):
        payload = json.loads(handler(args))
        assert payload["ok"] is False
        assert payload["error"]["type"] == "configuration_error"
    assert not any(item["path"] == "/v1/resolve" for item in stub_phoenix.requests)


def test_list_handler_rejects_non_string_prefix(stub_phoenix, tmp_path):
    payload = json.loads(make_list_handler(_loader(stub_phoenix, tmp_path))({"prefix": ["unsafe"]}))
    assert payload["ok"] is False
    assert payload["error"]["type"] == "configuration_error"
    assert not any(item["path"].startswith("/v1/secrets/") for item in stub_phoenix.requests)


def test_status_payload_caps_timeout_and_accepts_explicit_session_channel(stub_phoenix, tmp_path, monkeypatch):
    loader = _loader(stub_phoenix, tmp_path)
    captured = {}

    class FakeClient:
        def __init__(self, config):
            captured["timeout"] = config.timeout_seconds

        def status(self, *, caller):
            captured["channel"] = caller.channel
            return {"ok": True}

    monkeypatch.setattr("hermes_phoenix.tools.PhoenixClient", FakeClient)
    assert status_payload(loader, timeout_cap=2.0, channel="telegram", platform="ignored") == {"ok": True}
    assert captured == {"timeout": 2.0, "channel": "telegram"}


def test_unexpected_status_exception_is_logged(caplog):
    def broken_loader():
        raise RuntimeError("synthetic failure")

    payload = status_payload(broken_loader)
    assert payload["ok"] is False
    assert "Unexpected Phoenix plugin error while building status payload" in caplog.text


def test_unexpected_tool_exception_is_logged(caplog):
    def broken_loader():
        raise RuntimeError("synthetic failure")

    payload = json.loads(make_list_handler(broken_loader)({}))
    assert payload["ok"] is False
    assert "Unexpected Phoenix plugin error while building tool result" in caplog.text
