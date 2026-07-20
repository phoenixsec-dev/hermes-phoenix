from __future__ import annotations

import json

from hermes_phoenix.config import load_plugin_config
from hermes_phoenix.tools import make_list_handler, make_resolve_handler


def _loader(stub_phoenix, tmp_path):
    token = tmp_path / "token"
    token.write_text("test-bootstrap-token")
    token.chmod(0o600)
    config = load_plugin_config(
        raw={
            "server": stub_phoenix.url,
            "token_file": str(token),
            "default_namespace": "services/hermes/kit-main",
        },
        environ={},
        profile_name="kit-main",
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
    assert payload["prefix"] == "services/hermes/kit-main/"
    assert "synthetic-secret-value" not in str(payload)


def test_resolve_handler_reports_partial_plaintext_result(stub_phoenix, tmp_path):
    payload = json.loads(
        make_resolve_handler(_loader(stub_phoenix, tmp_path))(
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
        "phoenix://services/hermes/kit-main/calendar/password": "synthetic-secret-value"
    }
    assert "secret-looking" not in str(payload)


def test_resolve_handler_rejects_empty_or_extra_arguments(stub_phoenix, tmp_path):
    handler = make_resolve_handler(_loader(stub_phoenix, tmp_path))
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
