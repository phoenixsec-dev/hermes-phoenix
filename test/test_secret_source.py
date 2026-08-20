from __future__ import annotations

import re
import sys
import types
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from hermes_phoenix.config import load_plugin_config
from hermes_phoenix.errors import NetworkError
from hermes_phoenix.scrub import get_scrub_registry
from hermes_phoenix.secret_source import make_phoenix_secret_source


def _install_fake_hermes_contract(monkeypatch):
    class ErrorKind(str, Enum):
        NOT_CONFIGURED = "not_configured"
        BINARY_MISSING = "binary_missing"
        AUTH_FAILED = "auth_failed"
        AUTH_EXPIRED = "auth_expired"
        REF_INVALID = "ref_invalid"
        NETWORK = "network"
        EMPTY_VALUE = "empty_value"
        TIMEOUT = "timeout"
        INTERNAL = "internal"

    @dataclass
    class FetchResult:
        secrets: dict[str, str] = field(default_factory=dict)
        applied: list[str] = field(default_factory=list)
        skipped: list[str] = field(default_factory=list)
        warnings: list[str] = field(default_factory=list)
        error: str | None = None
        error_kind: ErrorKind | None = None
        binary_path: Path | None = None

        @property
        def ok(self):
            return self.error is None

    class SecretSource:
        api_version = 1

        def fetch_timeout_seconds(self, cfg):
            try:
                value = float((cfg or {}).get("timeout_seconds", 120))
            except (TypeError, ValueError):
                return 120.0
            return value if value > 0 else 120.0

    def is_valid_env_name(value):
        return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value or ""))

    agent = types.ModuleType("agent")
    agent.__path__ = []
    package = types.ModuleType("agent.secret_sources")
    package.__path__ = []
    base = types.ModuleType("agent.secret_sources.base")
    base.SECRET_SOURCE_API_VERSION = 1
    base.ErrorKind = ErrorKind
    base.FetchResult = FetchResult
    base.SecretSource = SecretSource
    base.is_valid_env_name = is_valid_env_name
    monkeypatch.setitem(sys.modules, "agent", agent)
    monkeypatch.setitem(sys.modules, "agent.secret_sources", package)
    monkeypatch.setitem(sys.modules, "agent.secret_sources.base", base)
    return ErrorKind, FetchResult, SecretSource


def _config(stub_phoenix, tmp_path, **extra):
    token = tmp_path / "token"
    token.write_text("test-bootstrap-token")
    token.chmod(0o600)
    return load_plugin_config(
        raw={
            "server": stub_phoenix.url,
            "token_file": str(token),
            "default_namespace": "services/hermes/example-main",
            **extra,
        },
        environ={},
        profile_name="example-main",
    )


def test_secret_source_matches_api_v1_and_fetches_without_disk_cache(monkeypatch, stub_phoenix, tmp_path):
    ErrorKind, _FetchResult, SecretSource = _install_fake_hermes_contract(monkeypatch)
    config = _config(stub_phoenix, tmp_path, seal_mode=False, role="example-runtime")
    source = make_phoenix_secret_source(lambda: config)
    assert isinstance(source, SecretSource)
    assert (source.api_version, source.name, source.label, source.shape, source.scheme) == (
        1,
        "phoenix",
        "Phoenix Secrets Manager",
        "mapped",
        "phoenix",
    )

    home = tmp_path / "hermes-home"
    home.mkdir()
    result = source.fetch(
        {
            "enabled": True,
            "timeout_seconds": 20,
            "env": {
                "CALDAV_PASSWORD": "phoenix://services/hermes/example-main/calendar/password",
            },
        },
        home,
    )
    assert result.ok is True
    assert result.error_kind is None
    assert result.secrets == {"CALDAV_PASSWORD": "synthetic-secret-value"}
    assert list(home.iterdir()) == []
    assert get_scrub_registry().scrub("later synthetic-secret-value") == (
        "later [PHOENIX-SCRUBBED:CALDAV_PASSWORD]"
    )
    resolve_request = next(item for item in stub_phoenix.requests if item["path"] == "/v1/resolve")
    assert resolve_request["headers"]["Authorization"].startswith("Bearer phxs_")
    assert "X-Phoenix-Seal-Key" not in resolve_request["headers"]


def test_secret_source_requires_valid_env_map_and_never_raises(monkeypatch, stub_phoenix, tmp_path):
    ErrorKind, _FetchResult, _SecretSource = _install_fake_hermes_contract(monkeypatch)
    source = make_phoenix_secret_source(lambda: _config(stub_phoenix, tmp_path))

    empty = source.fetch({"enabled": True, "env": {}}, tmp_path)
    assert empty.error_kind == ErrorKind.NOT_CONFIGURED
    invalid_name = source.fetch(
        {"enabled": True, "env": {"BAD-NAME": "phoenix://services/a/key"}},
        tmp_path,
    )
    assert invalid_name.error_kind == ErrorKind.REF_INVALID
    invalid_ref = source.fetch({"enabled": True, "env": {"TOKEN": "relative/key"}}, tmp_path)
    assert invalid_ref.error_kind == ErrorKind.REF_INVALID

    broken = make_phoenix_secret_source(lambda: (_ for _ in ()).throw(RuntimeError("secret-text")))
    internal = broken.fetch(
        {"enabled": True, "env": {"TOKEN": "phoenix://services/a/key"}},
        tmp_path,
    )
    assert internal.error_kind == ErrorKind.INTERNAL
    assert "secret-text" not in internal.error


def test_secret_source_maps_timeout_to_host_taxonomy(monkeypatch, stub_phoenix, tmp_path):
    ErrorKind, _FetchResult, _SecretSource = _install_fake_hermes_contract(monkeypatch)
    source = make_phoenix_secret_source(lambda: _config(stub_phoenix, tmp_path))

    def timeout(*_args, **_kwargs):
        raise NetworkError("timed out", code="PHOENIX_TIMEOUT")

    monkeypatch.setattr("hermes_phoenix.secret_source.PhoenixClient.resolve", timeout)
    result = source.fetch(
        {"enabled": True, "env": {"TOKEN": "phoenix://services/a/key"}},
        tmp_path,
    )
    assert result.error_kind == ErrorKind.TIMEOUT
    assert result.secrets == {}
