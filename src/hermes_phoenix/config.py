"""Profile-local plugin configuration and validation."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from .errors import ConfigurationError
from .refs import validate_namespace

_ROLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ALLOWED_KEYS = {
    "server",
    "token_file",
    "role",
    "ca_file",
    "ca_cert",
    "client_cert",
    "client_key",
    "seal_key_file",
    "seal_mode",
    "default_namespace",
    "spec_path",
    "timeout_seconds",
    "enable_resolve",
    "scrub",
}
_ALLOWED_SCRUB_KEYS = {"enabled", "placeholder"}


@dataclass(frozen=True)
class ScrubConfig:
    enabled: bool = True
    placeholder: str = "[PHOENIX-SCRUBBED:{name}]"


@dataclass(frozen=True)
class PluginConfig:
    server: str
    profile_name: str
    token_file: Path | None
    role: str | None
    ca_file: Path | None
    client_cert: Path | None
    client_key: Path | None
    seal_key_file: Path | None
    seal_mode: bool
    default_namespace: str
    spec_path: Path | None
    timeout_seconds: float
    enable_resolve: bool
    scrub: ScrubConfig
    configuration_warnings: tuple[str, ...]

    @property
    def auth_mode(self) -> str:
        bearer = self.token_file is not None
        mtls = self.client_cert is not None and self.client_key is not None
        if bearer and mtls:
            return "bearer+mTLS"
        if mtls:
            return "mtls"
        return "bearer"


def _string(value: Any, *, label: str, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ConfigurationError(f"{label} is required")
        return None
    if not isinstance(value, str):
        raise ConfigurationError(f"{label} must be a string")
    result = value.strip()
    if not result:
        if required:
            raise ConfigurationError(f"{label} is required")
        return None
    return result


def _boolean(value: Any, *, label: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigurationError(f"{label} must be true or false")
    return value


def _path(value: Any, *, label: str) -> Path | None:
    raw = _string(value, label=label)
    if raw is None:
        return None
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ConfigurationError(f"{label} must be an absolute path or start with '~/'")
    return path


def _server(value: Any) -> str:
    raw = _string(value, label="plugins.entries.phoenix.server", required=True)
    assert raw is not None
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError("Phoenix server must be an http:// or https:// URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigurationError("Phoenix server URL must not contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise ConfigurationError("Phoenix server URL must not contain a path")
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def transport_warning(server: str) -> str | None:
    """Loud, never-fatal signal for plain HTTP to a non-loopback address.

    Deliberate posture, shared with the Phoenix server and the sibling
    openclaw-phoenix plugin: warn loudly on non-loopback plaintext, never
    refuse. This replaced an earlier hard-fail so the plugin cannot be
    stricter than the server it fronts; see the Transport posture section
    of DESIGN.md for the rationale.
    """
    parsed = urlsplit(server)
    if parsed.scheme != "http":
        return None
    hostname = (parsed.hostname or "").lower()
    try:
        is_loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = hostname == "localhost"
    if is_loopback:
        return None
    return (
        f"Phoenix server {server} is plain http:// to a non-loopback address: "
        "bearer tokens and secret values cross the network in cleartext, readable by "
        "anything on the network path. Phoenix plaintext is intended for loopback only; "
        "enable TLS on the Phoenix server and switch this profile to https:// whenever "
        "requests cross a wire."
    )


def _load_hermes_entry() -> Mapping[str, Any]:
    try:
        from hermes_cli.config import cfg_get, load_config

        config = load_config() or {}
        entry = cfg_get(config, "plugins", "entries", "phoenix", default={})
    except Exception as exc:
        raise ConfigurationError(
            "Could not load plugins.entries.phoenix from the active Hermes profile"
        ) from exc
    if not isinstance(entry, Mapping):
        raise ConfigurationError("plugins.entries.phoenix must be a mapping")
    return entry


def load_plugin_config(
    *,
    raw: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] | None = None,
    profile_name: str = "default",
) -> PluginConfig:
    env = os.environ if environ is None else environ
    source = dict(_load_hermes_entry() if raw is None else raw)
    unknown = sorted(set(source) - _ALLOWED_KEYS)
    if unknown:
        raise ConfigurationError(f"Unknown Phoenix plugin config key(s): {', '.join(unknown)}")

    scrub_raw = source.get("scrub", {})
    if not isinstance(scrub_raw, Mapping):
        raise ConfigurationError("plugins.entries.phoenix.scrub must be a mapping")
    unknown_scrub = sorted(set(scrub_raw) - _ALLOWED_SCRUB_KEYS)
    if unknown_scrub:
        raise ConfigurationError(f"Unknown Phoenix scrub config key(s): {', '.join(unknown_scrub)}")

    server = _server(source.get("server") or env.get("PHOENIX_SERVER"))
    token_file = _path(
        source.get("token_file") or env.get("PHOENIX_TOKEN_FILE"),
        label="plugins.entries.phoenix.token_file",
    )
    if source.get("ca_file") and source.get("ca_cert"):
        raise ConfigurationError("Configure only ca_file; ca_cert is a deprecated alias")
    ca_file = _path(
        source.get("ca_file") or source.get("ca_cert") or env.get("PHOENIX_CA_CERT"),
        label="ca_file",
    )
    client_cert = _path(
        source.get("client_cert") or env.get("PHOENIX_CLIENT_CERT"),
        label="client_cert",
    )
    client_key = _path(
        source.get("client_key") or env.get("PHOENIX_CLIENT_KEY"),
        label="client_key",
    )
    if (client_cert is None) != (client_key is None):
        raise ConfigurationError("mTLS requires both client_cert and client_key")
    if token_file is None and client_cert is None:
        raise ConfigurationError(
            "Phoenix runtime identity requires token_file or mTLS client_cert/client_key; PHOENIX_TOKEN is intentionally unsupported"
        )

    role = _string(source.get("role") or env.get("PHOENIX_ROLE"), label="role")
    if role and not _ROLE_RE.fullmatch(role):
        raise ConfigurationError("role contains unsupported characters")

    seal_mode = _boolean(source.get("seal_mode"), label="seal_mode", default=False)
    seal_key_file = _path(
        source.get("seal_key_file") or env.get("PHOENIX_SEAL_KEY"),
        label="seal_key_file",
    )
    if seal_mode and seal_key_file is None:
        raise ConfigurationError("seal_mode requires seal_key_file")

    raw_timeout = source.get("timeout_seconds", 10)
    if isinstance(raw_timeout, bool):
        raise ConfigurationError("timeout_seconds must be a positive number")
    try:
        timeout_seconds = float(raw_timeout)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError("timeout_seconds must be a positive number") from exc
    if timeout_seconds <= 0 or timeout_seconds > 300:
        raise ConfigurationError("timeout_seconds must be greater than 0 and no more than 300")

    namespace_raw = source.get("default_namespace") or f"services/hermes/{profile_name}"
    namespace = validate_namespace(_string(namespace_raw, label="default_namespace", required=True) or "")
    spec_path = _path(source.get("spec_path"), label="spec_path")
    enable_resolve = _boolean(source.get("enable_resolve"), label="enable_resolve", default=False)
    scrub_enabled = _boolean(scrub_raw.get("enabled"), label="scrub.enabled", default=True)
    placeholder = _string(scrub_raw.get("placeholder"), label="scrub.placeholder") or "[PHOENIX-SCRUBBED:{name}]"
    remainder = placeholder.replace("{name}", "", 1)
    if (
        placeholder.count("{name}") != 1
        or "{" in remainder
        or "}" in remainder
        or not remainder
    ):
        raise ConfigurationError(
            "scrub.placeholder must contain exactly one '{name}' field plus a literal delimiter"
        )

    warnings: list[str] = []
    plaintext_warning = transport_warning(server)
    if plaintext_warning is not None:
        warnings.append(plaintext_warning)
    if source.get("ca_cert"):
        warnings.append("ca_cert is a deprecated alias; use ca_file instead.")

    return PluginConfig(
        server=server,
        profile_name=profile_name,
        token_file=token_file,
        role=role,
        ca_file=ca_file,
        client_cert=client_cert,
        client_key=client_key,
        seal_key_file=seal_key_file,
        seal_mode=seal_mode,
        default_namespace=namespace,
        spec_path=spec_path,
        timeout_seconds=timeout_seconds,
        enable_resolve=enable_resolve,
        scrub=ScrubConfig(enabled=scrub_enabled, placeholder=placeholder),
        configuration_warnings=tuple(warnings),
    )
