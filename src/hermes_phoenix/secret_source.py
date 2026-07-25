"""Hermes SecretSource API v1 adapter for Phoenix.

Imports of the Hermes contract are intentionally lazy so the plugin's offline
unit tier remains runnable without Hermes installed.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Callable, Mapping

from .client import CallerContext, PhoenixClient
from .config import PluginConfig
from .errors import ApiError, ConfigurationError, IdentityError, NetworkError
from .refs import normalize_ref
from .scrub import get_scrub_registry


def make_phoenix_secret_source(config_loader: Callable[[], PluginConfig]):
    from agent.secret_sources.base import (  # type: ignore[import-not-found]
        SECRET_SOURCE_API_VERSION,
        ErrorKind,
        FetchResult,
        SecretSource,
        is_valid_env_name,
    )

    class PhoenixSecretSource(SecretSource):
        api_version = SECRET_SOURCE_API_VERSION
        name = "phoenix"
        label = "Phoenix Secrets Manager"
        shape = "mapped"
        scheme = "phoenix"

        def config_schema(self) -> dict:
            return {
                "enabled": {"description": "Master switch", "default": False},
                "env": {
                    "description": "Map of ENV_VAR to phoenix:// secret reference",
                    "default": {},
                },
                "timeout_seconds": {
                    "description": "Wall-clock and Phoenix request timeout",
                    "default": 20,
                },
                "override_existing": {
                    "description": "Resolved values overwrite .env/shell values",
                    "default": False,
                },
            }

        def fetch(self, cfg: dict, home_path: Path):  # noqa: ARG002 - API contract
            result = FetchResult()
            try:
                if not isinstance(cfg, dict):
                    result.error = "secrets.phoenix must be a mapping"
                    result.error_kind = ErrorKind.NOT_CONFIGURED
                    return result
                raw_env = cfg.get("env")
                if not isinstance(raw_env, Mapping) or not raw_env:
                    result.error = (
                        "secrets.phoenix.enabled is true but env is empty; add ENV_VAR: phoenix://... mappings"
                    )
                    result.error_kind = ErrorKind.NOT_CONFIGURED
                    return result

                config = config_loader()
                timeout = min(float(self.fetch_timeout_seconds(cfg)), 300.0)
                config = replace(config, timeout_seconds=timeout)

                bindings: dict[str, str] = {}
                for name, raw_ref in raw_env.items():
                    if not isinstance(name, str) or not is_valid_env_name(name):
                        result.error = "secrets.phoenix.env contains an invalid environment variable name"
                        result.error_kind = ErrorKind.REF_INVALID
                        return result
                    if not isinstance(raw_ref, str) or not raw_ref.strip().startswith("phoenix://"):
                        result.error = "secrets.phoenix.env values must be phoenix:// references"
                        result.error_kind = ErrorKind.REF_INVALID
                        return result
                    bindings[name] = normalize_ref(raw_ref.strip(), config.default_namespace)

                unique_refs = sorted(set(bindings.values()))
                resolved = PhoenixClient(config).resolve(
                    unique_refs,
                    caller=CallerContext(
                        profile=config.profile_name,
                        tool="secret-source",
                    ),
                    # SecretSource injects usable plaintext by contract. The
                    # plugin never decrypts envelopes, so it explicitly makes
                    # an unsealed request and fails if Phoenix policy forbids it.
                    sealed=False,
                )
                if resolved["errors"] or set(resolved["values"]) != set(unique_refs):
                    result.error = "Phoenix did not resolve every configured SecretSource reference"
                    result.error_kind = ErrorKind.REF_INVALID
                    return result

                registry = get_scrub_registry()
                for name in sorted(bindings):
                    value = resolved["values"][bindings[name]]
                    if not isinstance(value, str) or not value:
                        result.error = "Phoenix returned an empty SecretSource value"
                        result.error_kind = ErrorKind.EMPTY_VALUE
                        result.secrets.clear()
                        return result
                    result.secrets[name] = value
                    registry.register(value, name=name)
                return result
            except ConfigurationError as exc:
                result.error = "Phoenix SecretSource configuration or reference is invalid"
                result.error_kind = (
                    ErrorKind.REF_INVALID if exc.code == "PHOENIX_REF_INVALID" else ErrorKind.NOT_CONFIGURED
                )
            except IdentityError:
                result.error = "Phoenix SecretSource identity is missing, insecure, or invalid"
                result.error_kind = ErrorKind.AUTH_FAILED
            except NetworkError as exc:
                result.error = "Phoenix SecretSource request timed out" if exc.code == "PHOENIX_TIMEOUT" else "Phoenix is unreachable"
                result.error_kind = ErrorKind.TIMEOUT if exc.code == "PHOENIX_TIMEOUT" else ErrorKind.NETWORK
            except ApiError as exc:
                if exc.status in {401, 403}:
                    result.error = "Phoenix rejected the SecretSource identity"
                    result.error_kind = ErrorKind.AUTH_FAILED
                else:
                    result.error = "Phoenix SecretSource request failed"
                    result.error_kind = ErrorKind.INTERNAL
            except Exception:
                # Contract guarantee: fetch never raises and never reflects
                # unexpected exception text, paths, credentials, or values.
                result.error = "Phoenix SecretSource failed safely"
                result.error_kind = ErrorKind.INTERNAL
            return result

    return PhoenixSecretSource()
