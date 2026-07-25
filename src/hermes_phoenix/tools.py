"""Hermes tool schemas and handlers."""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from typing import Any, Callable

from .client import CallerContext, PhoenixClient
from .config import PluginConfig
from .errors import ConfigurationError, PhoenixPluginError

logger = logging.getLogger(__name__)

_MAX_RESOLVE_REFS = 50
_MAX_ARGUMENT_LENGTH = 1024

PHOENIX_STATUS_SCHEMA: dict[str, Any] = {
    "name": "phoenix_status",
    "description": (
        "Check Phoenix reachability and authenticate the active Hermes profile identity. "
        "Never returns secret values."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
}

PHOENIX_LIST_SCHEMA: dict[str, Any] = {
    "name": "phoenix_list",
    "description": "List Phoenix secret paths visible under a prefix. Never returns secret values.",
    "parameters": {
        "type": "object",
        "properties": {
            "prefix": {
                "type": "string",
                "description": "Optional path or phoenix:// prefix; defaults to the profile namespace.",
                "maxLength": _MAX_ARGUMENT_LENGTH,
            }
        },
        "additionalProperties": False,
    },
}

PHOENIX_RESOLVE_SCHEMA: dict[str, Any] = {
    "name": "phoenix_resolve",
    "description": (
        "Resolve one or more Phoenix refs. Sealed profiles return opaque PHOENIX_SEALED tokens; "
        "explicitly enabled unsealed profiles return plaintext in this direct result."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "refs": {
                "type": "array",
                "items": {"type": "string", "maxLength": _MAX_ARGUMENT_LENGTH},
                "minItems": 1,
                "maxItems": _MAX_RESOLVE_REFS,
            }
        },
        "required": ["refs"],
        "additionalProperties": False,
    },
}


def caller_from_kwargs(profile_name: str, *, tool: str, kwargs: dict[str, Any]) -> CallerContext:
    return CallerContext(
        profile=profile_name,
        session_id=kwargs.get("session_id") if isinstance(kwargs.get("session_id"), str) else None,
        channel=None,
        tool=tool,
        task_id=kwargs.get("task_id") if isinstance(kwargs.get("task_id"), str) else None,
    )


def status_payload(
    config_loader: Callable[[], PluginConfig],
    *,
    channel: str | None = None,
    timeout_cap: float | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    try:
        config = config_loader()
        if timeout_cap is not None and config.timeout_seconds > timeout_cap:
            config = replace(config, timeout_seconds=timeout_cap)
        caller = replace(
            caller_from_kwargs(config.profile_name, tool="phoenix_status", kwargs=kwargs),
            channel=channel,
        )
        return PhoenixClient(config).status(caller=caller)
    except PhoenixPluginError as exc:
        return {"ok": False, "error": exc.to_payload().as_dict()}
    except Exception:
        logger.exception("Unexpected Phoenix plugin error while building status payload")
        return {
            "ok": False,
            "error": {
                "type": "internal_error",
                "status": 0,
                "error": "Unexpected Phoenix plugin error",
                "remediation": "Check the Hermes gateway log for the exception without exposing credentials to the model.",
            },
        }


def _failure_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, PhoenixPluginError):
        return {"ok": False, "error": exc.to_payload().as_dict()}
    logger.exception("Unexpected Phoenix plugin error while building tool result")
    return {
        "ok": False,
        "error": {
            "type": "internal_error",
            "status": 0,
            "error": "Unexpected Phoenix plugin error",
            "remediation": "Check the Hermes gateway log for the exception without exposing credentials to the model.",
        },
    }


def list_payload(
    config_loader: Callable[[], PluginConfig],
    args: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    try:
        if not isinstance(args, dict) or set(args) - {"prefix"}:
            raise ConfigurationError("phoenix_list accepts only the optional prefix argument")
        prefix = args.get("prefix")
        if prefix is not None and (not isinstance(prefix, str) or len(prefix) > _MAX_ARGUMENT_LENGTH):
            raise ConfigurationError(f"phoenix_list prefix must be a string up to {_MAX_ARGUMENT_LENGTH} characters")
        config = config_loader()
        caller = caller_from_kwargs(config.profile_name, tool="phoenix_list", kwargs=kwargs)
        result = PhoenixClient(config).list(prefix, caller=caller)
        paths = result["paths"]
        return {
            "ok": True,
            "prefix": result["prefix"],
            "count": len(paths),
            "paths": paths,
        }
    except Exception as exc:
        return _failure_payload(exc)


def resolve_payload(
    config_loader: Callable[[], PluginConfig],
    args: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    try:
        if not isinstance(args, dict) or set(args) != {"refs"}:
            raise ConfigurationError("phoenix_resolve requires only the refs argument")
        refs = args.get("refs")
        if (
            not isinstance(refs, list)
            or not 1 <= len(refs) <= _MAX_RESOLVE_REFS
            or any(not isinstance(ref, str) or not ref.strip() or len(ref) > _MAX_ARGUMENT_LENGTH for ref in refs)
        ):
            raise ConfigurationError(
                f"phoenix_resolve refs must contain 1 to {_MAX_RESOLVE_REFS} non-empty strings"
            )
        config = config_loader()
        if not config.enable_resolve:
            raise ConfigurationError(
                "phoenix_resolve is disabled",
                code="PHOENIX_RESOLVE_DISABLED",
                remediation=(
                    "Set plugins.entries.phoenix.enable_resolve to true and restart Hermes only after "
                    "reviewing the configured sealed or explicitly unsealed resolution behavior."
                ),
            )
        caller = caller_from_kwargs(config.profile_name, tool="phoenix_resolve", kwargs=kwargs)
        result = PhoenixClient(config).resolve(refs, caller=caller)
        values = result["values"]
        errors = result["errors"]
        return {
            "ok": not errors,
            "partial": bool(errors and values),
            "mode": result["mode"],
            "values": values,
            "errors": errors,
            "requested": len(refs),
            "resolved": len(values),
        }
    except Exception as exc:
        return _failure_payload(exc)


def make_status_handler(config_loader: Callable[[], PluginConfig]):
    def handle(_args: dict[str, Any], **kwargs: Any) -> str:
        return json.dumps(status_payload(config_loader, **kwargs), sort_keys=True)

    return handle


def make_list_handler(config_loader: Callable[[], PluginConfig]):
    def handle(args: dict[str, Any], **kwargs: Any) -> str:
        return json.dumps(list_payload(config_loader, args, **kwargs), sort_keys=True)

    return handle


def make_resolve_handler(config_loader: Callable[[], PluginConfig]):
    def handle(args: dict[str, Any], **kwargs: Any) -> str:
        return json.dumps(resolve_payload(config_loader, args, **kwargs), sort_keys=True)

    return handle
