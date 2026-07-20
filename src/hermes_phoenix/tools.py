"""Hermes tool schemas and handlers."""

from __future__ import annotations

import json
from typing import Any, Callable

from .client import CallerContext, PhoenixClient
from .config import PluginConfig
from .errors import PhoenixPluginError

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


def caller_from_kwargs(profile_name: str, *, tool: str, kwargs: dict[str, Any]) -> CallerContext:
    return CallerContext(
        profile=profile_name,
        session_id=kwargs.get("session_id") if isinstance(kwargs.get("session_id"), str) else None,
        channel=kwargs.get("platform") if isinstance(kwargs.get("platform"), str) else None,
        tool=tool,
        task_id=kwargs.get("task_id") if isinstance(kwargs.get("task_id"), str) else None,
    )


def status_payload(config_loader: Callable[[], PluginConfig], **kwargs: Any) -> dict[str, Any]:
    try:
        config = config_loader()
        caller = caller_from_kwargs(config.profile_name, tool="phoenix_status", kwargs=kwargs)
        return PhoenixClient(config).status(caller=caller)
    except PhoenixPluginError as exc:
        return {"ok": False, "error": exc.to_payload().as_dict()}
    except Exception:
        return {
            "ok": False,
            "error": {
                "type": "internal_error",
                "status": 0,
                "error": "Unexpected Phoenix plugin error",
                "remediation": "Check the Hermes gateway log for the exception without exposing credentials to the model.",
            },
        }


def make_status_handler(config_loader: Callable[[], PluginConfig]):
    def handle(_args: dict[str, Any], **kwargs: Any) -> str:
        return json.dumps(status_payload(config_loader, **kwargs), sort_keys=True)

    return handle
