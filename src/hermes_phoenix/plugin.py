"""Hermes-coupled registration module.

Keep Hermes imports lazy and confined to configuration loading so this package's
unit tier can run without installing Hermes.
"""

from __future__ import annotations

import logging
from typing import Any

from .cli import make_cli_handler, make_slash_handler, setup_cli
from .config import PluginConfig, load_plugin_config
from .tools import (
    PHOENIX_LIST_SCHEMA,
    PHOENIX_RESOLVE_SCHEMA,
    PHOENIX_STATUS_SCHEMA,
    make_list_handler,
    make_resolve_handler,
    make_status_handler,
    status_payload,
)

logger = logging.getLogger(__name__)


def register(ctx: Any) -> None:
    """Register the status-first Phoenix surface without blocking Hermes startup."""
    profile_name = getattr(ctx, "profile_name", "default") or "default"

    def config_loader() -> PluginConfig:
        return load_plugin_config(profile_name=profile_name)

    registrations = (
        (
            "phoenix_status tool",
            lambda: ctx.register_tool(
                name="phoenix_status",
                toolset="phoenix",
                schema=PHOENIX_STATUS_SCHEMA,
                handler=make_status_handler(config_loader),
                description="Check Phoenix reachability and active profile authentication.",
                emoji="🔐",
            ),
        ),
        (
            "phoenix_list tool",
            lambda: ctx.register_tool(
                name="phoenix_list",
                toolset="phoenix_list",
                schema=PHOENIX_LIST_SCHEMA,
                handler=make_list_handler(config_loader),
                description="List Phoenix secret paths visible to the active profile identity.",
                emoji="📋",
            ),
        ),
        (
            "phoenix_resolve tool",
            lambda: ctx.register_tool(
                name="phoenix_resolve",
                toolset="phoenix_resolve",
                schema=PHOENIX_RESOLVE_SCHEMA,
                handler=make_resolve_handler(config_loader),
                description="Resolve Phoenix refs; plaintext until sealed mode support lands.",
                emoji="🔑",
            ),
        ),
        (
            "hermes phoenix CLI",
            lambda: ctx.register_cli_command(
                name="phoenix",
                help="Phoenix Secrets Manager diagnostics",
                setup_fn=setup_cli,
                handler_fn=make_cli_handler(config_loader),
                description="Check Phoenix connectivity and profile identity.",
            ),
        ),
        (
            "/phoenix status command",
            lambda: ctx.register_command(
                name="phoenix",
                handler=make_slash_handler(config_loader),
                description="Check Phoenix connectivity and profile identity.",
                args_hint="status",
            ),
        ),
    )
    for label, operation in registrations:
        try:
            operation()
        except Exception:
            logger.warning("Could not register %s", label, exc_info=True)

    seen_sessions: set[str] = set()

    def on_session_start(**kwargs: Any) -> None:
        session_id = kwargs.get("session_id")
        if isinstance(session_id, str) and session_id in seen_sessions:
            return
        if isinstance(session_id, str):
            seen_sessions.add(session_id)
        payload = status_payload(config_loader, **kwargs)
        if not payload.get("ok"):
            error = payload.get("error", {})
            logger.warning(
                "Phoenix preflight warning for profile %s: %s",
                profile_name,
                error.get("error", "status check failed") if isinstance(error, dict) else "status check failed",
            )

    try:
        ctx.register_hook("on_session_start", on_session_start)
    except Exception:
        logger.warning("Could not register Phoenix on_session_start hook", exc_info=True)

    # Registration-time preflight is diagnostic only. All failures are reduced
    # to safe warnings; runtime tools independently enforce identity checks.
    payload = status_payload(config_loader)
    if not payload.get("ok"):
        error = payload.get("error", {})
        logger.warning(
            "Phoenix startup preflight warning for profile %s: %s",
            profile_name,
            error.get("error", "status check failed") if isinstance(error, dict) else "status check failed",
        )
