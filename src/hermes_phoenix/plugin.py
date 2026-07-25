"""Hermes-coupled registration module.

Keep Hermes imports lazy and confined to configuration loading so this package's
unit tier can run without installing Hermes.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Any

from .cli import make_cli_handler, make_slash_handler, setup_cli
from .config import PluginConfig, load_plugin_config
from .identity import read_runtime_token
from .scrub import get_scrub_registry, register_spec_environment
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
_secret_source_unavailable_logged = False


def register(ctx: Any) -> None:
    """Register the status-first Phoenix surface without blocking Hermes startup."""
    profile_name = getattr(ctx, "profile_name", "default") or "default"

    def config_loader() -> PluginConfig:
        return load_plugin_config(profile_name=profile_name)

    registration_config: PluginConfig | None = None
    try:
        registration_config = config_loader()
    except Exception:
        # Configuration failures remain visible through status/list handlers,
        # but plaintext resolve must fail closed by never being registered.
        logger.warning(
            "Could not load Phoenix config during registration; phoenix_resolve remains disabled"
        )
    else:
        for warning in registration_config.configuration_warnings:
            logger.warning("Phoenix configuration warning: %s", warning)

        scrub = get_scrub_registry()
        scrub_config = getattr(registration_config, "scrub", None)
        if scrub_config is not None:
            scrub.configure(
                enabled=bool(getattr(scrub_config, "enabled", True)),
                placeholder=str(
                    getattr(scrub_config, "placeholder", "[PHOENIX-SCRUBBED:{name}]")
                ),
            )
        token_file = getattr(registration_config, "token_file", None)
        if token_file is not None:
            try:
                scrub.register(
                    read_runtime_token(token_file),
                    name=f"{profile_name}-phoenix-token",
                )
            except Exception:
                logger.warning("Could not register the Phoenix runtime token with output scrubbing")
        spec_path = getattr(registration_config, "spec_path", None)
        if spec_path is not None:
            try:
                register_spec_environment(spec_path, registry=scrub)
            except Exception:
                logger.warning("Could not load Phoenix spec_path names for output scrubbing")

    scrub = get_scrub_registry()

    def transform_terminal_output(*, output: str, **_kwargs: Any) -> str:
        return scrub.scrub(output)

    def transform_tool_result(*, tool_name: str, result: str, **_kwargs: Any) -> str:
        # Explicitly enabled unsealed phoenix_resolve is documented as plaintext
        # in its direct result. Registration protects subsequent output only.
        if tool_name == "phoenix_resolve":
            return result
        return scrub.scrub(result)

    def register_secret_source() -> None:
        from .secret_source import make_phoenix_secret_source

        ctx.register_secret_source(make_phoenix_secret_source(config_loader))

    registrations = [
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
            "transform_terminal_output hook",
            lambda: ctx.register_hook("transform_terminal_output", transform_terminal_output),
        ),
        (
            "transform_tool_result hook",
            lambda: ctx.register_hook("transform_tool_result", transform_tool_result),
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
    ]
    global _secret_source_unavailable_logged
    if callable(getattr(ctx, "register_secret_source", None)):
        registrations.append(
            (
                "Phoenix SecretSource",
                register_secret_source,
            )
        )
    elif not _secret_source_unavailable_logged:
        logger.info(
            "Hermes does not expose register_secret_source; Phoenix SecretSource registration was skipped"
        )
        _secret_source_unavailable_logged = True

    if registration_config is not None and registration_config.enable_resolve:
        registrations.insert(
            2,
            (
                "phoenix_resolve tool",
                lambda: ctx.register_tool(
                    name="phoenix_resolve",
                    toolset="phoenix_resolve",
                    schema=PHOENIX_RESOLVE_SCHEMA,
                    handler=make_resolve_handler(config_loader),
                    description="Resolve Phoenix refs using the profile's configured sealed or unsealed mode.",
                    emoji="🔑",
                ),
            ),
        )
    for label, operation in registrations:
        try:
            operation()
        except Exception:
            logger.warning("Could not register %s", label, exc_info=True)

    seen_sessions: OrderedDict[str, None] = OrderedDict()
    max_seen_sessions = 256

    def on_session_start(**kwargs: Any) -> None:
        session_id = kwargs.get("session_id")
        if isinstance(session_id, str) and session_id in seen_sessions:
            return
        if isinstance(session_id, str):
            seen_sessions[session_id] = None
            if len(seen_sessions) > max_seen_sessions:
                seen_sessions.popitem(last=False)
        platform = kwargs.get("platform") if isinstance(kwargs.get("platform"), str) else None
        payload = status_payload(
            config_loader,
            channel=platform,
            timeout_cap=2.0,
            **kwargs,
        )
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
