"""Registration helpers for `hermes phoenix` and `/phoenix`."""

from __future__ import annotations

import argparse
import json
from typing import Any, Callable, Mapping

from .config import PluginConfig
from .tools import status_payload
from .verify import verify_all_profiles, verify_profile


def setup_cli(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="phoenix_command", required=True)
    commands.add_parser("status", help="Check Phoenix connectivity and profile authentication")
    verify = commands.add_parser("verify", help="Dry-run validate Phoenix configuration and refs")
    verify.add_argument(
        "--all-profiles",
        action="store_true",
        help="Verify expected sibling Hermes profiles and reject duplicate identity material",
    )


def make_cli_handler(config_loader: Callable[[], PluginConfig]):
    def handle(args: argparse.Namespace) -> int:
        if args.phoenix_command == "status":
            payload = status_payload(config_loader)
        elif args.phoenix_command == "verify":
            try:
                if bool(getattr(args, "all_profiles", False)):
                    from hermes_constants import get_default_hermes_root

                    payload = verify_all_profiles(get_default_hermes_root())
                else:
                    from hermes_cli.config import load_config

                    raw_config = load_config() or {}
                    if not isinstance(raw_config, Mapping):
                        raise TypeError("Hermes config was not a mapping")
                    payload = verify_profile(config_loader(), raw_config)
            except Exception:
                payload = {
                    "ok": False,
                    "checks": [
                        {
                            "name": "verify",
                            "ok": False,
                            "error": {
                                "type": "internal_error",
                                "status": 0,
                                "error": "Phoenix verify failed safely",
                                "code": "PHOENIX_VERIFY_INTERNAL",
                            },
                        }
                    ],
                    "refs": {"total": 0, "ok": 0, "failed": 0},
                }
        else:
            return 2
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if payload.get("ok") else 1

    return handle


def make_slash_handler(config_loader: Callable[[], PluginConfig]):
    def handle(raw_args: str) -> str:
        command = raw_args.strip().lower() or "status"
        if command != "status":
            return "Usage: /phoenix status"
        return json.dumps(status_payload(config_loader), sort_keys=True)

    return handle
