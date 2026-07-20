"""Registration helpers for `hermes phoenix` and `/phoenix`."""

from __future__ import annotations

import argparse
import json
from typing import Any, Callable

from .config import PluginConfig
from .tools import status_payload


def setup_cli(parser: argparse.ArgumentParser) -> None:
    commands = parser.add_subparsers(dest="phoenix_command", required=True)
    commands.add_parser("status", help="Check Phoenix connectivity and profile authentication")


def make_cli_handler(config_loader: Callable[[], PluginConfig]):
    def handle(args: argparse.Namespace) -> int:
        if args.phoenix_command != "status":
            return 2
        payload = status_payload(config_loader)
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
