"""Phoenix Secrets Manager integration for Hermes."""

from __future__ import annotations

from .plugin import register

__version__ = "0.1.0"
SUPPORTED_HERMES = ">=0.18.2"

__all__ = ["SUPPORTED_HERMES", "__version__", "register"]
