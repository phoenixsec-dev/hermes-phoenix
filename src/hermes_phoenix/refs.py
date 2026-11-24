"""Validation and normalization for Phoenix references and paths."""

from __future__ import annotations

import re

from .errors import ConfigurationError

_REF_PREFIX = "phoenix://"
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _validate_segments(value: str, *, label: str) -> list[str]:
    segments = value.split("/")
    if not segments or any(
        not segment or segment in {".", ".."} or not _SEGMENT_RE.fullmatch(segment)
        for segment in segments
    ):
        raise ConfigurationError(
            f"{label} contains an invalid path segment",
            code="PHOENIX_REF_INVALID",
            remediation="Use letters, digits, '.', '_', or '-' and no empty, '.' or '..' segments.",
        )
    return segments


def validate_namespace(namespace: str) -> str:
    value = namespace.strip().strip("/")
    _validate_segments(value, label="default_namespace")
    return value


def normalize_ref(value: str, default_namespace: str | None = None) -> str:
    ref = value.strip()
    if not ref:
        raise ConfigurationError("Phoenix ref is required", code="PHOENIX_REF_REQUIRED")
    if "*" in ref:
        # The server answers this hint too, but a `*` never reaches it from here.
        raise ConfigurationError(
            "wildcards are not secret names; to list a folder, use phoenix_list",
            code="PHOENIX_REF_INVALID",
        )
    if ref.startswith(_REF_PREFIX):
        path = ref[len(_REF_PREFIX) :]
    else:
        if not default_namespace:
            raise ConfigurationError(
                "Phoenix ref must use phoenix:// when default_namespace is not configured",
                code="PHOENIX_REF_INVALID",
            )
        if ref.startswith("/"):
            raise ConfigurationError("Phoenix ref must not start with '/'", code="PHOENIX_REF_INVALID")
        path = f"{validate_namespace(default_namespace)}/{ref}"
    segments = _validate_segments(path, label="Phoenix ref")
    if len(segments) < 2:
        raise ConfigurationError(
            "Phoenix ref must include a namespace and secret path",
            code="PHOENIX_REF_INVALID",
        )
    return f"{_REF_PREFIX}{'/'.join(segments)}"


# Same wording as the Phoenix CLI and MCP server, so agents learn one rule.
_LIST_WILDCARD_HELP = (
    "list takes a folder (services/browser, services/browser/ or services/browser/*); "
    "other wildcards are not supported"
)


def _strip_folder_wildcard(raw_prefix: str) -> str:
    """Turn the folder forms `x/y`, `x/y/` and `x/y/*` into `x/y/`-style input.

    Mirrors listFolder in the Phoenix CLI: one trailing `*` after a slash is
    allowed; any other `*`, `?` or `[` is rejected before a request is sent.
    """
    folder = raw_prefix.removesuffix("*")
    stripped = folder != raw_prefix
    bare = folder.removeprefix(_REF_PREFIX)
    if any(ch in folder for ch in "*?[") or (stripped and bare and not bare.endswith("/")):
        raise ConfigurationError(
            f"{raw_prefix!r}: {_LIST_WILDCARD_HELP}",
            code="PHOENIX_LIST_WILDCARD",
            remediation="List the folder instead, for example services/browser/.",
        )
    return folder


def normalize_list_prefix(value: str | None, default_namespace: str | None = None) -> str:
    raw_prefix = _strip_folder_wildcard((value or "").strip())
    if raw_prefix.startswith(_REF_PREFIX):
        prefix = raw_prefix[len(_REF_PREFIX) :].strip("/")
        if not prefix:
            raise ConfigurationError(
                "Phoenix root listing is not allowed",
                code="PHOENIX_REF_INVALID",
                remediation="Provide a phoenix:// prefix below a namespace.",
            )
    elif raw_prefix:
        if raw_prefix.startswith("/"):
            raise ConfigurationError("Phoenix list prefix must not start with '/'", code="PHOENIX_REF_INVALID")
        if not default_namespace:
            raise ConfigurationError(
                "Phoenix list prefix must use phoenix:// when default_namespace is not configured",
                code="PHOENIX_REF_INVALID",
            )
        prefix = f"{validate_namespace(default_namespace)}/{raw_prefix.strip('/')}"
    elif default_namespace:
        prefix = validate_namespace(default_namespace)
    else:
        raise ConfigurationError(
            "Phoenix root listing is not allowed",
            code="PHOENIX_REF_INVALID",
            remediation="Configure default_namespace or provide a phoenix:// prefix.",
        )
    return f"{'/'.join(_validate_segments(prefix, label='Phoenix list prefix'))}/"
