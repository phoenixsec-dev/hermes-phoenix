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


def normalize_list_prefix(value: str | None, default_namespace: str | None = None) -> str:
    prefix = (value or "").strip()
    if prefix.startswith(_REF_PREFIX):
        prefix = prefix[len(_REF_PREFIX) :]
    elif not prefix and default_namespace:
        prefix = validate_namespace(default_namespace)
    elif prefix and default_namespace and "/" not in prefix:
        prefix = f"{validate_namespace(default_namespace)}/{prefix}"
    prefix = prefix.strip("/")
    if not prefix:
        return ""
    return f"{'/'.join(_validate_segments(prefix, label='Phoenix list prefix'))}/"
