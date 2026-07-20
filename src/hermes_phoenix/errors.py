"""Safe error taxonomy for Phoenix plugin surfaces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ErrorPayload:
    type: str
    status: int
    error: str
    code: str | None = None
    detail: str | None = None
    remediation: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "status": self.status,
            "error": self.error,
            **({"code": self.code} if self.code else {}),
            **({"detail": self.detail} if self.detail else {}),
            **({"remediation": self.remediation} if self.remediation else {}),
        }


class PhoenixPluginError(Exception):
    """Base exception whose public representation is safe for tools and logs."""

    error_type = "internal_error"
    status = 0

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        detail: str | None = None,
        remediation: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.detail = detail
        self.remediation = remediation

    def to_payload(self) -> ErrorPayload:
        return ErrorPayload(
            type=self.error_type,
            status=self.status,
            error=str(self),
            code=self.code,
            detail=self.detail,
            remediation=self.remediation,
        )


class ConfigurationError(PhoenixPluginError):
    error_type = "configuration_error"


class IdentityError(PhoenixPluginError):
    error_type = "identity_error"


class NetworkError(PhoenixPluginError):
    error_type = "network_error"


class ApiError(PhoenixPluginError):
    error_type = "http_error"

    def __init__(self, message: str, *, status: int, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.status = status
        if status in {401, 403}:
            self.error_type = "access_denied"
        elif status == 202:
            self.error_type = "approval_required"
