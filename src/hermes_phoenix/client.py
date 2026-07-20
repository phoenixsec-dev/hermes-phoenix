"""Small stdlib Phoenix HTTP client used by plugin runtime surfaces."""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

from .config import PluginConfig
from .errors import ApiError, ConfigurationError, NetworkError
from .identity import fingerprint_runtime_token, read_runtime_token, validate_private_key_file
from .refs import normalize_list_prefix, normalize_ref

_MAX_RESPONSE_BYTES = 1024 * 1024
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]+")


@dataclass(frozen=True)
class CallerContext:
    profile: str
    session_id: str | None = None
    channel: str | None = None
    tool: str | None = None
    task_id: str | None = None


def _audit_value(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = " ".join(_CONTROL_RE.sub(" ", value).split())[:256]
    return cleaned or None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class PhoenixClient:
    def __init__(self, config: PluginConfig) -> None:
        self.config = config
        if config.role:
            raise ConfigurationError(
                "Role-scoped runtime session minting is not implemented in this scaffold",
                code="PHOENIX_ROLE_NOT_IMPLEMENTED",
                remediation="Unset role for direct bootstrap-identity use until role session support lands.",
            )
        self._identity_fingerprint = (
            fingerprint_runtime_token(config.token_file) if config.token_file is not None else None
        )
        self._opener = self._build_opener()

    def _build_opener(self) -> urllib.request.OpenerDirector:
        context = ssl.create_default_context(cafile=str(self.config.ca_cert) if self.config.ca_cert else None)
        if self.config.client_cert and self.config.client_key:
            validate_private_key_file(self.config.client_key)
            try:
                context.load_cert_chain(str(self.config.client_cert), str(self.config.client_key))
            except (OSError, ssl.SSLError) as exc:
                raise ConfigurationError(
                    "Could not load Phoenix mTLS certificate and private key",
                    code="PHOENIX_MTLS_INVALID",
                ) from exc
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPHandler(),
            urllib.request.HTTPSHandler(context=context),
            _NoRedirectHandler(),
        )

    def _headers(self, caller: CallerContext) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.config.token_file:
            headers["Authorization"] = f"Bearer {read_runtime_token(self.config.token_file)}"
        values = {
            "X-Hermes-Profile": caller.profile,
            "X-Hermes-Session-Id": caller.session_id,
            "X-Hermes-Channel": caller.channel,
            "X-Hermes-Tool": caller.tool,
            "X-Hermes-Task-Id": caller.task_id,
        }
        for key, value in values.items():
            sanitized = _audit_value(value)
            if sanitized:
                headers[key] = sanitized
        return headers

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        caller: CallerContext,
        query: Mapping[str, str] | None = None,
        body: Mapping[str, Any] | None = None,
        expected_status: int = 200,
    ) -> Mapping[str, Any]:
        url = f"{self.config.server}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        body_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        headers = self._headers(caller)
        if body_bytes is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            raw = exc.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise ApiError(
                    "Phoenix error response exceeded the size limit",
                    status=exc.code,
                    code="PHOENIX_RESPONSE_TOO_LARGE",
                ) from exc
            code = "PHOENIX_AUTH_REJECTED" if exc.code in {401, 403} else "PHOENIX_HTTP_ERROR"
            raise ApiError(
                f"Phoenix request failed with HTTP {exc.code}",
                status=exc.code,
                code=code,
                remediation="Check Phoenix server logs and audit records for safe diagnostic detail.",
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise NetworkError(
                "Could not reach Phoenix",
                code="PHOENIX_UNREACHABLE",
                detail=f"Could not reach configured Phoenix server at {self.config.server}",
                remediation="Check the server URL, network path, CA, and mTLS configuration.",
            ) from exc

        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ApiError("Phoenix response exceeded the size limit", status=status, code="PHOENIX_RESPONSE_TOO_LARGE")
        if status < 200 or status >= 300:
            raise ApiError(f"Phoenix request failed with HTTP {status}", status=status)
        if status != expected_status:
            code = "PHOENIX_APPROVAL_REQUIRED" if status == 202 else "PHOENIX_HTTP_ERROR"
            message = "Phoenix request requires approval" if status == 202 else f"Phoenix request returned HTTP {status}"
            raise ApiError(
                message,
                status=status,
                code=code,
                remediation="Use an operator-approved, non-step-up runtime role for unattended Hermes tool calls."
                if status == 202
                else "Check Phoenix server logs and audit records for safe diagnostic detail.",
            )
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(
                "Phoenix returned a non-JSON response",
                status=status,
                code="PHOENIX_NON_JSON_RESPONSE",
                remediation="Verify the Phoenix API URL and any reverse proxy in front of it.",
            ) from exc
        if not isinstance(payload, dict):
            raise ApiError("Phoenix response was not a JSON object", status=status, code="PHOENIX_RESPONSE_INVALID")
        return payload

    def health(self, *, caller: CallerContext) -> Mapping[str, Any]:
        return self._request_json("GET", "/v1/health", caller=caller)

    def check_auth(self, *, caller: CallerContext) -> None:
        # /v1/policy/check authenticates every valid identity before returning
        # the policy decision. A 200 with allowed=false is still a successful
        # auth probe for a least-privilege identity that lacks this sentinel
        # path; 401/403 means the credentials themselves were rejected.
        self._request_json(
            "GET",
            "/v1/policy/check",
            caller=caller,
            query={
                "path": f"{self.config.default_namespace}/startup-preflight-auth-probe",
                "check": "allow_unseal",
            },
        )

    def list(self, prefix: str | None = None, *, caller: CallerContext) -> dict[str, Any]:
        normalized_prefix = normalize_list_prefix(prefix, self.config.default_namespace)
        encoded_prefix = "/".join(
            urllib.parse.quote(segment, safe="")
            for segment in normalized_prefix.rstrip("/").split("/")
            if segment
        )
        if encoded_prefix:
            encoded_prefix += "/"
        payload = self._request_json(
            "GET",
            f"/v1/secrets/{encoded_prefix}",
            caller=caller,
        )
        raw_paths = payload.get("paths")
        if not isinstance(raw_paths, list) or not all(isinstance(path, str) for path in raw_paths):
            raise ApiError(
                "Phoenix list response was invalid",
                status=200,
                code="PHOENIX_RESPONSE_INVALID",
            )
        paths: list[str] = []
        for path in raw_paths:
            try:
                normalized_path = normalize_ref(f"phoenix://{path}")[len("phoenix://") :]
            except ConfigurationError as exc:
                raise ApiError(
                    "Phoenix list response contained an invalid path",
                    status=200,
                    code="PHOENIX_RESPONSE_INVALID",
                ) from exc
            if normalized_prefix and not normalized_path.startswith(normalized_prefix):
                raise ApiError(
                    "Phoenix list response contained a path outside the requested prefix",
                    status=200,
                    code="PHOENIX_RESPONSE_INVALID",
                )
            paths.append(normalized_path)
        return {"prefix": normalized_prefix, "paths": paths}

    def resolve(self, refs: list[str], *, caller: CallerContext) -> dict[str, Any]:
        if self.config.seal_mode:
            raise ConfigurationError(
                "Sealed resolve support is not implemented in this phase",
                code="PHOENIX_SEALED_NOT_IMPLEMENTED",
                remediation="Keep phoenix_resolve disallowed until the sealed-response phase is installed.",
            )
        normalized_refs = [normalize_ref(ref, self.config.default_namespace) for ref in refs]
        payload = self._request_json(
            "POST",
            "/v1/resolve",
            caller=caller,
            body={"refs": normalized_refs},
        )
        raw_values = payload.get("values", {})
        raw_errors = payload.get("errors", {})
        if not isinstance(raw_values, dict) or not isinstance(raw_errors, dict):
            raise ApiError(
                "Phoenix resolve response was invalid",
                status=200,
                code="PHOENIX_RESPONSE_INVALID",
            )
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in raw_values.items()):
            raise ApiError(
                "Phoenix resolve response contained invalid values",
                status=200,
                code="PHOENIX_RESPONSE_INVALID",
            )
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in raw_errors.items()):
            raise ApiError(
                "Phoenix resolve response contained invalid errors",
                status=200,
                code="PHOENIX_RESPONSE_INVALID",
            )
        requested = set(normalized_refs)
        value_refs = set(raw_values)
        error_refs = set(raw_errors)
        if value_refs & error_refs or value_refs | error_refs != requested:
            raise ApiError(
                "Phoenix resolve response did not match the requested refs",
                status=200,
                code="PHOENIX_RESPONSE_INVALID",
            )
        # Server-controlled error strings are deliberately replaced rather than
        # copied into a model-visible tool result.
        errors = {ref: "Phoenix did not resolve this ref." for ref in raw_errors}
        return {"mode": "plaintext", "values": dict(raw_values), "errors": errors}

    def status(self, *, caller: CallerContext) -> dict[str, Any]:
        raw_health = self.health(caller=caller)
        self.check_auth(caller=caller)
        reported_status = raw_health.get("status")
        health_status = (
            reported_status
            if isinstance(reported_status, str) and reported_status in {"ok", "healthy", "ready"}
            else "reachable"
        )
        return {
            "ok": True,
            "server": self.config.server,
            "profile": self.config.profile_name,
            "auth_mode": self.config.auth_mode,
            "seal_mode": self.config.seal_mode,
            "health": {"status": health_status},
            "notes": [
                "Authenticated status preflight passed.",
                "Phoenix REST API version reporting and TLS certificate metadata are not available in this scaffold.",
            ],
        }
