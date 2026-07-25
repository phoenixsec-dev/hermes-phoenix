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
from .errors import ApiError, ConfigurationError, NetworkError, SealedResponseError
from .identity import fingerprint_runtime_token, read_runtime_token, validate_private_key_file
from .refs import normalize_list_prefix, normalize_ref
from .scrub import get_scrub_registry
from .seal import (
    SealedEnvelopeValidationError,
    build_seal_header,
    encode_opaque_sealed_token,
    validate_sealed_envelope,
)

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
        if config.token_file is not None:
            get_scrub_registry().register(
                read_runtime_token(config.token_file),
                name=f"{config.profile_name}-phoenix-token",
            )
        self._opener = self._build_opener()

    def _build_opener(self) -> urllib.request.OpenerDirector:
        try:
            context = ssl.create_default_context(
                cafile=str(self.config.ca_file) if self.config.ca_file else None
            )
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except (OSError, ssl.SSLError) as exc:
            raise ConfigurationError(
                "Could not load the Phoenix CA trust file",
                code="PHOENIX_CA_FILE_INVALID",
                remediation="Confirm ca_file is a readable PEM CA bundle for the Phoenix server certificate.",
            ) from exc
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
            "X-Phoenix-Tool": caller.tool,
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
        request_headers: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        url = f"{self.config.server}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"
        body_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        headers = self._headers(caller)
        if request_headers:
            headers.update(request_headers)
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
        if status != 200:
            raise ApiError(
                f"Phoenix request returned HTTP {status}",
                status=status,
                code="PHOENIX_HTTP_ERROR",
                remediation="Check Phoenix server logs and audit records for safe diagnostic detail.",
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
        if raw_paths is None:
            raw_paths = []
        if not isinstance(raw_paths, list) or not all(isinstance(path, str) for path in raw_paths):
            raise ApiError(
                "Phoenix list response was invalid",
                status=200,
                code="PHOENIX_RESPONSE_INVALID",
            )
        paths: list[str] = []
        for path in raw_paths:
            if (
                not path.startswith(normalized_prefix)
                or _CONTROL_RE.search(path)
                or any(segment in {".", ".."} for segment in path.split("/"))
            ):
                raise ApiError(
                    "Phoenix list response contained a path outside the requested prefix",
                    status=200,
                    code="PHOENIX_RESPONSE_INVALID",
                )
            paths.append(path)
        return {"prefix": normalized_prefix, "paths": paths}

    @staticmethod
    def _sealed_contract_error(code: str) -> SealedResponseError:
        return SealedResponseError(
            "Phoenix sealed response contract violation",
            status=200,
            code=code,
            remediation=(
                "Confirm the Phoenix server supports sealed resolve responses and that the configured "
                "agent public seal key matches this profile."
            ),
        )

    def resolve(
        self,
        refs: list[str],
        *,
        caller: CallerContext,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        normalized_refs = [normalize_ref(ref, self.config.default_namespace) for ref in refs]
        request_headers: dict[str, str] = {}
        if self.config.seal_mode:
            if self.config.seal_key_file is None:
                raise ConfigurationError(
                    "seal_mode requires seal_key_file",
                    code="PHOENIX_SEAL_KEY_INVALID",
                )
            request_headers["X-Phoenix-Seal-Key"] = build_seal_header(self.config.seal_key_file)
        payload = self._request_json(
            "POST",
            "/v1/resolve",
            caller=caller,
            query={"dry_run": "true"} if dry_run else None,
            body={"refs": normalized_refs},
            request_headers=request_headers,
        )

        raw_errors = payload.get("errors", {})
        if not isinstance(raw_errors, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in raw_errors.items()
        ):
            if self.config.seal_mode and not dry_run:
                raise self._sealed_contract_error("PHOENIX_SEALED_VALUES_INVALID")
            raise ApiError("Phoenix resolve response contained invalid errors", status=200, code="PHOENIX_RESPONSE_INVALID")

        requested = set(normalized_refs)
        error_refs = set(raw_errors)
        if not error_refs <= requested:
            if self.config.seal_mode and not dry_run:
                raise self._sealed_contract_error("PHOENIX_SEALED_VALUES_INVALID")
            raise ApiError("Phoenix resolve response did not match the requested refs", status=200, code="PHOENIX_RESPONSE_INVALID")
        errors = {ref: "Phoenix did not resolve this ref." for ref in raw_errors}

        if self.config.seal_mode and not dry_run:
            if "sealed_values" in payload and not isinstance(payload.get("sealed_values"), dict):
                raise self._sealed_contract_error("PHOENIX_SEALED_VALUES_INVALID")
            raw_sealed_values = payload.get("sealed_values", {})
            assert isinstance(raw_sealed_values, dict)
            sealed_refs = set(raw_sealed_values)
            if (
                not all(isinstance(ref, str) for ref in sealed_refs)
                or not sealed_refs <= requested
                or sealed_refs & error_refs
            ):
                raise self._sealed_contract_error("PHOENIX_SEALED_VALUES_INVALID")
            missing_refs = requested - error_refs - sealed_refs
            if missing_refs:
                # Any payload["values"] plaintext is deliberately neither read nor reflected.
                raise self._sealed_contract_error("PHOENIX_SEALED_VALUES_MISSING")

            sealed_values: dict[str, str] = {}
            try:
                for ref in sorted(sealed_refs):
                    envelope = validate_sealed_envelope(raw_sealed_values[ref], ref)
                    sealed_values[ref] = encode_opaque_sealed_token(envelope)
            except (KeyError, SealedEnvelopeValidationError) as exc:
                raise self._sealed_contract_error("PHOENIX_SEALED_VALUES_INVALID") from exc
            return {"mode": "sealed", "values": sealed_values, "errors": errors}

        raw_values = payload.get("values", {})
        if not isinstance(raw_values, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in raw_values.items()
        ):
            raise ApiError("Phoenix resolve response contained invalid values", status=200, code="PHOENIX_RESPONSE_INVALID")
        value_refs = set(raw_values)
        if value_refs & error_refs or value_refs | error_refs != requested:
            raise ApiError("Phoenix resolve response did not match the requested refs", status=200, code="PHOENIX_RESPONSE_INVALID")
        if dry_run and any(value != "ok" for value in raw_values.values()):
            raise ApiError("Phoenix dry-run response contained an invalid status", status=200, code="PHOENIX_RESPONSE_INVALID")

        values = dict(raw_values)
        if not dry_run:
            registry = get_scrub_registry()
            for ref, value in values.items():
                registry.register_ref_value(ref, value)
        return {"mode": "dry_run" if dry_run else "plaintext", "values": values, "errors": errors}

    def status(self, *, caller: CallerContext) -> dict[str, Any]:
        seal_key_status = "not_configured"
        if self.config.seal_key_file is not None:
            try:
                build_seal_header(self.config.seal_key_file)
                seal_key_status = "valid"
            except Exception:
                seal_key_status = "invalid"

        raw_health = self.health(caller=caller)
        self.check_auth(caller=caller)
        reported_status = raw_health.get("status")
        health_status = (
            reported_status
            if isinstance(reported_status, str) and reported_status in {"ok", "healthy", "ready"}
            else "reachable"
        )
        notes = [
            "Authenticated status preflight passed.",
            "Phoenix REST API version reporting and TLS certificate metadata are not available in this scaffold.",
            *self.config.configuration_warnings,
        ]
        if seal_key_status == "invalid":
            notes.append("Phoenix seal key configuration is invalid; sealed resolve fails closed.")
        elif self.config.seal_mode:
            notes.append("Phoenix sealed resolve mode is enabled.")
        return {
            "ok": True,
            "server": self.config.server,
            "profile": self.config.profile_name,
            "auth_mode": self.config.auth_mode,
            "seal_mode": self.config.seal_mode,
            "seal_configuration": {"key": seal_key_status},
            "health": {"status": health_status},
            "notes": notes,
        }
