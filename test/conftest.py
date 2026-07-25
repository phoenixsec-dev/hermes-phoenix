from __future__ import annotations

import base64
import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from hermes_phoenix.scrub import get_scrub_registry
from hermes_phoenix.session import ROLE_SESSIONS


@pytest.fixture(autouse=True)
def reset_scrub_registry():
    registry = get_scrub_registry()
    registry.reset_for_tests()
    ROLE_SESSIONS.reset_for_tests()
    yield
    registry.reset_for_tests()
    ROLE_SESSIONS.reset_for_tests()


class StubPhoenix:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.session_mint_count = 0
        self.session_renew_count = 0
        self.session_ttl_seconds = 3600
        self.deny_session_renewal = False
        self.list_payload: dict[str, Any] = {
            "paths": [
                "services/hermes/kit-main/calendar/password",
                "services/hermes/kit-main/storage/token",
            ]
        }
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                owner.requests.append({"path": self.path, "headers": dict(self.headers)})
                if self.path.startswith("/v1/health"):
                    self._reply(200, {"status": "ok", "untrusted": "secret-looking health field"})
                elif self.path.startswith("/v1/policy/check"):
                    if self.headers.get("Authorization") == "Bearer test-bootstrap-token":
                        self._reply(200, {"allowed": False})
                    else:
                        self._reply(401, {"error": "unauthorized", "code": "UNAUTHORIZED"})
                elif self.path == "/v1/secrets/services/hermes/kit-main/":
                    self._reply(200, owner.list_payload)
                elif self.path.startswith("/non-json"):
                    self._raw(200, b"secret-looking response that must not escape", "text/plain")
                elif self.path.startswith("/secret-error"):
                    self._reply(
                        403,
                        {
                            "error": "secret-looking server error",
                            "detail": "secret-looking detail",
                            "remediation": "secret-looking remediation",
                        },
                    )
                elif self.path.startswith("/large-error"):
                    self._raw(500, b"x" * (1024 * 1024 + 1), "text/plain")
                elif self.path.startswith("/redirect-target"):
                    self._reply(200, {"followed": True})
                elif self.path.startswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", "/redirect-target")
                    self.end_headers()
                else:
                    self._reply(404, {"error": "not found"})

            def do_POST(self) -> None:  # noqa: N802
                content_length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(content_length)
                try:
                    body = json.loads(raw_body) if raw_body else {}
                except json.JSONDecodeError:
                    body = None
                owner.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                if self.path == "/v1/session/mint" and isinstance(body, dict):
                    role = body.get("role")
                    if role == "approval-role":
                        self._reply(
                            202,
                            {
                                "status": "approval_required",
                                "approval_id": "apr_synthetic",
                                "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
                            },
                        )
                    elif role == "denied-role":
                        self._reply(403, {"error": "secret-looking denial detail"})
                    elif self.headers.get("Authorization") == "Bearer test-bootstrap-token":
                        owner.session_mint_count += 1
                        self._reply(
                            200,
                            {
                                "session_token": f"phxs_synthetic-{owner.session_mint_count}",
                                "role": role,
                                "expires_at": (
                                    datetime.now(UTC) + timedelta(seconds=owner.session_ttl_seconds)
                                ).isoformat(),
                            },
                        )
                    else:
                        self._reply(401, {"error": "secret-looking bootstrap failure"})
                elif self.path == "/v1/session/renew" and isinstance(body, dict):
                    if owner.deny_session_renewal:
                        self._reply(403, {"error": "secret-looking renewal denial"})
                    elif str(self.headers.get("Authorization", "")).startswith("Bearer phxs_"):
                        owner.session_renew_count += 1
                        self._reply(
                            200,
                            {
                                "session_token": f"phxs_renewed-{owner.session_renew_count}",
                                "expires_at": (
                                    datetime.now(UTC) + timedelta(hours=1)
                                ).isoformat(),
                            },
                        )
                    else:
                        self._reply(403, {"error": "secret-looking renewal failure"})
                elif self.path.startswith("/v1/resolve") and isinstance(body, dict):
                    refs = body.get("refs", [])
                    errors = (
                        {"phoenix://services/hermes/kit-main/missing": "secret-looking server diagnostic"}
                        if "phoenix://services/hermes/kit-main/missing" in refs
                        else {}
                    )
                    successful_refs = [ref for ref in refs if ref not in errors]
                    if self.path == "/v1/resolve?dry_run=true":
                        self._reply(200, {"values": {ref: "ok" for ref in successful_refs}, "errors": errors})
                    elif self.headers.get("X-Phoenix-Seal-Key"):
                        sealed_values = {
                            ref: {
                                "version": 1,
                                "algorithm": "x25519-xsalsa20-poly1305",
                                "path": ref.removeprefix("phoenix://"),
                                "ref": ref,
                                "ephemeral_key": base64.b64encode(b"e" * 32).decode(),
                                "nonce": base64.b64encode(b"n" * 24).decode(),
                                "ciphertext": base64.b64encode(b"c" * 32).decode(),
                            }
                            for ref in successful_refs
                        }
                        self._reply(200, {"sealed_values": sealed_values, "errors": errors})
                    else:
                        values = {ref: "synthetic-secret-value" for ref in successful_refs}
                        self._reply(200, {"values": values, "errors": errors})
                else:
                    self._reply(404, {"error": "not found"})

            def _reply(self, status: int, body: dict[str, Any]) -> None:
                self._raw(status, json.dumps(body).encode(), "application/json")

            def _raw(self, status: int, data: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()


@pytest.fixture
def stub_phoenix():
    stub = StubPhoenix()
    try:
        yield stub
    finally:
        stub.close()
