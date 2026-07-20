from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest


class StubPhoenix:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
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
