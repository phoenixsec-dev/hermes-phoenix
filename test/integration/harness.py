"""Throwaway real-Phoenix integration harness.

The sibling Phoenix checkout is read-only: optional Go builds write binaries to
a temporary directory and server state to a separate temporary directory.
"""

from __future__ import annotations

import atexit
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PHOENIX_SRC = REPO_ROOT.parent / "phoenix"

_LIVE_SERVERS: list["PhoenixServer"] = []
_LIVE_DIRS: list[Path] = []


@atexit.register
def _cleanup_at_exit() -> None:
    for server in list(_LIVE_SERVERS):
        server.stop()
    for directory in reversed(_LIVE_DIRS):
        shutil.rmtree(directory, ignore_errors=True)


@dataclass(frozen=True)
class Availability:
    available: bool
    reason: str = ""
    server_bin: Path | None = None
    cli_bin: Path | None = None
    source: Path | None = None
    go_bin: str | None = None


@dataclass(frozen=True)
class Binaries:
    server: Path
    cli: Path
    build_dir: Path | None = None

    def cleanup(self) -> None:
        if self.build_dir is not None:
            shutil.rmtree(self.build_dir, ignore_errors=True)
            if self.build_dir in _LIVE_DIRS:
                _LIVE_DIRS.remove(self.build_dir)


def detect_availability(environ: dict[str, str] | None = None) -> Availability:
    env = os.environ if environ is None else environ
    configured_server = env.get("PHOENIX_SERVER_BIN", "").strip()
    if configured_server:
        server = Path(configured_server)
        cli = Path(env.get("PHOENIX_CLI_BIN", "").strip() or server.with_name("phoenix"))
        if not server.is_file():
            return Availability(False, "PHOENIX_SERVER_BIN is not a file")
        if not cli.is_file():
            return Availability(False, "Phoenix CLI is unavailable; set PHOENIX_CLI_BIN")
        return Availability(True, server_bin=server, cli_bin=cli)

    source = Path(env.get("PHOENIX_SRC", "").strip() or DEFAULT_PHOENIX_SRC).resolve()
    if not (source / "go.mod").is_file():
        return Availability(False, "No sibling Phoenix source checkout or prebuilt server binary is available")

    configured_go = env.get("GO_BIN", "").strip()
    if configured_go:
        go_path = Path(configured_go).expanduser()
        if not go_path.is_file() or not os.access(go_path, os.X_OK):
            return Availability(False, "GO_BIN does not name an executable Go toolchain")
    else:
        home = Path(env.get("HOME", "").strip() or Path.home())
        found = shutil.which("go", path=env.get("PATH"))
        candidates = [
            Path(found) if found else None,
            home / ".local" / "go" / "bin" / "go",
            Path("/usr/local/go/bin/go"),
        ]
        go_path = next(
            (
                candidate
                for candidate in candidates
                if candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK)
            ),
            None,
        )
        if go_path is None:
            return Availability(False, "Go is unavailable and PHOENIX_SERVER_BIN was not provided")
    go_bin = str(go_path)
    try:
        probe = subprocess.run([go_bin, "version"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return Availability(False, "Configured Go toolchain is not runnable")
    if probe.returncode != 0 or not re.fullmatch(
        r"go version go\d+\.\S+ \S+/\S+\s*",
        probe.stdout,
    ):
        return Availability(False, "Configured Go toolchain is not runnable")
    return Availability(True, source=source, go_bin=go_bin)


def ensure_binaries(availability: Availability) -> Binaries:
    if not availability.available:
        raise RuntimeError(availability.reason)
    if availability.server_bin is not None and availability.cli_bin is not None:
        return Binaries(server=availability.server_bin, cli=availability.cli_bin)
    assert availability.source is not None and availability.go_bin is not None
    build_dir = Path(tempfile.mkdtemp(prefix="hermes-phoenix-int-bin-"))
    _LIVE_DIRS.append(build_dir)
    commands = (
        ("./cmd/phoenix-server", build_dir / "phoenix-server"),
        ("./cmd/phoenix", build_dir / "phoenix"),
    )
    build_env = {
        **os.environ,
        "GOCACHE": str(build_dir / "go-build-cache"),
        "GOMODCACHE": str(build_dir / "go-module-cache"),
        "GOFLAGS": "-mod=readonly",
    }
    for package, output in commands:
        result = subprocess.run(
            [availability.go_bin, "build", "-o", str(output), package],
            cwd=availability.source,
            env=build_env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Phoenix Go build failed for {package}: exit {result.returncode}")
    return Binaries(server=build_dir / "phoenix-server", cli=build_dir / "phoenix", build_dir=build_dir)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class PhoenixServer:
    def __init__(self, binaries: Binaries) -> None:
        self.binaries = binaries
        self.run_dir = Path(tempfile.mkdtemp(prefix="hermes-phoenix-int-run-"))
        _LIVE_DIRS.append(self.run_dir)
        self.process: subprocess.Popen[str] | None = None
        self.admin_token = ""
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.home = self.run_dir / "home"
        self.home.mkdir()
        _LIVE_SERVERS.append(self)

    @property
    def config_path(self) -> Path:
        return self.run_dir / "config.json"

    def init(self) -> None:
        result = subprocess.run(
            [str(self.binaries.server), "--init", str(self.run_dir)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"phoenix-server --init failed with exit {result.returncode}")
        match = re.search(r"ADMIN TOKEN[\s\S]*?\n([a-f0-9]{32,})", result.stdout)
        if match is None:
            raise RuntimeError("Could not parse one-time Phoenix admin token")
        self.admin_token = match.group(1)
        self.patch_config(lambda config: config["server"].update({"listen": f"127.0.0.1:{self.port}"}))

    def patch_config(self, mutate: Callable[[dict], None]) -> None:
        config = json.loads(self.config_path.read_text())
        mutate(config)
        self.config_path.write_text(json.dumps(config, indent=2) + "\n")

    def start(self) -> None:
        self.process = subprocess.Popen(
            [str(self.binaries.server), "--config", str(self.config_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for _ in range(100):
            if self.process.poll() is not None:
                raise RuntimeError("Phoenix server exited during startup")
            try:
                with urllib.request.urlopen(f"{self.url}/v1/health", timeout=0.5) as response:
                    if response.status == 200:
                        return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("Phoenix server did not become healthy")

    def stop(self) -> None:
        process = self.process
        self.process = None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if self in _LIVE_SERVERS:
            _LIVE_SERVERS.remove(self)

    def dispose(self) -> None:
        self.stop()
        shutil.rmtree(self.run_dir, ignore_errors=True)
        if self.run_dir in _LIVE_DIRS:
            _LIVE_DIRS.remove(self.run_dir)

    def cli(self, args: list[str], *, token: str | None = None) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "HOME": str(self.home),
            "PHOENIX_SERVER": self.url,
            "PHOENIX_TOKEN": token or self.admin_token,
        }
        result = subprocess.run(
            [str(self.binaries.cli), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Phoenix CLI command failed with exit {result.returncode}")
        return result
