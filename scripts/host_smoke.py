#!/usr/bin/env python3
"""Tier 3 host smoke: real Hermes venv at the pinned tag, scratch profile.

What it proves, against a throwaway local Phoenix server:

1. pip shape — the plugin installs into a real Hermes venv and
   ``hermes phoenix status`` / ``hermes phoenix verify`` report ``ok: true``.
2. ``plugins.enabled`` gating — with the plugin absent from the allowlist,
   the ``hermes phoenix`` CLI surface is not registered.
3. directory shape — after uninstalling the pip package, the same checks
   pass with the plugin installed as ``$HERMES_HOME/plugins/phoenix``.

Skip-don't-fail convention (matches the Tier 2 harness): missing
prerequisites — no Hermes checkout, missing pinned tag, no Phoenix
server/toolchain, unsupported Python, or a failed Hermes venv build —
produce a clean SKIP and exit 0. Set ``HERMES_SMOKE_REQUIRED=1`` to turn
any SKIP into a failure for release gates. Once prerequisites are
satisfied, every check failure is a hard failure (exit 1).

Environment:
    HERMES_SRC              Hermes checkout (default: sibling ../hermes)
    HERMES_SMOKE_TAG        pinned tag (default: v2026.7.7.2)
    HERMES_SMOKE_REQUIRED   "1" turns SKIP into failure
    PHOENIX_SERVER_BIN / PHOENIX_CLI_BIN / PHOENIX_SRC / GO_BIN
                            forwarded to the Tier 2 harness

Everything (clone, venv, Phoenix binaries/state, profile home, identity
files) lives in one temporary directory with synthetic values only; the
Hermes and Phoenix checkouts are never modified.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TAG = "v2026.7.7.2"
SYNTHETIC_TOKEN = "synthetic-host-smoke-token"
SYNTHETIC_VALUE = "synthetic-host-smoke-value"
NAMESPACE = "hermes-smoke"


def _load_harness():
    path = REPO_ROOT / "test" / "integration" / "harness.py"
    spec = importlib.util.spec_from_file_location("host_smoke_harness", path)
    module = importlib.util.module_from_spec(spec)
    # Register before exec: dataclass processing resolves annotations
    # through sys.modules[cls.__module__].
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _skip(reason: str) -> int:
    if os.environ.get("HERMES_SMOKE_REQUIRED"):
        print(f"host-smoke: FAIL (required, but unavailable): {reason}")
        return 1
    print(f"host-smoke: SKIP: {reason}")
    return 0


def _fail(reason: str, output: str = "") -> int:
    print(f"host-smoke: FAIL: {reason}")
    if output:
        tail = "\n".join(output.splitlines()[-25:])
        print(tail)
    return 1


def _run(argv: list[str], *, env: dict[str, str] | None = None,
         timeout: int = 300, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _extract_json(stdout: str) -> dict | None:
    """Best-effort extraction of the printed JSON payload from CLI output."""
    text = stdout.strip()
    try:
        payload = json.loads(text)
        return payload if isinstance(payload, dict) else None
    except json.JSONDecodeError:
        pass
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("{"):
            candidate = "\n".join(lines[index:])
            end = candidate.rfind("}")
            if end < 0:
                continue
            try:
                payload = json.loads(candidate[: end + 1])
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                return payload
    return None


def _hermes_env(home: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PHOENIX_")
    }
    env["HERMES_HOME"] = str(home)
    return env


def _write_profile_config(home: Path, *, enabled: bool, server_url: str,
                          token_file: Path, seal_key: Path, spec: Path) -> None:
    # JSON is valid YAML; emitting JSON avoids a YAML dependency here.
    config = {
        "plugins": {
            "enabled": ["phoenix"] if enabled else [],
            "entries": {
                "phoenix": {
                    "server": server_url,
                    "token_file": str(token_file),
                    "default_namespace": NAMESPACE,
                    "enable_resolve": False,
                    "seal_mode": True,
                    "seal_key_file": str(seal_key),
                    "spec_path": str(spec),
                }
            },
        }
    }
    (home / "config.yaml").write_text(json.dumps(config, indent=2) + "\n")


def _check_cli_ok(hermes: Path, home: Path, args: list[str], label: str) -> str | None:
    """Run a hermes phoenix CLI command; return an error string or None."""
    try:
        result = _run([str(hermes), "phoenix", *args], env=_hermes_env(home))
    except subprocess.TimeoutExpired:
        return f"{label}: timed out"
    payload = _extract_json(result.stdout)
    if payload is None:
        return f"{label}: no JSON payload on stdout\n{result.stdout}\n{result.stderr}"
    if payload.get("ok") is not True:
        return f"{label}: printed ok != true\n{json.dumps(payload, indent=2)[:2000]}"
    return None


def main() -> int:
    # --- prerequisites (SKIP zone) -------------------------------------
    if not (3, 11) <= sys.version_info[:2] < (3, 14):
        return _skip(f"Python {sys.version_info[0]}.{sys.version_info[1]} is outside the supported >=3.11,<3.14 range")

    hermes_src = Path(os.environ.get("HERMES_SRC", "").strip() or REPO_ROOT.parent / "hermes").resolve()
    if not (hermes_src / "pyproject.toml").is_file():
        return _skip(f"No Hermes checkout at {hermes_src}; set HERMES_SRC")

    tag = os.environ.get("HERMES_SMOKE_TAG", "").strip() or DEFAULT_TAG
    probe = _run(["git", "-C", str(hermes_src), "rev-parse", "--verify", "--quiet", f"{tag}^{{commit}}"])
    if probe.returncode != 0:
        return _skip(f"Hermes checkout at {hermes_src} does not have the pinned tag {tag}")

    harness = _load_harness()
    availability = harness.detect_availability()
    if not availability.available:
        return _skip(f"Phoenix unavailable for the smoke: {availability.reason}")

    workspace = Path(tempfile.mkdtemp(prefix="hermes-phoenix-host-smoke-"))
    binaries = None
    server = None
    try:
        # Hermetic Hermes source at the pinned tag (never the live worktree).
        # git archive works on shallow/partial clones where a local re-clone
        # would fail, and exports exactly the tagged tree.
        clone_dir = workspace / "hermes-src"
        clone_dir.mkdir()
        archive = subprocess.run(
            ["git", "-C", str(hermes_src), "archive", "--format=tar", tag],
            capture_output=True,
            timeout=600,
        )
        if archive.returncode != 0:
            return _skip(
                f"could not export Hermes {tag} from {hermes_src}: "
                + archive.stderr.decode(errors="replace").strip()
            )
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
            tar.extractall(clone_dir, filter="data")
        print(f"host-smoke: using Hermes {tag} exported from {hermes_src}")

        # Real Hermes venv. A failed build counts as unavailability (SKIP).
        venv_dir = workspace / "venv"
        created = _run([sys.executable, "-m", "venv", str(venv_dir)], timeout=300)
        if created.returncode != 0:
            return _skip(f"could not create a venv with {sys.executable}")
        pip = venv_dir / "bin" / "pip"
        hermes_bin = venv_dir / "bin" / "hermes"
        install = _run([str(pip), "install", str(clone_dir)], timeout=3600)
        if install.returncode != 0:
            tail = "\n".join((install.stdout + "\n" + install.stderr).splitlines()[-25:])
            print(tail)
            return _skip("pip install of Hermes failed; prepare the host per the Hermes docs")
        print("host-smoke: Hermes venv ready")

        # --- prerequisites satisfied: everything below is PASS/FAIL ----
        install_plugin = _run([str(pip), "install", str(REPO_ROOT)], timeout=900)
        if install_plugin.returncode != 0:
            return _fail("pip install of hermes-phoenix failed", install_plugin.stdout + install_plugin.stderr)
        print("host-smoke: PASS pip install (hermes-phoenix)")

        # Throwaway Phoenix with synthetic identity and one synthetic secret.
        try:
            binaries = harness.ensure_binaries(availability)
            server = harness.PhoenixServer(binaries)
            server.init()
            server.start()
            server.cli(["set", f"{NAMESPACE}/example-secret", "-v", SYNTHETIC_VALUE])
            server.cli(["agent", "create", NAMESPACE, "-t", SYNTHETIC_TOKEN,
                        "--acl", f"{NAMESPACE}/*:read"])
            seal_key = server.run_dir / "smoke.seal.key"
            server.cli(["keypair", "generate", NAMESPACE, "-o", str(seal_key)])
        except RuntimeError as exc:
            return _fail(f"throwaway Phoenix setup failed: {exc}")
        token_file = server.run_dir / "smoke.token"
        token_file.write_text(SYNTHETIC_TOKEN)
        token_file.chmod(0o600)
        spec = server.run_dir / "smoke.spec"
        spec.write_text(f"SMOKE_EXAMPLE_SECRET=phoenix://{NAMESPACE}/example-secret\n")
        print(f"host-smoke: throwaway Phoenix ready at {server.url}")

        home = workspace / "home"
        home.mkdir()
        profile = dict(server_url=server.url, token_file=token_file,
                       seal_key=seal_key, spec=spec)

        # 1) pip shape: status + verify against the enabled scratch profile.
        _write_profile_config(home, enabled=True, **profile)
        for args, label in ((["status"], "pip-shape hermes phoenix status"),
                            (["verify"], "pip-shape hermes phoenix verify")):
            error = _check_cli_ok(hermes_bin, home, args, label)
            if error:
                return _fail(error)
            print(f"host-smoke: PASS {label}")

        # 2) plugins.enabled gating: allowlist without "phoenix" must not
        #    register the CLI surface at all.
        _write_profile_config(home, enabled=False, **profile)
        gated = _run([str(hermes_bin), "phoenix", "status"], env=_hermes_env(home))
        gated_payload = _extract_json(gated.stdout)
        if gated_payload is not None and gated_payload.get("ok") is True:
            return _fail("plugins.enabled gating: 'hermes phoenix status' succeeded with the plugin disabled")
        print("host-smoke: PASS plugins.enabled gating (CLI absent when not enabled)")

        # 3) directory shape: remove the pip package, install as a
        #    directory plugin, and repeat the checks.
        uninstall = _run([str(pip), "uninstall", "-y", "hermes-phoenix"], timeout=300)
        if uninstall.returncode != 0:
            return _fail("pip uninstall of hermes-phoenix failed", uninstall.stdout + uninstall.stderr)
        plugin_dir = home / "plugins" / "phoenix"
        shutil.copytree(REPO_ROOT / "src" / "hermes_phoenix", plugin_dir,
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy2(REPO_ROOT / "plugin.yaml", plugin_dir / "plugin.yaml")
        _write_profile_config(home, enabled=True, **profile)
        for args, label in ((["status"], "directory-shape hermes phoenix status"),
                            (["verify"], "directory-shape hermes phoenix verify")):
            error = _check_cli_ok(hermes_bin, home, args, label)
            if error:
                return _fail(error)
            print(f"host-smoke: PASS {label}")

        print("host-smoke: OK")
        return 0
    finally:
        if server is not None:
            server.dispose()
        if binaries is not None:
            binaries.cleanup()
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
