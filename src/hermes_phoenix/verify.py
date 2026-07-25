"""Machine-readable `hermes phoenix verify` implementation."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .client import CallerContext, PhoenixClient
from .config import PluginConfig
from .errors import ConfigurationError, PhoenixPluginError
from .identity_validation import load_profile_snapshots, validate_profile_identity_uniqueness
from .refs import normalize_ref
from .scrub import read_env_spec
from .seal import build_seal_header


def collect_verify_refs(config: PluginConfig, raw_hermes_config: Mapping[str, Any]) -> tuple[str, ...]:
    refs: set[str] = set()
    if config.spec_path is not None:
        refs.update(entry.ref for entry in read_env_spec(config.spec_path) if entry.ref is not None)

    secrets = raw_hermes_config.get("secrets")
    if isinstance(secrets, Mapping):
        source = secrets.get("phoenix")
        if source is not None and not isinstance(source, Mapping):
            raise ConfigurationError("secrets.phoenix must be a mapping", code="PHOENIX_VERIFY_CONFIG_INVALID")
        if isinstance(source, Mapping):
            env_map = source.get("env", {})
            if not isinstance(env_map, Mapping):
                raise ConfigurationError("secrets.phoenix.env must be a mapping", code="PHOENIX_VERIFY_CONFIG_INVALID")
            for raw_ref in env_map.values():
                if not isinstance(raw_ref, str) or not raw_ref.strip().startswith("phoenix://"):
                    raise ConfigurationError(
                        "secrets.phoenix.env values must be phoenix:// references",
                        code="PHOENIX_VERIFY_CONFIG_INVALID",
                    )
                refs.add(normalize_ref(raw_ref.strip(), config.default_namespace))
    return tuple(sorted(refs))


def _safe_error(error: Exception) -> dict[str, Any]:
    if isinstance(error, PhoenixPluginError):
        payload = error.to_payload().as_dict()
        allowed = ("type", "status", "error", "code", "remediation", "approval_id", "expires_at")
        return {key: payload[key] for key in allowed if key in payload}
    return {
        "type": "internal_error",
        "status": 0,
        "error": "Phoenix verify failed safely",
        "code": "PHOENIX_VERIFY_INTERNAL",
    }


def verify_profile(config: PluginConfig, raw_hermes_config: Mapping[str, Any]) -> dict[str, Any]:
    caller = CallerContext(profile=config.profile_name, tool="verify")
    checks: list[dict[str, Any]] = []
    ref_ok = 0
    ref_fail = 0

    try:
        refs = collect_verify_refs(config, raw_hermes_config)
        checks.append({"name": "config", "ok": True})
    except Exception as exc:
        return {
            "profile": config.profile_name,
            "ok": False,
            "checks": [{"name": "config", "ok": False, "error": _safe_error(exc)}],
            "refs": {"total": 0, "ok": 0, "failed": 0},
        }

    try:
        client = PhoenixClient(config)
        checks.append({"name": "identity", "ok": True})
    except Exception as exc:
        return {
            "profile": config.profile_name,
            "ok": False,
            "checks": [
                *checks,
                {"name": "identity", "ok": False, "error": _safe_error(exc)},
            ],
            "refs": {"total": len(refs), "ok": 0, "failed": len(refs)},
        }

    if config.seal_mode:
        try:
            if config.seal_key_file is None:
                raise ConfigurationError("seal_mode requires seal_key_file", code="PHOENIX_SEAL_KEY_INVALID")
            build_seal_header(config.seal_key_file)
            checks.append({"name": "seal_configuration", "ok": True})
        except Exception as exc:
            checks.append({"name": "seal_configuration", "ok": False, "error": _safe_error(exc)})
    else:
        checks.append({"name": "seal_configuration", "ok": True, "mode": "disabled"})

    try:
        client.health(caller=caller)
        checks.append({"name": "health", "ok": True})
    except Exception as exc:
        checks.append({"name": "health", "ok": False, "error": _safe_error(exc)})

    try:
        client.check_auth(caller=caller)
        checks.append({"name": "authentication", "ok": True})
    except Exception as exc:
        checks.append({"name": "authentication", "ok": False, "error": _safe_error(exc)})

    if refs:
        try:
            result = client.resolve(list(refs), caller=caller, dry_run=True)
            errors = result["errors"]
            for ref in refs:
                if ref in errors:
                    ref_fail += 1
                    checks.append(
                        {
                            "name": "ref",
                            "ok": False,
                            "ref": ref,
                            "error": {
                                "type": "reference_error",
                                "status": 200,
                                "error": "Phoenix did not resolve this ref.",
                                "code": "PHOENIX_REF_VERIFY_FAILED",
                            },
                        }
                    )
                else:
                    ref_ok += 1
                    checks.append({"name": "ref", "ok": True, "ref": ref})
            if config.seal_mode:
                checks.append({"name": "sealed_handshake", "ok": True})
        except Exception as exc:
            ref_fail = len(refs)
            checks.append({"name": "ref_batch", "ok": False, "error": _safe_error(exc)})
            if config.seal_mode:
                checks.append({"name": "sealed_handshake", "ok": False, "error": _safe_error(exc)})
    elif config.seal_mode:
        # Exercise header validation without inventing a real value-bearing ref.
        probe = f"phoenix://{config.default_namespace}/verify-handshake-probe"
        try:
            client.resolve([probe], caller=caller, dry_run=True)
            checks.append({"name": "sealed_handshake", "ok": True})
        except Exception as exc:
            checks.append({"name": "sealed_handshake", "ok": False, "error": _safe_error(exc)})

    try:
        listing = client.list(caller=caller)
        checks.append(
            {
                "name": "default_namespace_visibility",
                "ok": True,
                "visible_path_count": len(listing["paths"]),
            }
        )
    except Exception as exc:
        checks.append(
            {
                "name": "default_namespace_visibility",
                "ok": False,
                "error": _safe_error(exc),
            }
        )

    return {
        "profile": config.profile_name,
        "ok": all(bool(check.get("ok")) for check in checks),
        "checks": checks,
        "refs": {"total": len(refs), "ok": ref_ok, "failed": ref_fail},
    }


def verify_all_profiles(root: Path) -> dict[str, Any]:
    try:
        snapshots = load_profile_snapshots(root)
        configured = validate_profile_identity_uniqueness(snapshots)
    except Exception as exc:
        return {
            "ok": False,
            "all_profiles": True,
            "identity_check": {"ok": False, "error": _safe_error(exc)},
            "profiles": [],
        }

    reports = [verify_profile(profile.config, profile.raw) for profile in configured]
    return {
        "ok": bool(reports) and all(report["ok"] for report in reports),
        "all_profiles": True,
        "identity_check": {"ok": True, "configured_profiles": len(configured)},
        "profiles": reports,
    }
