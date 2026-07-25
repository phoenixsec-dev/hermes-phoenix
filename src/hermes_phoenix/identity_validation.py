"""Cross-profile Phoenix identity validation for the operator CLI."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .config import PluginConfig, load_plugin_config
from .errors import ConfigurationError, IdentityError
from .identity import fingerprint_private_key_file, fingerprint_runtime_token
from .seal import fingerprint_seal_public_key

_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_MAX_CONFIG_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class ProfileSnapshot:
    name: str
    raw: Mapping[str, Any]


@dataclass(frozen=True)
class ConfiguredProfile:
    name: str
    raw: Mapping[str, Any]
    config: PluginConfig


def _read_regular_config(path: Path, profile: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConfigurationError(
            f"Hermes profile {profile} config is missing, unreadable, or a symlink",
            code="PHOENIX_PROFILE_CONFIG_INVALID",
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_CONFIG_BYTES:
            raise ConfigurationError(
                f"Hermes profile {profile} config is unsafe or too large",
                code="PHOENIX_PROFILE_CONFIG_INVALID",
            )
        chunks: list[bytes] = []
        remaining = _MAX_CONFIG_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > _MAX_CONFIG_BYTES:
            raise ConfigurationError(
                f"Hermes profile {profile} config is too large",
                code="PHOENIX_PROFILE_CONFIG_INVALID",
            )
        return data
    finally:
        os.close(fd)


def discover_profile_config_paths(root: Path) -> tuple[tuple[str, Path], ...]:
    """Return only the default config and direct valid profiles/* siblings."""
    candidates: list[tuple[str, Path]] = []
    default_config = root / "config.yaml"
    if default_config.exists() or default_config.is_symlink():
        candidates.append(("default", default_config))

    profiles_root = root / "profiles"
    if profiles_root.is_symlink():
        raise ConfigurationError(
            "Hermes profiles directory must not be a symlink for --all-profiles",
            code="PHOENIX_PROFILE_CONFIG_INVALID",
        )
    if profiles_root.is_dir():
        for entry in sorted(profiles_root.iterdir(), key=lambda item: item.name):
            if not _PROFILE_RE.fullmatch(entry.name):
                continue
            if entry.is_symlink() or not entry.is_dir():
                continue
            config_path = entry / "config.yaml"
            if config_path.exists() or config_path.is_symlink():
                candidates.append((entry.name, config_path))
    return tuple(candidates)


def load_profile_snapshots(
    root: Path,
    *,
    yaml_load: Callable[[str], Any] | None = None,
) -> tuple[ProfileSnapshot, ...]:
    if yaml_load is None:
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ConfigurationError(
                "Hermes YAML support is unavailable",
                code="PHOENIX_PROFILE_CONFIG_INVALID",
            ) from exc
        yaml_load = yaml.safe_load

    snapshots: list[ProfileSnapshot] = []
    for name, path in discover_profile_config_paths(root):
        raw_bytes = _read_regular_config(path, name)
        try:
            raw_text = raw_bytes.decode("utf-8")
            loaded = yaml_load(raw_text) or {}
        except Exception as exc:
            raise ConfigurationError(
                f"Hermes profile {name} config could not be parsed",
                code="PHOENIX_PROFILE_CONFIG_INVALID",
            ) from exc
        if not isinstance(loaded, Mapping):
            raise ConfigurationError(
                f"Hermes profile {name} config must be a mapping",
                code="PHOENIX_PROFILE_CONFIG_INVALID",
            )
        snapshots.append(ProfileSnapshot(name=name, raw=loaded))
    return tuple(snapshots)


def _plugin_entry(raw: Mapping[str, Any]) -> Mapping[str, Any] | None:
    plugins = raw.get("plugins")
    if not isinstance(plugins, Mapping):
        return None
    entries = plugins.get("entries")
    if not isinstance(entries, Mapping):
        return None
    entry = entries.get("phoenix")
    if entry is None:
        return None
    if not isinstance(entry, Mapping):
        raise ConfigurationError("Phoenix plugin entry must be a mapping", code="PHOENIX_PROFILE_CONFIG_INVALID")
    return entry


def validate_profile_identity_uniqueness(
    snapshots: tuple[ProfileSnapshot, ...],
) -> tuple[ConfiguredProfile, ...]:
    token_owners: dict[str, str] = {}
    seal_owners: dict[str, str] = {}
    mtls_key_owners: dict[str, str] = {}
    configured: list[ConfiguredProfile] = []

    for snapshot in snapshots:
        entry = _plugin_entry(snapshot.raw)
        if entry is None:
            continue
        try:
            config = load_plugin_config(raw=entry, environ={}, profile_name=snapshot.name)
            if config.client_key is not None:
                mtls_key_fingerprint = fingerprint_private_key_file(config.client_key)
                previous = mtls_key_owners.get(mtls_key_fingerprint)
                if previous is not None:
                    raise IdentityError(
                        f"Hermes profiles {previous} and {snapshot.name} share Phoenix mTLS private-key material",
                        code="PHOENIX_DUPLICATE_IDENTITY_MATERIAL",
                        remediation="Provision a distinct Phoenix client identity for every Hermes profile.",
                    )
                mtls_key_owners[mtls_key_fingerprint] = snapshot.name
            if config.token_file is not None:
                token_fingerprint = fingerprint_runtime_token(config.token_file)
                previous = token_owners.get(token_fingerprint)
                if previous is not None:
                    raise IdentityError(
                        f"Hermes profiles {previous} and {snapshot.name} share Phoenix token material",
                        code="PHOENIX_DUPLICATE_IDENTITY_MATERIAL",
                        remediation="Configure a distinct Phoenix bootstrap identity for every Hermes profile.",
                    )
                token_owners[token_fingerprint] = snapshot.name
            if config.seal_key_file is not None:
                seal_fingerprint = fingerprint_seal_public_key(config.seal_key_file)
                previous = seal_owners.get(seal_fingerprint)
                if previous is not None:
                    raise IdentityError(
                        f"Hermes profiles {previous} and {snapshot.name} share Phoenix seal-key material",
                        code="PHOENIX_DUPLICATE_IDENTITY_MATERIAL",
                        remediation="Generate and register a distinct Phoenix seal key for every Hermes profile.",
                    )
                seal_owners[seal_fingerprint] = snapshot.name
        except IdentityError as exc:
            if exc.code == "PHOENIX_DUPLICATE_IDENTITY_MATERIAL":
                raise
            raise IdentityError(
                f"Hermes profile {snapshot.name} Phoenix identity material could not be validated",
                code="PHOENIX_IDENTITY_MATERIAL_UNREADABLE",
                remediation=(
                    "Fix that profile's token, seal key, or mTLS private-key configuration and owner-only permissions."
                ),
            ) from exc
        except Exception as exc:
            raise IdentityError(
                f"Hermes profile {snapshot.name} Phoenix identity material could not be validated",
                code="PHOENIX_IDENTITY_MATERIAL_UNREADABLE",
                remediation=(
                    "Fix that profile's token, seal key, or mTLS private-key configuration and owner-only permissions."
                ),
            ) from exc
        configured.append(ConfiguredProfile(name=snapshot.name, raw=snapshot.raw, config=config))
    return tuple(configured)
