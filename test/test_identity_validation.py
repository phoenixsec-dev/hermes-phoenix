from __future__ import annotations

import json
import os

import pytest

from hermes_phoenix.errors import ConfigurationError, IdentityError
from hermes_phoenix.identity_validation import (
    discover_profile_config_paths,
    load_profile_snapshots,
    validate_profile_identity_uniqueness,
)

SEAL_PRIVATE_KEY = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="


def _credential(path, value):
    path.write_text(value)
    path.chmod(0o600)
    return path


def _config(token_file, *, seal_key_file=None):
    entry = {
        "server": "http://127.0.0.1:9090",
        "token_file": str(token_file),
        "default_namespace": "services/hermes/test",
    }
    if seal_key_file is not None:
        entry.update({"seal_mode": True, "seal_key_file": str(seal_key_file)})
    return {"plugins": {"entries": {"phoenix": entry}}}


def _mtls_config(cert_file, key_file):
    return {
        "plugins": {
            "entries": {
                "phoenix": {
                    "server": "https://phoenix.example:9090",
                    "client_cert": str(cert_file),
                    "client_key": str(key_file),
                }
            }
        }
    }


def _write_profile(root, name, config):
    directory = root if name == "default" else root / "profiles" / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "config.yaml").write_text(json.dumps(config))


def test_discovers_only_default_and_direct_valid_profile_configs(tmp_path):
    token = _credential(tmp_path / "token", "default-token-value")
    _write_profile(tmp_path, "default", _config(token))
    _write_profile(tmp_path, "kit-main", _config(token))
    _write_profile(tmp_path, "INVALID.NAME", _config(token))
    nested = tmp_path / "profiles" / "kit-main" / "profiles" / "nested"
    nested.mkdir(parents=True)
    (nested / "config.yaml").write_text("{}")

    assert [(name, path.name) for name, path in discover_profile_config_paths(tmp_path)] == [
        ("default", "config.yaml"),
        ("kit-main", "config.yaml"),
    ]


def test_all_profile_identity_validation_accepts_unique_material(tmp_path):
    default_token = _credential(tmp_path / "default.token", "default-token-value")
    default_seal = _credential(tmp_path / "default.seal", SEAL_PRIVATE_KEY)
    kit_token = _credential(tmp_path / "kit.token", "kit-token-value")
    kit_seal = _credential(
        tmp_path / "kit.seal",
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
    )
    _write_profile(tmp_path, "default", _config(default_token, seal_key_file=default_seal))
    _write_profile(tmp_path, "kit-main", _config(kit_token, seal_key_file=kit_seal))

    snapshots = load_profile_snapshots(tmp_path, yaml_load=json.loads)
    configured = validate_profile_identity_uniqueness(snapshots)
    assert [profile.name for profile in configured] == ["default", "kit-main"]


@pytest.mark.parametrize("material", ["token", "seal"])
def test_all_profile_identity_validation_rejects_duplicate_material_without_leakage(tmp_path, material):
    token_a = _credential(tmp_path / "a.token", "shared-token-value")
    token_b = _credential(
        tmp_path / "b.token",
        "shared-token-value" if material == "token" else "different-token-value",
    )
    seal_a = _credential(tmp_path / "a.seal", SEAL_PRIVATE_KEY)
    seal_b = _credential(
        tmp_path / "b.seal",
        SEAL_PRIVATE_KEY if material == "seal" else "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
    )
    _write_profile(tmp_path, "default", _config(token_a, seal_key_file=seal_a))
    _write_profile(tmp_path, "kit-main", _config(token_b, seal_key_file=seal_b))

    snapshots = load_profile_snapshots(tmp_path, yaml_load=json.loads)
    with pytest.raises(IdentityError) as caught:
        validate_profile_identity_uniqueness(snapshots)
    payload = str(caught.value.to_payload().as_dict())
    assert caught.value.code == "PHOENIX_DUPLICATE_IDENTITY_MATERIAL"
    assert "default" in payload and "kit-main" in payload
    assert "shared-token-value" not in payload
    assert str(token_a) not in payload
    assert str(seal_a) not in payload


def test_all_profile_identity_validation_rejects_duplicate_mtls_private_keys(tmp_path):
    cert_a = tmp_path / "a.crt"
    cert_b = tmp_path / "b.crt"
    cert_a.write_text("synthetic-public-cert-a")
    cert_b.write_text("synthetic-public-cert-b")
    key_a = _credential(tmp_path / "a.key", "synthetic-shared-private-key")
    key_b = _credential(tmp_path / "b.key", "synthetic-shared-private-key")
    _write_profile(tmp_path, "default", _mtls_config(cert_a, key_a))
    _write_profile(tmp_path, "kit-main", _mtls_config(cert_b, key_b))

    snapshots = load_profile_snapshots(tmp_path, yaml_load=json.loads)
    with pytest.raises(IdentityError) as caught:
        validate_profile_identity_uniqueness(snapshots)
    payload = str(caught.value.to_payload().as_dict())
    assert caught.value.code == "PHOENIX_DUPLICATE_IDENTITY_MATERIAL"
    assert "mTLS private-key" in payload
    assert "synthetic-shared-private-key" not in payload
    assert str(key_a) not in payload


def test_all_profile_identity_validation_fails_closed_on_insecure_material_without_path(tmp_path):
    token = _credential(tmp_path / "insecure.token", "profile-token-value")
    token.chmod(0o644)
    _write_profile(tmp_path, "kit-main", _config(token))
    snapshots = load_profile_snapshots(tmp_path, yaml_load=json.loads)
    with pytest.raises(IdentityError) as caught:
        validate_profile_identity_uniqueness(snapshots)
    payload = str(caught.value.to_payload().as_dict())
    assert caught.value.code == "PHOENIX_IDENTITY_MATERIAL_UNREADABLE"
    assert "kit-main" in payload
    assert str(token) not in payload
    assert "profile-token-value" not in payload


def test_valid_named_symlink_profile_directory_fails_closed(tmp_path):
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    target = tmp_path / "external-profile"
    target.mkdir()
    (target / "config.yaml").write_text("{}")
    os.symlink(target, profiles / "kit-main")
    with pytest.raises(ConfigurationError) as caught:
        discover_profile_config_paths(tmp_path)
    assert caught.value.code == "PHOENIX_PROFILE_CONFIG_INVALID"
    assert "kit-main" in str(caught.value)
    assert str(target) not in str(caught.value.to_payload().as_dict())


def test_profile_config_symlink_is_rejected_without_following(tmp_path):
    real = tmp_path / "real.yaml"
    real.write_text("{}")
    os.symlink(real, tmp_path / "config.yaml")
    with pytest.raises(ConfigurationError) as caught:
        load_profile_snapshots(tmp_path, yaml_load=json.loads)
    assert caught.value.code == "PHOENIX_PROFILE_CONFIG_INVALID"
