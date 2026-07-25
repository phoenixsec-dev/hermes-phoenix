from __future__ import annotations

import argparse
import json

from hermes_phoenix.cli import make_cli_handler, setup_cli
from hermes_phoenix.config import load_plugin_config
from hermes_phoenix.verify import collect_verify_refs, verify_all_profiles, verify_profile

SEAL_PRIVATE_KEY = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="


def _config(stub_phoenix, tmp_path, **extra):
    token = tmp_path / "token"
    token.write_text("test-bootstrap-token")
    token.chmod(0o600)
    return load_plugin_config(
        raw={
            "server": stub_phoenix.url,
            "token_file": str(token),
            "default_namespace": "services/hermes/kit-main",
            **extra,
        },
        environ={},
        profile_name="kit-main",
    )


def test_collect_verify_refs_uses_spec_and_secret_source_mappings(tmp_path, stub_phoenix):
    spec = tmp_path / "profile.spec"
    spec.write_text(
        "FROM_SPEC=phoenix://services/hermes/kit-main/calendar/password\n"
        "LITERAL=not-a-secret-value\n"
    )
    config = _config(stub_phoenix, tmp_path, spec_path=str(spec))
    refs = collect_verify_refs(
        config,
        {
            "secrets": {
                "phoenix": {
                    "env": {
                        "DB_PASSWORD": "phoenix://services/hermes/kit-main/storage/token",
                    }
                }
            }
        },
    )
    assert refs == (
        "phoenix://services/hermes/kit-main/calendar/password",
        "phoenix://services/hermes/kit-main/storage/token",
    )


def test_verify_is_machine_readable_dry_run_and_never_returns_values(stub_phoenix, tmp_path):
    seal_key = tmp_path / "seal.key"
    seal_key.write_text(SEAL_PRIVATE_KEY)
    seal_key.chmod(0o600)
    config = _config(
        stub_phoenix,
        tmp_path,
        seal_mode=True,
        seal_key_file=str(seal_key),
    )
    raw = {
        "secrets": {
            "phoenix": {
                "env": {
                    "CALDAV_PASSWORD": "phoenix://services/hermes/kit-main/calendar/password",
                }
            }
        }
    }
    report = verify_profile(config, raw)
    assert report["ok"] is True
    assert report["profile"] == "kit-main"
    assert report["refs"] == {"total": 1, "ok": 1, "failed": 0}
    assert any(check["name"] == "sealed_handshake" and check["ok"] for check in report["checks"])
    assert any(
        check["name"] == "default_namespace_visibility" and check["visible_path_count"] == 2
        for check in report["checks"]
    )
    rendered = json.dumps(report, sort_keys=True)
    assert "synthetic-secret-value" not in rendered
    assert "PHOENIX_SEALED:" not in rendered
    dry_request = next(item for item in stub_phoenix.requests if item["path"] == "/v1/resolve?dry_run=true")
    assert "X-Phoenix-Seal-Key" in dry_request["headers"]


def test_verify_reports_ref_failures_without_server_error_or_values(stub_phoenix, tmp_path):
    config = _config(stub_phoenix, tmp_path)
    report = verify_profile(
        config,
        {
            "secrets": {
                "phoenix": {
                    "env": {
                        "MISSING": "phoenix://services/hermes/kit-main/missing",
                    }
                }
            }
        },
    )
    assert report["ok"] is False
    assert report["refs"] == {"total": 1, "ok": 0, "failed": 1}
    rendered = json.dumps(report, sort_keys=True)
    assert "secret-looking" not in rendered
    assert "synthetic-secret-value" not in rendered
    assert "PHOENIX_REF_VERIFY_FAILED" in rendered


def test_sealed_verify_without_refs_still_exercises_handshake(stub_phoenix, tmp_path):
    seal_key = tmp_path / "seal.key"
    seal_key.write_text(SEAL_PRIVATE_KEY)
    seal_key.chmod(0o600)
    report = verify_profile(
        _config(stub_phoenix, tmp_path, seal_mode=True, seal_key_file=str(seal_key)),
        {},
    )
    assert report["ok"] is True
    assert report["refs"] == {"total": 0, "ok": 0, "failed": 0}
    assert any(check["name"] == "sealed_handshake" and check["ok"] for check in report["checks"])
    assert any(item["path"] == "/v1/resolve?dry_run=true" for item in stub_phoenix.requests)


def test_all_profiles_reports_identity_check_without_paths_or_fingerprints(stub_phoenix, tmp_path):
    root = tmp_path / "hermes"
    root.mkdir()
    token = root / "token"
    token.write_text("test-bootstrap-token")
    token.chmod(0o600)
    (root / "config.yaml").write_text(
        json.dumps(
            {
                "plugins": {
                    "entries": {
                        "phoenix": {
                            "server": stub_phoenix.url,
                            "token_file": str(token),
                            "default_namespace": "services/hermes/kit-main",
                        }
                    }
                }
            }
        )
    )
    report = verify_all_profiles(root)
    assert report["ok"] is True
    assert report["identity_check"] == {"ok": True, "configured_profiles": 1}
    rendered = json.dumps(report, sort_keys=True)
    assert str(token) not in rendered
    assert "test-bootstrap-token" not in rendered
    assert "fingerprint" not in rendered


def test_all_profiles_duplicate_identity_fails_before_network_and_hides_paths(stub_phoenix, tmp_path):
    root = tmp_path / "hermes"
    profiles = root / "profiles" / "kit-main"
    profiles.mkdir(parents=True)
    token_a = root / "default.token"
    token_b = root / "kit.token"
    for token in (token_a, token_b):
        token.write_text("shared-profile-token")
        token.chmod(0o600)
    for config_path, token in ((root / "config.yaml", token_a), (profiles / "config.yaml", token_b)):
        config_path.write_text(
            json.dumps(
                {
                    "plugins": {
                        "entries": {
                            "phoenix": {
                                "server": stub_phoenix.url,
                                "token_file": str(token),
                            }
                        }
                    }
                }
            )
        )
    report = verify_all_profiles(root)
    assert report["ok"] is False
    assert report["profiles"] == []
    assert report["identity_check"]["error"]["code"] == "PHOENIX_DUPLICATE_IDENTITY_MATERIAL"
    rendered = json.dumps(report, sort_keys=True)
    assert "shared-profile-token" not in rendered
    assert str(token_a) not in rendered
    assert not stub_phoenix.requests


def test_cli_registers_verify_and_prints_authoritative_top_level_ok(monkeypatch, stub_phoenix, tmp_path, capsys):
    parser = argparse.ArgumentParser()
    setup_cli(parser)
    args = parser.parse_args(["verify"])
    config = _config(stub_phoenix, tmp_path)

    hermes_cli_config = __import__("types").ModuleType("hermes_cli.config")
    hermes_cli_config.load_config = lambda: {}
    hermes_cli = __import__("types").ModuleType("hermes_cli")
    hermes_cli.__path__ = []
    monkeypatch.setitem(__import__("sys").modules, "hermes_cli", hermes_cli)
    monkeypatch.setitem(__import__("sys").modules, "hermes_cli.config", hermes_cli_config)

    return_code = make_cli_handler(lambda: config)(args)
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is True
    assert return_code == 0
