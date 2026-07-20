from __future__ import annotations

import os

import pytest

from hermes_phoenix.errors import IdentityError
from hermes_phoenix.identity import read_runtime_token, validate_private_key_file


def test_reads_owner_only_bootstrap_token(tmp_path):
    path = tmp_path / "token"
    path.write_text("bootstrap-token\n")
    path.chmod(0o600)
    assert read_runtime_token(path) == "bootstrap-token"


def test_rejects_broad_permissions(tmp_path):
    path = tmp_path / "token"
    path.write_text("bootstrap-token")
    path.chmod(0o644)
    with pytest.raises(IdentityError, match="group or other"):
        read_runtime_token(path)


def test_rejects_symlink(tmp_path):
    target = tmp_path / "target"
    target.write_text("bootstrap-token")
    target.chmod(0o600)
    link = tmp_path / "token"
    os.symlink(target, link)
    with pytest.raises(IdentityError, match="Could not open"):
        read_runtime_token(link)


def test_rejects_session_token(tmp_path):
    path = tmp_path / "token"
    path.write_text("phxs_short-lived")
    path.chmod(0o600)
    with pytest.raises(IdentityError, match="short-lived session"):
        read_runtime_token(path)


def test_private_key_validation_accepts_multiline_pem(tmp_path):
    path = tmp_path / "client.key"
    path.write_text("-----BEGIN PRIVATE KEY-----\nsynthetic-test-data\n-----END PRIVATE KEY-----\n")
    path.chmod(0o600)
    validate_private_key_file(path)
