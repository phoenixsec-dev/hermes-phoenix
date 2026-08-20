from __future__ import annotations

import base64
import os

import pytest

from hermes_phoenix.errors import IdentityError
from hermes_phoenix.seal import (
    SEALED_TOKEN_PREFIX,
    SealedEnvelopeValidationError,
    build_seal_header,
    encode_opaque_sealed_token,
    fingerprint_seal_public_key,
    load_seal_private_key,
    validate_sealed_envelope,
)

PRIVATE_KEY = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
PUBLIC_KEY = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
REF = "phoenix://services/hermes/example-main/calendar/password"


def _key_file(tmp_path, content=PRIVATE_KEY, mode=0o600):
    path = tmp_path / "seal.key"
    path.write_text(content + "\n")
    path.chmod(mode)
    return path


def _envelope(ref=REF):
    return {
        "version": 1,
        "algorithm": "x25519-xsalsa20-poly1305",
        "path": ref.removeprefix("phoenix://"),
        "ref": ref,
        "ephemeral_key": base64.b64encode(b"e" * 32).decode(),
        "nonce": base64.b64encode(b"n" * 24).decode(),
        "ciphertext": base64.b64encode(b"c" * 32).decode(),
    }


def test_reads_owner_only_private_key_and_derives_expected_public_key(tmp_path):
    path = _key_file(tmp_path)
    assert load_seal_private_key(path) == base64.b64decode(PRIVATE_KEY)
    assert build_seal_header(path) == PUBLIC_KEY
    fingerprint = fingerprint_seal_public_key(path)
    assert len(fingerprint) == 64
    assert PRIVATE_KEY not in fingerprint
    assert fingerprint == fingerprint_seal_public_key(path)


@pytest.mark.parametrize(
    "content",
    ["", "not-base64!", base64.b64encode(b"short").decode(), PRIVATE_KEY.rstrip("=")],
)
def test_rejects_empty_malformed_noncanonical_or_wrong_size_keys(tmp_path, content):
    path = _key_file(tmp_path, content)
    with pytest.raises(IdentityError) as caught:
        load_seal_private_key(path)
    assert caught.value.code == "PHOENIX_SEAL_KEY_INVALID"
    assert str(path) not in str(caught.value.to_payload().as_dict())


def test_rejects_broad_permissions_and_symlink(tmp_path):
    broad = _key_file(tmp_path, mode=0o644)
    with pytest.raises(IdentityError):
        load_seal_private_key(broad)

    target = tmp_path / "target.key"
    target.write_text(PRIVATE_KEY)
    target.chmod(0o600)
    broad.unlink()
    os.symlink(target, broad)
    with pytest.raises(IdentityError):
        load_seal_private_key(broad)


def test_validates_and_encodes_canonical_opaque_envelope():
    envelope = validate_sealed_envelope(_envelope(), REF)
    token = encode_opaque_sealed_token(envelope)
    assert token.startswith(SEALED_TOKEN_PREFIX)
    assert "calendar/password" not in token
    assert "synthetic-secret" not in token


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.pop("nonce"),
        lambda value: value.__setitem__("extra", "field"),
        lambda value: value.__setitem__("version", 2),
        lambda value: value.__setitem__("version", True),
        lambda value: value.__setitem__("algorithm", "other"),
        lambda value: value.__setitem__("path", "services/hermes/other/key"),
        lambda value: value.__setitem__("ref", "phoenix://services/hermes/other/key"),
        lambda value: value.__setitem__("ephemeral_key", base64.b64encode(b"e" * 31).decode()),
        lambda value: value.__setitem__("nonce", "not-base64!"),
        lambda value: value.__setitem__("ciphertext", base64.b64encode(b"short").decode()),
    ],
)
def test_rejects_invalid_required_envelope_fields(mutate):
    envelope = _envelope()
    mutate(envelope)
    with pytest.raises(SealedEnvelopeValidationError):
        validate_sealed_envelope(envelope, REF)
