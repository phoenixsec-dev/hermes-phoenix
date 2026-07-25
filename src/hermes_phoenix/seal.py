"""Phoenix sealed-response key and opaque-envelope handling.

The plugin validates and forwards sealed envelopes. It never decrypts them.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from nacl.public import PrivateKey

from .errors import IdentityError
from .identity import read_secure_file

SEAL_VERSION = 1
SEAL_ALGORITHM = "x25519-xsalsa20-poly1305"
SEAL_PRIVATE_KEY_BYTES = 32
SEAL_PUBLIC_KEY_BYTES = 32
SEAL_NONCE_BYTES = 24
SEALED_TOKEN_PREFIX = "PHOENIX_SEALED:"

_ENVELOPE_FIELDS = (
    "version",
    "algorithm",
    "path",
    "ref",
    "ephemeral_key",
    "nonce",
    "ciphertext",
)


class SealedEnvelopeValidationError(ValueError):
    """Raised internally when a sealed envelope violates the wire contract."""


def _decode_base64(value: str, *, expected_size: int | None = None, minimum_size: int = 1) -> bytes:
    if not value or any(character.isspace() for character in value):
        raise SealedEnvelopeValidationError("invalid base64 field")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SealedEnvelopeValidationError("invalid base64 field") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise SealedEnvelopeValidationError("non-canonical base64 field")
    if expected_size is not None and len(decoded) != expected_size:
        raise SealedEnvelopeValidationError("base64 field has the wrong size")
    if len(decoded) < minimum_size:
        raise SealedEnvelopeValidationError("base64 field is empty")
    return decoded


def load_seal_private_key(path: Path) -> bytes:
    """Read and strictly decode an owner-only X25519 private key file."""
    try:
        encoded = read_secure_file(path, label="Phoenix seal key")
        return _decode_base64(encoded, expected_size=SEAL_PRIVATE_KEY_BYTES)
    except (IdentityError, SealedEnvelopeValidationError) as exc:
        raise IdentityError(
            "Phoenix seal key is missing, unreadable, insecure, or malformed",
            code="PHOENIX_SEAL_KEY_INVALID",
            remediation=(
                "Configure seal_key_file as an owner-only regular non-symlink file containing "
                "one standard-base64 encoded 32-byte X25519 private key."
            ),
        ) from exc


def derive_seal_public_key(private_key: bytes) -> bytes:
    """Derive the raw 32-byte X25519 public key with PyNaCl."""
    if len(private_key) != SEAL_PRIVATE_KEY_BYTES:
        raise IdentityError("Phoenix seal private key has the wrong size", code="PHOENIX_SEAL_KEY_INVALID")
    try:
        public_key = bytes(PrivateKey(private_key).public_key)
    except Exception as exc:  # PyNaCl normalizes backend-specific failures.
        raise IdentityError(
            "Could not derive the Phoenix seal public key",
            code="PHOENIX_SEAL_KEY_INVALID",
        ) from exc
    if len(public_key) != SEAL_PUBLIC_KEY_BYTES:
        raise IdentityError("Phoenix seal public key has the wrong size", code="PHOENIX_SEAL_KEY_INVALID")
    return public_key


def build_seal_header(path: Path) -> str:
    public_key = derive_seal_public_key(load_seal_private_key(path))
    return base64.b64encode(public_key).decode("ascii")


def fingerprint_seal_public_key(path: Path) -> str:
    """Fingerprint public material only; never fingerprint/log the private key."""
    public_key = derive_seal_public_key(load_seal_private_key(path))
    return hashlib.sha256(public_key).hexdigest()


def validate_sealed_envelope(envelope: Any, requested_ref: str) -> dict[str, Any]:
    """Validate and canonicalize one envelope for an already-normalized ref."""
    if not isinstance(envelope, Mapping) or set(envelope) != set(_ENVELOPE_FIELDS):
        raise SealedEnvelopeValidationError("sealed envelope fields are invalid")

    version = envelope.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != SEAL_VERSION:
        raise SealedEnvelopeValidationError("sealed envelope version is invalid")
    if envelope.get("algorithm") != SEAL_ALGORITHM:
        raise SealedEnvelopeValidationError("sealed envelope algorithm is invalid")

    expected_path = requested_ref.removeprefix("phoenix://")
    path = envelope.get("path")
    ref = envelope.get("ref")
    if not isinstance(path, str) or not path or path != expected_path:
        raise SealedEnvelopeValidationError("sealed envelope path does not match")
    if not isinstance(ref, str) or ref != requested_ref:
        raise SealedEnvelopeValidationError("sealed envelope ref does not match")

    ephemeral_key = envelope.get("ephemeral_key")
    nonce = envelope.get("nonce")
    ciphertext = envelope.get("ciphertext")
    if not all(isinstance(value, str) for value in (ephemeral_key, nonce, ciphertext)):
        raise SealedEnvelopeValidationError("sealed envelope binary fields are invalid")
    _decode_base64(ephemeral_key, expected_size=SEAL_PUBLIC_KEY_BYTES)
    _decode_base64(nonce, expected_size=SEAL_NONCE_BYTES)
    # NaCl box ciphertext includes a 16-byte authenticator even for an empty payload.
    _decode_base64(ciphertext, minimum_size=16)

    return {
        "version": version,
        "algorithm": SEAL_ALGORITHM,
        "path": path,
        "ref": ref,
        "ephemeral_key": ephemeral_key,
        "nonce": nonce,
        "ciphertext": ciphertext,
    }


def encode_opaque_sealed_token(envelope: Mapping[str, Any]) -> str:
    canonical = json.dumps(dict(envelope), ensure_ascii=True, separators=(",", ":"))
    return f"{SEALED_TOKEN_PREFIX}{base64.b64encode(canonical.encode('utf-8')).decode('ascii')}"
