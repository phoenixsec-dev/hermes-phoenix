"""Secure profile identity file handling."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import IdentityError

_MAX_CREDENTIAL_BYTES = 64 * 1024


def _read_secure_bytes(path: Path, *, label: str) -> bytes:
    """Read a small owner-only regular file without following symlinks."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise IdentityError(
            f"Could not open {label}",
            code="PHOENIX_IDENTITY_FILE_UNREADABLE",
            remediation=f"Confirm {path} exists, is a regular file, and is readable by the Hermes user.",
        ) from exc

    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise IdentityError(f"{label} must be a regular file", code="PHOENIX_IDENTITY_FILE_UNSAFE")
        if info.st_uid != os.geteuid():
            raise IdentityError(
                f"{label} must be owned by the Hermes process user",
                code="PHOENIX_IDENTITY_FILE_UNSAFE",
            )
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise IdentityError(
                f"{label} has group or other permissions",
                code="PHOENIX_IDENTITY_FILE_PERMISSIONS",
                remediation=f"Run chmod 600 {path} (or chmod 400 for read-only material).",
            )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(fd, min(8192, _MAX_CREDENTIAL_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_CREDENTIAL_BYTES:
                raise IdentityError(f"{label} is unexpectedly large", code="PHOENIX_IDENTITY_FILE_INVALID")
        return b"".join(chunks)
    finally:
        os.close(fd)


def read_secure_file(path: Path, *, label: str) -> str:
    data = _read_secure_bytes(path, label=label)
    try:
        value = data.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise IdentityError(f"{label} is not valid UTF-8", code="PHOENIX_IDENTITY_FILE_INVALID") from exc
    if not value or "\n" in value or "\r" in value:
        raise IdentityError(f"{label} is empty or contains multiple lines", code="PHOENIX_IDENTITY_FILE_INVALID")
    return value


def read_runtime_token(path: Path) -> str:
    token = read_secure_file(path, label="Phoenix token file")
    if token.startswith("phxs_"):
        raise IdentityError(
            "Phoenix token file contains a short-lived session token",
            code="PHOENIX_SESSION_TOKEN_REJECTED",
            remediation="Configure a durable, profile-scoped bootstrap token file for runtime identity.",
        )
    return token


def validate_private_key_file(path: Path) -> None:
    data = _read_secure_bytes(path, label="Phoenix mTLS private key")
    if not data.strip():
        raise IdentityError("Phoenix mTLS private key is empty", code="PHOENIX_IDENTITY_FILE_INVALID")
