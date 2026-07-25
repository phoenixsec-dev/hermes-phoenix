"""Process-local Phoenix role session cache.

Session tokens never leave memory and are deliberately omitted from repr output.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Callable

_RENEW_WINDOW = timedelta(minutes=5)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class RoleSessionKey:
    server: str
    profile: str
    role: str
    identity: str
    seal_public_key: str = field(repr=False)


@dataclass(frozen=True)
class RoleSession:
    token: str = field(repr=False)
    expires_at: datetime


class RoleSessionCache:
    """Serialize mint/renew per process and retain no disk state."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[RoleSessionKey, RoleSession] = {}

    def acquire(
        self,
        key: RoleSessionKey,
        *,
        mint: Callable[[], RoleSession],
        renew: Callable[[RoleSession], RoleSession],
    ) -> RoleSession:
        with self._lock:
            now = _utcnow()
            current = self._entries.get(key)
            if current is None or current.expires_at <= now:
                session = mint()
                self._entries[key] = session
                return session
            if current.expires_at <= now + _RENEW_WINDOW:
                try:
                    session = renew(current)
                except Exception:
                    # Never keep using a token whose renewal was required but failed.
                    self._entries.pop(key, None)
                    raise
                self._entries[key] = session
                return session
            return current

    def reset_for_tests(self) -> None:
        with self._lock:
            self._entries.clear()


ROLE_SESSIONS = RoleSessionCache()
