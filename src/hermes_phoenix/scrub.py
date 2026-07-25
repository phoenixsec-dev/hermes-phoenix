"""Process-local value-aware output scrubbing for Hermes hooks."""

from __future__ import annotations

import base64
import os
import re
import threading
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .errors import ConfigurationError
from .refs import normalize_ref

MIN_REGISTERED_VALUE_LENGTH = 8
_MAX_SPEC_BYTES = 1024 * 1024
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_LABEL_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")
_SPEC_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\?)?=(.*)$")


@dataclass(frozen=True)
class EnvSpecEntry:
    name: str
    ref: str | None


def sanitize_label(label: str) -> str:
    cleaned = _LABEL_UNSAFE_RE.sub("-", label.strip()).strip("-._")[:64]
    return cleaned or "secret"


def label_from_ref(ref: str) -> str:
    return sanitize_label(ref.removeprefix("phoenix://").rstrip("/").rsplit("/", 1)[-1])


def _strip_trailing_comment(line: str) -> str:
    match = re.search(r"\s+#", line)
    return line[: match.start()].rstrip() if match else line


def read_env_spec(path: Path) -> tuple[EnvSpecEntry, ...]:
    """Read Path A names and refs without treating literal RHS text as values."""
    try:
        info = path.lstat()
        if path.is_symlink() or not path.is_file() or info.st_size > _MAX_SPEC_BYTES:
            raise OSError("unsafe spec file")
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(
            "Phoenix env spec is missing, unreadable, unsafe, or too large",
            code="PHOENIX_SPEC_INVALID",
            remediation="Configure spec_path as a readable regular refs-only Path A env-spec file.",
        ) from exc
    if len(raw) > _MAX_SPEC_BYTES:
        raise ConfigurationError("Phoenix env spec is too large", code="PHOENIX_SPEC_INVALID")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigurationError("Phoenix env spec is not valid UTF-8", code="PHOENIX_SPEC_INVALID") from exc
    if text.startswith("\ufeff"):
        raise ConfigurationError("Phoenix env spec must not contain a UTF-8 BOM", code="PHOENIX_SPEC_INVALID")

    entries: list[EnvSpecEntry] = []
    seen: set[str] = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_trailing_comment(raw_line).strip()
        if not line or line.startswith("#"):
            continue
        match = _SPEC_LINE_RE.fullmatch(line)
        if not match:
            raise ConfigurationError(
                f"Phoenix env spec line {line_number} is invalid",
                code="PHOENIX_SPEC_INVALID",
            )
        name, optional, raw_value = match.groups()
        if name in seen:
            raise ConfigurationError(
                f"Phoenix env spec repeats variable {name}",
                code="PHOENIX_SPEC_INVALID",
            )
        seen.add(name)
        value = raw_value.strip()
        ref = normalize_ref(value) if value.startswith("phoenix://") else None
        if optional and ref is None:
            raise ConfigurationError(
                f"Phoenix env spec line {line_number} uses ?= with a non-ref literal",
                code="PHOENIX_SPEC_INVALID",
            )
        entries.append(EnvSpecEntry(name=name, ref=ref))
    return tuple(entries)


class ScrubRegistry:
    """Thread-safe, process-only mapping from value forms to safe labels."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        placeholder: str = "[PHOENIX-SCRUBBED:{name}]",
    ) -> None:
        self._lock = threading.RLock()
        self._enabled = enabled
        self._placeholder = placeholder
        self._forms: dict[str, str] = {}
        self._pattern: re.Pattern[str] | None = None

    def configure(self, *, enabled: bool, placeholder: str) -> None:
        with self._lock:
            self._enabled = enabled
            if self._placeholder != placeholder:
                self._placeholder = placeholder
                self._pattern = None

    def register(self, value: str, *, name: str) -> bool:
        if not isinstance(value, str) or len(value) < MIN_REGISTERED_VALUE_LENGTH:
            return False
        label = sanitize_label(name)
        forms = {
            value,
            base64.b64encode(value.encode("utf-8")).decode("ascii"),
            urllib.parse.quote(value, safe=""),
        }
        with self._lock:
            changed = False
            for form in forms:
                existing = self._forms.get(form)
                selected = min(existing, label) if existing else label
                if existing != selected:
                    self._forms[form] = selected
                    changed = True
            if changed:
                self._pattern = None
        return True

    def register_ref_value(self, ref: str, value: str) -> bool:
        return self.register(value, name=label_from_ref(ref))

    def _compiled_pattern(self) -> re.Pattern[str] | None:
        if not self._forms:
            return None
        if self._pattern is not None:
            return self._pattern

        forms = sorted(self._forms, key=lambda item: (-len(item), item))
        secret_pattern = "|".join(re.escape(form) for form in forms)
        before, after = self._placeholder.split("{name}", 1)
        if before or after:
            placeholder_pattern = (
                re.escape(before) + r"[A-Za-z0-9._-]{1,64}" + re.escape(after)
            )
            expression = f"(?P<placeholder>{placeholder_pattern})|(?P<secret>{secret_pattern})"
        else:
            expression = f"(?P<secret>{secret_pattern})"
        self._pattern = re.compile(expression)
        return self._pattern

    def scrub(self, text: str) -> str:
        if not isinstance(text, str):
            text = str(text)
        with self._lock:
            if not self._enabled:
                return text
            pattern = self._compiled_pattern()
            if pattern is None:
                return text
            labels = dict(self._forms)
            placeholder = self._placeholder

        def replace(match: re.Match[str]) -> str:
            if match.groupdict().get("placeholder") is not None:
                return match.group(0)
            return placeholder.format(name=labels[match.group(0)])

        return pattern.sub(replace, text)

    def reset_for_tests(self) -> None:
        with self._lock:
            self._forms.clear()
            self._enabled = True
            self._placeholder = "[PHOENIX-SCRUBBED:{name}]"
            self._pattern = None


_REGISTRY = ScrubRegistry()


def get_scrub_registry() -> ScrubRegistry:
    return _REGISTRY


def register_spec_environment(
    path: Path,
    *,
    registry: ScrubRegistry | None = None,
    environ: Mapping[str, str] | None = None,
) -> tuple[EnvSpecEntry, ...]:
    entries = read_env_spec(path)
    target = registry or get_scrub_registry()
    env = os.environ if environ is None else environ
    for entry in entries:
        value = env.get(entry.name)
        if isinstance(value, str):
            target.register(value, name=entry.name)
    return entries
