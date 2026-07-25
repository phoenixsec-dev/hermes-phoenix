from __future__ import annotations

import base64
import urllib.parse

import pytest

from hermes_phoenix.errors import ConfigurationError
from hermes_phoenix.scrub import (
    ScrubRegistry,
    label_from_ref,
    read_env_spec,
    register_spec_environment,
)


def test_scrubs_literal_standard_base64_and_url_encoded_forms_idempotently():
    registry = ScrubRegistry()
    value = "synthetic value/with?symbols"
    encoded = base64.b64encode(value.encode()).decode()
    quoted = urllib.parse.quote(value, safe="")
    registry.register(value, name="CALDAV_PASSWORD")

    original = f"literal={value} base64={encoded} url={quoted}"
    scrubbed = registry.scrub(original)
    assert value not in scrubbed
    assert encoded not in scrubbed
    assert quoted not in scrubbed
    assert scrubbed.count("[PHOENIX-SCRUBBED:CALDAV_PASSWORD]") == 3
    assert registry.scrub(scrubbed) == scrubbed


def test_minimum_length_labels_and_deterministic_duplicate_ownership():
    registry = ScrubRegistry()
    assert registry.register("1234567", name="SHORT") is False
    assert registry.scrub("1234567") == "1234567"

    registry.register("shared-secret", name="z label")
    registry.register("shared-secret", name="a/label")
    assert registry.scrub("shared-secret") == "[PHOENIX-SCRUBBED:a-label]"
    assert label_from_ref("phoenix://services/hermes/kit/token value") == "token-value"


def test_longest_overlap_wins_and_custom_placeholder_is_respected():
    registry = ScrubRegistry(placeholder="<redacted:{name}>")
    registry.register("abcdefgh", name="short")
    registry.register("abcdefghij", name="long")
    assert registry.scrub("abcdefghij") == "<redacted:long>"
    assert registry.scrub("<redacted:long>") == "<redacted:long>"


def test_disabled_scrubber_returns_original_string():
    registry = ScrubRegistry(enabled=False)
    registry.register("synthetic-secret", name="TOKEN")
    assert registry.scrub("synthetic-secret") == "synthetic-secret"


def test_env_spec_registers_current_environment_values_but_not_literal_rhs(tmp_path):
    spec = tmp_path / "profile.spec"
    spec.write_text(
        "# refs and names only\n"
        "CALDAV_PASSWORD=phoenix://services/kit/caldav-password\n"
        "OPTIONAL_TOKEN?=phoenix://services/kit/optional-token # comment\n"
        "WHITEBOARD_BY=kit\n"
    )
    registry = ScrubRegistry()
    entries = register_spec_environment(
        spec,
        registry=registry,
        environ={
            "CALDAV_PASSWORD": "current-caldav-secret",
            "OPTIONAL_TOKEN": "current-optional-secret",
            "WHITEBOARD_BY": "current-environment-label",
        },
    )
    assert [(entry.name, entry.ref) for entry in entries] == [
        ("CALDAV_PASSWORD", "phoenix://services/kit/caldav-password"),
        ("OPTIONAL_TOKEN", "phoenix://services/kit/optional-token"),
        ("WHITEBOARD_BY", None),
    ]
    assert registry.scrub("current-caldav-secret") == "[PHOENIX-SCRUBBED:CALDAV_PASSWORD]"
    assert registry.scrub("current-optional-secret") == "[PHOENIX-SCRUBBED:OPTIONAL_TOKEN]"
    assert registry.scrub("current-environment-label") == "[PHOENIX-SCRUBBED:WHITEBOARD_BY]"
    assert registry.scrub("literal kit remains") == "literal kit remains"


@pytest.mark.parametrize(
    "content",
    [
        "BROKEN LINE\n",
        "DUP=phoenix://services/a/key\nDUP=phoenix://services/a/other\n",
        "OPTIONAL?=literal\n",
        "REF=phoenix://services/../key\n",
        "\ufeffREF=phoenix://services/a/key\n",
    ],
)
def test_env_spec_rejects_malformed_content(tmp_path, content):
    spec = tmp_path / "bad.spec"
    spec.write_text(content)
    with pytest.raises(ConfigurationError) as caught:
        read_env_spec(spec)
    assert caught.value.code in {"PHOENIX_SPEC_INVALID", "PHOENIX_REF_INVALID"}
