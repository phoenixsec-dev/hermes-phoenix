from __future__ import annotations

import pytest

from hermes_phoenix.errors import ConfigurationError
from hermes_phoenix.refs import normalize_list_prefix, normalize_ref


def test_normalize_ref_supports_absolute_and_relative_refs():
    assert normalize_ref("phoenix://services/kit/token") == "phoenix://services/kit/token"
    assert normalize_ref("calendar/password", "services/hermes/kit") == "phoenix://services/hermes/kit/calendar/password"


@pytest.mark.parametrize("value", ["phoenix://services/../token", "phoenix://services//token", "/absolute", "./token"])
def test_normalize_ref_rejects_unsafe_segments(value):
    with pytest.raises(ConfigurationError):
        normalize_ref(value, "services/hermes/kit")


def test_list_prefix_is_namespace_scoped():
    assert normalize_list_prefix(None, "services/hermes/kit") == "services/hermes/kit/"
    assert normalize_list_prefix("calendar", "services/hermes/kit") == "services/hermes/kit/calendar/"
    assert normalize_list_prefix("calendar/2026", "services/hermes/kit") == "services/hermes/kit/calendar/2026/"
    assert normalize_list_prefix("phoenix://services/shared", "services/hermes/kit") == "services/shared/"


@pytest.mark.parametrize(
    "value, default_namespace",
    [("phoenix://", "services/hermes/kit"), (None, None), ("calendar", None)],
)
def test_list_prefix_rejects_root_or_unscoped_relative_listing(value, default_namespace):
    with pytest.raises(ConfigurationError):
        normalize_list_prefix(value, default_namespace)
