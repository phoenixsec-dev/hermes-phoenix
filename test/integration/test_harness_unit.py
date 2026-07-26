from __future__ import annotations

import subprocess

from . import harness
from .harness import detect_availability


def test_detects_go_in_home_local_toolchain_when_not_on_path(tmp_path):
    source = tmp_path / "phoenix"
    source.mkdir()
    (source / "go.mod").write_text("module synthetic.invalid/phoenix\n")

    go = tmp_path / ".local" / "go" / "bin" / "go"
    go.parent.mkdir(parents=True)
    go.write_text("#!/bin/sh\necho 'go version go1.test linux/amd64'\n")
    go.chmod(0o755)

    availability = detect_availability(
        {
            "HOME": str(tmp_path),
            "PATH": "",
            "PHOENIX_SRC": str(source),
        }
    )
    assert availability.available is True
    assert availability.go_bin == str(go)


def test_rejects_executable_that_does_not_report_a_go_version(tmp_path):
    source = tmp_path / "phoenix"
    source.mkdir()
    (source / "go.mod").write_text("module synthetic.invalid/phoenix\n")
    fake = tmp_path / "fake-go"
    fake.write_text("#!/bin/sh\necho not-go\n")
    fake.chmod(0o755)
    availability = detect_availability(
        {
            "HOME": str(tmp_path),
            "PHOENIX_SRC": str(source),
            "GO_BIN": str(fake),
        }
    )
    assert availability.available is False
    assert "not runnable" in availability.reason


def test_version_probe_timeout_cleanly_reports_unavailable(tmp_path, monkeypatch):
    source = tmp_path / "phoenix"
    source.mkdir()
    (source / "go.mod").write_text("module synthetic.invalid/phoenix\n")
    fake = tmp_path / "fake-go"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="go version", timeout=10)

    monkeypatch.setattr(harness.subprocess, "run", timeout)
    availability = detect_availability(
        {
            "HOME": str(tmp_path),
            "PHOENIX_SRC": str(source),
            "GO_BIN": str(fake),
        }
    )
    assert availability.available is False
    assert "not runnable" in availability.reason


def test_explicit_invalid_go_bin_fails_without_fallback(tmp_path):
    source = tmp_path / "phoenix"
    source.mkdir()
    (source / "go.mod").write_text("module synthetic.invalid/phoenix\n")
    availability = detect_availability(
        {
            "HOME": str(tmp_path),
            "PHOENIX_SRC": str(source),
            "GO_BIN": str(tmp_path / "missing-go"),
        }
    )
    assert availability.available is False
    assert "GO_BIN" in availability.reason
