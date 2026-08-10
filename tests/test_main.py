"""Checks on the CLI entry point, mostly about failing legibly."""

from __future__ import annotations

import pytest

from whoopmcp.__main__ import main


def test_version_exits_cleanly(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])

    assert exc.value.code == 0
    assert "whoopmcp" in capsys.readouterr().out


def test_missing_config_reports_one_line_and_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Config is validated before the transport starts. If it were left to the
    # lifespan, anyio would wrap the error in an ExceptionGroup and the user
    # would get a traceback instead of a usable message.
    for name in ("WHOOP_CLIENT_ID", "WHOOP_CLIENT_SECRET", "WHOOP_REDIRECT_URI"):
        monkeypatch.delenv(name, raising=False)

    assert main([]) == 2

    err = capsys.readouterr().err
    assert err.startswith("whoopmcp: missing required environment variable")
    assert "Traceback" not in err


def test_bad_redirect_uri_reports_one_line_and_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "http://localhost:8080/callback")

    assert main([]) == 2

    assert "must not use http://" in capsys.readouterr().err
