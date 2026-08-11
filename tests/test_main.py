"""Checks on the CLI entry point, mostly about failing legibly."""

from __future__ import annotations

import time
from pathlib import Path

import httpx
import pytest
import respx

from whoopmcp.__main__ import main
from whoopmcp.auth import USER_ACCESS_URL, FileTokenStore, Token


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


# -- transport/host/port CLI <-> env merge (issue #27) ----------------------
#
# build_server() is monkeypatched to a fake server that just records the
# kwargs .run() was called with -- an unmocked run() would try to actually
# bind a socket and serve forever under streamable-http, or block reading
# stdin under stdio.


def _set_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://localhost:8443/callback")


class _RecordingServer:
    def __init__(self, calls: list[dict[str, object]]) -> None:
        self._calls = calls

    def run(self, **kwargs: object) -> None:
        self._calls.append(kwargs)


def test_cli_silence_lets_whoopmcp_transport_env_var_win(monkeypatch: pytest.MonkeyPatch) -> None:
    # --transport must default to None, not "stdio", or CLI silence would
    # always override WHOOPMCP_TRANSPORT with the argparse default.
    _set_required_env(monkeypatch)
    monkeypatch.setenv("WHOOPMCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("WHOOPMCP_HTTP_HOST", "192.0.2.1")
    monkeypatch.setenv("WHOOPMCP_HTTP_PORT", "9001")
    calls: list[dict[str, object]] = []
    monkeypatch.setattr("whoopmcp.server.build_server", lambda: _RecordingServer(calls))

    assert main([]) == 0

    assert calls == [{"transport": "streamable-http", "host": "192.0.2.1", "port": 9001}]


def test_cli_transport_flag_overrides_the_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required_env(monkeypatch)
    monkeypatch.setenv("WHOOPMCP_TRANSPORT", "streamable-http")
    calls: list[dict[str, object]] = []
    monkeypatch.setattr("whoopmcp.server.build_server", lambda: _RecordingServer(calls))

    assert main(["--transport", "stdio"]) == 0

    # stdio's run() overload takes no host/port kwargs.
    assert calls == [{"transport": "stdio"}]


def test_cli_host_and_port_override_config(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required_env(monkeypatch)
    monkeypatch.setenv("WHOOPMCP_HTTP_HOST", "192.0.2.1")
    monkeypatch.setenv("WHOOPMCP_HTTP_PORT", "9001")
    calls: list[dict[str, object]] = []
    monkeypatch.setattr("whoopmcp.server.build_server", lambda: _RecordingServer(calls))

    assert main(["--transport", "streamable-http", "--host", "127.0.0.2", "--port", "1234"]) == 0

    assert calls == [{"transport": "streamable-http", "host": "127.0.0.2", "port": 1234}]


# -- delete-member subcommand (issue #30) ------------------------------------
#
# The revoke-then-forget primitive (Authenticator.revoke_and_forget) is
# deliberately NOT an MCP tool -- server.py never registers it -- so an
# operator's only way to trigger it is this CLI subcommand. --whoop-user-id
# is a confirmation guard against operator error (there is exactly one live
# grant per process today; see auth.py/store.py for why), not a selector
# among several grants.


def _set_required_env_and_state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://localhost:8443/callback")
    monkeypatch.setenv("WHOOPMCP_STATE_DIR", str(tmp_path))


def test_delete_member_subcommand_revokes_and_removes_principal_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config

    config = Config.from_env()
    FileTokenStore(config.token_path).save(
        Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    )

    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="local", issuer=None, subject=None, whoop_user_id=42
    )
    conn.close()

    with respx.mock:
        route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(204))
        exit_code = main(["delete-member", "--whoop-user-id", "42"])

    assert exit_code == 0
    # Verified against the mock and the store/database, not merely that no
    # error was raised.
    assert route.called
    assert FileTokenStore(config.token_path).load() is None

    conn = store_module.open_store(config.cache_path)
    assert (
        store_module.get_member_for_principal(conn, client_id="local", issuer=None, subject=None)
        is None
    )
    conn.close()


def test_delete_member_subcommand_refuses_a_mismatched_whoop_user_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # --whoop-user-id must match the id already linked in principal_members;
    # it guards against operator error, it does not select among grants.
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config

    config = Config.from_env()
    FileTokenStore(config.token_path).save(
        Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    )

    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="local", issuer=None, subject=None, whoop_user_id=42
    )
    conn.close()

    with respx.mock:
        route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(204))
        exit_code = main(["delete-member", "--whoop-user-id", "999"])

    assert exit_code != 0
    # Neither side effect happened: no upstream revoke, and the token is
    # still there -- a mismatched id must refuse, not silently no-op-succeed.
    assert not route.called
    assert FileTokenStore(config.token_path).load() is not None
