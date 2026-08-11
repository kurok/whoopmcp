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


# -- delete-member: revoke-ordering / attribution fixes (issue #65) ---------
#
# Three regressions on top of the two tests above: (1) "grant already gone"
# (no stored credentials) must count as revoke-step success and still reach
# local deletion, instead of aborting with data intact; (2) a stored token
# that cannot be attributed to the requested member (linked ids != {id})
# must never be revoked -- upstream revoke is skipped entirely, and local
# deletion still proceeds; (3) a genuine transport failure on the revoke
# call must still abort with nothing deleted, unchanged from today.


def test_delete_member_subcommand_deletes_locally_when_no_credentials_are_stored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """access_token() raising "no stored credentials found" (no token file at
    all -- e.g. an operator already ran whoop_logout) must be treated as
    revoke-step success, not a reason to abort before local deletion."""
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config

    config = Config.from_env()
    # Deliberately no FileTokenStore(...).save(...) call: there is no token
    # file at all.

    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="local", issuer=None, subject=None, whoop_user_id=42
    )
    conn.close()

    with respx.mock:
        route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(204))
        exit_code = main(["delete-member", "--whoop-user-id", "42"])

    assert exit_code == 0
    # access_token() fails before revoke_upstream is ever reached, so the
    # HTTP endpoint is never called -- there was nothing to revoke.
    assert not route.called
    conn = store_module.open_store(config.cache_path)
    assert (
        store_module.get_member_for_principal(conn, client_id="local", issuer=None, subject=None)
        is None
    )
    conn.close()


def test_delete_member_subcommand_skips_revoke_for_an_unattributable_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two members have ever been linked (42 and 43), but there is only ever
    one stored token file -- it cannot be attributed to either. delete-member
    on 42 must not revoke that token (it may well be 43's live grant), yet
    must still remove 42's own principal link."""
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config

    config = Config.from_env()
    FileTokenStore(config.token_path).save(
        Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    )

    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="local-old", issuer=None, subject=None, whoop_user_id=42
    )
    store_module.link_principal_to_member(
        conn, client_id="local-new", issuer=None, subject=None, whoop_user_id=43
    )
    conn.close()

    with respx.mock:
        route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(204))
        exit_code = main(["delete-member", "--whoop-user-id", "42"])

    assert exit_code == 0
    assert not route.called
    # The token is not this member's to revoke, so it's left alone entirely.
    assert FileTokenStore(config.token_path).load() is not None

    conn = store_module.open_store(config.cache_path)
    assert (
        store_module.get_member_for_principal(
            conn, client_id="local-old", issuer=None, subject=None
        )
        is None
    )
    assert (
        store_module.get_member_for_principal(
            conn, client_id="local-new", issuer=None, subject=None
        )
        is not None
    )
    conn.close()


def test_delete_member_subcommand_still_aborts_on_a_genuine_transport_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression guard: a real failure talking to WHOOP's revoke endpoint
    (mocked here as a 500, distinct from the invalid_grant/no-credentials
    "nothing to revoke" cases) must still abort before any local deletion --
    the fix must not loosen this path."""
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
        route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(500))
        exit_code = main(["delete-member", "--whoop-user-id", "42"])

    assert exit_code != 0
    assert route.called
    # Nothing was deleted: neither the token nor the principal link.
    assert FileTokenStore(config.token_path).load() is not None
    conn = store_module.open_store(config.cache_path)
    assert (
        store_module.get_member_for_principal(conn, client_id="local", issuer=None, subject=None)
        is not None
    )
    conn.close()


# -- doctor subcommand argparse wiring (issue #35) ---------------------------
#
# doctor takes no arguments (a zero-argument health check, unlike
# delete-member/export-member/erase-member which all require
# --whoop-user-id) and must run even when required config is missing --
# see test_doctor.py for the diagnostic content itself; this only checks
# that argparse recognises the subcommand and dispatches to it at all.


def test_doctor_subcommand_is_recognised_by_argparse(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    # Exit code is doctor's own business (see test_doctor.py); this test only
    # asserts argparse dispatches "doctor" at all, rather than treating it as
    # an unknown subcommand (argparse's own exit code for that is 2, the same
    # code doctor itself never returns on a clean run -- so this alone would
    # be an ambiguous assertion without test_doctor.py's own exit-code tests).
    exit_code = main(["doctor"])

    assert isinstance(exit_code, int)


def test_doctor_subcommand_runs_before_config_validation_exits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Missing configuration is itself one of doctor's own checks -- unlike
    # every other subcommand, doctor must not be preempted by __main__.py's
    # own up-front `Config.from_env()` call, which normally exits 2 before
    # any subcommand dispatch runs at all.
    for name in ("WHOOP_CLIENT_ID", "WHOOP_CLIENT_SECRET", "WHOOP_REDIRECT_URI"):
        monkeypatch.delenv(name, raising=False)

    main(["doctor"])

    # Must reach doctor's own reporting rather than __main__.py's generic
    # early exit: a bare "missing required environment variable" one-liner
    # on stderr with no subcommand-specific framing would indicate the
    # up-front Config.from_env() call intercepted it before doctor ran.
    out = capsys.readouterr().out
    assert "configuration" in out.lower()


# -- backfill subcommand (issue #14) -----------------------------------------
#
# Like delete-member/export-member/erase-member/enforce-retention, backfill
# is deliberately CLI-only (#30/#32's operator-only precedent) and gated on
# the persistent store actually being enabled: PRIVACY.md promises the store
# is "off by default; only written if you set WHOOPMCP_CACHE=true", and
# backfill is the first bulk writer that would otherwise break that promise.


def test_backfill_subcommand_refuses_when_cache_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("WHOOPMCP_CACHE", raising=False)

    with respx.mock:
        exit_code = main(["backfill", "--whoop-user-id", "42"])
        # Refused before any network traffic: no route was ever needed.
        assert respx.calls.call_count == 0

    assert exit_code == 2
    err = capsys.readouterr().err
    # The refusal must tell the operator exactly which knob to turn.
    assert "WHOOPMCP_CACHE" in err
    assert "Traceback" not in err


def test_backfill_subcommand_refuses_an_unlinked_whoop_user_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Same confirmation guard as delete-member: --whoop-user-id must match
    # the member already linked in principal_members ("the user is an
    # argument, never ambient"), never name an arbitrary id.
    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    monkeypatch.setenv("WHOOPMCP_CACHE", "true")

    with respx.mock:
        exit_code = main(["backfill", "--whoop-user-id", "999"])
        assert respx.calls.call_count == 0

    assert exit_code == 2
    assert "999" in capsys.readouterr().err


def test_backfill_subcommand_runs_backfill_for_a_linked_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    monkeypatch.setenv("WHOOPMCP_CACHE", "true")

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

    recorded: dict[str, object] = {}

    async def fake_run_backfill(
        conn: object, client: object, config: object, whoop_user_id: int
    ) -> dict[str, int]:
        del conn, client, config
        recorded["whoop_user_id"] = whoop_user_id
        return {"recoveries": 0, "sleeps": 0, "cycles": 3, "workouts": 0}

    monkeypatch.setattr("whoopmcp.backfill.run_backfill", fake_run_backfill)

    exit_code = main(["backfill", "--whoop-user-id", "42"])

    assert exit_code == 0
    assert recorded["whoop_user_id"] == 42
    captured = capsys.readouterr()
    # The summary goes to stderr, never stdout: on stdio transport stdout
    # carries JSON-RPC framing, and no sibling subcommand writes there either.
    assert captured.out == ""
    assert "cycles" in captured.err
    # No token value on any output path.
    assert "access-tok" not in captured.err
    assert "refresh-tok" not in captured.err


def test_replay_webhook_subcommand_refuses_when_cache_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Same resolved-blocker gate as backfill/reconcile-webhooks: a pending
    # row's replay fetches from WHOOP and writes into the persistent store,
    # which PRIVACY.md promises is off by default (#19 review finding).
    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("WHOOPMCP_CACHE", raising=False)

    with respx.mock:
        exit_code = main(["replay-webhook", "--trace-id", "some-trace-id"])
        assert respx.calls.call_count == 0

    assert exit_code == 2
    err = capsys.readouterr().err
    assert "WHOOPMCP_CACHE" in err
    assert "Traceback" not in err


def test_replay_webhook_subcommand_reports_a_terminal_replay_as_a_no_op(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # replay_webhook_event returns False for an already-success/dead_letter
    # row (a safe no-op, per its own idempotency contract) -- the CLI must
    # say so plainly rather than reporting "replayed" for a call that
    # reprocessed nothing (#19 review finding: an operator re-running a
    # dead-lettered event after fixing the bug that caused it must be able
    # to tell whether their fix was actually exercised).
    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    monkeypatch.setenv("WHOOPMCP_CACHE", "true")

    async def fake_replay_webhook_event(
        conn: object, client: object, trace_id: str, **kwargs: object
    ) -> bool:
        del conn, client, kwargs
        assert trace_id == "already-done"
        return False  # already terminal -- nothing reprocessed

    monkeypatch.setattr(
        "whoopmcp.webhook_processor.replay_webhook_event", fake_replay_webhook_event
    )

    exit_code = main(["replay-webhook", "--trace-id", "already-done"])

    assert exit_code == 0
    err = capsys.readouterr().err
    assert "already-done" in err
    assert "already terminal" in err
    assert "nothing was reprocessed" in err
    # Must not claim a replay happened when it didn't.
    assert "whoopmcp: replayed" not in err
