"""Tests for the ``doctor`` subcommand (#35): configuration, credentials,
store, and sync-state checks, run as one pass over a local-mode install.

Written before ``whoopmcp.doctor`` exists -- every test below is expected to
fail on collection/import until that module and ``__main__.py``'s ``doctor``
subcommand are implemented. Nothing here calls the real WHOOP API; the one
check that reuses networked auth code (credentials) is exercised purely
against the local token store, matching ``test_auth.py``'s own precedent of
never hitting WHOOP in a test.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from whoopmcp.__main__ import main
from whoopmcp.auth import FileTokenStore, Token

ACCESS_TOKEN_VALUE = "super-secret-access-token-value"
REFRESH_TOKEN_VALUE = "super-secret-refresh-token-value"


def _set_required_env_and_state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://localhost:8443/callback")
    monkeypatch.setenv("WHOOPMCP_STATE_DIR", str(tmp_path))


def _valid_token() -> Token:
    return Token(
        ACCESS_TOKEN_VALUE,
        expires_at=time.time() + 3600,
        refresh_token=REFRESH_TOKEN_VALUE,
        scopes=("read:sleep", "offline"),
    )


def _expired_token() -> Token:
    return Token(
        ACCESS_TOKEN_VALUE,
        expires_at=time.time() - 3600,
        refresh_token=REFRESH_TOKEN_VALUE,
        scopes=("read:sleep", "offline"),
    )


# -- one test per diagnosed case (issue's "Tests to write") ------------------


def test_doctor_reports_missing_configuration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from whoopmcp.doctor import run_checks

    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("WHOOP_CLIENT_ID", raising=False)
    monkeypatch.delenv("WHOOP_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("WHOOP_REDIRECT_URI", raising=False)

    checks = run_checks()

    assert len(checks) == 1
    check = checks[0]
    assert check.name == "configuration"
    assert check.ok is False
    assert "missing required environment variable" in check.message
    # No Config could be built, so nothing downstream (credentials, store,
    # sync) can possibly have run -- run_checks must not fabricate results
    # for checks it never actually performed.


def test_doctor_reports_expired_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from whoopmcp.config import Config
    from whoopmcp.doctor import run_checks

    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    config = Config.from_env()
    FileTokenStore(config.token_path).save(_expired_token())

    checks = run_checks()

    by_name = {check.name: check for check in checks}
    credentials = by_name["credentials"]
    assert credentials.ok is False
    assert "expired" in credentials.message.lower()
    assert ACCESS_TOKEN_VALUE not in credentials.message
    assert REFRESH_TOKEN_VALUE not in credentials.message


def test_doctor_reports_unreachable_store(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from whoopmcp.config import Config
    from whoopmcp.doctor import run_checks

    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    config = Config.from_env()
    FileTokenStore(config.token_path).save(_valid_token())

    # cache_path is derived from state_dir; pointing state_dir at a location
    # whose "cache.sqlite3" name collides with a directory makes open_store
    # fail deterministically on every platform, unlike a chmod-based
    # permissions test which behaves differently on Windows.
    blocked_cache_path = config.cache_path
    blocked_cache_path.mkdir(parents=True)

    checks = run_checks()

    by_name = {check.name: check for check in checks}
    store_check = by_name["store"]
    assert store_check.ok is False
    # Redacted to the exception type only -- never a path or traceback,
    # mirroring server._check_token_store_reachable's own precedent.
    assert str(blocked_cache_path) not in store_check.message


def test_doctor_reports_stale_or_absent_sync(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from whoopmcp import store as store_module
    from whoopmcp.config import Config
    from whoopmcp.doctor import run_checks

    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    config = Config.from_env()
    FileTokenStore(config.token_path).save(_valid_token())

    conn = store_module.open_store(config.cache_path)
    try:
        store_module.link_principal_to_member(
            conn, client_id="local", issuer=None, subject=None, whoop_user_id=42
        )
    finally:
        conn.close()

    checks = run_checks()

    by_name = {check.name: check for check in checks}
    sync_check = by_name["sync"]
    # Zero sync_state rows today is expected and honest, not a failure --
    # #15 (scheduled incremental sync) has not been merged, so there has
    # never been a scheduled run to be stale against.
    assert sync_check.ok is True
    assert "no sync has ever run" in sync_check.message.lower()
    # Must not invent a staleness judgment or claim a schedule exists.
    assert "#15" in sync_check.message or "incremental sync" in sync_check.message.lower()


# -- exit codes ---------------------------------------------------------------


def test_doctor_exits_nonzero_when_any_check_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Valid config, but no token has ever been stored -- the credentials
    # check must fail, and doctor's own exit code must reflect it.
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    exit_code = main(["doctor"])

    assert exit_code != 0
    assert exit_code != 2  # 2 is reserved for the bad-argument class of error


def test_doctor_exits_zero_when_all_checks_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from whoopmcp.config import Config

    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    config = Config.from_env()
    FileTokenStore(config.token_path).save(_valid_token())

    # An openable, empty store (no linked member, no sync_state rows) is an
    # entirely healthy state, not a failure -- open_store's own migration
    # creates the schema on first use.
    from whoopmcp import store as store_module

    store_module.open_store(config.cache_path).close()

    exit_code = main(["doctor"])

    assert exit_code == 0


def test_doctor_never_prints_token_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp.config import Config

    config = Config.from_env()
    FileTokenStore(config.token_path).save(_valid_token())

    from whoopmcp import store as store_module

    store_module.open_store(config.cache_path).close()

    exit_code = main(["doctor"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert ACCESS_TOKEN_VALUE not in captured.out
    assert REFRESH_TOKEN_VALUE not in captured.out
    assert ACCESS_TOKEN_VALUE not in captured.err
    assert REFRESH_TOKEN_VALUE not in captured.err


# -- local entry point stays importable without hosted-only extras ----------


def test_entry_point_importable_without_optional_extras() -> None:
    # There is no "hosted" extras group in pyproject.toml at all -- hosted
    # mode's only distinct dependency (starlette, via the mcp SDK) is a base
    # dependency, so there is no hosted-vs-local dependency split for this
    # test to assert on. What IS extras-gated is `keyring` (a local-mode
    # token backend), lazily imported inside KeyringTokenStore.__init__
    # (auth.py), never at module scope -- importing the entry point must
    # never require it, or any other extras-gated dependency, to be
    # installed. Run in a fresh subprocess rather than merely re-importing
    # in-process, since a module already imported by the test process would
    # short-circuit the real check via sys.modules.
    result = subprocess.run(
        [sys.executable, "-c", "import whoopmcp.__main__"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
