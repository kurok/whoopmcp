from __future__ import annotations

import asyncio
import base64
import contextlib
import io
import json
import logging
import os
import stat
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from whoopmcp.auth import (
    AUTHORIZE_URL,
    TOKEN_URL,
    USER_ACCESS_URL,
    Authenticator,
    AuthError,
    EncryptedFileTokenStore,
    FileTokenStore,
    Token,
    atomic_write_text,
    build_authorize_url,
)
from whoopmcp.config import Config


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config.from_env(
        {
            "WHOOP_CLIENT_ID": "cid",
            "WHOOP_CLIENT_SECRET": "csecret",
            "WHOOP_REDIRECT_URI": "https://localhost:8443/callback",
            "WHOOPMCP_STATE_DIR": str(tmp_path),
        }
    )


# -- authorize URL ---------------------------------------------------------


def test_authorize_url_carries_the_documented_parameters(config: Config) -> None:
    url, state = build_authorize_url(config)
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    assert url.startswith(AUTHORIZE_URL)
    assert query["client_id"] == ["cid"]
    assert query["response_type"] == ["code"]
    assert query["redirect_uri"] == ["https://localhost:8443/callback"]
    assert query["state"] == [state]
    assert "offline" in query["scope"][0].split()


def test_authorize_url_state_is_unpredictable(config: Config) -> None:
    states = {build_authorize_url(config)[1] for _ in range(20)}

    assert len(states) == 20


# -- state verification ----------------------------------------------------


def test_verify_state_accepts_the_pending_state(config: Config) -> None:
    auth = Authenticator(config)
    url = auth.start_login()
    state = parse_qs(urlparse(url).query)["state"][0]

    auth.verify_state(state)  # must not raise


def test_verify_state_rejects_a_foreign_state(config: Config) -> None:
    auth = Authenticator(config)
    auth.start_login()

    with pytest.raises(AuthError, match="state mismatch"):
        auth.verify_state("attacker-supplied")


def test_verify_state_rejects_when_no_login_is_pending(config: Config) -> None:
    with pytest.raises(AuthError, match="no login in progress"):
        Authenticator(config).verify_state("anything")


# -- single-use state (issue #120) ------------------------------------------
#
# OAuth's security BCP requires state to be single-use: a successful
# verification must consume it so a second verification of the same value
# fails, while a failed verification must NOT consume it (D2).


def test_verify_state_is_consumed_on_successful_verification(config: Config) -> None:
    """Test 1 (headline): one start_login(), then verify_state(state) succeeds
    and a second verify_state(state) raises AuthError.

    This test MUST FAIL against current main -- the state is not cleared on
    successful verification, so the second call would also succeed.
    """
    auth = Authenticator(config)
    url = auth.start_login()
    state = parse_qs(urlparse(url).query)["state"][0]

    # First verification succeeds
    auth.verify_state(state)

    # Second verification must fail with the state now consumed
    with pytest.raises(AuthError, match="no login in progress"):
        auth.verify_state(state)


def test_verify_state_mismatch_does_not_consume_pending_state(config: Config) -> None:
    """Test 2: A mismatch does not consume the pending state (D2).

    verify_state("wrong") raises, and a subsequent verify_state(correct)
    still succeeds. This is important because clearing on mismatch would let
    an attacker kill a legitimate in-progress login by sending one bad value.
    """
    auth = Authenticator(config)
    url = auth.start_login()
    state = parse_qs(urlparse(url).query)["state"][0]

    # A mismatch raises but does NOT consume the state
    with pytest.raises(AuthError, match="state mismatch"):
        auth.verify_state("wrong-state")

    # The correct state can still verify
    auth.verify_state(state)


def test_fresh_start_login_issues_new_state(config: Config) -> None:
    """Test 3: A fresh start_login() issues a new state and the previous one
    no longer verifies.
    """
    auth = Authenticator(config)

    # First login
    url1 = auth.start_login()
    state1 = parse_qs(urlparse(url1).query)["state"][0]
    auth.verify_state(state1)  # Consume the first state

    # Second login with a new state
    url2 = auth.start_login()
    state2 = parse_qs(urlparse(url2).query)["state"][0]

    # The states must be different
    assert state1 != state2

    # The old state no longer verifies. A new login is pending (state2), so
    # per D2 the old value is indistinguishable from any other wrong guess:
    # it raises "state mismatch", exactly like test 2's foreign value, and
    # does not consume the new pending state. Raising "no login in progress"
    # here would require remembering previously-consumed values, which would
    # hand an attacker an oracle distinguishing "was once a real state" from
    # "never issued".
    with pytest.raises(AuthError, match="state mismatch"):
        auth.verify_state(state1)

    # The new state should verify
    auth.verify_state(state2)


@respx.mock
async def test_both_real_flows_work_end_to_end(config: Config) -> None:
    """Test 4: Both real flows (verify-then-exchange) work end to end.

    Tests the __main__.py login path and server.py's whoop_complete_login,
    each doing verify-then-exchange once. Mock HTTP with respx.
    """
    # Mock the token endpoint
    respx.post(TOKEN_URL).mock(
        return_value=respx.MockResponse(
            200,
            json={
                "access_token": "new-access-token",
                "expires_in": 3600,
                "refresh_token": "new-refresh-token",
                "scope": "read:sleep offline",
            },
        )
    )

    auth = Authenticator(config)

    # Simulate __main__.py's _login flow: verify-then-exchange
    url = auth.start_login()
    state = parse_qs(urlparse(url).query)["state"][0]
    auth.verify_state(state)
    token = await auth.exchange_code("auth-code-123")
    assert token.access_token == "new-access-token"

    # Verify the token was persisted
    assert FileTokenStore(config.token_path).load() == token

    # Clear for the second flow test
    auth.logout()
    FileTokenStore(config.token_path).clear()

    # Simulate server.py's whoop_complete_login flow: verify-then-exchange
    url = auth.start_login()
    state = parse_qs(urlparse(url).query)["state"][0]
    auth.verify_state(state)
    token = await auth.exchange_code("another-code-456")
    assert token.access_token == "new-access-token"

    # Verify the token was persisted
    assert FileTokenStore(config.token_path).load() == token


def test_state_does_not_appear_in_exception_messages_or_logs(
    config: Config, caplog: pytest.LogCaptureFixture
) -> None:
    """Test 6: No state value reaches any log record or exception message.

    State is cryptographic material and must never appear in error messages
    or logs, on either the verify or exchange path.
    """
    caplog.set_level(logging.DEBUG)

    auth = Authenticator(config)
    url = auth.start_login()
    state = parse_qs(urlparse(url).query)["state"][0]

    # Consume the state on verify path
    auth.verify_state(state)

    # Try to verify again -- the exception should not leak the state value
    with pytest.raises(AuthError) as exc_info:
        auth.verify_state(state)

    error_message = str(exc_info.value)
    assert state not in error_message, (
        f"state value {state!r} leaked in exception message: {error_message}"
    )

    # Check logs do not contain state
    # caplog.text is every captured record's message plus its formatted exc_info
    assert state not in caplog.text, f"state value {state!r} leaked in log records"

    # Also check each record individually
    for record in caplog.records:
        assert state not in record.getMessage(), (
            f"state value {state!r} leaked in log message: {record.getMessage()}"
        )
        if record.exc_text:
            assert state not in record.exc_text, (
                f"state value {state!r} leaked in log exc_text: {record.exc_text}"
            )


# -- token -----------------------------------------------------------------


def test_token_from_response_computes_absolute_expiry() -> None:
    token = Token.from_response(
        {"access_token": "a", "expires_in": 3600, "refresh_token": "r", "scope": "read:sleep"},
        now=1_000.0,
    )

    assert token.expires_at == 4_600.0
    assert token.refresh_token == "r"
    assert token.scopes == ("read:sleep",)


def test_token_from_response_rejects_a_malformed_body() -> None:
    with pytest.raises(AuthError, match="malformed token response"):
        Token.from_response({"expires_in": 3600})


def test_token_is_expired_before_it_actually_expires() -> None:
    # The skew exists so a request in flight across the boundary does not 401.
    assert Token("a", expires_at=time.time() + 30).expired is True
    assert Token("a", expires_at=time.time() + 600).expired is False


def test_token_round_trips_through_json() -> None:
    token = Token("a", expires_at=1234.0, refresh_token="r", scopes=("read:sleep", "offline"))

    assert Token.from_json(token.to_json()) == token


# -- file store ------------------------------------------------------------


def test_file_store_round_trips(tmp_path: Path) -> None:
    store = FileTokenStore(tmp_path / "nested" / "token.json")
    token = Token("a", expires_at=1234.0, refresh_token="r")

    store.save(token)

    assert store.load() == token


def test_file_store_is_empty_before_first_save(tmp_path: Path) -> None:
    assert FileTokenStore(tmp_path / "token.json").load() is None


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_saved_token_is_not_readable_by_other_users(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    FileTokenStore(path).save(Token("a", expires_at=1234.0))

    mode = stat.S_IMODE(path.stat().st_mode)

    assert mode & (stat.S_IRWXG | stat.S_IRWXO) == 0, f"token file is mode {mode:o}"


@pytest.mark.skipif(os.name != "nt", reason="the gap being warned about is Windows-only")
def test_windows_save_warns_that_permissions_are_not_enforced(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # `Path.touch(mode=0o600)` is a no-op on Windows -- the file lands at 0666.
    # The mode cannot be fixed here, so the user has to be told, and pointed at
    # the keyring backend that does protect it.
    store = FileTokenStore(tmp_path / "token.json")

    with caplog.at_level(logging.WARNING, logger="whoopmcp.auth"):
        store.save(Token("a", expires_at=1234.0))
        store.save(Token("b", expires_at=1234.0))

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]

    assert len(warnings) == 1, "the warning should fire once, not on every refresh"
    assert "keyring" in warnings[0].getMessage()


def test_file_store_reports_a_corrupt_token_file(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(AuthError, match="unreadable"):
        FileTokenStore(path).load()


def test_clear_removes_the_token(tmp_path: Path) -> None:
    store = FileTokenStore(tmp_path / "token.json")
    store.save(Token("a", expires_at=1234.0))

    store.clear()

    assert store.load() is None


def test_clear_on_a_missing_file_is_not_an_error(tmp_path: Path) -> None:
    FileTokenStore(tmp_path / "token.json").clear()


def test_logout_forgets_the_pending_login(config: Config) -> None:
    auth = Authenticator(config)
    auth.start_login()

    auth.logout()

    with pytest.raises(AuthError, match="no login in progress"):
        auth.verify_state("anything")


# -- exchange_code --------------------------------------------------------


@respx.mock
async def test_exchange_code_posts_correct_form_and_returns_token(config: Config) -> None:
    route = respx.post(TOKEN_URL).mock(
        return_value=respx.MockResponse(
            200,
            json={
                "access_token": "new-access-token",
                "expires_in": 3600,
                "refresh_token": "new-refresh-token",
                "scope": "read:sleep offline",
            },
        )
    )

    auth = Authenticator(config)
    token = await auth.exchange_code("auth-code-123")

    assert token.access_token == "new-access-token"
    assert token.refresh_token == "new-refresh-token"
    assert token.scopes == ("read:sleep", "offline")
    assert route.called
    request = route.calls.last.request
    assert request.content == (
        b"grant_type=authorization_code&code=auth-code-123&"
        b"client_id=cid&client_secret=csecret&"
        b"redirect_uri=https%3A%2F%2Flocalhost%3A8443%2Fcallback"
    )
    # Verify token was persisted
    assert FileTokenStore(config.token_path).load() == token


@respx.mock
async def test_exchange_code_400_response_raises_auth_error_without_leaking_secret(
    config: Config,
) -> None:
    respx.post(TOKEN_URL).mock(
        return_value=respx.MockResponse(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "The authorization code is invalid.",
            },
        )
    )

    auth = Authenticator(config)
    with pytest.raises(AuthError) as exc_info:
        await auth.exchange_code("bad-code")

    assert "csecret" not in str(exc_info.value)


# -- refresh ---------------------------------------------------------------


@respx.mock
async def test_refresh_posts_correct_form_and_rotates_token(config: Config) -> None:
    old_token = Token(
        "old-access",
        expires_at=1000.0,
        refresh_token="old-refresh",
        scopes=("read:sleep", "offline"),
    )

    route = respx.post(TOKEN_URL).mock(
        return_value=respx.MockResponse(
            200,
            json={
                "access_token": "new-access-token",
                "expires_in": 3600,
                "refresh_token": "new-refresh-token",
                "scope": "read:sleep offline",
            },
        )
    )

    auth = Authenticator(config)
    new_token = await auth.refresh(old_token)

    assert new_token.access_token == "new-access-token"
    assert new_token.refresh_token == "new-refresh-token"
    assert new_token.refresh_token != old_token.refresh_token
    assert route.called
    request = route.calls.last.request
    assert b"grant_type=refresh_token" in request.content
    assert b"refresh_token=old-refresh" in request.content
    assert b"client_id=cid" in request.content
    assert b"client_secret=csecret" in request.content
    assert b"scope=offline" in request.content
    # Verify the new token (not the old one) was persisted
    persisted = FileTokenStore(config.token_path).load()
    assert persisted == new_token
    assert persisted.refresh_token == "new-refresh-token"


@respx.mock
async def test_refresh_400_response_raises_auth_error_without_leaking_secret(
    config: Config,
) -> None:
    old_token = Token("old-access", expires_at=1000.0, refresh_token="old-refresh")

    respx.post(TOKEN_URL).mock(
        return_value=respx.MockResponse(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "Refresh token is expired.",
            },
        )
    )

    auth = Authenticator(config)
    with pytest.raises(AuthError) as exc_info:
        await auth.refresh(old_token)

    assert "csecret" not in str(exc_info.value)


# -- access_token ----------------------------------------------------------


async def test_access_token_returns_non_expired_token_without_http_call(
    config: Config,
) -> None:
    # Pre-populate the store with a non-expired token.
    store = FileTokenStore(config.token_path)
    token = Token(
        "cached-access",
        expires_at=time.time() + 3600,
        refresh_token="cached-refresh",
    )
    store.save(token)

    with respx.mock:
        # If we use respx.post, any POST call will fail the route. This confirms
        # no HTTP call is made.
        route = respx.post(TOKEN_URL)

        auth = Authenticator(config)
        result = await auth.access_token()

        assert result == "cached-access"
        assert not route.called


@respx.mock
async def test_access_token_refreshes_expired_token_with_refresh_token(
    config: Config,
) -> None:
    # Pre-populate the store with an expired token that has a refresh token.
    store = FileTokenStore(config.token_path)
    expired_token = Token(
        "expired-access",
        expires_at=time.time() - 100,
        refresh_token="expired-refresh",
    )
    store.save(expired_token)

    route = respx.post(TOKEN_URL).mock(
        return_value=respx.MockResponse(
            200,
            json={
                "access_token": "new-access-token",
                "expires_in": 3600,
                "refresh_token": "new-refresh-token",
                "scope": "read:sleep offline",
            },
        )
    )

    auth = Authenticator(config)
    result = await auth.access_token()

    assert result == "new-access-token"
    assert route.called


@pytest.mark.asyncio
async def test_access_token_raises_auth_error_when_expired_with_no_refresh_token(
    config: Config,
) -> None:
    # Pre-populate the store with an expired token with no refresh token.
    store = FileTokenStore(config.token_path)
    expired_token = Token("expired-access", expires_at=time.time() - 100)
    store.save(expired_token)

    auth = Authenticator(config)
    with pytest.raises(AuthError, match="whoop_login"):
        await auth.access_token()


@pytest.mark.asyncio
async def test_access_token_raises_auth_error_when_no_stored_token(
    config: Config,
) -> None:
    # Do not pre-populate the store.
    auth = Authenticator(config)
    with pytest.raises(AuthError, match="whoop_login"):
        await auth.access_token()


# -- single-flight refresh (issue #12) --------------------------------------


def _mock_new_token_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "access_token": "new-access",
            "expires_in": 3600,
            "refresh_token": "new-refresh",
            "scope": "offline",
        },
    )


async def test_concurrent_access_token_calls_issue_exactly_one_refresh(
    config: Config,
) -> None:
    # A naive (non-single-flighted) Authenticator would let every concurrent
    # caller see the same expired token and independently refresh it -- N
    # calls in, N POSTs out. The event-gated side_effect below forces all N
    # callers to genuinely be in flight at once, so this test only passes if
    # the implementation actually serializes refreshes.
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    calls_started = asyncio.Event()

    async def slow_refresh(request: httpx.Request) -> httpx.Response:
        calls_started.set()
        await asyncio.sleep(0.01)  # give every concurrent caller a chance to reach the POST
        return _mock_new_token_response()

    with respx.mock:
        route = respx.post(TOKEN_URL).mock(side_effect=slow_refresh)

        auth = Authenticator(config)
        results = await asyncio.gather(*(auth.access_token() for _ in range(10)))

    assert route.call_count == 1
    assert results == ["new-access"] * 10
    persisted = store.load()
    assert persisted is not None
    assert persisted.refresh_token == "new-refresh"


async def test_losing_refresh_cannot_overwrite_the_winners_stored_token(
    config: Config,
) -> None:
    # Bypass access_token() and call refresh() directly on the same expired
    # token from two concurrent callers -- the exact unit issue #12's Anchors
    # section calls out. Only the winner may hit the network; the loser must
    # come back with the winner's stored token, not clobber it with a
    # second, redundant response.
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    calls_started = asyncio.Event()

    async def slow_refresh(request: httpx.Request) -> httpx.Response:
        calls_started.set()
        await asyncio.sleep(0.01)
        return _mock_new_token_response()

    with respx.mock:
        route = respx.post(TOKEN_URL).mock(side_effect=slow_refresh)

        auth = Authenticator(config)
        results = await asyncio.gather(auth.refresh(expired), auth.refresh(expired))

    assert route.call_count == 1
    assert results[0] == results[1]
    persisted = store.load()
    assert persisted == results[0]
    assert persisted in results


async def test_concurrent_refresh_failure_is_not_retried_by_every_waiter(
    config: Config,
) -> None:
    # The store-recheck alone only catches a *successful* prior refresh: it
    # short-circuits when the store holds a fresher, non-expired token, but
    # after a failed refresh clears the store to None, a waiter reacquiring
    # the lock sees nothing to short-circuit on and would retry the same
    # already-dead refresh_token itself. Single-flighting must cover failure
    # too -- "do not retry a refresh token that WHOOP has already killed"
    # applies to every waiter, not just the first caller to notice expiry.
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    async def slow_invalid_grant(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.01)
        return httpx.Response(
            400,
            json={"error": "invalid_grant", "error_description": "Refresh token is expired."},
        )

    with respx.mock:
        route = respx.post(TOKEN_URL).mock(side_effect=slow_invalid_grant)

        auth = Authenticator(config)
        results = await asyncio.gather(
            auth.refresh(expired), auth.refresh(expired), return_exceptions=True
        )

    assert route.call_count == 1  # not 2 -- the second caller must not retry the dead token
    assert all(isinstance(r, AuthError) for r in results)
    assert all("whoop_login" in str(r) for r in results)


def test_interrupted_write_leaves_previous_token_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # FileTokenStore.save() has been atomic (write-to-temp, then an atomic
    # replace) since issue #1, but never had a test proving an interrupted
    # write can't corrupt or lose the previously-saved token. Since #98 the
    # write goes through the file object `os.fdopen` hands back for the
    # `tempfile.mkstemp` fd, not `Path.write_text` -- and `io.TextIOWrapper`
    # is an immutable extension type pytest's monkeypatch can't patch
    # directly, so the injection point is `os.fdopen` itself, wrapped to
    # return a stand-in whose `write` fails.
    path = tmp_path / "token.json"
    store = FileTokenStore(path)
    original = Token("orig-access", expires_at=1234.0, refresh_token="orig-refresh")
    store.save(original)

    real_fdopen = os.fdopen

    class _BoomOnWrite:
        def __init__(self, real: io.TextIOWrapper) -> None:
            self._real = real

        def __enter__(self) -> _BoomOnWrite:
            return self

        def __exit__(self, *exc_info: object) -> None:
            self._real.close()

        def write(self, data: str) -> int:
            raise OSError("disk full")

    def fake_fdopen(fd: int, *args: object, **kwargs: object) -> _BoomOnWrite:
        return _BoomOnWrite(real_fdopen(fd, *args, **kwargs))

    monkeypatch.setattr(os, "fdopen", fake_fdopen)

    new_token = Token("new-access", expires_at=5678.0, refresh_token="new-refresh")
    with pytest.raises(OSError):
        store.save(new_token)

    monkeypatch.undo()

    assert store.load() == original
    assert path.read_text(encoding="utf-8")  # still parseable, not truncated/empty


@respx.mock
async def test_refresh_with_invalid_grant_clears_store_and_hints_whoop_login(
    config: Config,
) -> None:
    store = FileTokenStore(config.token_path)
    old_token = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(old_token)

    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "Refresh token is expired.",
            },
        )
    )

    auth = Authenticator(config)
    with pytest.raises(AuthError, match="whoop_login"):
        await auth.refresh(old_token)

    assert route.call_count == 1  # no fallthrough to a second attempt
    assert FileTokenStore(config.token_path).load() is None


async def test_refresh_lock_is_a_test_double_not_asyncio_lock(config: Config) -> None:
    # Authenticator must drive serialization through whatever RefreshLock it
    # is given, rather than an asyncio.Lock it constructs itself -- proven by
    # injecting a fake that merely counts calls.
    class FakeLock:
        def __init__(self) -> None:
            self.acquire_count = 0
            self.release_count = 0

        async def acquire(self) -> None:
            self.acquire_count += 1

        def release(self) -> None:
            self.release_count += 1

    fake_lock = FakeLock()

    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    with respx.mock:
        respx.post(TOKEN_URL).mock(return_value=_mock_new_token_response())

        auth = Authenticator(config, refresh_lock=fake_lock)
        result = await auth.access_token()

    assert result == "new-access"
    assert fake_lock.acquire_count == 1
    assert fake_lock.release_count == 1


# -- envelope encryption at rest (issue #30) ---------------------------------
#
# EncryptedFileTokenStore does not exist yet. These tests specify: records
# carry the key version they were sealed under; rotation re-seals lazily
# (on the next load, not a forced bulk migration) with both the old and new
# key coexisting in the environment for as long as that transition takes.


def test_encrypted_file_store_round_trips(tmp_path: Path) -> None:
    key = os.urandom(32)
    store = EncryptedFileTokenStore(tmp_path / "token.json", keys={1: key}, current_version=1)
    token = Token("a", expires_at=1234.0, refresh_token="r")

    store.save(token)

    assert store.load() == token


def test_encrypted_file_store_never_writes_plaintext_token_to_disk(tmp_path: Path) -> None:
    key = os.urandom(32)
    path = tmp_path / "token.json"
    store = EncryptedFileTokenStore(path, keys={1: key}, current_version=1)
    token = Token("access-tok-marker", expires_at=1234.0, refresh_token="refresh-tok-marker")

    store.save(token)

    on_disk = path.read_text(encoding="utf-8")
    assert "access-tok-marker" not in on_disk
    assert "refresh-tok-marker" not in on_disk


def test_encrypted_file_store_stamps_the_key_version_it_sealed_under(tmp_path: Path) -> None:
    key = os.urandom(32)
    path = tmp_path / "token.json"
    store = EncryptedFileTokenStore(path, keys={1: key}, current_version=1)

    store.save(Token("a", expires_at=1234.0, refresh_token="r"))

    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["v"] == 1


def test_encrypted_file_store_reseals_lazily_on_load_after_rotation(tmp_path: Path) -> None:
    key_v1 = os.urandom(32)
    key_v2 = os.urandom(32)
    path = tmp_path / "token.json"
    token = Token("a", expires_at=1234.0, refresh_token="r")

    EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).save(token)
    assert json.loads(path.read_text(encoding="utf-8"))["v"] == 1

    # v2 becomes current; both keys must be present in the environment for
    # the duration of the transition -- no forced bulk re-encrypt pass.
    rotated_store = EncryptedFileTokenStore(path, keys={1: key_v1, 2: key_v2}, current_version=2)
    loaded = rotated_store.load()

    assert loaded == token
    # A read rewrites the record under the current version, lazily.
    assert json.loads(path.read_text(encoding="utf-8"))["v"] == 2

    # A second, still-v1 record elsewhere continues to load fine against the
    # same two-key keyring -- both versions genuinely coexist.
    other_path = tmp_path / "other-token.json"
    EncryptedFileTokenStore(other_path, keys={1: key_v1}, current_version=1).save(token)
    other_store = EncryptedFileTokenStore(
        other_path, keys={1: key_v1, 2: key_v2}, current_version=2
    )
    assert other_store.load() == token


def test_encrypted_file_store_fails_closed_if_old_key_removed_before_rotation_completes(
    tmp_path: Path,
) -> None:
    """#69 test 4's negative half. test_encrypted_file_store_reseals_lazily_on
    _load_after_rotation above already proves the positive case (both keys
    present, rotation completes, re-seals under N+1) end to end -- fully
    covered, not restated here. What no existing test drives is the
    unfinished-rotation failure mode: an operator retires the old key
    (removes it from the env/keyring) before every v1 record has been
    touched by a read. That must fail closed on the still-v1 record, not
    silently lose it or fall back to plaintext.

    test_unknown_key_version_raises_sealerror_not_keyerror in test_crypto.py
    proves the underlying crypto.unseal primitive fails closed on an unknown
    version with a hand-built envelope -- but never through
    EncryptedFileTokenStore.load()/save(), and never with a *real* rotation
    setup (current_version actually advanced, a real save() under the old
    key first). This closes that gap at the layer #69 asks about, and
    additionally confirms the on-disk file is left completely unchanged --
    no data loss, and no partial/corrupt rewrite attempt either.
    """
    key_v1 = os.urandom(32)
    key_v2 = os.urandom(32)
    path = tmp_path / "token.json"
    token = Token("a", expires_at=1234.0, refresh_token="r")

    EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).save(token)
    before = path.read_bytes()
    assert json.loads(before)["v"] == 1

    # Rotation is "in progress": current_version is 2, but the old key (1)
    # was removed from the environment before this record was ever read
    # under the new configuration -- the exact unfinished-rotation window.
    store_missing_old_key = EncryptedFileTokenStore(path, keys={2: key_v2}, current_version=2)

    with pytest.raises(AuthError):
        store_missing_old_key.load()

    # Fails closed with no data loss: the file on disk is untouched, still
    # readable under the old key, still stamped v1 -- nothing was silently
    # dropped or rewritten mid-failure.
    after = path.read_bytes()
    assert after == before
    assert EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).load() == token


def test_encrypted_file_store_is_empty_before_first_save(tmp_path: Path) -> None:
    key = os.urandom(32)
    store = EncryptedFileTokenStore(tmp_path / "token.json", keys={1: key}, current_version=1)

    assert store.load() is None


def test_encrypted_file_store_clear_removes_the_token(tmp_path: Path) -> None:
    key = os.urandom(32)
    store = EncryptedFileTokenStore(tmp_path / "token.json", keys={1: key}, current_version=1)
    store.save(Token("a", expires_at=1234.0))

    store.clear()

    assert store.load() is None


def test_encrypted_store_never_logs_key_or_plaintext_on_sealerror(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Encryption at rest is worthless if a decrypt failure logs the very
    # material it was meant to protect. Corrupt the ciphertext on disk so
    # load() must hit the auth-tag-failure path, and assert nothing sensitive
    # reaches any log record produced along the way.
    key = os.urandom(32)
    path = tmp_path / "token.json"
    refresh_marker = "super-secret-refresh-xyz-marker"
    EncryptedFileTokenStore(path, keys={1: key}, current_version=1).save(
        Token("a", expires_at=1234.0, refresh_token=refresh_marker)
    )

    on_disk = json.loads(path.read_text(encoding="utf-8"))
    ct = bytearray(base64.b64decode(on_disk["ct"]))
    ct[0] ^= 0xFF
    on_disk["ct"] = base64.b64encode(bytes(ct)).decode("ascii")
    path.write_text(json.dumps(on_disk), encoding="utf-8")

    caplog.set_level(logging.DEBUG)
    with pytest.raises(AuthError):
        EncryptedFileTokenStore(path, keys={1: key}, current_version=1).load()

    assert refresh_marker not in caplog.text
    assert base64.b64encode(key).decode("ascii") not in caplog.text
    assert key.hex() not in caplog.text


# -- no token material in logs, on every path (issue #30) --------------------
#
# Encryption at rest does not help if the process logs the plaintext on an
# exception path -- this matters more than the cipher choice. Checked over
# the full record text (message plus any exc_info-formatted traceback), not
# just `record.message`, across the success, expiry-driven-refresh and
# invalid_grant paths.


async def test_no_token_material_in_logs_across_success_expiry_and_invalid_grant(
    config: Config, caplog: pytest.LogCaptureFixture
) -> None:
    sentinel_access = "SENTINEL-ACCESS-TOKEN-abc123"
    sentinel_refresh = "SENTINEL-REFRESH-TOKEN-xyz789"
    sentinel_new_access = "SENTINEL-NEW-ACCESS-def456"
    sentinel_new_refresh = "SENTINEL-NEW-REFRESH-ghi012"

    caplog.set_level(logging.DEBUG)

    auth = Authenticator(config)

    # -- success: exchange_code ------------------------------------------
    with respx.mock:
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": sentinel_access,
                    "expires_in": 3600,
                    "refresh_token": sentinel_refresh,
                    "scope": "offline",
                },
            )
        )
        await auth.exchange_code("some-auth-code")

    # -- expiry-driven refresh (renew) ------------------------------------
    with respx.mock:
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": sentinel_new_access,
                    "expires_in": 3600,
                    "refresh_token": sentinel_new_refresh,
                    "scope": "offline",
                },
            )
        )
        expiring = Token(
            sentinel_access, expires_at=time.time() - 100, refresh_token=sentinel_refresh
        )
        await auth.refresh(expiring)

    # -- invalid_grant -----------------------------------------------------
    with respx.mock:
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "invalid_grant",
                    "error_description": "Refresh token is expired.",
                },
            )
        )
        dead = Token(
            sentinel_new_access,
            expires_at=time.time() - 100,
            refresh_token=sentinel_new_refresh,
        )
        with pytest.raises(AuthError):
            await auth.refresh(dead)

    for sentinel in (
        sentinel_access,
        sentinel_refresh,
        sentinel_new_access,
        sentinel_new_refresh,
    ):
        # caplog.text is every captured record's message plus its formatted
        # exc_info, concatenated -- the full record text, not only .message.
        assert sentinel not in caplog.text
        for record in caplog.records:
            assert sentinel not in record.getMessage()
            if record.exc_text:
                assert sentinel not in record.exc_text


# -- revoke-then-forget (issue #30) -------------------------------------------
#
# Deleting a member deletes the local token AND calls DELETE /v2/user/access
# so the grant is revoked upstream rather than merely forgotten locally.
# Deliberately NOT on client.py (whose own module docstring explains why the
# MCP tool surface must never be able to reach this call) and NOT registered
# as an MCP tool -- this lives only on the operator-initiated deletion path.


@respx.mock
async def test_revoke_and_forget_calls_delete_and_clears_local_token(config: Config) -> None:
    store = FileTokenStore(config.token_path)
    token = Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    store.save(token)

    route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(204))

    auth = Authenticator(config)
    await auth.revoke_and_forget()

    # Verified against the mock and the store, not merely "no exception was
    # raised": the DELETE must have actually been made, and the local token
    # must actually be gone afterward.
    assert route.called
    request = route.calls.last.request
    assert request.headers["authorization"] == "Bearer access-tok"
    assert FileTokenStore(config.token_path).load() is None


@respx.mock
async def test_revoke_and_forget_refreshes_an_expired_token_before_revoking(
    config: Config,
) -> None:
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "renewed-access",
                "expires_in": 3600,
                "refresh_token": "renewed-refresh",
                "scope": "offline",
            },
        )
    )
    delete_route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(204))

    auth = Authenticator(config)
    await auth.revoke_and_forget()

    assert delete_route.called
    assert delete_route.calls.last.request.headers["authorization"] == "Bearer renewed-access"
    assert FileTokenStore(config.token_path).load() is None


@respx.mock
async def test_revoke_and_forget_raises_auth_error_without_leaking_the_token_on_failure(
    config: Config,
) -> None:
    store = FileTokenStore(config.token_path)
    store.save(Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok"))

    respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(500))

    auth = Authenticator(config)
    with pytest.raises(AuthError) as exc_info:
        await auth.revoke_and_forget()

    assert "access-tok" not in str(exc_info.value)


# -- atomic_write_text's temp file (issue #98) --------------------------------
#
# The helper writes a member's full health record in plaintext for
# `export-member --out PATH`, at a path the *operator* chooses -- possibly a
# world-writable one like /tmp. So the temp file it writes through must be
# unpredictably named and created O_EXCL: a name an attacker can guess can be
# pre-created as a symlink, and every step of a
# touch/chmod/write_text/replace sequence follows symlinks.
#
# `os.symlink` needs privileges on Windows, and POSIX modes mean nothing
# there, so both kinds of assertion below are skipped on it (#89).


@pytest.mark.skipif(os.name == "nt", reason="os.symlink needs privileges on Windows")
def test_write_does_not_follow_a_pre_created_symlink_at_the_predictable_temp_name(
    tmp_path: Path,
) -> None:
    """The #98 regression test.

    ``path.with_suffix(".tmp")`` is guessable from the destination alone, so
    an attacker who can write to the destination's directory can plant a
    symlink there *before* the write and have the plaintext delivered
    wherever they point it -- and, because the symlink is what then gets
    renamed onto the destination, have every later read follow it too.
    """
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    attacker = tmp_path / "attacker" / "stolen.json"
    attacker.parent.mkdir()
    path = out_dir / "export.json"
    (out_dir / "export.tmp").symlink_to(attacker)

    atomic_write_text(path, "SECRET-HEALTH-RECORD")

    assert not attacker.exists(), (
        f"the plaintext was written through the planted symlink to {attacker}"
    )
    assert not path.is_symlink(), "the destination is a symlink -- later reads follow it too"
    assert path.read_text(encoding="utf-8") == "SECRET-HEALTH-RECORD"


@pytest.mark.skipif(os.name == "nt", reason="os.symlink needs privileges on Windows")
def test_write_replaces_a_destination_that_is_itself_a_symlink(tmp_path: Path) -> None:
    """A pre-existing symlink *at the destination* must be replaced, not
    written through -- which is what ``os.replace`` does, unlike opening the
    destination path for writing."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    attacker = tmp_path / "attacker" / "stolen.json"
    attacker.parent.mkdir()
    path = out_dir / "export.json"
    path.symlink_to(attacker)

    atomic_write_text(path, "SECRET-HEALTH-RECORD")

    assert not attacker.exists(), (
        f"the plaintext was written through the destination symlink to {attacker}"
    )
    assert not path.is_symlink()
    assert path.read_text(encoding="utf-8") == "SECRET-HEALTH-RECORD"


def test_a_successful_write_leaves_no_temp_file_behind(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    path = out_dir / "export.json"

    atomic_write_text(path, "contents")

    assert sorted(p.name for p in out_dir.iterdir()) == ["export.json"]


def test_a_failed_write_leaves_no_temp_file_behind(tmp_path: Path) -> None:
    """A lone surrogate cannot be encoded as UTF-8, so the write raises
    whichever way the helper writes it -- and the temp file it had already
    created must not survive the failure (nor may cleanup swallow the
    original error)."""
    out_dir = tmp_path / "out"
    path = out_dir / "export.json"

    with pytest.raises(UnicodeEncodeError):
        atomic_write_text(path, "\ud800")

    assert list(out_dir.iterdir()) == [], (
        f"a temp file survived the failed write: {[p.name for p in out_dir.iterdir()]}"
    )


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_write_keeps_its_existing_guarantees(tmp_path: Path) -> None:
    """The properties callers already rely on, restated so a rewrite of the
    internals cannot quietly drop them: mode 0600, exact contents, and a
    pre-existing destination replaced rather than appended to."""
    path = tmp_path / "state" / "token.json"

    atomic_write_text(path, "first")
    atomic_write_text(path, "second")

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & (stat.S_IRWXG | stat.S_IRWXO) == 0, f"file is mode {mode:o}"
    assert path.read_text(encoding="utf-8") == "second"


# -- lazy re-seal with missing current key (issue #103) -----------------------
#
# EncryptedFileTokenStore.load() currently leaks a raw SealError when the
# current_version key is missing. The fix: catch SealError from the lazy
# re-seal, log a warning, and return the token anyway. This test suite
# ensures the behavior, assertions about logging (no secrets), and that the
# happy path (both keys present) still rotates as expected.


def test_lazy_reseal_missing_current_key_returns_unrotated_token(tmp_path: Path) -> None:
    """Test 1: headline case. Seal under v1, load with current_version=2 and
    no v2 key → returns valid Token (the original stored value), raises nothing.

    This test MUST FAIL against current main with the raw SealError; the fix
    wraps the lazy re-seal in its own try/except to handle it gracefully.
    """
    key_v1 = os.urandom(32)
    path = tmp_path / "token.json"
    token = Token("access-token-test", expires_at=1234.0, refresh_token="refresh-token-test")

    # Seal under v1
    EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).save(token)

    # Load with current_version=2, but only v1 key is present (no v2).
    # Before the fix: raw SealError escapes.
    # After the fix: load returns the unrotated token without raising.
    store_missing_v2 = EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=2)
    loaded = store_missing_v2.load()

    assert loaded is not None
    assert loaded == token
    assert loaded.access_token == "access-token-test"
    assert loaded.refresh_token == "refresh-token-test"


def test_lazy_reseal_missing_key_emits_warning_naming_version(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Test 2: a warning is emitted at WARNING level on the whoopmcp.auth
    logger, naming the missing version."""
    key_v1 = os.urandom(32)
    path = tmp_path / "token.json"
    token = Token("a", expires_at=1234.0, refresh_token="r")

    EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).save(token)

    caplog.set_level(logging.WARNING, logger="whoopmcp.auth")
    store = EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=2)
    store.load()

    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) >= 1, "at least one warning must be emitted"

    # The warning must name the missing version (2 in this case)
    warning_texts = [r.getMessage() for r in warnings]
    assert any("2" in text for text in warning_texts), (
        f"warning must name the missing version 2, got: {warning_texts}"
    )


def test_lazy_reseal_missing_key_log_contains_no_secrets(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Test 3: no secret in the log. The access token, refresh token, and key
    bytes must not appear anywhere in the captured log text (message + exc_text).

    This is the most critical test: a store that logs a secret while
    "fixing availability" is a far worse bug than the one being fixed.
    """
    key_v1 = os.urandom(32)
    path = tmp_path / "token.json"
    sentinel_access = "SENTINEL-ACCESS-TOKEN-test-abc123"
    sentinel_refresh = "SENTINEL-REFRESH-TOKEN-test-xyz789"
    token = Token(sentinel_access, expires_at=1234.0, refresh_token=sentinel_refresh)

    EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).save(token)

    caplog.set_level(logging.DEBUG)
    store = EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=2)
    store.load()

    # caplog.text is every captured record's message + formatted exc_text
    assert sentinel_access not in caplog.text, "access token leaked in logs"
    assert sentinel_refresh not in caplog.text, "refresh token leaked in logs"
    assert base64.b64encode(key_v1).decode("ascii") not in caplog.text, "key leaked in logs (b64)"
    assert key_v1.hex() not in caplog.text, "key leaked in logs (hex)"

    # Also check individual records
    for record in caplog.records:
        message = record.getMessage()
        assert sentinel_access not in message
        assert sentinel_refresh not in message
        if record.exc_text:
            assert sentinel_access not in record.exc_text
            assert sentinel_refresh not in record.exc_text


def test_lazy_reseal_missing_key_leaves_file_unchanged(tmp_path: Path) -> None:
    """Test 4: the file is left unchanged. Still sealed at v=1, byte-identical,
    no partial write."""
    key_v1 = os.urandom(32)
    path = tmp_path / "token.json"
    token = Token("a", expires_at=1234.0, refresh_token="r")

    EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).save(token)
    before = path.read_bytes()
    before_dict = json.loads(before)
    assert before_dict["v"] == 1

    # Load with missing v2 key
    store = EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=2)
    store.load()

    # File must be byte-identical, not touched
    after = path.read_bytes()
    assert after == before
    after_dict = json.loads(after)
    assert after_dict["v"] == 1


def test_lazy_reseal_with_both_keys_present_still_rotates(tmp_path: Path) -> None:
    """Test 5: happy rotation still re-seals (fact #2 from brief). When both
    the old and new keys are present, load() rotates the record under the new
    key, and the envelope becomes v=2 on disk."""
    key_v1 = os.urandom(32)
    key_v2 = os.urandom(32)
    path = tmp_path / "token.json"
    token = Token("a", expires_at=1234.0, refresh_token="r")

    # Seal under v1
    EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).save(token)
    assert json.loads(path.read_text(encoding="utf-8"))["v"] == 1

    # Load with both keys present; current is v2
    store = EncryptedFileTokenStore(path, keys={1: key_v1, 2: key_v2}, current_version=2)
    loaded = store.load()

    # Token returned intact
    assert loaded == token
    # File re-sealed under v2
    assert json.loads(path.read_text(encoding="utf-8"))["v"] == 2


def test_lazy_reseal_missing_key_is_not_suppressed_by_direct_save_call(
    tmp_path: Path,
) -> None:
    """Test 6: save() itself must still raise when the current key is missing
    (D4). Only the *lazy re-seal inside load()* degrades to a warning. A
    direct save() call must keep raising because silently failing to persist
    a freshly obtained token would lose it.

    The exception raised by a direct save() call is SealError (from the crypto
    layer), not AuthError -- AuthError wrapping is only in the load() path for
    the initial unseal. This test verifies save() raises (does not degrade to
    a warning), without prescribing the exact exception type."""
    from whoopmcp.crypto import SealError

    key_v1 = os.urandom(32)
    path = tmp_path / "token.json"
    token = Token("a", expires_at=1234.0, refresh_token="r")

    store = EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=2)

    # Direct save() call must raise (SealError from the crypto layer),
    # not degrade to a warning
    with pytest.raises(SealError):
        store.save(token)


def test_lazy_reseal_missing_key_warns_once_with_independent_flag(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Test 7: warn-once (D3). Three consecutive load() calls emit exactly one
    warning. And the Windows mode warning (which uses self._warned) is not
    suppressed by the missing-key warning (which uses a distinct flag),
    proving the two flags are independent."""
    key_v1 = os.urandom(32)
    path = tmp_path / "token.json"
    token = Token("a", expires_at=1234.0, refresh_token="r")

    EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).save(token)

    caplog.set_level(logging.WARNING, logger="whoopmcp.auth")
    store = EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=2)

    # Three consecutive load() calls
    store.load()
    store.load()
    store.load()

    # Count warnings about missing re-seal key (the new one from this fix).
    # Before the fix, they would be bare SealErrors, not warnings.
    # After the fix, they should warn once per store instance, not three times.
    # Match on "key version 2", not a bare "2": on Windows `_MODES_ENFORCED`
    # is False, so `save`'s file-permissions warning also fires and embeds the
    # tmp path -- a path containing the digit 2 would be miscounted here.
    reseal_warnings = [
        r
        for r in caplog.records
        if r.levelno >= logging.WARNING and "key version 2" in r.getMessage()
    ]

    # Only one warning should be emitted (warn-once), not three
    assert len(reseal_warnings) == 1, (
        f"expected exactly 1 re-seal warning (warn-once), got {len(reseal_warnings)}: "
        f"{[r.getMessage() for r in reseal_warnings]}"
    )


def test_lazy_reseal_windows_and_missing_key_warnings_are_independent(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test 7 (continued): the Windows mode warning flag (self._warned) and the
    missing-key re-seal warning flag must be distinct. This test proves it by:
    1. Mocking the Windows check to enable the Windows warning
    2. Triggering both conditions
    3. Asserting both warnings appear (proving one doesn't suppress the other)
    """
    if os.name == "nt":
        pytest.skip("This test is only meaningful on non-Windows (testing the mock)")

    from whoopmcp.crypto import SealError

    key_v1 = os.urandom(32)
    path = tmp_path / "token.json"
    token = Token("a", expires_at=1234.0, refresh_token="r")

    EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).save(token)

    # Mock the Windows detection so save() emits its Windows warning
    caplog.set_level(logging.WARNING, logger="whoopmcp.auth")

    class MockedStore(EncryptedFileTokenStore):
        _MODES_ENFORCED = False  # Pretend Windows to trigger that warning

    store = MockedStore(path, keys={1: key_v1}, current_version=2)

    # First save() triggers the Windows warning (and sets _warned=True) --
    # but per D4, save() must still raise on a missing current key rather
    # than degrade to a warning, so it also raises SealError here. The
    # Windows warning fires before that raise (save() logs it before
    # calling seal()), so the raise doesn't stop us observing it below.
    with pytest.raises(SealError):
        store.save(token)

    # Now load() would normally trigger the missing-key re-seal warning
    store.load()

    # Both warnings should appear (not suppressed by the shared flag)
    all_warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]

    # We should see:
    # - One Windows warning (from save)
    # - One missing-key warning (from load's lazy re-seal attempt)
    # Matched on substrings specific to each warning's own wording, not a
    # bare "2" -- tmp_path's own generated name can itself contain a "2"
    # (e.g. a `pytest-123` numbering), which would make a bare-digit filter
    # miscount the Windows warning as a reseal warning too.
    windows_warnings = [r for r in all_warnings if "keyring" in r.getMessage()]
    reseal_warnings = [r for r in all_warnings if "key version 2" in r.getMessage()]

    assert len(windows_warnings) == 1, (
        f"expected 1 Windows warning, got {len(windows_warnings)}: "
        f"{[r.getMessage() for r in windows_warnings]}"
    )
    assert len(reseal_warnings) == 1, (
        f"expected 1 re-seal warning, got {len(reseal_warnings)}: "
        f"{[r.getMessage() for r in reseal_warnings]}"
    )


def test_genuine_decrypt_failure_still_raises_autherror(tmp_path: Path) -> None:
    """Test 8: no regression on a genuine decrypt failure. A record whose own
    version's key is wrong (or the ciphertext is tampered with) still raises
    AuthError, not SealError and not a silent success.

    This is different from the missing current_version case: here, we're trying
    to decrypt a record sealed under v1, we have the v1 key, but the ciphertext
    is tampered with. This is NOT the missing-key-during-re-seal case; it's a
    genuine decrypt failure and must still raise."""
    key_v1 = os.urandom(32)
    path = tmp_path / "token.json"
    token = Token("a", expires_at=1234.0, refresh_token="r")

    # Save under v1
    EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1).save(token)

    # Tamper with ciphertext on disk
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    ct = bytearray(base64.b64decode(on_disk["ct"]))
    ct[0] ^= 0xFF
    on_disk["ct"] = base64.b64encode(bytes(ct)).decode("ascii")
    path.write_text(json.dumps(on_disk), encoding="utf-8")

    # Load with v1 key present (not missing) -- but the ciphertext is corrupt
    store = EncryptedFileTokenStore(path, keys={1: key_v1}, current_version=1)

    # Must raise AuthError (decrypt failure), not SealError
    with pytest.raises(AuthError, match="failed to decrypt"):
        store.load()


# -- logout() interlock with in-flight refresh (issue #123) --------------------
#
# When a refresh is in flight and logout() runs, the refresh must not
# overwrite the now-empty store. Tests 1 and 2 MUST FAIL against current main
# (before the epoch fix is implemented), confirming the credentials resurrect.


async def test_logout_during_refresh_leaves_store_empty(config: Config) -> None:
    """Test 1 (headline): Start a refresh, call logout() while in flight, assert
    the store is still empty and self._token is None.

    MUST FAIL against current main -- the resurrected token is expected to be
    in the store and self._token after the refresh completes.
    """
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    refresh_started = asyncio.Event()
    proceed = asyncio.Event()

    async def slow_refresh(request: httpx.Request) -> httpx.Response:
        refresh_started.set()
        await proceed.wait()
        await asyncio.sleep(0.01)
        return _mock_new_token_response()

    with respx.mock:
        respx.post(TOKEN_URL).mock(side_effect=slow_refresh)

        auth = Authenticator(config)
        # Start the refresh in a task
        refresh_task = asyncio.create_task(auth.access_token())

        # Wait for the refresh to start (POST is in flight)
        await refresh_started.wait()

        # Call logout() synchronously while refresh is in flight
        auth.logout()

        # Let the refresh complete
        proceed.set()

        # The refresh completes and returns a token to its own caller,
        # but that token must NOT be persisted. It's also acceptable if
        # logout causes a later error, but for now we expect the caller
        # to get the token.
        with contextlib.suppress(AuthError):
            await refresh_task

        # CRITICAL ASSERTION: the store must be empty
        assert store.load() is None, (
            f"store should be empty after logout during refresh, but contains {store.load()}"
        )
        assert auth._token is None, "auth._token should be None after logout"


async def test_revoke_and_forget_during_refresh_leaves_store_empty(config: Config) -> None:
    """Test 2: `revoke_and_forget()` must also not be undone by an in-flight refresh.

    The interleaving matters and the obvious one does not test anything.
    `revoke_and_forget` refreshes first when the stored token is expired, so a
    refresh started beforehand simply *coalesces* onto the same task -- the
    save then happens before the revoke, and the test passes on unfixed code
    while proving nothing (this is exactly how the first version of this test
    was vacuous).

    So: hold the store's token LIVE (no refresh needed inside
    `revoke_and_forget`), gate its DELETE, start a *separate* refresh while
    that DELETE is in flight, then let the DELETE finish -- which runs
    `logout()` and bumps the epoch -- and only then let the refresh complete.
    The refresh must find the epoch changed and discard its result.
    """
    store = FileTokenStore(config.token_path)
    live_token = Token("live-access", expires_at=time.time() + 3600, refresh_token="live-refresh")
    store.save(live_token)

    delete_started = asyncio.Event()
    finish_delete = asyncio.Event()
    finish_refresh = asyncio.Event()

    async def gated_delete(request: httpx.Request) -> httpx.Response:
        delete_started.set()
        await finish_delete.wait()
        return httpx.Response(204)

    async def gated_refresh(request: httpx.Request) -> httpx.Response:
        await finish_refresh.wait()
        return _mock_new_token_response()

    with respx.mock:
        respx.delete(USER_ACCESS_URL).mock(side_effect=gated_delete)
        respx.post(TOKEN_URL).mock(side_effect=gated_refresh)

        auth = Authenticator(config)
        revoke_task = asyncio.create_task(auth.revoke_and_forget())
        await delete_started.wait()

        # A refresh now in flight, started while the revoke is mid-DELETE.
        refresh_task = asyncio.create_task(
            auth.refresh(
                Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
            )
        )
        for _ in range(50):
            await asyncio.sleep(0)
            if auth._inflight_refresh is not None:
                break

        finish_delete.set()
        with contextlib.suppress(AuthError):
            await revoke_task
        assert store.load() is None, "revoke_and_forget should have cleared the store"

        finish_refresh.set()
        with contextlib.suppress(AuthError):
            await refresh_task

        assert store.load() is None, (
            "a refresh completing after revoke_and_forget must not repopulate the store, "
            f"but it contains {store.load()}"
        )
        assert auth._token is None, "the discarded refresh must not become the session credential"


async def test_refresh_without_logout_still_persists_normally(config: Config) -> None:
    """Test 3: Regression test. A normal refresh with no interleaved logout
    still persists the token and sets self._token exactly as before.

    This ensures the fix doesn't break the happy path.
    """
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    with respx.mock:
        respx.post(TOKEN_URL).mock(return_value=_mock_new_token_response())

        auth = Authenticator(config)
        result = await auth.access_token()

    assert result == "new-access"
    persisted = store.load()
    assert persisted is not None
    assert persisted.access_token == "new-access"
    assert persisted.refresh_token == "new-refresh"
    assert auth._token == persisted


async def test_concurrent_refresh_still_coalesces_with_one_request(config: Config) -> None:
    """Test 4: Coalescing still works. Two concurrent refresh() calls issue
    exactly one token-endpoint request.

    This ensures the epoch fix doesn't break the coalescing optimization.
    """
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    with respx.mock:
        route = respx.post(TOKEN_URL).mock(return_value=_mock_new_token_response())

        auth = Authenticator(config)
        results = await asyncio.gather(
            auth.refresh(expired),
            auth.refresh(expired),
        )

    # CRITICAL ASSERTION: exactly one request, not two
    assert route.call_count == 1, (
        f"expected 1 token endpoint request for coalesced refresh, got {route.call_count}"
    )
    assert results[0] == results[1]
    assert results[0].access_token == "new-access"


async def test_logout_during_refresh_does_not_raise_out_of_caller(config: Config) -> None:
    """Test 5: Logout during refresh does not crash the caller.

    The tool call that triggered the refresh may finish with whatever token it
    obtained. It must not crash due to the interleaved logout.
    """
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    refresh_started = asyncio.Event()
    proceed = asyncio.Event()

    async def slow_refresh(request: httpx.Request) -> httpx.Response:
        refresh_started.set()
        await proceed.wait()
        await asyncio.sleep(0.01)
        return _mock_new_token_response()

    with respx.mock:
        respx.post(TOKEN_URL).mock(side_effect=slow_refresh)

        auth = Authenticator(config)
        refresh_task = asyncio.create_task(auth.refresh(expired))

        await refresh_started.wait()
        auth.logout()
        proceed.set()

        # The caller must not crash
        result = await refresh_task

        # The caller gets the token (it's not persisted, but the caller gets what they asked for)
        assert result is not None
        assert result.access_token == "new-access"


async def test_refresh_after_logout_works_normally(config: Config) -> None:
    """Test 6: A later, post-logout refresh works normally.

    The epoch must not permanently wedge the store. After logout and a fresh
    login, refresh should work normally again.
    """
    store = FileTokenStore(config.token_path)

    # First: login, then logout, confirm store is empty
    token = Token("old-access", expires_at=time.time() + 3600, refresh_token="old-refresh")
    store.save(token)

    auth = Authenticator(config)
    auth.logout()

    assert store.load() is None

    # Now re-login (simulate exchange_code or direct store.save)
    new_token = Token("access-2", expires_at=time.time() - 100, refresh_token="refresh-2")
    store.save(new_token)

    # Refresh should work normally
    with respx.mock:
        respx.post(TOKEN_URL).mock(return_value=_mock_new_token_response())

        result = await auth.refresh(new_token)

    assert result.access_token == "new-access"
    persisted = store.load()
    assert persisted is not None
    assert persisted.access_token == "new-access"
    assert auth._token == persisted


async def test_logout_before_refresh_task_starts_leaves_store_empty(config: Config) -> None:
    """Regression test for review finding B1.

    `refresh()` creates the `_do_refresh` task with `asyncio.ensure_future`
    and then suspends awaiting it -- the task has not actually run a single
    line yet at that point. If `logout()` happens to run in that same
    window (any ready callback in the same event-loop tick, e.g. a sibling
    `whoop_logout` tool call -- see fact #4), a naive fix that captures the
    epoch as the first line *inside* `_do_refresh` captures the epoch
    *after* the logout already bumped it, so the check at the end of
    `_do_refresh` passes and the forgotten grant's rotated token gets
    written back to disk anyway.

    This must FAIL if the epoch is captured inside `_do_refresh` instead of
    at the top of `refresh()` (i.e. it is the regression test for the fix
    actually shipped, not just for the mid-flight case tests 1 and 2
    already cover).
    """
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    with respx.mock:
        route = respx.post(TOKEN_URL).mock(return_value=_mock_new_token_response())

        auth = Authenticator(config)
        refresh_task = asyncio.create_task(auth.refresh(expired))

        # Spin the loop just enough for refresh() to run up to the point
        # where it has created (but not yet started running) the
        # _do_refresh task, and confirm the POST genuinely has not fired
        # yet -- otherwise this test would silently degenerate into test 1.
        for _ in range(50):
            if auth._inflight_refresh is not None:
                break
            await asyncio.sleep(0)
        assert auth._inflight_refresh is not None, (
            "refresh() should have registered its in-flight task by now"
        )
        assert route.call_count == 0, (
            "the token-endpoint POST must not have started yet -- this test "
            "only exercises the pre-request window if it hasn't"
        )

        # logout() runs synchronously, "before the request" from
        # _do_refresh's point of view.
        auth.logout()

        result = await refresh_task

        # The in-flight caller still gets its token back (D2) ...
        assert result.access_token == "new-access"
        # ... but it must never have been written back to disk or installed
        # as the session credential -- that is the invariant this issue
        # protects.
        assert store.load() is None, (
            f"store should be empty after a pre-request logout, but contains {store.load()}"
        )
        assert auth._token is None, "auth._token should be None after logout"


# -- issue #122: invalid_grant conflates "stale token" with "grant gone" --------
#
# WHOOP rotates refresh tokens on use, so a stale token failing usually means it
# was superseded -- and acting on the wrong reading destroys a valid credential
# another process just saved. The tests below verify the fixes for D1-D3.
#
# Tests 1, 2, and 4 MUST FAIL against current main.


async def test_issue_122_test_1_store_superseding_expired_token_is_refreshed(
    config: Config,
) -> None:
    """Test 1 (D1): The store's superseding-but-expired token is what gets refreshed.

    Seed the store with a fresher-but-expired token, call refresh() with a
    stale one, and assert the token endpoint received the STORE's refresh
    token, not the caller's stale one.

    MUST FAIL against current main -- the code requires the stored token to be
    non-expired to use the short-circuit (line 676: `not current.expired`).
    When the store's token is expired, the code falls through and tries to
    refresh the caller's stale token instead.
    """
    store = FileTokenStore(config.token_path)

    # Store holds a fresher token (different refresh_token) but it is expired
    store_token = Token(
        access_token="store-access",
        expires_at=time.time() - 100,  # expired
        refresh_token="store-refresh",
    )
    store.save(store_token)

    # Caller has a stale version of the same grant (older refresh_token)
    caller_token = Token(
        access_token="old-access",
        expires_at=time.time() - 100,
        refresh_token="old-refresh",
    )

    with respx.mock:
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "new-access",
                    "expires_in": 3600,
                    "refresh_token": "new-refresh",
                    "scope": "offline",
                },
            )
        )

        auth = Authenticator(config)
        await auth.refresh(caller_token)

    # CRITICAL ASSERTION: The token endpoint must have received the STORE's
    # refresh token, not the caller's stale one. We inspect the actual request
    # body sent to verify which refresh token was used.
    assert route.called, "token endpoint must have been called"
    request = route.calls.last.request
    request_body = request.content.decode()

    # The request must contain the store's "store-refresh", not the stale "old-refresh"
    assert "refresh_token=store-refresh" in request_body, (
        f"Expected store's token 'store-refresh' in request, but got: {request_body}"
    )
    assert "refresh_token=old-refresh" not in request_body, (
        f"Expected NOT to send caller's stale token, but found 'old-refresh' in: {request_body}"
    )


async def test_issue_122_test_2_superseded_invalid_grant_does_not_clear_store(
    config: Config,
) -> None:
    """Test 2 (D2): A superseded-token invalid_grant does not clear the store.

    Store holds a fresher token, the caller's stale one fails with invalid_grant
    -> the store still holds the fresher token afterwards.

    MUST FAIL against current main -- the code unconditionally clears the store
    on invalid_grant (lines 714-716), destroying the fresher token that another
    process just saved.
    """
    store = FileTokenStore(config.token_path)

    # Store holds a fresher token
    store_token = Token(
        access_token="store-access",
        expires_at=time.time() - 100,
        refresh_token="store-refresh",
    )
    store.save(store_token)

    # Caller has a stale version
    caller_token = Token(
        access_token="old-access",
        expires_at=time.time() - 100,
        refresh_token="old-refresh",
    )

    with respx.mock:
        # The caller's stale token is rejected with invalid_grant
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "invalid_grant",
                    "error_description": "Refresh token is expired.",
                },
            )
        )

        auth = Authenticator(config)
        with pytest.raises(AuthError):
            await auth.refresh(caller_token)

    # CRITICAL ASSERTION: The store must still hold the fresher token.
    # A test that only checks the exception type would pass the broken code.
    persisted = store.load()
    assert persisted is not None, "store must not be cleared"
    assert persisted.refresh_token == "store-refresh", (
        f"store should still hold the fresher token, but got: {persisted.refresh_token}"
    )


async def test_issue_122_test_3_genuine_invalid_grant_clears_store_and_raises(
    config: Config,
) -> None:
    """Test 3 (genuine case, D3): The store holds the very token WHOOP rejected.

    When the token that failed is the same one in the store, clear it and raise
    GrantAlreadyGoneError, exactly as today. This proves the fix does not break
    the genuine case.
    """
    from whoopmcp.auth import GrantAlreadyGoneError

    store = FileTokenStore(config.token_path)

    # Store and caller both have the same token
    token = Token(
        access_token="access",
        expires_at=time.time() - 100,
        refresh_token="refresh",
    )
    store.save(token)

    with respx.mock:
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "invalid_grant",
                    "error_description": "Refresh token is expired.",
                },
            )
        )

        auth = Authenticator(config)
        with pytest.raises(GrantAlreadyGoneError):
            await auth.refresh(token)

    # Store must be cleared
    assert store.load() is None, "store should be cleared for the genuine case"


async def test_issue_122_test_4_erase_member_does_not_report_fake_revoke_success(
    config: Config,
) -> None:
    """Test 4 (fact #3, D3): erase-member does not report a revoke that did not happen.

    Drive the CLI path where refresh fails on a superseded token and assert it
    does NOT treat the revoke step as succeeded (i.e., does not catch
    GrantAlreadyGoneError). The genuine case (store holds the failed token)
    would raise GrantAlreadyGoneError, which the CLI catches as success. But when
    the store has moved on (superseded token), the refresh failure must raise a
    plain AuthError, not GrantAlreadyGoneError, so the CLI treats it as a real
    failure and aborts rather than reporting a revoke that did not happen.
    """
    store = FileTokenStore(config.token_path)

    # Store holds a fresher token
    store_token = Token(
        access_token="store-access",
        expires_at=time.time() - 100,
        refresh_token="store-refresh",
    )
    store.save(store_token)

    # Caller has a stale version
    caller_token = Token(
        access_token="old-access",
        expires_at=time.time() - 100,
        refresh_token="old-refresh",
    )

    with respx.mock:
        # The caller's stale token is rejected with invalid_grant
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "invalid_grant",
                    "error_description": "Refresh token is expired.",
                },
            )
        )

        auth = Authenticator(config)
        with pytest.raises(AuthError) as exc_info:
            # This simulates the revoke_and_forget() call from erase-member.
            # It will attempt to refresh the (stale) token if expired.
            await auth.refresh(caller_token)

    # CRITICAL ASSERTION: The exception must be a plain AuthError, not
    # GrantAlreadyGoneError. The CLI code catches GrantAlreadyGoneError as
    # "nothing to revoke" and reports success. If this raises GrantAlreadyGoneError,
    # the CLI would report a successful revoke when the grant is still live at WHOOP.
    from whoopmcp.auth import GrantAlreadyGoneError

    assert not isinstance(exc_info.value, GrantAlreadyGoneError), (
        "Must raise plain AuthError, not GrantAlreadyGoneError, when the store has "
        "moved on to a fresher token. GrantAlreadyGoneError would cause erase-member "
        "to report a revoke that did not happen."
    )


async def test_issue_122_test_5_logout_during_refresh_leaves_store_empty_123(
    config: Config,
) -> None:
    """Test 5 (D4): #123's interlock still holds.

    A logout during refresh still leaves the store empty. This ensures the fix
    for #122 does not disturb #123's epoch interlock.
    """
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    refresh_started = asyncio.Event()
    proceed = asyncio.Event()

    async def slow_refresh(request: httpx.Request) -> httpx.Response:
        refresh_started.set()
        await proceed.wait()
        await asyncio.sleep(0.01)
        return _mock_new_token_response()

    with respx.mock:
        respx.post(TOKEN_URL).mock(side_effect=slow_refresh)

        auth = Authenticator(config)
        refresh_task = asyncio.create_task(auth.access_token())

        await refresh_started.wait()
        auth.logout()
        proceed.set()

        with contextlib.suppress(AuthError):
            await refresh_task

        # CRITICAL ASSERTION: #123's interlock must still work
        assert store.load() is None
        assert auth._token is None


async def test_issue_122_test_6_coalescing_intact(
    config: Config,
) -> None:
    """Test 6: Coalescing intact.

    Two concurrent refreshes still share one token-endpoint request. This ensures
    the fix for #122 does not break the coalescing optimization.
    """
    store = FileTokenStore(config.token_path)
    expired = Token("old-access", expires_at=time.time() - 100, refresh_token="old-refresh")
    store.save(expired)

    with respx.mock:
        route = respx.post(TOKEN_URL).mock(return_value=_mock_new_token_response())

        auth = Authenticator(config)
        results = await asyncio.gather(
            auth.refresh(expired),
            auth.refresh(expired),
        )

    # CRITICAL ASSERTION: exactly one request, not two
    assert route.call_count == 1, (
        f"expected 1 token endpoint request for coalesced refresh, got {route.call_count}"
    )
    assert results[0] == results[1]
    assert results[0].access_token == "new-access"
