from __future__ import annotations

import asyncio
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
    Authenticator,
    AuthError,
    FileTokenStore,
    Token,
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
    # FileTokenStore.save() has been atomic (write-to-.tmp, then Path.replace)
    # since issue #1, but never had a test proving an interrupted write can't
    # corrupt or lose the previously-saved token. This should already pass
    # against the current, unchanged FileTokenStore.
    path = tmp_path / "token.json"
    store = FileTokenStore(path)
    original = Token("orig-access", expires_at=1234.0, refresh_token="orig-refresh")
    store.save(original)

    def boom(self: Path, *args: object, **kwargs: object) -> int:
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", boom)

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
