from __future__ import annotations

import asyncio
import base64
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
