from __future__ import annotations

import stat
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from whoopmcp.auth import (
    AUTHORIZE_URL,
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


def test_saved_token_is_not_readable_by_other_users(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    FileTokenStore(path).save(Token("a", expires_at=1234.0))

    mode = stat.S_IMODE(path.stat().st_mode)

    assert mode & (stat.S_IRWXG | stat.S_IRWXO) == 0, f"token file is mode {mode:o}"


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


# -- not yet implemented ---------------------------------------------------
#
# These pin the contract the network layer must satisfy, and fail loudly the
# moment someone implements one without deleting its guard here.


async def test_exchange_code_is_not_implemented(config: Config) -> None:
    with pytest.raises(NotImplementedError, match="issue #1"):
        await Authenticator(config).exchange_code("code")


async def test_access_token_is_not_implemented(config: Config) -> None:
    with pytest.raises(NotImplementedError, match="issue #1"):
        await Authenticator(config).access_token()
