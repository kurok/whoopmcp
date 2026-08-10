from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx

from whoopmcp.auth import TOKEN_URL, Authenticator, FileTokenStore, Token
from whoopmcp.client import (
    BASE_URL,
    MAX_PAGE_SIZE,
    RateLimitedError,
    WhoopAPIError,
    WhoopClient,
    build_collection_params,
)
from whoopmcp.config import Config

# -- fixture setup ---------------------------------------------------------


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


@pytest.fixture
def auth(config: Config) -> Authenticator:
    FileTokenStore(config.token_path).save(
        Token(
            "valid-access-token",
            expires_at=time.time() + 3600,
            refresh_token="valid-refresh-token",
        )
    )
    return Authenticator(config)


# -- build_collection_params tests (existing) --------------------------------


def test_no_parameters_yields_an_empty_query() -> None:
    assert build_collection_params() == {}


def test_datetimes_are_serialised_as_iso8601() -> None:
    params = build_collection_params(
        start=datetime(2026, 7, 1, tzinfo=UTC),
        end=datetime(2026, 8, 1, tzinfo=UTC),
    )

    assert params == {"start": "2026-07-01T00:00:00+00:00", "end": "2026-08-01T00:00:00+00:00"}


def test_strings_pass_through_unchanged() -> None:
    params = build_collection_params(start="2026-07-01T00:00:00Z")

    assert params["start"] == "2026-07-01T00:00:00Z"


def test_limit_is_clamped_to_the_api_maximum() -> None:
    # WHOOP 400s on limit > 25 rather than truncating, so clamping here keeps
    # a caller's optimistic `limit=1000` from failing the whole request.
    assert build_collection_params(limit=1000)["limit"] == str(MAX_PAGE_SIZE)


def test_limit_below_the_maximum_is_preserved() -> None:
    assert build_collection_params(limit=10)["limit"] == "10"


@pytest.mark.parametrize("limit", [0, -1])
def test_non_positive_limit_is_rejected(limit: int) -> None:
    with pytest.raises(ValueError, match="limit must be >= 1"):
        build_collection_params(limit=limit)


def test_next_token_uses_the_api_spelling() -> None:
    # WHOOP spells the cursor `nextToken`, not `next_token`.
    assert build_collection_params(next_token="abc") == {"nextToken": "abc"}


def test_empty_next_token_is_omitted() -> None:
    assert "nextToken" not in build_collection_params(next_token="")


# -- _get, _get_page, paginate tests (issue #2) ----------------------------


@respx.mock
async def test_get_with_200_attaches_bearer_token_and_returns_body(
    config: Config, auth: Authenticator
) -> None:
    """Test 1: A 200 response carries the Authorization header."""
    route = respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(200, json={"user_id": 1, "email": "a@b.com"})
    )

    async with WhoopClient(config, auth) as client:
        result = await client.get_profile()

    assert result == {"user_id": 1, "email": "a@b.com"}
    assert route.called
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer valid-access-token"


@respx.mock
async def test_get_with_401_refreshes_token_and_retries(
    config: Config, auth: Authenticator
) -> None:
    """Test 2: 401-then-refresh-then-200 flow with token replacement."""
    # First request returns 401, second returns 200
    profile_route = respx.get(f"{BASE_URL}/v2/user/profile/basic")
    profile_route.side_effect = [
        httpx.Response(401, json={"error": "Unauthorized"}),
        httpx.Response(200, json={"user_id": 1, "email": "a@b.com"}),
    ]

    # Token refresh returns a new token
    token_route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "refreshed-access-token",
                "expires_in": 3600,
                "refresh_token": "refreshed-refresh-token",
            },
        )
    )

    async with WhoopClient(config, auth) as client:
        result = await client.get_profile()

    assert result == {"user_id": 1, "email": "a@b.com"}
    assert profile_route.called
    assert token_route.called
    # Second profile request should use the refreshed token
    auth_header = profile_route.calls[1].request.headers["Authorization"]
    assert auth_header == "Bearer refreshed-access-token"
    # Token endpoint should have been called to refresh
    assert len(token_route.calls) >= 1


@respx.mock
async def test_get_with_401_twice_gives_up_and_raises_error(
    config: Config, auth: Authenticator
) -> None:
    """Test 3: 401 twice, refresh succeeds but API still rejects, raises WhoopAPIError."""
    # Both requests return 401
    profile_route = respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(401, json={"error": "Unauthorized"})
    )

    # Token refresh succeeds (grant is valid at the token endpoint)
    token_route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "refreshed-but-rejected-token",
                "expires_in": 3600,
                "refresh_token": "refreshed-refresh-token",
            },
        )
    )

    async with WhoopClient(config, auth) as client:
        with pytest.raises(WhoopAPIError) as exc_info:
            await client.get_profile()

    assert exc_info.value.status == 401
    # Confirm the profile route was hit exactly twice (initial + retry)
    assert len(profile_route.calls) == 2
    assert token_route.called


@respx.mock
async def test_get_with_429_and_rate_limit_reset_header(
    config: Config, auth: Authenticator
) -> None:
    """Test 4: 429 with X-RateLimit-Reset header raises RateLimitedError."""
    reset_time = 1700000000.0
    respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(
            429,
            json={"error": "rate_limited"},
            headers={"X-RateLimit-Reset": str(int(reset_time))},
        )
    )

    async with WhoopClient(config, auth) as client:
        with pytest.raises(RateLimitedError) as exc_info:
            await client.get_profile()

    assert exc_info.value.status == 429
    assert exc_info.value.retry_after == pytest.approx(reset_time, abs=1.0)


@respx.mock
async def test_get_with_429_without_rate_limit_reset_header(
    config: Config, auth: Authenticator
) -> None:
    """Test 5: 429 without X-RateLimit-Reset raises RateLimitedError with None."""
    respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(429, json={"error": "rate_limited"})
    )

    async with WhoopClient(config, auth) as client:
        with pytest.raises(RateLimitedError) as exc_info:
            await client.get_profile()

    assert exc_info.value.status == 429
    assert exc_info.value.retry_after is None


@respx.mock
async def test_get_with_429_and_unparseable_rate_limit_reset_header(
    config: Config, auth: Authenticator
) -> None:
    """A malformed X-RateLimit-Reset header must not crash the error path."""
    respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(
            429,
            json={"error": "rate_limited"},
            headers={"X-RateLimit-Reset": "not-a-number"},
        )
    )

    async with WhoopClient(config, auth) as client:
        with pytest.raises(RateLimitedError) as exc_info:
            await client.get_profile()

    assert exc_info.value.retry_after is None


@respx.mock
async def test_get_with_500_raises_api_error(config: Config, auth: Authenticator) -> None:
    """Test 6: 5xx error raises WhoopAPIError (not RateLimitedError)."""
    respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(500, json={"error": "internal_server_error"})
    )

    async with WhoopClient(config, auth) as client:
        with pytest.raises(WhoopAPIError) as exc_info:
            await client.get_profile()

    assert exc_info.value.status == 500
    assert not isinstance(exc_info.value, RateLimitedError)


@respx.mock
async def test_paginate_walks_multiple_pages_following_next_token(
    config: Config, auth: Authenticator
) -> None:
    """Test 7: Multi-page pagination with nextToken cursor."""
    recovery_route = respx.get(f"{BASE_URL}/v2/recovery")
    recovery_route.side_effect = [
        httpx.Response(
            200,
            json={
                "records": [{"id": 1}, {"id": 2}],
                "next_token": "abc",
            },
        ),
        httpx.Response(
            200,
            json={
                "records": [{"id": 3}],
                "next_token": None,
            },
        ),
    ]

    async with WhoopClient(config, auth) as client:
        records = [r async for r in client.paginate("/v2/recovery", {})]

    assert records == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert len(recovery_route.calls) == 2
    # Confirm the second request included the nextToken parameter
    second_request = recovery_route.calls[1].request
    assert "nextToken=abc" in str(second_request.url)


@respx.mock
async def test_paginate_stops_at_max_records_without_fetching_next_page(
    config: Config, auth: Authenticator
) -> None:
    """Test 8: max_records truncation stops fetching when limit is met."""
    recovery_route = respx.get(f"{BASE_URL}/v2/recovery")
    recovery_route.side_effect = [
        httpx.Response(
            200,
            json={
                "records": [{"id": 1}, {"id": 2}, {"id": 3}],
                "next_token": "abc",
            },
        ),
        httpx.Response(
            200,
            json={
                "records": [{"id": 4}, {"id": 5}],
                "next_token": None,
            },
        ),
    ]

    async with WhoopClient(config, auth) as client:
        records = [r async for r in client.paginate("/v2/recovery", {}, max_records=2)]

    assert len(records) == 2
    # Critical: the second page should never be requested
    assert len(recovery_route.calls) == 1


@respx.mock
async def test_error_messages_do_not_leak_tokens(config: Config, auth: Authenticator) -> None:
    """Test 9: Error messages don't contain the bearer token string.

    The refresh itself must succeed here (mirroring the 401-twice scenario),
    so the raised error is client.py's own WhoopAPIError, built from the API
    response -- not auth.py's AuthError, which is already covered by its own
    leak tests and isn't what this issue's error-mapping code produces.
    """
    respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(401, json={"error": "Unauthorized"})
    )

    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "refreshed-access-token",
                "expires_in": 3600,
                "refresh_token": "refreshed-refresh-token",
            },
        )
    )

    async with WhoopClient(config, auth) as client:
        with pytest.raises(WhoopAPIError) as exc_info:
            await client.get_profile()

    error_str = str(exc_info.value)
    assert "valid-access-token" not in error_str
    assert "refreshed-access-token" not in error_str
