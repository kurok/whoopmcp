"""Checks on the MCP surface itself: what tools exist and how they are declared.

These matter more than they look. The tool list and its annotations are the
contract an MCP client sees, and a tool that quietly loses `readOnlyHint` is
a tool a client may stop asking permission for.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from whoopmcp.auth import TOKEN_URL, Authenticator, FileTokenStore, Token
from whoopmcp.client import BASE_URL, WhoopClient
from whoopmcp.config import Config
from whoopmcp.server import AppContext, build_server

#: Every tool the server promises. Adding one here without registering it, or
#: registering one without listing it here, fails the suite.
EXPECTED_TOOLS = {
    "whoop_auth_status",
    "whoop_login",
    "whoop_complete_login",
    "whoop_logout",
    "get_profile",
    "get_body_measurement",
    "list_recoveries",
    "list_sleeps",
    "list_cycles",
    "list_workouts",
    "get_sleep",
    "get_workout",
    "summarize_period",
    "metric_trend",
    "correlate_metrics",
    "compare_periods",
}

#: The only tools allowed to change anything. Everything else is a read.
MUTATING_TOOLS = {"whoop_complete_login", "whoop_logout"}


# -- fixture helpers for data-tool testing ---------------------------------


async def call_tool(
    server: MCPServer[AppContext], name: str, arguments: dict[str, Any], app_context: AppContext
) -> Any:
    """Call a tool with proper context wiring, and unwrap its return value.

    `MCPServer.call_tool()` always packages a tool's return into a
    `CallToolResult` (`convert_result=True`, unconditionally) -- it is never
    the plain dict/str the tool body returned. Every data-tool test here
    asserts on that dict directly (`result["count"]`, etc.), so unwrap it
    once, here, rather than repeating `.structured_content` at every call
    site. `structured_content` is populated for a dict-returning tool (every
    one of issue #5's) and `None` for a string-returning tool -- fall back
    to the raw result in that case so a caller after `str`-typed content
    (like issue #4's auth tools) still gets what it expects.
    """
    request_context = ServerRequestContext(
        session=None,  # type: ignore[arg-type]
        lifespan_context=app_context,
        protocol_version="2025-06-18",
        method="tools/call",
    )
    context = Context(request_context=request_context, mcp_server=server)
    result = await server.call_tool(name, arguments, context=context)
    if result.structured_content is not None:
        return result.structured_content
    return result


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
def app_context(config: Config) -> AppContext:
    auth = Authenticator(config)
    client = WhoopClient(config, auth)
    return AppContext(config=config, auth=auth, client=client)


@pytest.fixture
def server() -> MCPServer[AppContext]:
    return build_server()


@pytest.fixture(autouse=True)
def _seed_valid_token(config: Config) -> None:
    FileTokenStore(config.token_path).save(
        Token("fake-access-token", expires_at=time.time() + 3600, refresh_token="fake-refresh")
    )


# -- fixture helpers for data generation -----------------------------------


def profile_fixture() -> dict[str, Any]:
    """A profile record from GET /v2/user/profile/basic."""
    return {
        "user_id": 12345,
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe",
    }


def body_measurement_fixture() -> dict[str, Any]:
    """A body measurement record from GET /v2/user/measurement/body."""
    return {
        "height_meter": 1.75,
        "weight_kilogram": 75.5,
        "max_heart_rate": 190,
    }


def recovery_fixture(
    cycle_id: int = 123, score_state: str = "SCORED", recovery_score: float = 65.0
) -> dict[str, Any]:
    """A recovery record from GET /v2/recovery or /v2/cycle/{id}/recovery."""
    record: dict[str, Any] = {
        "cycle_id": cycle_id,
        "created_at": "2026-08-01T06:30:00Z",
        "score_state": score_state,
    }
    if score_state == "SCORED":
        record["score"] = {
            "recovery_score": recovery_score,
            "hrv_rmssd_milli": 48.5,
            "resting_heart_rate": 55,
            "user_calibrating": False,
            "spo2_percentage": 98.0,
            "skin_temp_celsius": 36.5,
        }
    return record


def sleep_fixture(
    sleep_id: str = "sleep-uuid-1",
    score_state: str = "SCORED",
    nap: bool = False,
) -> dict[str, Any]:
    """A sleep record from GET /v2/activity/sleep/{id} or /v2/activity/sleep."""
    record: dict[str, Any] = {
        "id": sleep_id,
        "start": "2026-08-01T22:00:00Z",
        "end": "2026-08-02T07:00:00Z",
        "nap": nap,
        "score_state": score_state,
    }
    if score_state == "SCORED":
        record["score"] = {
            "sleep_performance_percentage": 87.0,
            "sleep_efficiency_percentage": 90.5,
            "respiratory_rate": 14.2,
            "stage_summary": {
                "total_awake_time_milli": 900000,
                "total_light_sleep_time_milli": 14400000,
                "total_slow_wave_sleep_time_milli": 7200000,
                "total_rem_sleep_time_milli": 5400000,
                "total_in_bed_time_milli": 28800000,
            },
        }
    return record


def cycle_fixture(
    cycle_id: int = 456, score_state: str = "SCORED", strain: float = 12.0
) -> dict[str, Any]:
    """A cycle record from GET /v2/cycle or /v2/cycle/{id}."""
    record: dict[str, Any] = {
        "id": cycle_id,
        "start": "2026-08-01T22:00:00Z",
        "end": "2026-08-02T22:00:00Z",
        "score_state": score_state,
    }
    if score_state == "SCORED":
        record["score"] = {
            "strain": strain,
            "kilojoule": 2850.0,
            "average_heart_rate": 78,
            "max_heart_rate": 155,
        }
    return record


def workout_fixture(
    workout_id: str = "workout-uuid-1",
    score_state: str = "SCORED",
    strain: float = 8.5,
) -> dict[str, Any]:
    """A workout record from GET /v2/activity/workout/{id} or /v2/activity/workout."""
    record: dict[str, Any] = {
        "id": workout_id,
        "sport_name": "running",
        "start": "2026-08-01T06:00:00Z",
        "end": "2026-08-01T07:30:00Z",
        "score_state": score_state,
    }
    if score_state == "SCORED":
        record["score"] = {
            "strain": strain,
            "average_heart_rate": 145,
            "max_heart_rate": 180,
            "zone_duration": {
                "zone_zero_milli": 0,
                "zone_one_milli": 180000,
                "zone_two_milli": 1200000,
                "zone_three_milli": 2400000,
                "zone_four_milli": 1500000,
                "zone_five_milli": 600000,
            },
        }
    return record


# -- existing fixture (preserved) ------------------------------------------


@pytest.fixture
async def tools() -> dict[str, object]:
    listed = await build_server().list_tools()
    return {tool.name: tool for tool in listed}


async def test_registers_exactly_the_expected_tools(tools: dict[str, object]) -> None:
    assert set(tools) == EXPECTED_TOOLS


async def test_data_tools_are_annotated_read_only(tools: dict[str, object]) -> None:
    not_read_only = {
        name
        for name, tool in tools.items()
        if name not in MUTATING_TOOLS and not getattr(tool.annotations, "read_only_hint", False)  # type: ignore[attr-defined]
    }

    assert not_read_only == set()


async def test_only_logout_is_destructive(tools: dict[str, object]) -> None:
    destructive = {
        name
        for name, tool in tools.items()
        if getattr(tool.annotations, "destructive_hint", False)  # type: ignore[attr-defined]
    }

    assert destructive == {"whoop_logout"}


async def test_every_tool_has_a_description(tools: dict[str, object]) -> None:
    # The description is what the model reads to choose a tool; an empty one
    # makes the tool effectively invisible.
    undescribed = {
        name
        for name, tool in tools.items()
        if not (getattr(tool, "description", "") or "").strip()  # type: ignore[attr-defined]
    }

    assert undescribed == set()


async def test_server_carries_usage_instructions() -> None:
    instructions = build_server().instructions or ""

    assert "cycle" in instructions.lower()
    assert "not clinical" in instructions.lower()


# -- auth tool tests (issue #4) -----------------------------------------------


async def test_whoop_auth_status_never_logged_in(
    server: object, config: Config, app_context: AppContext
) -> None:
    """Test whoop_auth_status when no token has ever been saved."""
    # The autouse _seed_valid_token fixture (added for the data tools' tests,
    # which need a working token to make an authenticated call) seeds one
    # before every test in this file -- clear it to genuinely test "never
    # logged in" rather than "logged in, then somehow logged out again".
    FileTokenStore(config.token_path).clear()

    status_dict = await call_tool(server, "whoop_auth_status", {}, app_context)

    # Must clearly distinguish this state from "token expired" or "token valid".
    assert status_dict == {"logged_in": False}, status_dict


async def test_whoop_auth_status_token_expired(
    server: object, config: Config, app_context: AppContext
) -> None:
    """Test whoop_auth_status when a token has expired but a refresh_token exists."""
    # Pre-save an expired token with a refresh token
    expired_token = Token(
        "fake-expired-access",
        expires_at=time.time() - 1000,  # well in the past
        refresh_token="fake-refresh",
        scopes=("read:sleep", "offline"),
    )
    FileTokenStore(config.token_path).save(expired_token)

    status_dict = await call_tool(server, "whoop_auth_status", {}, app_context)

    # Must distinguish "expired" from both "never logged in" and "valid" --
    # logged_in True (there IS a token) but expired True (it can't be used
    # as-is), with the granted scopes still visible.
    assert status_dict["logged_in"] is True, status_dict
    assert status_dict["expired"] is True, status_dict
    assert set(status_dict["scopes"]) == {"read:sleep", "offline"}
    # And never the never-logged-in shape.
    assert status_dict != {"logged_in": False}


async def test_whoop_auth_status_valid_token_with_scopes(
    server: object, config: Config, app_context: AppContext
) -> None:
    """Test whoop_auth_status with a valid, non-expired token and scopes."""
    # Pre-save a non-expired token with specific scopes
    valid_token = Token(
        "fake-access-token",
        expires_at=time.time() + 3600,  # expires in 1 hour
        refresh_token="fake-refresh-token",
        scopes=("read:sleep", "offline"),
    )
    FileTokenStore(config.token_path).save(valid_token)

    status_dict = await call_tool(server, "whoop_auth_status", {}, app_context)

    assert status_dict["logged_in"] is True
    assert status_dict["expired"] is False
    assert set(status_dict["scopes"]) == {"read:sleep", "offline"}
    # The literal token values must never appear anywhere in the response.
    result_str = str(status_dict)
    assert "fake-access-token" not in result_str, "Result must not expose the access token"
    assert "fake-refresh-token" not in result_str, "Result must not expose the refresh token"


async def test_whoop_login(server: object, app_context: AppContext) -> None:
    """Test whoop_login returns a URL with the expected structure."""
    result = await call_tool(server, "whoop_login", {}, app_context)
    # whoop_login returns a str; a scalar return's structured_content is
    # {"result": <the string>} (this SDK's auto-structured-output convention).
    url_text = str(result["result"])

    # Result should contain the authorize URL, hosted at the real WHOOP host --
    # parse it out and check the actual hostname rather than a raw substring
    # search over the whole message (CodeQL flags that as incomplete URL
    # sanitization: "https://evil.example/api.prod.whoop.com" would also
    # contain the substring without actually being the WHOOP host).
    # Anchored to the real host, not a bare "https://\S+" -- this message's
    # prose itself mentions "https://" in a parenthetical earlier on
    # ("...other than https://)..."), which a loose pattern would match first.
    url_match = re.search(r"https://api\.prod\.whoop\.com\S+", url_text)
    assert url_match, f"Expected an authorization URL in the response, got: {url_text}"
    assert urlparse(url_match.group(0)).hostname == "api.prod.whoop.com", (
        f"Expected the authorization URL's host to be api.prod.whoop.com, got: {url_text}"
    )
    # Result should mention the custom-scheme redirect (whoopmcp://)
    # and indicate that an error page is expected
    assert "error" in url_text.lower() or "browser" in url_text.lower(), (
        f"Expected result to mention browser/error page for custom-scheme redirect, got: {url_text}"
    )


async def test_whoop_complete_login_happy_path(
    server: object, config: Config, app_context: AppContext
) -> None:
    """Test whoop_complete_login succeeds with valid code and state."""
    # Step 1: Call whoop_login to set up the pending state
    login_result = await call_tool(server, "whoop_login", {}, app_context)
    login_text = str(login_result["result"])

    # Pull the URL out of the surrounding instructional prose -- whoop_login's
    # response is a message, not a bare URL, so extract the substring rather
    # than urlparse-ing the whole text (which only works by accident if the
    # URL happens to be the last thing in the string).
    url_match = re.search(r"https://api\.prod\.whoop\.com\S+", login_text)
    assert url_match, f"Expected an authorize URL in the response, got: {login_text}"
    query = parse_qs(urlparse(url_match.group(0)).query)
    assert "state" in query, f"Expected 'state' in URL, got: {login_text}"
    state = query["state"][0]

    # Step 2: Mock TOKEN_URL to return a successful token response
    with respx.mock:
        respx.post(TOKEN_URL).mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "access_token": "fake-access-token",
                    "expires_in": 3600,
                    "refresh_token": "fake-refresh-token",
                    "scope": "read:sleep offline",
                },
            )
        )

        # Step 3: Call whoop_complete_login with the code and state
        complete_result = await call_tool(
            server,
            "whoop_complete_login",
            {"code": "fake-auth-code", "state": state},
            app_context,
        )

    result_str = str(complete_result["result"])

    # Result should NOT contain the literal token values
    assert "fake-access-token" not in result_str, "Result must not expose the access token"
    assert "fake-refresh-token" not in result_str, "Result must not expose the refresh token"

    # Result should report the granted scopes
    assert "read:sleep" in result_str.lower() or "scopes" in result_str.lower(), (
        f"Expected result to mention granted scopes, got: {result_str}"
    )


async def test_whoop_complete_login_state_mismatch(
    server: object, config: Config, app_context: AppContext
) -> None:
    """Test whoop_complete_login fails when state doesn't match.

    MCPServer.call_tool() (Tool.run(), specifically) catches any exception
    raised by a tool body and re-raises it wrapped as ToolError -- it does
    NOT surface as a CallToolResult with is_error=True. That conversion
    happens one layer up, in the protocol-level request handler, which this
    test harness bypasses entirely. So the mismatch (Authenticator.verify_state
    raising AuthError) must be asserted as a raised ToolError here.
    """
    # Step 1: Call whoop_login to set up a pending state
    await call_tool(server, "whoop_login", {}, app_context)

    # Step 2: Call whoop_complete_login with a WRONG state
    # This should fail because the state won't match the one set by start_login
    with pytest.raises(ToolError, match="state mismatch"):
        await call_tool(
            server,
            "whoop_complete_login",
            {"code": "fake-auth-code", "state": "attacker-supplied-wrong-state"},
            app_context,
        )


async def test_whoop_logout(server: object, config: Config, app_context: AppContext) -> None:
    """Test whoop_logout clears the token and reports success."""
    # Step 1: Pre-save a token
    token = Token(
        "fake-access-token",
        expires_at=time.time() + 3600,
        refresh_token="fake-refresh-token",
        scopes=("read:sleep", "offline"),
    )
    FileTokenStore(config.token_path).save(token)

    # Verify the token is there
    assert FileTokenStore(config.token_path).load() is not None

    # Step 2: Call whoop_logout
    result = await call_tool(server, "whoop_logout", {}, app_context)

    # Step 3: Verify the token is now gone
    assert FileTokenStore(config.token_path).load() is None, "Token should be cleared after logout"

    # Step 4: Check response mentions "whoop" and grant NOT being revoked
    logout_text = str(result["result"])
    assert "whoop" in logout_text.lower(), (
        f"Expected response to mention 'whoop', got: {logout_text}"
    )
    # Response should indicate grant is NOT revoked on WHOOP's servers.
    # Common patterns: "revoke", "still", "server", etc.
    assert (
        "revoke" in logout_text.lower()
        or "still" in logout_text.lower()
        or "server" in logout_text.lower()
    ), f"Expected response to indicate grant is NOT revoked server-side, got: {logout_text}"


# -- data tool tests -------------------------------------------------------


@respx.mock
async def test_get_profile(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """get_profile returns profile data and sends bearer token."""
    fixture = profile_fixture()
    route = respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(server, "get_profile", {}, app_context)

    assert result == fixture
    assert route.called
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer fake-access-token"


@respx.mock
async def test_get_body_measurement(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """get_body_measurement returns measurement data and sends bearer token."""
    fixture = body_measurement_fixture()
    route = respx.get(f"{BASE_URL}/v2/user/measurement/body").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(server, "get_body_measurement", {}, app_context)

    assert result == fixture
    assert route.called
    request = route.calls.last.request
    assert request.headers["Authorization"] == "Bearer fake-access-token"


@respx.mock
async def test_list_recoveries_happy_path(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_recoveries returns trimmed records with count and no next_token."""
    recovery1 = recovery_fixture(cycle_id=100, recovery_score=65.0)
    recovery2 = recovery_fixture(cycle_id=101, recovery_score=72.5)

    respx.get(f"{BASE_URL}/v2/recovery").mock(
        return_value=httpx.Response(
            200,
            json={"records": [recovery1, recovery2], "next_token": None},
        )
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(
            server,
            "list_recoveries",
            {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
            app_context,
        )

    assert result["count"] == 2
    assert len(result["records"]) == 2
    assert result["next_token"] is None
    assert "note" not in result
    # Verify trimming: should have score fields but not extra fields
    for record in result["records"]:
        assert "recovery_score" in record
        assert "hrv_rmssd_milli" in record
        assert "resting_heart_rate" in record
        assert "user_calibrating" not in record
        assert "spo2_percentage" not in record
        assert "skin_temp_celsius" not in record


@respx.mock
async def test_list_sleeps_happy_path(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_sleeps returns trimmed records with stage_durations_milli mapping."""
    sleep1 = sleep_fixture(sleep_id="sleep-1")
    sleep2 = sleep_fixture(sleep_id="sleep-2")

    respx.get(f"{BASE_URL}/v2/activity/sleep").mock(
        return_value=httpx.Response(
            200,
            json={"records": [sleep1, sleep2], "next_token": None},
        )
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(
            server,
            "list_sleeps",
            {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
            app_context,
        )

    assert result["count"] == 2
    assert len(result["records"]) == 2
    assert result["next_token"] is None
    # Verify trimming and field remapping
    for record in result["records"]:
        assert "sleep_performance_percentage" in record
        assert "sleep_efficiency_percentage" in record
        assert "respiratory_rate" in record
        assert "stage_durations_milli" in record
        assert record["stage_durations_milli"]["awake"] == 900000
        assert record["stage_durations_milli"]["light"] == 14400000
        assert record["stage_durations_milli"]["deep"] == 7200000
        assert record["stage_durations_milli"]["rem"] == 5400000
        assert "total_in_bed_time_milli" not in record


@respx.mock
async def test_list_cycles_happy_path(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_cycles returns trimmed records with expected fields."""
    cycle1 = cycle_fixture(cycle_id=456, strain=12.0)
    cycle2 = cycle_fixture(cycle_id=457, strain=14.5)

    respx.get(f"{BASE_URL}/v2/cycle").mock(
        return_value=httpx.Response(
            200,
            json={"records": [cycle1, cycle2], "next_token": None},
        )
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(
            server,
            "list_cycles",
            {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
            app_context,
        )

    assert result["count"] == 2
    assert len(result["records"]) == 2
    assert result["next_token"] is None
    for record in result["records"]:
        assert "strain" in record
        assert "average_heart_rate" in record
        assert "max_heart_rate" in record
        assert "kilojoule" in record


@respx.mock
async def test_list_workouts_happy_path(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_workouts returns trimmed records with zone_durations_milli mapping."""
    workout1 = workout_fixture(workout_id="w-1")
    workout2 = workout_fixture(workout_id="w-2", strain=9.0)

    respx.get(f"{BASE_URL}/v2/activity/workout").mock(
        return_value=httpx.Response(
            200,
            json={"records": [workout1, workout2], "next_token": None},
        )
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(
            server,
            "list_workouts",
            {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
            app_context,
        )

    assert result["count"] == 2
    assert len(result["records"]) == 2
    assert result["next_token"] is None
    for record in result["records"]:
        assert "sport_name" in record
        assert "strain" in record
        assert "average_heart_rate" in record
        assert "max_heart_rate" in record
        assert "zone_durations_milli" in record
        assert record["zone_durations_milli"]["zone_zero"] == 0
        assert record["zone_durations_milli"]["zone_five"] == 600000


@respx.mock
async def test_list_recoveries_with_unscored_record(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_recoveries includes unscored records but without score fields."""
    scored = recovery_fixture(cycle_id=100, score_state="SCORED")
    unscored = recovery_fixture(cycle_id=101, score_state="PENDING_SCORE")

    respx.get(f"{BASE_URL}/v2/recovery").mock(
        return_value=httpx.Response(
            200,
            json={"records": [scored, unscored], "next_token": None},
        )
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(
            server,
            "list_recoveries",
            {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
            app_context,
        )

    assert result["count"] == 2
    # First record should have score fields
    assert "recovery_score" in result["records"][0]
    assert result["records"][0]["score_state"] == "SCORED"
    # Second record should have score_state but no score fields
    assert result["records"][1]["score_state"] == "PENDING_SCORE"
    assert "recovery_score" not in result["records"][1]


@respx.mock
async def test_list_recoveries_with_pagination(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_recoveries with next_token includes note and next_token in response."""
    recovery1 = recovery_fixture(cycle_id=100)
    recovery2 = recovery_fixture(cycle_id=101)

    respx.get(f"{BASE_URL}/v2/recovery").mock(
        return_value=httpx.Response(
            200,
            json={"records": [recovery1, recovery2], "next_token": "cursor-abc"},
        )
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(
            server,
            "list_recoveries",
            {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
            app_context,
        )

    assert result["count"] == 2
    assert result["next_token"] == "cursor-abc"
    assert "note" in result
    assert "more records" in result["note"].lower()


@respx.mock
async def test_list_recoveries_default_date_range(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_recoveries with no start/end defaults to last 7 days."""
    recovery = recovery_fixture()

    route = respx.get(f"{BASE_URL}/v2/recovery").mock(
        return_value=httpx.Response(
            200,
            json={"records": [recovery], "next_token": None},
        )
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(server, "list_recoveries", {}, app_context)

    assert result["count"] >= 0
    # Check that the request included start and end parameters
    request = route.calls.last.request
    url_str = str(request.url)
    assert "start=" in url_str
    assert "end=" in url_str
    # Parse the dates from the query string and check the gap
    parsed = parse_qs(urlparse(str(request.url)).query)
    start_str = parsed.get("start", [None])[0]
    end_str = parsed.get("end", [None])[0]
    if start_str and end_str:
        start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
        gap_days = (end - start).days
        assert 6 <= gap_days <= 8, f"Expected ~7 day gap, got {gap_days}"


@respx.mock
async def test_list_sleeps_with_explicit_next_token(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_sleeps threads explicit next_token to WhoopClient."""
    sleep = sleep_fixture()

    route = respx.get(f"{BASE_URL}/v2/activity/sleep").mock(
        return_value=httpx.Response(
            200,
            json={"records": [sleep], "next_token": None},
        )
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        await call_tool(server, "list_sleeps", {"next_token": "cursor-xyz"}, app_context)

    assert route.called
    request = route.calls.last.request
    assert "nextToken=cursor-xyz" in str(request.url)


@respx.mock
async def test_get_sleep(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """get_sleep returns trimmed single sleep record."""
    fixture = sleep_fixture(sleep_id="sleep-123")

    respx.get(f"{BASE_URL}/v2/activity/sleep/sleep-123").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(server, "get_sleep", {"sleep_id": "sleep-123"}, app_context)

    assert result["id"] == "sleep-123"
    assert "sleep_performance_percentage" in result
    assert "stage_durations_milli" in result
    assert "total_in_bed_time_milli" not in result


@respx.mock
async def test_get_workout(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """get_workout returns trimmed single workout record."""
    fixture = workout_fixture(workout_id="workout-456")

    respx.get(f"{BASE_URL}/v2/activity/workout/workout-456").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(server, "get_workout", {"workout_id": "workout-456"}, app_context)

    assert result["id"] == "workout-456"
    assert "sport_name" in result
    assert "strain" in result
    assert "zone_durations_milli" in result


@respx.mock
async def test_list_recoveries_rate_limited_error(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_recoveries returns rate_limited response on RateLimitedError."""
    reset_time = time.time() + 60
    respx.get(f"{BASE_URL}/v2/recovery").mock(
        return_value=httpx.Response(
            429,
            json={"error": "rate_limited"},
            headers={"X-RateLimit-Reset": str(int(reset_time))},
        )
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        result = await call_tool(
            server,
            "list_recoveries",
            {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
            app_context,
        )

    assert result["error"] == "rate_limited"
    assert "retry_after_seconds" in result
    assert result["retry_after_seconds"] > 0
    assert "retry" in result["message"].lower()
