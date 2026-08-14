"""Checks on the MCP surface itself: what tools exist and how they are declared.

These matter more than they look. The tool list and its annotations are the
contract an MCP client sees, and a tool that quietly loses `readOnlyHint` is
a tool a client may stop asking permission for.
"""

from __future__ import annotations

import base64
import inspect
import json
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
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
from whoopmcp.server import (
    _MAX_LIST_LIMIT,
    AppContext,
    Principal,
    build_server,
    lifespan,
)
from whoopmcp.store import (
    link_principal_to_member,
    open_store,
    upsert_body_measurement,
    upsert_cycle,
    upsert_profile,
    upsert_recovery,
    upsert_sleep,
    upsert_workout,
)

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
    "whoop_sync",
    "whoop_data_coverage",
    "summarize_period",
    "metric_trend",
    "correlate_metrics",
    "compare_periods",
    "whoop_timeseries",
    "whoop_outliers",
    "whoop_streaks",
}

#: The only tools allowed to change anything. Everything else is a read.
#: ``whoop_sync`` (#15) writes upserted records to the local store -- never
#: to WHOOP itself, which it only ever GETs -- but that is still a real
#: environment change per MCP's own read_only_hint semantics.
MUTATING_TOOLS = {"whoop_complete_login", "whoop_logout", "whoop_sync"}

#: Every prompt the server promises (#26). Same contract as EXPECTED_TOOLS:
#: adding one here without registering it, or vice versa, fails the suite.
EXPECTED_PROMPTS = {
    "morning_readiness_briefing",
    "weekly_training_review",
    "sleep_debt_investigation",
}

#: The one resource surface the server promises (#26): a single URI template
#: dispatching on its trailing `item` segment, not four static resources --
#: this SDK's `MCPServer.resource()` rejects a `Context`-typed parameter on
#: any URI with no `{param}` at registration time, so a per-user identity
#: gate could never run inside a static resource's function.
EXPECTED_RESOURCE_TEMPLATES = {"whoop://user/{item}"}


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
    # user_id matches profile_fixture()'s "user_id": 12345, so a test that
    # mocks the profile endpoint and one that doesn't stay consistent with
    # each other about who "the" user is.
    #
    # store_conn= plus the principal_members row (#29): every tool now
    # resolves identity via resolve_member_id, which requires a store and
    # errors without a mapping for the calling principal --
    # ("__local__", None, None) is _principal_key's own sentinel for a
    # request-less (stdio-shaped) Context, exactly what call_tool's
    # ServerRequestContext(session=None, ...) builds.
    conn = open_store(":memory:")
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=12345
    )
    yield AppContext(
        config=config,
        auth=auth,
        client=client,
        principal=Principal(user_id=12345),
        store_conn=conn,
    )
    conn.close()


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
    cycle_id: int = 123,
    score_state: str = "SCORED",
    recovery_score: float = 65.0,
    created_at: str = "2026-08-01T06:30:00Z",
) -> dict[str, Any]:
    """A recovery record from GET /v2/recovery or /v2/cycle/{id}/recovery."""
    record: dict[str, Any] = {
        "cycle_id": cycle_id,
        "created_at": created_at,
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
    created_at: str = "2026-08-01T22:00:00Z",
) -> dict[str, Any]:
    """A sleep record from GET /v2/activity/sleep/{id} or /v2/activity/sleep.

    ``created_at`` is a real WHOOP field on every collection (issue #3's own
    fixtures already assume it for Cycle-shaped records, in
    test_correlate_joins_strain_cycle_records_by_own_id) -- analysis.py's
    trend()/correlate() index it directly, so a fixture missing it would
    crash them with a KeyError rather than exercising the real behavior.
    """
    record: dict[str, Any] = {
        "id": sleep_id,
        "created_at": created_at,
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
    cycle_id: int = 456,
    score_state: str = "SCORED",
    strain: float = 12.0,
    created_at: str = "2026-08-01T22:00:00Z",
) -> dict[str, Any]:
    """A cycle record from GET /v2/cycle or /v2/cycle/{id}.

    ``created_at`` is a real WHOOP field on every collection (see
    sleep_fixture's docstring for why this matters for analysis.py).
    """
    record: dict[str, Any] = {
        "id": cycle_id,
        "created_at": created_at,
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


@pytest.fixture
async def prompts() -> dict[str, object]:
    listed = await build_server().list_prompts()
    return {prompt.name: prompt for prompt in listed}


@pytest.fixture
async def resources() -> dict[str, object]:
    listed = await build_server().list_resources()
    return {str(resource.uri): resource for resource in listed}


@pytest.fixture
async def resource_templates() -> dict[str, object]:
    listed = await build_server().list_resource_templates()
    return {template.uri_template: template for template in listed}


async def test_registers_exactly_the_expected_prompts(prompts: dict[str, object]) -> None:
    assert set(prompts) == EXPECTED_PROMPTS


async def test_registers_exactly_the_expected_resources(
    resources: dict[str, object], resource_templates: dict[str, object]
) -> None:
    # Templates are never concrete resources -- list_resources() stays empty
    # by design, so a later concrete resource would show up here instead of
    # being silently ignored.
    assert resources == {}
    assert set(resource_templates) == EXPECTED_RESOURCE_TEMPLATES


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

    # Step 2: Mock TOKEN_URL, and the profile endpoint whoop_complete_login
    # now also calls (issue #8: it resolves a Principal after a successful
    # exchange), to both return successful responses.
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
        respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
            return_value=respx.MockResponse(200, json=profile_fixture())
        )

        # Step 3: Call whoop_complete_login with the code and state. Its
        # principal resolution goes through app.client -- unlike
        # exchange_code, which opens its own short-lived httpx.AsyncClient --
        # so, unlike the rest of this file's auth-tool tests, client must
        # already be entered as an async context manager here.
        async with WhoopClient(config, app_context.auth) as client:
            app_context.client = client
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
#
# #16 repointed every one of these at the local store: none of them makes an
# HTTP call any more, so none of them mocks WHOOP with respx. Every test
# below seeds app_context.store_conn directly (via the store's own upsert_*
# functions) instead. The two tests this file used to carry for a
# RateLimitedError surfacing through list_recoveries/summarize_period are
# gone outright, not just rewritten: a store-backed tool never calls
# WhoopClient at all on its happy path, so RateLimitedError is no longer a
# reachable outcome for either of them.


async def test_get_profile(app_context: AppContext, server: MCPServer[AppContext]) -> None:
    """get_profile returns the stored profile, plus a "coverage" envelope."""
    assert app_context.store_conn is not None
    fixture = profile_fixture()
    upsert_profile(app_context.store_conn, 12345, fixture)

    result = await call_tool(server, "get_profile", {}, app_context)

    assert {key: value for key, value in result.items() if key != "coverage"} == fixture
    assert result["coverage"]["profile"]["synced"] is True


async def test_get_profile_not_synced(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A never-synced profile is an explicit miss, not an empty dict."""
    result = await call_tool(server, "get_profile", {}, app_context)

    assert result["error"] == "not_synced"
    assert result["coverage"]["profile"] == {"synced": False, "last_updated_at": None}


async def test_get_body_measurement(app_context: AppContext, server: MCPServer[AppContext]) -> None:
    """get_body_measurement returns the stored measurement, plus "coverage"."""
    assert app_context.store_conn is not None
    fixture = body_measurement_fixture()
    upsert_body_measurement(app_context.store_conn, 12345, fixture)

    result = await call_tool(server, "get_body_measurement", {}, app_context)

    assert {key: value for key, value in result.items() if key != "coverage"} == fixture
    assert result["coverage"]["body_measurement"]["synced"] is True


async def test_list_recoveries_happy_path(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_recoveries returns trimmed records with count, no next_token, and coverage."""
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=100, recovery_score=65.0, created_at="2026-08-02T06:00:00Z"),
    )
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=101, recovery_score=72.5, created_at="2026-08-03T06:00:00Z"),
    )

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
    assert result["coverage"]["recoveries"]["earliest"] == "2026-08-02T06:00:00Z"
    assert "range_coverage" in result
    # Verify trimming: should have score fields but not extra fields
    for record in result["records"]:
        assert "recovery_score" in record
        assert "hrv_rmssd_milli" in record
        assert "resting_heart_rate" in record
        assert "user_calibrating" not in record
        assert "spo2_percentage" not in record
        assert "skin_temp_celsius" not in record


async def test_list_sleeps_happy_path(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_sleeps with detail="full" returns trimmed records with stage_durations mapping."""
    assert app_context.store_conn is not None
    upsert_sleep(app_context.store_conn, 12345, sleep_fixture(sleep_id="sleep-1"))
    upsert_sleep(
        app_context.store_conn,
        12345,
        sleep_fixture(sleep_id="sleep-2", created_at="2026-08-02T22:00:00Z"),
    )

    result = await call_tool(
        server,
        "list_sleeps",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z", "detail": "full"},
        app_context,
    )

    assert result["count"] == 2
    assert len(result["records"]) == 2
    assert result["next_token"] is None
    assert result["units"] == {"stage_durations": "milliseconds"}
    for record in result["records"]:
        assert "sleep_performance_percentage" in record
        assert "sleep_efficiency_percentage" in record
        assert "respiratory_rate" in record
        assert "stage_durations" in record
        assert record["stage_durations"]["awake"] == 900000
        assert record["stage_durations"]["light"] == 14400000
        assert record["stage_durations"]["deep"] == 7200000
        assert record["stage_durations"]["rem"] == 5400000
        assert "total_in_bed_time_milli" not in record


async def test_list_cycles_happy_path(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_cycles returns trimmed records with expected fields."""
    assert app_context.store_conn is not None
    upsert_cycle(app_context.store_conn, 12345, cycle_fixture(cycle_id=456, strain=12.0))
    upsert_cycle(
        app_context.store_conn,
        12345,
        cycle_fixture(cycle_id=457, strain=14.5, created_at="2026-08-02T22:00:00Z"),
    )

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


async def test_list_workouts_happy_path(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_workouts with detail="full" returns trimmed records with zone_durations mapping."""
    assert app_context.store_conn is not None
    upsert_workout(app_context.store_conn, 12345, workout_fixture(workout_id="w-1"))
    upsert_workout(app_context.store_conn, 12345, workout_fixture(workout_id="w-2", strain=9.0))

    result = await call_tool(
        server,
        "list_workouts",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z", "detail": "full"},
        app_context,
    )

    assert result["count"] == 2
    assert len(result["records"]) == 2
    assert result["next_token"] is None
    assert result["units"] == {"zone_durations": "milliseconds"}
    for record in result["records"]:
        assert "sport_name" in record
        assert "strain" in record
        assert "average_heart_rate" in record
        assert "max_heart_rate" in record
        assert "zone_durations" in record
        assert record["zone_durations"]["zone_zero"] == 0
        assert record["zone_durations"]["zone_five"] == 600000


async def test_list_recoveries_with_unscored_record(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_recoveries includes unscored records but without score fields."""
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=100, score_state="SCORED", created_at="2026-08-01T06:00:00Z"),
    )
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(
            cycle_id=101, score_state="PENDING_SCORE", created_at="2026-08-02T06:00:00Z"
        ),
    )

    result = await call_tool(
        server,
        "list_recoveries",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
        app_context,
    )

    assert result["count"] == 2
    assert "recovery_score" in result["records"][0]
    assert result["records"][0]["score_state"] == "SCORED"
    assert result["records"][1]["score_state"] == "PENDING_SCORE"
    assert "recovery_score" not in result["records"][1]


async def test_list_recoveries_with_pagination(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A limit smaller than the held rows returns a next_token and a note;
    passing that next_token back continues from exactly where it left off."""
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=100, created_at="2026-08-01T06:00:00Z"),
    )
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=101, created_at="2026-08-02T06:00:00Z"),
    )

    first = await call_tool(
        server,
        "list_recoveries",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z", "limit": 1},
        app_context,
    )

    assert first["count"] == 1
    assert first["next_token"] is not None
    assert "note" in first
    assert "more" in first["note"].lower()
    assert first["records"][0]["cycle_id"] == 100

    second = await call_tool(
        server, "list_recoveries", {"next_token": first["next_token"]}, app_context
    )

    assert second["count"] == 1
    assert second["records"][0]["cycle_id"] == 101
    assert second["next_token"] is None


async def test_list_recoveries_rejects_a_zero_limit(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """limit=0 is rejected outright, not silently turned into an
    empty-page-with-a-self-referential-cursor loop: next_token encodes
    offset + limit, so a zero limit would produce a continuation token
    identical to the one that led to it -- an infinite empty-page walk that
    never resolves to "no more data" (#16 review finding)."""
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=100, created_at="2026-08-01T06:00:00Z"),
    )

    with pytest.raises(ToolError, match="limit"):
        await call_tool(
            server,
            "list_recoveries",
            {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z", "limit": 0},
            app_context,
        )


async def test_list_recoveries_one_sided_range_wholly_outside_coverage_is_flagged(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A one-sided range (only `end` given) that falls wholly before the
    held coverage window must be flagged, not silently reported as
    "within_coverage" -- the #16 review's blocking finding: _range_status
    special-cased the one-sided branches and each originally fell through
    to `within_coverage` whenever the OTHER bound was unset, regardless of
    whether the given bound actually overlapped anything held."""
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=100, created_at="2026-08-01T06:00:00Z"),
    )

    result = await call_tool(
        server,
        "list_recoveries",
        {"end": "2020-06-01T00:00:00Z"},
        app_context,
    )

    assert result["records"] == []
    assert result["range_coverage"]["recoveries"]["status"] == "wholly_outside_coverage"
    assert "message" in result["range_coverage"]["recoveries"]


async def test_list_recoveries_accepts_a_timezone_naive_timestamp(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A start/end value with no `Z`/offset (a plausible, not malicious,
    model input that drops the documented UTC suffix) is treated as UTC,
    not raised as an offset-naive-vs-aware comparison TypeError against the
    store's own always-aware coverage bounds (#16 review finding)."""
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=100, created_at="2026-08-02T06:00:00Z"),
    )

    result = await call_tool(
        server,
        "list_recoveries",
        {"start": "2026-08-01T00:00:00", "end": "2026-08-08T00:00:00"},
        app_context,
    )

    # The point of this test is that offset-naive bounds compare cleanly
    # against the store's aware coverage values at all -- pre-fix, this
    # call never returned; it raised. Which status comes back (this range
    # extends past the single held record, so "partly_outside_coverage" is
    # the correct answer) is incidental to what's being regression-tested.
    assert result["count"] == 1
    assert result["range_coverage"]["recoveries"]["status"] in (
        "within_coverage",
        "partly_outside_coverage",
    )


async def test_list_recoveries_default_date_range(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """list_recoveries with no start/end defaults to the last 7 days."""
    assert app_context.store_conn is not None
    now = datetime.now(UTC)
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=100, created_at=(now - timedelta(days=3)).isoformat()),
    )
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=101, created_at=(now - timedelta(days=10)).isoformat()),
    )

    result = await call_tool(server, "list_recoveries", {}, app_context)

    assert {record["cycle_id"] for record in result["records"]} == {100}


# -- issue #173: upper-bound limit validation for list tools ----------------


@pytest.mark.parametrize(
    "tool_name,fixture_fn,upsert_fn",
    [
        ("list_recoveries", recovery_fixture, upsert_recovery),
        ("list_sleeps", sleep_fixture, upsert_sleep),
        ("list_workouts", workout_fixture, upsert_workout),
        ("list_cycles", cycle_fixture, upsert_cycle),
    ],
)
async def test_list_tools_reject_limit_above_ceiling(
    app_context: AppContext,
    server: MCPServer[AppContext],
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    fixture_fn: Callable[..., dict[str, Any]],
    upsert_fn: Callable[..., Any],
) -> None:
    """A limit above 1000 is rejected outright with a clear error naming the
    ceiling, raised BEFORE any store call. This test wraps the relevant store
    function to ensure it is never invoked when validation fails.

    Validates the fix for issue #173: list tools must cap at _MAX_LIST_LIMIT
    to avoid overflow when the tool adds +1 for pagination lookahead.
    """
    assert app_context.store_conn is not None
    upsert_fn(app_context.store_conn, 12345, fixture_fn())

    # Wrap the store's get_* function to track whether it's called
    from whoopmcp import store

    store_func_name = f"get_{tool_name.replace('list_', '')}"
    original_func = getattr(store, store_func_name)
    store_called = []

    def wrapped_store_func(*args, **kwargs):
        store_called.append(True)
        return original_func(*args, **kwargs)

    monkeypatch.setattr(store, store_func_name, wrapped_store_func)

    # Test with a limit well above the ceiling
    with pytest.raises(ToolError, match="1000"):
        await call_tool(
            server,
            tool_name,
            {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z", "limit": 1001},
            app_context,
        )

    # Verify the store function was never called
    assert not store_called, f"{store_func_name} should not be called when limit is rejected"


@pytest.mark.parametrize(
    "tool_name,fixture_fn,upsert_fn",
    [
        ("list_recoveries", recovery_fixture, upsert_recovery),
        ("list_sleeps", sleep_fixture, upsert_sleep),
        ("list_workouts", workout_fixture, upsert_workout),
        ("list_cycles", cycle_fixture, upsert_cycle),
    ],
)
async def test_list_tools_reject_limit_of_max_int64(
    app_context: AppContext,
    server: MCPServer[AppContext],
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    fixture_fn: Callable[..., dict[str, Any]],
    upsert_fn: Callable[..., Any],
) -> None:
    """limit = 2**63 - 1 produces a ValueError from _require_positive_limit,
    not an OverflowError. Raw 2**63-1 binds fine in sqlite, but the tool adds
    +1 for pagination lookahead, causing overflow. Validation must catch this
    before reaching the store.

    This test ensures the implementation's upper bound catches the overflow
    case, raising the validation error early with a clear message.
    """
    assert app_context.store_conn is not None
    upsert_fn(app_context.store_conn, 12345, fixture_fn())

    from whoopmcp import store

    store_func_name = f"get_{tool_name.replace('list_', '')}"
    original_func = getattr(store, store_func_name)
    store_called = []

    def wrapped_store_func(*args, **kwargs):
        store_called.append(True)
        return original_func(*args, **kwargs)

    monkeypatch.setattr(store, store_func_name, wrapped_store_func)

    # Test with 2**63 - 1 (max int64)
    with pytest.raises(ToolError) as exc_info:
        await call_tool(
            server,
            tool_name,
            {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z", "limit": 2**63 - 1},
            app_context,
        )

    # Should have ValueError message, not OverflowError
    assert "limit" in str(exc_info.value).lower()
    assert not store_called, f"{store_func_name} should not be called when limit is rejected"


@pytest.mark.parametrize(
    "tool_name,make_record,upsert_fn,id_field",
    [
        (
            "list_recoveries",
            lambda i: recovery_fixture(cycle_id=100 + i, created_at=f"2026-08-0{i + 1}T06:30:00Z"),
            upsert_recovery,
            "cycle_id",
        ),
        (
            "list_sleeps",
            lambda i: sleep_fixture(
                sleep_id=f"sleep-{i}", created_at=f"2026-08-0{i + 1}T22:00:00Z"
            ),
            upsert_sleep,
            "id",
        ),
        (
            "list_workouts",
            lambda i: {
                **workout_fixture(workout_id=f"workout-{i}"),
                "start": f"2026-08-01T{i % 24:02d}:{i % 60:02d}:00Z",
                "end": f"2026-08-01T{(i + 1) % 24:02d}:{(i + 1) % 60:02d}:00Z",
            },
            upsert_workout,
            "id",
        ),
        (
            "list_cycles",
            lambda i: cycle_fixture(cycle_id=500 + i, created_at=f"2026-08-0{i + 1}T22:00:00Z"),
            upsert_cycle,
            "id",
        ),
    ],
)
async def test_paging_survives_the_ceiling_including_continuation(
    app_context: AppContext,
    server: MCPServer[AppContext],
    tool_name: str,
    make_record: Callable[[int], dict[str, Any]],
    upsert_fn: Callable[..., Any],
    id_field: str,
) -> None:
    """The ceiling must not disturb the pagination it exists to protect (#173).

    Two distinct things, because a ceiling can break either one:

    1. ``limit`` exactly at the ceiling is *accepted*. The bound is
       inclusive-allow, so an off-by-one that rejects 1000 fails here.
    2. A real multi-page walk still completes. ``_require_positive_limit`` runs
       on the continuation request too, not just the first page, so a validator
       that mishandled a resumed walk would strand a caller mid-history.

    The walk is what makes this non-vacuous. A single call with ``limit=1000``
    over a handful of records returns ``next_token=None`` and never exercises
    continuation at all -- it would pass against a build whose cursor logic was
    entirely broken.
    """
    assert app_context.store_conn is not None
    total = 5
    for i in range(total):
        upsert_fn(app_context.store_conn, 12345, make_record(i))

    window = {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"}

    # 1. At and just below the ceiling: accepted, and every record comes back.
    for limit in (_MAX_LIST_LIMIT, _MAX_LIST_LIMIT - 1):
        result = await call_tool(server, tool_name, {**window, "limit": limit}, app_context)
        assert len(result["records"]) == total, f"limit={limit} must still return every record"
        assert result["next_token"] is None, f"limit={limit} covers all {total}, so no next page"

    # 2. A genuine multi-page walk, two records at a time, driven by the cursor
    #    the server itself returns. Collected as a list so a page repeating a
    #    record it already served shows up as a duplicate rather than being
    #    silently absorbed by a set.
    seen: list[Any] = []
    page = await call_tool(server, tool_name, {**window, "limit": 2}, app_context)
    assert page["next_token"] is not None, "5 records at limit=2 must have a second page"
    for _ in range(10):  # bounded: a cursor that never terminates fails below
        seen.extend(record[id_field] for record in page["records"])
        if page["next_token"] is None:
            break
        page = await call_tool(
            server, tool_name, {"next_token": page["next_token"], "limit": 2}, app_context
        )
    else:
        raise AssertionError("pagination never terminated")

    assert len(seen) == total, f"the walk must serve every record exactly once, got {seen}"
    assert len(set(seen)) == total, f"the walk must not repeat a record, got {seen}"
    assert set(seen) == {record[id_field] for record in [make_record(i) for i in range(total)]}


async def test_paging_at_the_ceiling_with_continuation(
    app_context: AppContext,
    server: MCPServer[AppContext],
) -> None:
    """A multi-page walk at the ceiling limit itself, exercising the real case the
    ceiling logic must protect. Seeds _MAX_LIST_LIMIT + 5 records (1005) so that
    a limit=_MAX_LIST_LIMIT request returns exactly _MAX_LIST_LIMIT records on page 1
    plus a next_token, and the continuation returns the remaining 5 on page 2 with
    no next_token.

    This test is essential and non-vacuous: it fails if _require_positive_limit caps
    (offset + limit) instead of just limit, which is a plausible misreading of the fix.
    """
    assert app_context.store_conn is not None
    total = _MAX_LIST_LIMIT + 5
    for i in range(total):
        # A distinct `start` per record, set on the dict because sleep_fixture
        # takes no `start` argument and hardcodes one. get_sleeps is
        # `ORDER BY start` with no tiebreaker, so identical starts would leave
        # the ordering of two separate LIMIT/OFFSET queries unspecified -- and
        # every assertion below about serving each record exactly once would
        # rest on a tie order SQLite never promised.
        record = sleep_fixture(sleep_id=f"sleep-{i}")
        moment = datetime(2026, 8, 1, tzinfo=UTC) + timedelta(minutes=i)
        record["start"] = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
        record["end"] = (moment + timedelta(hours=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record["created_at"] = record["start"]
        upsert_sleep(app_context.store_conn, 12345, record)

    window = {"start": "2026-08-01T00:00:00Z", "end": "2026-08-31T23:59:59Z"}

    # 1. limit=_MAX_LIST_LIMIT returns exactly _MAX_LIST_LIMIT records plus next_token
    page1 = await call_tool(
        server, "list_sleeps", {**window, "limit": _MAX_LIST_LIMIT}, app_context
    )
    assert len(page1["records"]) == _MAX_LIST_LIMIT, (
        f"limit={_MAX_LIST_LIMIT} must return exactly {_MAX_LIST_LIMIT} records"
    )
    assert page1["next_token"] is not None, "1005 records at limit=1000 must have a next page"

    # 2. limit=_MAX_LIST_LIMIT - 1 also works (just below ceiling)
    page_below = await call_tool(
        server, "list_sleeps", {**window, "limit": _MAX_LIST_LIMIT - 1}, app_context
    )
    assert len(page_below["records"]) == _MAX_LIST_LIMIT - 1, (
        f"limit={_MAX_LIST_LIMIT - 1} must return {_MAX_LIST_LIMIT - 1} records"
    )
    assert page_below["next_token"] is not None, "1005 records at limit=999 must have a next page"

    # 3. Continue with next_token from page 1, get the remaining 5 records
    page2 = await call_tool(
        server,
        "list_sleeps",
        {"next_token": page1["next_token"], "limit": _MAX_LIST_LIMIT},
        app_context,
    )
    assert len(page2["records"]) == 5, "page 2 must return the remaining 5 records"
    assert page2["next_token"] is None, "page 2 must have no next_token"

    # 4. Verify all records recovered exactly once, no duplicates
    all_ids = [record["id"] for record in page1["records"]]
    all_ids.extend(record["id"] for record in page2["records"])
    assert len(all_ids) == total, f"must serve exactly {total} records"
    assert len(set(all_ids)) == total, f"must not repeat any record, got {all_ids}"
    expected_ids = {f"sleep-{i}" for i in range(total)}
    assert set(all_ids) == expected_ids, "must serve exactly the seeded records"


async def test_list_sleeps_pagination_continues_with_the_returned_cursor(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A store-backed list_* tool's next_token is its own opaque cursor now,
    not a value forwarded verbatim to WHOOP -- passing it back continues the
    walk regardless of what start/end (if anything) the caller resends."""
    assert app_context.store_conn is not None
    upsert_sleep(app_context.store_conn, 12345, sleep_fixture(sleep_id="sleep-1"))
    upsert_sleep(
        app_context.store_conn,
        12345,
        sleep_fixture(sleep_id="sleep-2", created_at="2026-08-02T22:00:00Z"),
    )

    first = await call_tool(
        server,
        "list_sleeps",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z", "limit": 1},
        app_context,
    )
    assert first["next_token"] is not None

    second = await call_tool(
        server, "list_sleeps", {"next_token": first["next_token"]}, app_context
    )

    assert second["records"][0]["id"] == "sleep-2"
    assert second["next_token"] is None


async def test_get_sleep(app_context: AppContext, server: MCPServer[AppContext]) -> None:
    """get_sleep returns a trimmed single sleep record, plus coverage."""
    assert app_context.store_conn is not None
    upsert_sleep(app_context.store_conn, 12345, sleep_fixture(sleep_id="sleep-123"))

    result = await call_tool(server, "get_sleep", {"sleep_id": "sleep-123"}, app_context)

    assert result["id"] == "sleep-123"
    assert "sleep_performance_percentage" in result
    assert "stage_durations" in result
    assert result["units"] == {"stage_durations": "milliseconds"}
    assert "total_in_bed_time_milli" not in result
    assert "coverage" in result


async def test_get_sleep_not_synced(app_context: AppContext, server: MCPServer[AppContext]) -> None:
    """No sleep has ever been synced: an explicit "not_synced" miss."""
    result = await call_tool(server, "get_sleep", {"sleep_id": "sleep-123"}, app_context)

    assert result["error"] == "not_synced"


async def test_get_sleep_not_found_in_store(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Sleeps exist, but not this id: "not_found_in_store", not "not_synced"."""
    assert app_context.store_conn is not None
    upsert_sleep(app_context.store_conn, 12345, sleep_fixture(sleep_id="sleep-real"))

    result = await call_tool(server, "get_sleep", {"sleep_id": "sleep-missing"}, app_context)

    assert result["error"] == "not_found_in_store"


async def test_get_workout(app_context: AppContext, server: MCPServer[AppContext]) -> None:
    """get_workout returns a trimmed single workout record, plus coverage."""
    assert app_context.store_conn is not None
    upsert_workout(app_context.store_conn, 12345, workout_fixture(workout_id="workout-456"))

    result = await call_tool(server, "get_workout", {"workout_id": "workout-456"}, app_context)

    assert result["id"] == "workout-456"
    assert "sport_name" in result
    assert "strain" in result
    assert "zone_durations" in result
    assert result["units"] == {"zone_durations": "milliseconds"}
    assert "coverage" in result


# -- analysis tool tests (issue #6) ----------------------------------------


async def test_summarize_period_every_result_carries_sample_size(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Every metric in summarize_period's result has a count key.

    Pre-#16 this test also asserted each WHOOP route was hit exactly once,
    to avoid a redundant live fetch per metric sharing a collection.
    Post-#16, collections are read from the local store once per
    _summarize_window call regardless of how many respx routes anything
    mocks -- a redundant SQL read has no rate-limit cost worth a dedicated
    regression test any more.
    """
    assert app_context.store_conn is not None
    for i in range(3):
        upsert_recovery(
            app_context.store_conn,
            12345,
            recovery_fixture(cycle_id=100 + i, created_at=f"2026-08-{i + 1:02d}T06:00:00Z"),
        )
        upsert_sleep(
            app_context.store_conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-{i}", created_at=f"2026-08-{i + 1:02d}T22:00:00Z"),
        )
        upsert_cycle(
            app_context.store_conn,
            12345,
            cycle_fixture(cycle_id=456 + i, created_at=f"2026-08-{i + 1:02d}T22:00:00Z"),
        )

    result = await call_tool(
        server,
        "summarize_period",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
        app_context,
    )

    for metric in (
        "recovery_score",
        "hrv",
        "resting_heart_rate",
        "sleep_performance",
        "sleep_efficiency",
        "strain",
    ):
        assert "count" in result["summaries"][metric]
        assert isinstance(result["summaries"][metric]["count"], int)
    assert set(result["coverage"]) == {"recoveries", "sleeps", "cycles"}


async def test_summarize_period_insufficient_data_for_one_metric_does_not_block_others(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """One thin collection doesn't blank out all metrics."""
    assert app_context.store_conn is not None
    for i in range(3):
        upsert_recovery(
            app_context.store_conn,
            12345,
            recovery_fixture(cycle_id=100 + i, created_at=f"2026-08-{i + 1:02d}T06:00:00Z"),
        )
        upsert_sleep(
            app_context.store_conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-{i}", created_at=f"2026-08-{i + 1:02d}T22:00:00Z"),
        )
    # Cycle with only 1 record (insufficient for stdev, which needs >=2).
    upsert_cycle(app_context.store_conn, 12345, cycle_fixture(cycle_id=456, strain=12.0))

    result = await call_tool(
        server,
        "summarize_period",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
        app_context,
    )

    assert result["summaries"]["strain"]["error"] == "insufficient_data"
    assert "message" in result["summaries"]["strain"]
    assert "mean" in result["summaries"]["recovery_score"]
    assert "count" in result["summaries"]["recovery_score"]
    assert isinstance(result["summaries"]["recovery_score"]["mean"], (int, float))


async def test_summarize_period_reports_actual_range_across_all_collections(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """The "period" reported must reflect every collection fetched, not just recovery."""
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        12345,
        recovery_fixture(cycle_id=100, created_at="2026-08-01T06:00:00Z"),
    )
    upsert_sleep(
        app_context.store_conn,
        12345,
        sleep_fixture(sleep_id="sleep-1", created_at="2026-08-05T22:00:00Z"),
    )
    upsert_cycle(
        app_context.store_conn,
        12345,
        cycle_fixture(cycle_id=456, created_at="2026-08-10T22:00:00Z"),
    )

    result = await call_tool(
        server,
        "summarize_period",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-12T00:00:00Z"},
        app_context,
    )

    assert result["period"]["start"] == "2026-08-01T06:00:00Z"
    assert result["period"]["end"] == "2026-08-10T22:00:00Z"


async def test_metric_trend_happy_path(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Metric trend with 8+ records returns slope_per_day and endpoints."""
    assert app_context.store_conn is not None
    for i in range(8):
        upsert_recovery(
            app_context.store_conn,
            12345,
            {
                "cycle_id": 100 + i,
                "created_at": f"2026-08-{i + 1:02d}T06:00:00Z",
                "score_state": "SCORED",
                "score": {
                    "recovery_score": 60.0 + 10.0 * i,
                    "hrv_rmssd_milli": 48.5,
                    "resting_heart_rate": 55,
                },
            },
        )

    result = await call_tool(
        server,
        "metric_trend",
        {
            "metric": "recovery_score",
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-09T00:00:00Z",
        },
        app_context,
    )

    assert result["metric"] == "recovery_score"
    assert result["count"] == 8
    assert result["first"] == 60.0
    assert result["last"] == 130.0
    assert result["slope_per_day"] > 0
    assert result["coverage"]["recoveries"]["earliest"] == "2026-08-01T06:00:00Z"
    assert "range_coverage" in result


async def test_metric_trend_insufficient_data(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Metric trend with only 1 record returns whole-response error."""
    assert app_context.store_conn is not None
    upsert_recovery(app_context.store_conn, 12345, recovery_fixture(cycle_id=100))

    result = await call_tool(
        server,
        "metric_trend",
        {
            "metric": "recovery_score",
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-04T00:00:00Z",
        },
        app_context,
    )

    assert result["error"] == "insufficient_data"
    assert "message" in result
    assert "slope_per_day" not in result
    assert "coverage" in result


async def test_metric_trend_cycle_sourced_metric(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """metric_trend must not crash for a metric sourced from Cycle records."""
    assert app_context.store_conn is not None
    for i in range(8):
        upsert_cycle(
            app_context.store_conn,
            12345,
            cycle_fixture(
                cycle_id=100 + i, strain=float(10 + i), created_at=f"2026-08-{i + 1:02d}T22:00:00Z"
            ),
        )

    result = await call_tool(
        server,
        "metric_trend",
        {"metric": "strain", "start": "2026-08-01T00:00:00Z", "end": "2026-08-09T00:00:00Z"},
        app_context,
    )

    assert result["metric"] == "strain"
    assert result["count"] == 8
    assert result["first"] == 10.0
    assert result["last"] == 17.0
    assert result["period"]["start"] is not None
    assert result["period"]["end"] is not None


async def test_metric_trend_constant_value_returns_error_shape(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """metric_trend on a constant-value series returns the error shape."""
    assert app_context.store_conn is not None
    for i in range(8):
        upsert_recovery(
            app_context.store_conn,
            12345,
            recovery_fixture(
                cycle_id=100 + i, recovery_score=65.0, created_at=f"2026-08-{i + 1:02d}T06:00:00Z"
            ),
        )

    result = await call_tool(
        server,
        "metric_trend",
        {
            "metric": "recovery_score",
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-09T00:00:00Z",
        },
        app_context,
    )

    assert result["error"] == "insufficient_data"
    assert "message" in result
    assert "slope_per_day" not in result
    assert "r_squared" not in result


async def test_metric_trend_includes_r_squared_and_rolling_windows(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """metric_trend response includes r_squared and rolling_Nd fields on success."""
    assert app_context.store_conn is not None
    for i in range(10):
        upsert_recovery(
            app_context.store_conn,
            12345,
            recovery_fixture(
                cycle_id=100 + i,
                recovery_score=50.0 + float(i),
                created_at=f"2026-08-{i + 1:02d}T06:00:00Z",
            ),
        )

    result = await call_tool(
        server,
        "metric_trend",
        {
            "metric": "recovery_score",
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-11T00:00:00Z",
        },
        app_context,
    )

    assert result["metric"] == "recovery_score"
    assert result["count"] == 10
    assert "slope_per_day" in result
    assert "period" in result
    assert isinstance(result["r_squared"], float)
    assert 0.0 <= result["r_squared"] <= 1.0
    assert result["fit_quality"] in {"strong", "moderate", "weak", "negligible"}
    for key in ("rolling_7d", "rolling_30d", "rolling_90d"):
        assert isinstance(result[key], list)
        for point in result[key]:
            assert isinstance(point["date"], str)
            assert isinstance(point["value"], (int, float))


async def test_correlate_metrics_reuses_one_fetch_for_same_collection_metrics(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Correlate with both metrics from the same collection produces a full sweep."""
    assert app_context.store_conn is not None
    for i in range(1, 9):
        upsert_recovery(
            app_context.store_conn,
            12345,
            {
                "cycle_id": i,
                "created_at": f"2026-08-{i:02d}T06:00:00Z",
                "score_state": "SCORED",
                "score": {
                    "recovery_score": float(i * 10),
                    "hrv_rmssd_milli": float(i * 5),
                    "resting_heart_rate": 55,
                },
            },
        )

    result = await call_tool(
        server,
        "correlate_metrics",
        {
            "metric_a": "recovery_score",
            "metric_b": "hrv",
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-09T00:00:00Z",
        },
        app_context,
    )

    assert result["metric_a"] == "recovery_score"
    assert result["metric_b"] == "hrv"
    by_lag = {entry["lag_days"]: entry for entry in result["sweep"]}
    assert by_lag[0]["count"] == 8
    assert "r" in by_lag[0]
    assert set(result["coverage"]) == {"recoveries"}


async def test_correlate_metrics_different_collections(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Correlate with metrics from different collections covers both entities."""
    assert app_context.store_conn is not None
    for i in range(1, 9):
        upsert_recovery(
            app_context.store_conn,
            12345,
            {
                "cycle_id": i,
                "created_at": f"2026-08-{i:02d}T06:00:00Z",
                "score_state": "SCORED",
                "score": {
                    "recovery_score": float(i * 10),
                    "hrv_rmssd_milli": 48.5,
                    "resting_heart_rate": 55,
                },
            },
        )
        upsert_cycle(
            app_context.store_conn,
            12345,
            {
                "id": i,
                "created_at": f"2026-08-{i:02d}T22:00:00Z",
                "start": f"2026-08-{i:02d}T22:00:00Z",
                "end": f"2026-08-{i + 1:02d}T22:00:00Z",
                "score_state": "SCORED",
                "score": {
                    "strain": float(i * 2),
                    "kilojoule": 2850.0,
                    "average_heart_rate": 78,
                    "max_heart_rate": 155,
                },
            },
        )

    result = await call_tool(
        server,
        "correlate_metrics",
        {
            "metric_a": "strain",
            "metric_b": "recovery_score",
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-09T00:00:00Z",
        },
        app_context,
    )

    assert result["metric_a"] == "strain"
    assert result["metric_b"] == "recovery_score"
    by_lag = {entry["lag_days"]: entry for entry in result["sweep"]}
    assert by_lag[0]["count"] == 8
    assert "r" in by_lag[0]
    assert set(result["coverage"]) == {"recoveries", "cycles"}


async def test_correlate_metrics_insufficient_samples(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Correlate with fewer than 8 matched pairs refuses every lag, with no top-level error."""
    assert app_context.store_conn is not None
    for i in range(1, 4):
        upsert_recovery(
            app_context.store_conn,
            12345,
            {
                "cycle_id": i,
                "created_at": f"2026-08-{i:02d}T06:00:00Z",
                "score_state": "SCORED",
                "score": {
                    "recovery_score": float(i * 10),
                    "hrv_rmssd_milli": 48.5,
                    "resting_heart_rate": 55,
                },
            },
        )
        upsert_cycle(
            app_context.store_conn,
            12345,
            {
                "id": i,
                "created_at": f"2026-08-{i:02d}T22:00:00Z",
                "start": f"2026-08-{i:02d}T22:00:00Z",
                "end": f"2026-08-{i + 1:02d}T22:00:00Z",
                "score_state": "SCORED",
                "score": {"strain": float(i * 2), "average_heart_rate": 78, "max_heart_rate": 155},
            },
        )

    result = await call_tool(
        server,
        "correlate_metrics",
        {
            "metric_a": "strain",
            "metric_b": "recovery_score",
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-08T00:00:00Z",
        },
        app_context,
    )

    assert "error" not in result
    assert len(result["sweep"]) == 7  # default radius 3 -> lags -3..+3
    for entry in result["sweep"]:
        assert entry["refused"] is True


async def test_correlate_metrics_explicit_lag_days_returns_full_sweep(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """An explicit lag_days sets the sweep radius: 2*lag_days+1 entries."""
    assert app_context.store_conn is not None
    for i in range(1, 16):
        upsert_recovery(
            app_context.store_conn,
            12345,
            {
                "cycle_id": i,
                "created_at": f"2026-08-{i:02d}T06:00:00Z",
                "score_state": "SCORED",
                "score": {
                    "recovery_score": float(i * 10),
                    "hrv_rmssd_milli": float(i * 5),
                    "resting_heart_rate": 55,
                },
            },
        )

    result = await call_tool(
        server,
        "correlate_metrics",
        {
            "metric_a": "recovery_score",
            "metric_b": "hrv",
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-16T00:00:00Z",
            "lag_days": 2,
        },
        app_context,
    )

    assert len(result["sweep"]) == 5
    assert sorted(entry["lag_days"] for entry in result["sweep"]) == [-2, -1, 0, 1, 2]
    assert any(
        entry["refused"] is False and "r" in entry and "spearman_r" in entry and "count" in entry
        for entry in result["sweep"]
    )


async def test_correlate_metrics_constant_metric_all_lags_refused_no_top_level_error(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A constant metric makes every lag a refusal, never a top-level "error"."""
    assert app_context.store_conn is not None
    for i in range(1, 10):
        upsert_recovery(
            app_context.store_conn,
            12345,
            recovery_fixture(
                cycle_id=i, created_at=f"2026-08-{i:02d}T06:00:00Z", recovery_score=65.0
            ),
        )
        upsert_cycle(
            app_context.store_conn,
            12345,
            cycle_fixture(cycle_id=i, created_at=f"2026-08-{i:02d}T22:00:00Z", strain=float(i * 2)),
        )

    result = await call_tool(
        server,
        "correlate_metrics",
        {
            "metric_a": "recovery_score",
            "metric_b": "strain",
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-10T00:00:00Z",
        },
        app_context,
    )

    assert "error" not in result
    for entry in result["sweep"]:
        assert entry["refused"] is True
        assert "message" in entry


async def test_correlate_metrics_rejects_negative_lag_days(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A negative lag_days is rejected outright, not silently turned into an
    empty sweep (range(-lag_days, lag_days + 1) for lag_days=-2 is empty)."""
    with pytest.raises(ToolError, match="lag_days"):
        await call_tool(
            server,
            "correlate_metrics",
            {
                "metric_a": "recovery_score",
                "metric_b": "strain",
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-10T00:00:00Z",
                "lag_days": -2,
            },
            app_context,
        )


async def test_correlate_metrics_clamps_an_oversized_lag_days(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A caller-supplied lag_days far beyond any reasonable sweep is clamped
    to _MAX_LAG_SWEEP_RADIUS rather than producing an enormous sweep."""
    result = await call_tool(
        server,
        "correlate_metrics",
        {
            "metric_a": "recovery_score",
            "metric_b": "strain",
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-10T00:00:00Z",
            "lag_days": 400,
        },
        app_context,
    )

    assert len(result["sweep"]) == 29
    assert sorted(entry["lag_days"] for entry in result["sweep"]) == list(range(-14, 15))


async def test_compare_periods_happy_path(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Compare periods returns summaries and delta for both windows."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    for i, score in enumerate((60.0, 65.0, 70.0)):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=100 + i, recovery_score=score, created_at=f"2026-08-{i + 1:02d}T06:00:00Z"
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-b-{i}", created_at=f"2026-08-{i + 1:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=456 + i, strain=10.0 + i, created_at=f"2026-08-{i + 1:02d}T22:00:00Z"
            ),
        )
    for i, score in enumerate((75.0, 80.0, 85.0)):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=200 + i, recovery_score=score, created_at=f"2026-08-{i + 11:02d}T06:00:00Z"
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-c-{i}", created_at=f"2026-08-{i + 8:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=556 + i, strain=14.0 + i, created_at=f"2026-08-{i + 11:02d}T22:00:00Z"
            ),
        )

    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2026-08-01T00:00:00Z",
            "baseline_end": "2026-08-08T00:00:00Z",
            "comparison_start": "2026-08-08T00:00:00Z",
            "comparison_end": "2026-08-15T00:00:00Z",
        },
        app_context,
    )

    assert "baseline" in result
    assert "comparison" in result
    assert "delta" in result
    baseline_mean = result["baseline"]["summary"]["recovery_score"]["mean"]
    comparison_mean = result["comparison"]["summary"]["recovery_score"]["mean"]
    assert baseline_mean != comparison_mean
    delta_mean = result["delta"]["recovery_score"]["delta_mean"]
    assert delta_mean == pytest.approx(comparison_mean - baseline_mean, abs=0.1)
    assert set(result["coverage"]) == {"recoveries", "sleeps", "cycles"}
    assert set(result["range_coverage"]) == {"recoveries", "sleeps", "cycles"}


async def test_compare_periods_includes_effect_size(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Compare periods includes effect_size (Cohen's d) for each metric.

    Nine days per period rather than the three this originally used: #183 gave
    the effect size a per-group floor of ``MIN_EFFECT_SAMPLES``, and three would
    now be withheld -- so the test would have been asserting the absence of the
    thing its name is about. The withheld case has its own test below.
    """
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    for i, score in enumerate((55.0, 56.0, 57.0, 58.0, 59.0, 60.0, 61.0, 62.0, 63.0)):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=100 + i, recovery_score=score, created_at=f"2026-08-{i + 1:02d}T06:00:00Z"
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-b-{i}", created_at=f"2026-08-{i + 1:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=456 + i, strain=10.0 + i, created_at=f"2026-08-{i + 1:02d}T22:00:00Z"
            ),
        )
    for i, score in enumerate((75.0, 76.0, 77.0, 78.0, 79.0, 80.0, 81.0, 82.0, 83.0)):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=200 + i, recovery_score=score, created_at=f"2026-08-{i + 11:02d}T06:00:00Z"
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-c-{i}", created_at=f"2026-08-{i + 11:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=556 + i, strain=14.0 + i, created_at=f"2026-08-{i + 11:02d}T22:00:00Z"
            ),
        )

    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2026-08-01T00:00:00Z",
            "baseline_end": "2026-08-09T23:59:59Z",
            "comparison_start": "2026-08-11T00:00:00Z",
            "comparison_end": "2026-08-19T23:59:59Z",
        },
        app_context,
    )

    assert "effect_size" in result["delta"]["recovery_score"]
    assert isinstance(result["delta"]["recovery_score"]["effect_size"], (int, float))
    assert result["delta"]["recovery_score"]["effect_size"] > 0


async def test_compare_periods_coverage_asymmetric_high_vs_low(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Compare periods flags coverage_asymmetric when one period has much less coverage."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    for i in range(30):
        day = (i % 30) + 1
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=100 + i, recovery_score=65.0, created_at=f"2026-08-{day:02d}T06:00:00Z"
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-b-{i}", created_at=f"2026-08-{day:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(cycle_id=456 + i, strain=12.0, created_at=f"2026-08-{day:02d}T22:00:00Z"),
        )
    for i, day in enumerate((1, 2, 3, 4)):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=200 + i, recovery_score=75.0 + i, created_at=f"2026-09-{day:02d}T06:00:00Z"
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-c-{i}", created_at=f"2026-09-{day:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=556 + i, strain=14.0 + i, created_at=f"2026-09-{day:02d}T22:00:00Z"
            ),
        )

    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2026-08-01T00:00:00Z",
            "baseline_end": "2026-08-31T23:59:59Z",
            "comparison_start": "2026-09-01T00:00:00Z",
            "comparison_end": "2026-09-30T23:59:59Z",
        },
        app_context,
    )

    assert result["delta"]["recovery_score"]["coverage_asymmetric"] is True


async def test_compare_periods_coverage_asymmetric_similar_coverage(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Compare periods does NOT flag coverage_asymmetric when coverage is similar."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    for i, score in enumerate((65.0, 70.0, 68.0)):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=100 + i, recovery_score=score, created_at=f"2026-08-{i + 1:02d}T06:00:00Z"
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-b-{i}", created_at=f"2026-08-{i + 1:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=456 + i, strain=12.0 + i, created_at=f"2026-08-{i + 1:02d}T22:00:00Z"
            ),
        )
    for i, score in enumerate((75.0, 76.0, 74.0)):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=200 + i, recovery_score=score, created_at=f"2026-08-{i + 8:02d}T06:00:00Z"
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-c-{i}", created_at=f"2026-08-{i + 8:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=556 + i, strain=14.0 + i, created_at=f"2026-08-{i + 8:02d}T22:00:00Z"
            ),
        )

    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2026-08-01T00:00:00Z",
            "baseline_end": "2026-08-03T23:59:59Z",
            "comparison_start": "2026-08-08T00:00:00Z",
            "comparison_end": "2026-08-10T23:59:59Z",
        },
        app_context,
    )

    assert result["delta"]["recovery_score"]["coverage_asymmetric"] is False


async def test_compare_periods_period_length_note_non_multiple_of_7(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Compare periods sets period_length_note when a period is not a multiple of 7.

    period_length_note is pure date arithmetic on the requested boundaries
    (see _period_length_note) -- it holds regardless of what data, if any,
    the store has for either period, so this test needs no store seeding.
    """
    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2026-08-01T00:00:00Z",
            "baseline_end": "2026-08-06T00:00:00Z",
            "comparison_start": "2026-08-10T00:00:00Z",
            "comparison_end": "2026-08-17T00:00:00Z",
        },
        app_context,
    )

    assert result["period_length_note"] is not None
    assert isinstance(result["period_length_note"], str)


async def test_compare_periods_period_length_note_both_multiples_of_7(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Compare periods sets period_length_note to None when both periods are multiples of 7."""
    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2026-08-01T00:00:00Z",
            "baseline_end": "2026-08-08T00:00:00Z",
            "comparison_start": "2026-08-10T00:00:00Z",
            "comparison_end": "2026-08-24T00:00:00Z",
        },
        app_context,
    )

    assert result["period_length_note"] is None


# -- issue #183: effect size floor tests -----------------------------------


async def test_compare_periods_effect_size_withheld_below_min_floor(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Compare periods withholds effect_size when n < MIN_EFFECT_SAMPLES.

    This test verifies the fix for issue #183: two observations per group
    produce d=16.26, which is numerically correct but unstable. The tool now
    checks MIN_EFFECT_SAMPLES (8) on BOTH groups and withholds effect_size
    when either group is below the threshold, providing effect_size_note
    to explain why. delta_mean and all other comparisons still work.
    """
    assert app_context.store_conn is not None
    conn = app_context.store_conn

    # Baseline: 2 scored recovery/sleep/cycle days with varying scores
    # This provides count=2 per group, which is the issue's exact scenario
    for i in range(2):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=100 + i,
                recovery_score=61.0 + i,
                created_at=f"2026-08-{i + 1:02d}T06:00:00Z",
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-base-{i}", created_at=f"2026-08-{i + 1:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=456 + i, strain=10.0 + i, created_at=f"2026-08-{i + 1:02d}T22:00:00Z"
            ),
        )

    # Comparison: 2 scored recovery/sleep/cycle days with higher scores
    for i in range(2):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=200 + i,
                recovery_score=84.0 + i,
                created_at=f"2026-08-{i + 8:02d}T06:00:00Z",
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-comp-{i}", created_at=f"2026-08-{i + 11:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=556 + i, strain=14.0 + i, created_at=f"2026-08-{i + 8:02d}T22:00:00Z"
            ),
        )

    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2026-08-01T00:00:00Z",
            "baseline_end": "2026-08-02T23:59:59Z",
            "comparison_start": "2026-08-08T00:00:00Z",
            "comparison_end": "2026-08-09T23:59:59Z",
        },
        app_context,
    )

    # Verify effect_size is withheld (None) and effect_size_note explains why
    recovery_delta = result["delta"]["recovery_score"]
    assert recovery_delta["effect_size"] is None, "effect_size should be None when n < 8"
    assert "effect_size_note" in recovery_delta, (
        "effect_size_note key must be present when effect_size is withheld"
    )
    assert isinstance(recovery_delta["effect_size_note"], str), (
        f"effect_size_note must be a string, got {type(recovery_delta['effect_size_note'])}"
    )
    # The note should mention the floor or the minimum sample count
    note_lower = recovery_delta["effect_size_note"].lower()
    assert "8" in note_lower or "min" in note_lower or "insufficient" in note_lower, (
        f"effect_size_note should mention the floor (8), got: {recovery_delta['effect_size_note']}"
    )

    # Verify that delta_mean is STILL PRESENT (compare_periods doesn't refuse wholesale)
    assert "delta_mean" in recovery_delta, (
        "delta_mean must still be present even when effect_size is withheld"
    )
    assert isinstance(recovery_delta["delta_mean"], (int, float)), (
        f"delta_mean should be numeric, got {type(recovery_delta['delta_mean'])}"
    )

    # Verify that the comparison still computed the delta correctly
    # baseline: [61, 62] -> mean ~61.5, comparison: [84, 85] -> mean ~84.5
    # delta_mean should be roughly 23
    assert recovery_delta["delta_mean"] == pytest.approx(23.0, abs=0.5), (
        f"delta_mean should be ~23, got {recovery_delta['delta_mean']}"
    )


async def test_compare_periods_effect_size_with_period_length_note_both_appear(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Compare periods can have BOTH effect_size_note AND period_length_note independently.

    This test verifies that issue #183's fix doesn't replace or interfere with
    the existing period_length_note warning. When both conditions are true
    (insufficient effect size samples AND non-multiple-of-7 periods), both
    notes should appear.
    """
    assert app_context.store_conn is not None
    conn = app_context.store_conn

    # Seed only 2 scored days per period (insufficient for effect size)
    for i in range(2):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=100 + i,
                recovery_score=65.0 + i,
                created_at=f"2026-08-{i + 1:02d}T06:00:00Z",
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-base-{i}", created_at=f"2026-08-{i + 1:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=456 + i, strain=12.0 + i, created_at=f"2026-08-{i + 1:02d}T22:00:00Z"
            ),
        )

    for i in range(2):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=200 + i,
                recovery_score=75.0 + i,
                created_at=f"2026-08-{i + 8:02d}T06:00:00Z",
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-comp-{i}", created_at=f"2026-08-{i + 8:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=556 + i, strain=14.0 + i, created_at=f"2026-08-{i + 8:02d}T22:00:00Z"
            ),
        )

    # Use date ranges that are NOT multiples of 7 (so period_length_note fires)
    # Baseline: Aug 1-6 (6 days, not a multiple of 7)
    # Comparison: Aug 8-13 (6 days, not a multiple of 7)
    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2026-08-01T00:00:00Z",
            "baseline_end": "2026-08-06T23:59:59Z",
            "comparison_start": "2026-08-08T00:00:00Z",
            "comparison_end": "2026-08-13T23:59:59Z",
        },
        app_context,
    )

    # Both notes should be present
    assert result["period_length_note"] is not None, (
        "period_length_note should fire for non-multiple-of-7 periods"
    )
    recovery_delta = result["delta"]["recovery_score"]
    assert "effect_size_note" in recovery_delta, (
        "effect_size_note should be present due to insufficient samples"
    )
    assert recovery_delta["effect_size"] is None, (
        "effect_size should be None due to insufficient samples"
    )


async def test_summarize_period_includes_median_and_days_missing(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Summarize period response includes median and days_missing for each metric."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    for i, score in enumerate((60.0, 70.0, 80.0)):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=100 + i, recovery_score=score, created_at=f"2026-08-{i + 1:02d}T06:00:00Z"
            ),
        )
        upsert_sleep(
            conn,
            12345,
            sleep_fixture(sleep_id=f"sleep-{i}", created_at=f"2026-08-{i + 1:02d}T22:00:00Z"),
        )
        upsert_cycle(
            conn,
            12345,
            cycle_fixture(
                cycle_id=456 + i, strain=12.0 + i, created_at=f"2026-08-{i + 1:02d}T22:00:00Z"
            ),
        )

    result = await call_tool(
        server,
        "summarize_period",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-03T23:59:59Z"},
        app_context,
    )

    assert "median" in result["summaries"]["recovery_score"]
    assert "days_missing" in result["summaries"]["recovery_score"]
    assert result["summaries"]["recovery_score"]["median"] == pytest.approx(70.0)
    assert result["summaries"]["recovery_score"]["days_missing"] == 0


async def test_summarize_period_zero_records_all_metrics_insufficient(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Summarize period with no matching records returns insufficient_data for all metrics."""
    result = await call_tool(
        server,
        "summarize_period",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
        app_context,
    )

    assert isinstance(result, dict)
    assert "summaries" in result
    for metric in (
        "recovery_score",
        "hrv",
        "resting_heart_rate",
        "sleep_performance",
        "sleep_efficiency",
        "strain",
    ):
        assert result["summaries"][metric]["error"] == "insufficient_data"


# -- identity tests (issue #8) ----------------------------------------------

#: The 14 tools _ensure_matches_live_grant must gate -- every data and
#: analysis tool (including #15's whoop_sync, which writes to the local
#: store but still resolves identity through the same gate before touching
#: WHOOP), and none of the 4 auth tools (those are how a principal gets
#: created, or must keep working regardless of one). Issue #29 renamed
#: the gate from a bare `_ensure_principal(app)` to `_ensure_matches_live
#: _grant(ctx)`, which still calls `_ensure_principal` internally (so an
#: unauthenticated caller still fails exactly as before) and additionally
#: refuses a resolved identity that doesn't match this process's one live
#: WHOOP grant.
_PRINCIPAL_GATED_TOOLS = {
    "get_profile",
    "get_body_measurement",
    "list_recoveries",
    "list_sleeps",
    "list_cycles",
    "list_workouts",
    "get_sleep",
    "get_workout",
    "whoop_sync",
    "whoop_data_coverage",
    "summarize_period",
    "metric_trend",
    "correlate_metrics",
    "compare_periods",
    "whoop_timeseries",
    "whoop_outliers",
    "whoop_streaks",
}


@respx.mock
async def test_lifespan_resolves_principal_from_profile_response(
    config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AppContext exposes a principal after a successful lifespan() run.

    Exercises the real lifespan() context manager -- not the app_context
    fixture, which bypasses it entirely -- so this actually confirms
    resolution comes from the mocked /v2/user/profile/basic response, not
    from an environment variable naming a user.
    """
    # lifespan() calls Config.from_env() with no arguments, so it reads
    # os.environ directly, unlike the `config` fixture (which builds a
    # Config from an explicit dict). Point the real environment at the same
    # values so lifespan()'s own Config lands on the same state_dir, where
    # the autouse _seed_valid_token fixture already saved a usable token.
    # Clear any ambient WHOOPMCP_* env vars first so they don't interfere.
    for name in (
        "WHOOPMCP_TOKEN_BACKEND",
        "WHOOPMCP_SCOPES",
        "WHOOPMCP_STATE_DIR",
        "WHOOPMCP_CACHE",
        "WHOOPMCP_TIMEOUT",
        "WHOOPMCP_RATE_LIMIT_PER_MINUTE",
        "WHOOPMCP_RATE_LIMIT_PER_DAY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("WHOOP_CLIENT_ID", config.client_id)
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", config.client_secret)
    monkeypatch.setenv("WHOOP_REDIRECT_URI", config.redirect_uri)
    monkeypatch.setenv("WHOOPMCP_STATE_DIR", str(config.state_dir))

    fixture = profile_fixture()
    respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    async with lifespan(build_server()) as app:
        principal = app.principal

    assert principal == Principal(user_id=fixture["user_id"])


@pytest.mark.parametrize("tool_name", ["get_profile", "list_recoveries", "summarize_period"])
async def test_gated_tool_without_principal_raises_typed_not_authenticated_error(
    server: MCPServer[AppContext], app_context: AppContext, tool_name: str
) -> None:
    """A data/analysis tool with no resolved principal fails clean and fast.

    No respx mock is set up here on purpose: _ensure_principal must raise
    before any network activity, so if it didn't, this would attempt (and
    fail on) a real HTTP call rather than silently passing.
    """
    app_context.principal = None
    arguments = (
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"}
        if tool_name == "summarize_period"
        else {}
    )

    with pytest.raises(ToolError, match="whoop_login"):
        await call_tool(server, tool_name, arguments, app_context)


async def test_whoop_logout_clears_principal(
    server: MCPServer[AppContext], app_context: AppContext
) -> None:
    """whoop_logout clears principal back to None on the AppContext it was given."""
    assert app_context.principal is not None  # the fixture seeds one

    await call_tool(server, "whoop_logout", {}, app_context)

    assert app_context.principal is None


@respx.mock
async def test_whoop_complete_login_sets_resolved_principal(
    server: MCPServer[AppContext], config: Config, app_context: AppContext
) -> None:
    """whoop_complete_login resolves and sets a principal after a successful exchange."""
    app_context.principal = None  # start from "no identity", like a fresh login

    login_result = await call_tool(server, "whoop_login", {}, app_context)
    login_text = str(login_result["result"])
    url_match = re.search(r"https://api\.prod\.whoop\.com\S+", login_text)
    assert url_match, f"Expected an authorize URL in the response, got: {login_text}"
    state = parse_qs(urlparse(url_match.group(0)).query)["state"][0]

    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "fake-access-token",
                "expires_in": 3600,
                "refresh_token": "fake-refresh-token",
                "scope": "read:sleep offline",
            },
        )
    )
    fixture = profile_fixture()
    respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(200, json=fixture)
    )

    async with WhoopClient(config, app_context.auth) as client:
        app_context.client = client
        await call_tool(
            server,
            "whoop_complete_login",
            {"code": "fake-auth-code", "state": state},
            app_context,
        )

    assert app_context.principal == Principal(user_id=fixture["user_id"])


@pytest.mark.parametrize("tool_name", ["whoop_auth_status", "whoop_login", "whoop_logout"])
async def test_auth_tools_work_without_a_principal(
    server: MCPServer[AppContext], app_context: AppContext, tool_name: str
) -> None:
    """The 3 non-mutating auth tools never require a principal.

    whoop_complete_login is the 4th auth tool and is implicitly covered by
    test_whoop_complete_login_sets_resolved_principal above, which also runs
    it with app_context.principal starting out None.
    """
    app_context.principal = None

    # None of these three should raise -- they either report or clear
    # identity-related state themselves, rather than requiring one.
    await call_tool(server, tool_name, {}, app_context)


def test_every_principal_gated_tool_source_calls_ensure_principal(
    server: MCPServer[AppContext],
) -> None:
    """Structural, greppable check that every gated tool's own body calls the gate.

    Registry lookup (server._tool_manager.get_tool(name).fn), not
    inspect.getsource on _register_data_tools/_register_analysis_tools
    directly: those two functions each define several tool closures back to
    back, so scanning their combined source for "_ensure_matches_live_grant("
    would pass even if only one of the 8 (or 4) tools nested inside actually
    called it. Pulling each registered Tool's own `.fn` off the tool manager
    and reading ITS source in isolation checks every one of the 12 tools
    individually, which is what actually catches a tool added later that
    skips the gate.

    Checks for `_ensure_matches_live_grant(`, not the bare `_ensure_principal(`
    this test's name still references: issue #29 moved every gated tool onto
    that wrapper, which still calls `_ensure_principal` internally (so this
    remains, transitively, a check that every tool calls it) and additionally
    ties the gate to a resolved, per-request identity rather than only "is
    anyone logged in".
    """
    for name in _PRINCIPAL_GATED_TOOLS:
        tool = server._tool_manager.get_tool(name)
        assert tool is not None, f"{name} is not registered"
        source = inspect.getsource(tool.fn)
        assert "_ensure_matches_live_grant(" in source, (
            f"{name} never calls _ensure_matches_live_grant -- an unauthenticated "
            "or cross-tenant caller would reach the network instead of getting a "
            "typed error"
        )
        # The absence check this acceptance criterion actually cares about:
        # a tool resolving its own config/identity from ambient state
        # (env/global) instead of through the AppContext it was given.
        assert "Config.from_env(" not in source, (
            f"{name} appears to resolve configuration directly rather than "
            "through the AppContext it was given"
        )


async def test_auth_tools_are_not_principal_gated(server: MCPServer[AppContext]) -> None:
    """None of the 4 auth tools call _ensure_principal -- they predate having one.

    Registry lookup, for the same reason as the test above.
    """
    for name in ("whoop_auth_status", "whoop_login", "whoop_complete_login", "whoop_logout"):
        tool = server._tool_manager.get_tool(name)
        assert tool is not None, f"{name} is not registered"
        source = inspect.getsource(tool.fn)
        assert "_ensure_principal(" not in source, (
            f"{name} is an auth tool and must keep working with no resolved "
            "principal, but its body calls _ensure_principal"
        )


# -- issue #179: cursor validation -------------------------------------------


@pytest.mark.parametrize(
    "tool_name,fixture_fn,upsert_fn",
    [
        ("list_recoveries", recovery_fixture, upsert_recovery),
        ("list_sleeps", sleep_fixture, upsert_sleep),
        ("list_workouts", workout_fixture, upsert_workout),
        ("list_cycles", cycle_fixture, upsert_cycle),
    ],
)
async def test_list_tools_reject_out_of_range_offset_too_large(
    app_context: AppContext,
    server: MCPServer[AppContext],
    tool_name: str,
    fixture_fn: Callable[..., dict[str, Any]],
    upsert_fn: Callable[..., Any],
) -> None:
    """A forged token with offset=2**63 (out of range) raises ValueError, not OverflowError.

    This tests the explicit ceiling at _MAX_CURSOR_OFFSET = 2**63 - 1, ensuring
    that an out-of-range offset is caught before reaching the store and raises
    a clear "not a valid pagination cursor" error.
    """
    assert app_context.store_conn is not None
    upsert_fn(app_context.store_conn, 12345, fixture_fn())

    # Forge a cursor with an offset that's too large (2**63)
    forged_cursor = base64.urlsafe_b64encode(
        json.dumps({"offset": 2**63, "start": None, "end": None}).encode("utf-8")
    ).decode("ascii")

    with pytest.raises(ToolError, match="not a valid pagination cursor"):
        await call_tool(
            server,
            tool_name,
            {
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-08T00:00:00Z",
                "next_token": forged_cursor,
            },
            app_context,
        )


@pytest.mark.parametrize(
    "tool_name,fixture_fn,upsert_fn",
    [
        ("list_recoveries", recovery_fixture, upsert_recovery),
        ("list_sleeps", sleep_fixture, upsert_sleep),
        ("list_workouts", workout_fixture, upsert_workout),
        ("list_cycles", cycle_fixture, upsert_cycle),
    ],
)
async def test_list_tools_reject_negative_offset(
    app_context: AppContext,
    server: MCPServer[AppContext],
    tool_name: str,
    fixture_fn: Callable[..., dict[str, Any]],
    upsert_fn: Callable[..., Any],
) -> None:
    """A forged token with a negative offset raises ValueError, not silent reordering.

    SQLite treats negative OFFSET as 0, which would silently re-serve earlier rows.
    The validation must reject negative offsets with a clear error.
    """
    assert app_context.store_conn is not None
    upsert_fn(app_context.store_conn, 12345, fixture_fn())

    # Forge a cursor with a negative offset
    forged_cursor = base64.urlsafe_b64encode(
        json.dumps({"offset": -5, "start": None, "end": None}).encode("utf-8")
    ).decode("ascii")

    with pytest.raises(ToolError, match="not a valid pagination cursor"):
        await call_tool(
            server,
            tool_name,
            {
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-08T00:00:00Z",
                "next_token": forged_cursor,
            },
            app_context,
        )


@pytest.mark.parametrize(
    "tool_name,fixture_fn,upsert_fn,bad_cursor",
    [
        # bad base64 padding
        ("list_recoveries", recovery_fixture, upsert_recovery, "not-base64!!!"),
        # valid base64 but not JSON
        (
            "list_sleeps",
            sleep_fixture,
            upsert_sleep,
            base64.urlsafe_b64encode(b"not json").decode("ascii"),
        ),
        # valid JSON but missing "offset" key
        (
            "list_workouts",
            workout_fixture,
            upsert_workout,
            base64.urlsafe_b64encode(b'{"start": null, "end": null}').decode("ascii"),
        ),
        # valid JSON with non-integer offset
        (
            "list_cycles",
            cycle_fixture,
            upsert_cycle,
            base64.urlsafe_b64encode(b'{"offset": "abc", "start": null, "end": null}').decode(
                "ascii"
            ),
        ),
        # valid JSON but payload is a list (not dict)
        (
            "list_recoveries",
            recovery_fixture,
            upsert_recovery,
            base64.urlsafe_b64encode(b"[1, 2, 3]").decode("ascii"),
        ),
        # empty string (neither base64 nor JSON)
        ("list_sleeps", sleep_fixture, upsert_sleep, ""),
    ],
)
async def test_list_tools_reject_malformed_cursors(
    app_context: AppContext,
    server: MCPServer[AppContext],
    tool_name: str,
    fixture_fn: Callable[..., dict[str, Any]],
    upsert_fn: Callable[..., Any],
    bad_cursor: str,
) -> None:
    """Each malformed-cursor shape (bad base64, bad JSON, missing keys, etc.)
    raises the same clear ValueError, not driver-specific exceptions.

    This covers all the malformed cases from issue #179's description:
    - bad base64 → binascii.Error
    - valid base64, not JSON → JSONDecodeError
    - missing "offset" key → KeyError
    - non-integer offset → ValueError from int()
    - JSON list (not dict) → TypeError
    - empty string → JSONDecodeError
    """
    assert app_context.store_conn is not None
    upsert_fn(app_context.store_conn, 12345, fixture_fn())

    with pytest.raises(ToolError, match="not a valid pagination cursor"):
        await call_tool(
            server,
            tool_name,
            {
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-08T00:00:00Z",
                "next_token": bad_cursor,
            },
            app_context,
        )


@pytest.mark.parametrize(
    "tool_name,make_record,upsert_fn,id_field",
    [
        (
            "list_recoveries",
            lambda i: recovery_fixture(
                cycle_id=1000 + i, created_at=f"2026-08-{i + 1:02d}T06:30:00Z"
            ),
            upsert_recovery,
            "cycle_id",
        ),
        (
            "list_sleeps",
            # `start`, not `created_at`: get_sleeps is ORDER BY start with no
            # tiebreaker, so records sharing a start leave the order of two
            # separate LIMIT/OFFSET queries unspecified and the walk below
            # flaky. sleep_fixture hardcodes start, hence the override.
            lambda i: {
                **sleep_fixture(sleep_id=f"sleep-{i}"),
                "start": f"2026-08-01T{i:02d}:00:00Z",
                "end": f"2026-08-01T{i:02d}:45:00Z",
            },
            upsert_sleep,
            "id",
        ),
        (
            "list_workouts",
            lambda i: {
                **workout_fixture(workout_id=f"workout-{i}"),
                "start": f"2026-08-{i + 1:02d}T06:00:00Z",
                "end": f"2026-08-{i + 1:02d}T07:30:00Z",
            },
            upsert_workout,
            "id",
        ),
        (
            "list_cycles",
            # Same reason as sleeps above: get_cycles is ORDER BY start too.
            lambda i: {
                **cycle_fixture(cycle_id=2000 + i),
                "start": f"2026-08-01T{i:02d}:00:00Z",
                "end": f"2026-08-01T{i:02d}:45:00Z",
            },
            upsert_cycle,
            "id",
        ),
    ],
)
async def test_list_tools_accept_legitimate_large_offset_and_continue(
    app_context: AppContext,
    server: MCPServer[AppContext],
    tool_name: str,
    make_record: Callable[[int], dict[str, Any]],
    upsert_fn: Callable[..., Any],
    id_field: str,
) -> None:
    """A legitimate round-trip cursor with a large but valid offset continues unchanged.

    Seeds 10 records and walks the first five a page at a time, so the walk runs
    at offsets 0 through 4, then forges a cursor at the legal ceiling
    (2**63 - 1) and checks it is accepted -- it returns no records, since the
    offset is far past the end, and that is the point: accepted, not refused.

    Non-vacuous in two directions: it fails if the implementation over-rejects
    (rejecting the ceiling itself, or offset 0), and the id assertions at the end
    fail if the cursor stops advancing, since five pages each holding one record
    is equally true of a cursor stuck at offset 0.
    """
    assert app_context.store_conn is not None
    total = 10
    for i in range(total):
        upsert_fn(app_context.store_conn, 12345, make_record(i))

    window = {"start": "2026-08-01T00:00:00Z", "end": "2026-08-09T00:00:00Z"}

    # First, walk through the first 5 records one at a time
    seen: list[Any] = []
    page = await call_tool(server, tool_name, {**window, "limit": 1}, app_context)
    for page_num in range(5):
        assert page["count"] == 1
        assert len(page["records"]) == 1
        seen.extend(record[id_field] for record in page["records"])
        if page_num < 4:  # not on the last iteration
            assert page["next_token"] is not None
            page = await call_tool(
                server, tool_name, {"next_token": page["next_token"], "limit": 1}, app_context
            )

    # Now forge a cursor with the maximum legal offset (2**63 - 1)
    # and verify it is accepted without raising
    max_offset_cursor = base64.urlsafe_b64encode(
        json.dumps(
            {"offset": 2**63 - 1, "start": "2026-08-01T00:00:00Z", "end": "2026-08-09T00:00:00Z"}
        ).encode("utf-8")
    ).decode("ascii")

    # This call should NOT raise. It may return 0 records (the offset is beyond the end),
    # but the point is that a valid large offset is accepted.
    result = await call_tool(
        server,
        tool_name,
        {"next_token": max_offset_cursor, "limit": 1},
        app_context,
    )

    # Verify the result has the expected structure (proving the call succeeded)
    assert "records" in result
    assert "count" in result
    assert "coverage" in result
    # At such a large offset, we expect 0 records (the offset is past the end)
    assert result["count"] == 0

    # The walk above is only worth anything if it asserts the cursor MOVED.
    # Five pages each holding one record is equally true of a cursor stuck at
    # offset 0 re-serving the same row, so compare the ids actually served.
    assert len(seen) == 5, f"the walk must serve five records, got {seen}"
    assert len(set(seen)) == 5, f"a stuck cursor would repeat a record: {seen}"
    assert seen == [record[id_field] for record in (make_record(i) for i in range(5))], (
        f"the walk must serve the first five seeded records in order, got {seen}"
    )
    assert len(result["records"]) == 0


async def test_zero_offset_cursor_is_accepted(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """``offset = 0`` sits inside the valid range, not on the rejected side of it.

    No server-issued cursor ever carries it -- every ``next_token`` encodes
    ``offset + limit`` and ``limit`` is at least 1 -- so this is only reachable
    by forging one, and a forged zero is harmless: it addresses the first page,
    exactly what no cursor at all would. It is pinned because the range check
    has two ends and the ceiling end is pinned; a later tightening to
    ``0 < offset`` would otherwise pass the whole suite.
    """
    assert app_context.store_conn is not None
    for i in range(3):
        record = sleep_fixture(sleep_id=f"sleep-{i}")
        record["start"] = f"2026-08-01T{i:02d}:00:00Z"
        record["end"] = f"2026-08-01T{i:02d}:45:00Z"
        upsert_sleep(app_context.store_conn, 12345, record)

    zero_cursor = base64.urlsafe_b64encode(
        json.dumps(
            {"offset": 0, "start": "2026-08-01T00:00:00Z", "end": "2026-08-02T00:00:00Z"}
        ).encode("utf-8")
    ).decode("ascii")

    result = await call_tool(server, "list_sleeps", {"next_token": zero_cursor}, app_context)

    assert [record["id"] for record in result["records"]] == ["sleep-0", "sleep-1", "sleep-2"], (
        "a zero-offset cursor must address the first page, not be rejected"
    )


#: Cursor payloads that must all be refused identically. Each entry is a shape
#: the decode could plausibly meet in the wild or from a forged token; several
#: were reaching the caller as a driver-level error before #179.
_BAD_CURSOR_PAYLOADS: list[tuple[str, str]] = [
    ("offset_infinity", '{"offset": Infinity, "start": null, "end": null}'),
    ("offset_overflowing_float", '{"offset": 1e400, "start": null, "end": null}'),
    ("offset_negative_infinity", '{"offset": -Infinity, "start": null, "end": null}'),
    ("offset_float", '{"offset": 2.9, "start": null, "end": null}'),
    ("offset_numeric_string", '{"offset": "12", "start": null, "end": null}'),
    ("offset_bool", '{"offset": true, "start": null, "end": null}'),
    ("start_is_object", '{"offset": 0, "start": {"a": 1}, "end": null}'),
    ("start_is_list", '{"offset": 0, "start": [1], "end": null}'),
    ("end_is_number", '{"offset": 0, "start": null, "end": 5}'),
    ("missing_start", '{"offset": 1}'),
    ("missing_end", '{"offset": 1, "start": null}'),
]


@pytest.mark.parametrize(
    "shape,payload", _BAD_CURSOR_PAYLOADS, ids=[s for s, _ in _BAD_CURSOR_PAYLOADS]
)
async def test_cursor_shapes_that_used_to_reach_the_driver(
    app_context: AppContext, server: MCPServer[AppContext], shape: str, payload: str
) -> None:
    """Each of these decoded cleanly and failed somewhere lower down.

    ``Infinity`` and an overflowing float literal are accepted by ``json.loads``
    and become ``float("inf")``; ``int()`` on that raises ``OverflowError``,
    which is an ``ArithmeticError`` rather than a ``ValueError`` and so escaped
    the decode handler entirely -- surfacing the very ``OverflowError`` #179 was
    filed to remove. A non-string ``start``/``end`` reached the query and raised
    ``sqlite3.ProgrammingError: Error binding parameter``. A missing ``start``
    or ``end`` key raised a bare ``KeyError``.
    """
    token = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")

    with pytest.raises(ToolError) as excinfo:
        await call_tool(server, "list_sleeps", {"next_token": token}, app_context)

    # Exact tail match, not a substring search: the guarantee is one *identical*
    # message, so a variant that appended "(offset 5 out of range)" would still
    # satisfy a `match=` search while breaking the property.
    assert str(excinfo.value).endswith("next_token is not a valid pagination cursor"), (
        f"{shape} must give the one unified message, got: {excinfo.value}"
    )


async def test_rejected_cursor_never_echoes_the_token_or_the_cause(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """The rejection must not reflect caller-controlled input back at the caller.

    A ``next_token`` is attacker-influenceable (tool arguments are
    model-generated), so echoing it, or the decode exception's own text, puts
    bytes the caller chose into an error string that may be logged or shown.
    The underlying exception stays reachable through ``__cause__`` for a
    developer reading a traceback; it must not appear in the message.

    Untested until now, which mattered: appending the token or ``exc`` to the
    message passed the entire suite, because every other cursor test asserts
    with a substring search that a longer message still satisfies.
    """
    marker = "SENTINEL-do-not-echo-abc123"
    payload = json.dumps({"offset": -1, "start": marker, "end": None})
    token = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")

    with pytest.raises(ToolError) as excinfo:
        await call_tool(server, "list_sleeps", {"next_token": token}, app_context)

    rendered = str(excinfo.value)
    assert marker not in rendered, "the cursor's own contents leaked into the error"
    assert token not in rendered, "the raw token leaked into the error"
    assert rendered.endswith("next_token is not a valid pagination cursor")

    # Nothing from the chained cause -- the phrasing sqlite/binascii/json would
    # have contributed -- may appear either.
    for fragment in (
        "Incorrect padding",
        "Expecting value",
        "invalid literal",
        "binding parameter",
    ):
        assert fragment not in rendered


# -- issue #181 tests (expected_days truncation bug) -------------------------


async def test_summarize_period_interior_gap_reported_as_missing_day(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """An interior gap in coverage is reported as missing days.

    This is the main test for issue #181: expected_days was computed using
    .days (truncating partial days), causing gaps to be silently swallowed
    when the clamp max(0, expected_days - len(unique_dates)) hid the
    undercount.

    Seed records on Aug 1 and Aug 3 only, leaving Aug 2 empty. Window is
    2026-08-01T00:00:00Z to 2026-08-03T23:59:59Z (3 calendar days).
    Current buggy code: expected_days = 2 (truncated), unique_dates = 2
                       -> days_missing = max(0, 2 - 2) = 0 (WRONG)
    Correct code:      expected_days = 3, unique_dates = 2
                       -> days_missing = max(0, 3 - 2) = 1 (CORRECT)
    """
    assert app_context.store_conn is not None
    conn = app_context.store_conn

    # Seed recovery on Aug 1 and Aug 3 only (Aug 2 is empty)
    upsert_recovery(
        conn,
        12345,
        recovery_fixture(cycle_id=100, recovery_score=65.0, created_at="2026-08-01T06:00:00Z"),
    )
    upsert_recovery(
        conn,
        12345,
        recovery_fixture(cycle_id=102, recovery_score=75.0, created_at="2026-08-03T06:00:00Z"),
    )

    result = await call_tool(
        server,
        "summarize_period",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-03T23:59:59Z"},
        app_context,
    )

    # The gap on Aug 2 should be reported as 1 missing day
    assert result["summaries"]["recovery_score"]["days_missing"] == 1, (
        f"Expected days_missing=1 (Aug 2 is missing), got "
        f"{result['summaries']['recovery_score']['days_missing']}"
    )


async def test_summarize_period_fully_covered_no_regression(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A fully-covered window still reports zero missing days.

    This test ensures no regression: when all days in a window have data,
    days_missing must remain 0.
    """
    assert app_context.store_conn is not None
    conn = app_context.store_conn

    # Seed recovery on all three days: Aug 1, 2, 3
    for i, (day, score) in enumerate([(1, 65.0), (2, 70.0), (3, 75.0)]):
        upsert_recovery(
            conn,
            12345,
            recovery_fixture(
                cycle_id=100 + i, recovery_score=score, created_at=f"2026-08-{day:02d}T06:00:00Z"
            ),
        )

    result = await call_tool(
        server,
        "summarize_period",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-03T23:59:59Z"},
        app_context,
    )

    # All three days have data, so no days missing
    assert result["summaries"]["recovery_score"]["days_missing"] == 0, (
        f"Expected days_missing=0 (all days covered), got "
        f"{result['summaries']['recovery_score']['days_missing']}"
    )


async def test_summarize_period_non_utc_offset_uses_utc_dates(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Window boundaries with non-UTC offsets count as UTC calendar dates.

    The window start/end are parsed as ISO 8601 and converted to UTC for
    calendar date calculations, consistent with how unique_dates are computed
    in analysis.summarize() (via .astimezone(UTC).date()).

    Example: window "2026-08-01T00:00:00+13:00" (Aug 1 midnight in +13)
    is Aug 0 23:00:00 UTC (previous day in UTC). The contract is that
    expected_days counts the UTC calendar dates the window spans.

    Here we use "-11:00" offset (American Samoa UTC-11): a recovery record
    created at "2026-08-02T12:00:00-11:00" is actually
    "2026-08-02T23:00:00Z" in UTC (same UTC calendar date).
    If we request a window in -11 offset that spans Aug 1-3 in that zone,
    it will span a different range in UTC calendar dates. We verify the
    reported days_missing matches the UTC calculation, not the local one.
    """
    assert app_context.store_conn is not None
    conn = app_context.store_conn

    # Create records on Aug 2 and Aug 4 in -11:00 time
    # "2026-08-02T12:00:00-11:00" is "2026-08-02T23:00:00Z" in UTC
    # "2026-08-04T12:00:00-11:00" is "2026-08-04T23:00:00Z" in UTC
    upsert_recovery(
        conn,
        12345,
        recovery_fixture(cycle_id=200, recovery_score=60.0, created_at="2026-08-02T12:00:00-11:00"),
    )
    upsert_recovery(
        conn,
        12345,
        recovery_fixture(cycle_id=202, recovery_score=70.0, created_at="2026-08-04T12:00:00-11:00"),
    )

    # Window expressed in -11:00 offset, spanning Aug 1-4 in that zone
    # "2026-08-01T00:00:00-11:00" is "2026-08-01T11:00:00Z" in UTC
    # "2026-08-04T23:59:59-11:00" is "2026-08-05T10:59:59Z" in UTC
    # So the UTC calendar dates are Aug 1, 2, 3, 4, 5 (5 distinct dates)
    # But we only have records on UTC Aug 2 and 4 (2 distinct dates)
    # Expected missing: 5 - 2 = 3
    result = await call_tool(
        server,
        "summarize_period",
        {
            "start": "2026-08-01T00:00:00-11:00",
            "end": "2026-08-04T23:59:59-11:00",
        },
        app_context,
    )

    # The window spans 5 UTC calendar dates (Aug 1-5), we have data for 2,
    # so 3 days are missing.
    assert result["summaries"]["recovery_score"]["days_missing"] == 3, (
        f"Expected days_missing=3 (window spans 5 UTC dates, only 2 have data), "
        f"got {result['summaries']['recovery_score']['days_missing']}"
    )


async def test_compare_periods_coverage_ratio_reflects_days_missing(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """compare_periods coverage ratios derive from expected_days correctly.

    The coverage_asymmetric flag and coverage ratios are computed as
    1 - days_missing/expected_days. This test ensures the coverage value
    is correct when days_missing is properly computed.

    We set up two periods with known data:
    - Baseline (Aug 1-3): has data on Aug 1 and 3 only (Aug 2 missing)
      -> expected_days = 3, days_missing = 1, coverage = 1 - 1/3 ≈ 0.667
    - Comparison (Aug 8-10): has data on all 3 days
      -> expected_days = 3, days_missing = 0, coverage = 1 - 0/3 = 1.0
    - abs(0.667 - 1.0) = 0.333, which is NOT > 0.5, so coverage_asymmetric = False
    """
    assert app_context.store_conn is not None
    conn = app_context.store_conn

    # Baseline period: Aug 1-3 with gap on Aug 2
    upsert_recovery(
        conn,
        12345,
        recovery_fixture(cycle_id=100, recovery_score=65.0, created_at="2026-08-01T06:00:00Z"),
    )
    upsert_recovery(
        conn,
        12345,
        recovery_fixture(cycle_id=102, recovery_score=75.0, created_at="2026-08-03T06:00:00Z"),
    )

    # Comparison period: Aug 8-10 fully covered
    upsert_recovery(
        conn,
        12345,
        recovery_fixture(cycle_id=200, recovery_score=70.0, created_at="2026-08-08T06:00:00Z"),
    )
    upsert_recovery(
        conn,
        12345,
        recovery_fixture(cycle_id=201, recovery_score=72.0, created_at="2026-08-09T06:00:00Z"),
    )
    upsert_recovery(
        conn,
        12345,
        recovery_fixture(cycle_id=202, recovery_score=68.0, created_at="2026-08-10T06:00:00Z"),
    )

    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2026-08-01T00:00:00Z",
            "baseline_end": "2026-08-03T23:59:59Z",
            "comparison_start": "2026-08-08T00:00:00Z",
            "comparison_end": "2026-08-10T23:59:59Z",
        },
        app_context,
    )

    # Baseline: expected_days=3, days_missing=1 (Aug 2), coverage ≈ 0.667
    baseline_days_missing = result["baseline"]["summary"]["recovery_score"]["days_missing"]
    assert baseline_days_missing == 1, (
        f"Baseline expected days_missing=1 (Aug 2 gap), got {baseline_days_missing}"
    )

    # Comparison: expected_days=3, days_missing=0 (all covered), coverage = 1.0
    comparison_days_missing = result["comparison"]["summary"]["recovery_score"]["days_missing"]
    assert comparison_days_missing == 0, (
        f"Comparison expected days_missing=0 (all covered), got {comparison_days_missing}"
    )

    # coverage_asymmetric: |0.667 - 1.0| = 0.333, which is NOT > 0.5
    coverage_asymmetric = result["delta"]["recovery_score"]["coverage_asymmetric"]
    assert coverage_asymmetric is False, (
        f"Expected coverage_asymmetric=False (0.333 difference < 0.5), got {coverage_asymmetric}"
    )


async def test_window_length_is_two_measures_not_one(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A midnight-to-midnight week is 7 days long and touches 8 calendar dates.

    Both numbers are right; they answer different questions, which is why #181
    split them. ``days_missing`` compares against the distinct UTC dates a
    record can carry, so it needs dates-touched (8). ``period_length_note``
    warns about weekday/weekend imbalance, which is about duration, so it needs
    elapsed days (7) -- feeding it 8 makes every whole-week window look partial
    and fires the warning on precisely the periods that are balanced.

    Pinned together in one test because the failure mode is using one value for
    both: whichever measure you keep, the other consumer silently goes wrong.
    """
    assert app_context.store_conn is not None
    # Seven of the eight dates covered; Aug 8 (the boundary instant) is not.
    for day in range(1, 8):
        upsert_recovery(
            app_context.store_conn,
            12345,
            recovery_fixture(cycle_id=900 + day, created_at=f"2026-08-{day:02d}T06:30:00Z"),
        )

    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2026-08-01T00:00:00Z",
            "baseline_end": "2026-08-08T00:00:00Z",
            "comparison_start": "2026-08-10T00:00:00Z",
            "comparison_end": "2026-08-24T00:00:00Z",
        },
        app_context,
    )

    # Duration: 7 and 14 days, both whole weeks, so no imbalance warning.
    assert result["period_length_note"] is None, (
        "a midnight-to-midnight week is a whole week; the note must not fire"
    )

    # Dates touched: Aug 1..Aug 8 is 8, of which 7 carry a record.
    baseline = result["baseline"]["summary"]["recovery_score"]
    assert baseline["days_missing"] == 1, (
        "8 dates span the window and 7 carry a record, so exactly one is missing"
    )
