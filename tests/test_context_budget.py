"""Every tool's worst-case response stays under its context-budget ceiling.

Two distinct "worst case" regimes matter here, and conflating them would
under-test the analysis tools while over-building the data-tool fixtures:

- The 8 data tools only ever see one page at a time -- WHOOP caps a page at
  25 records (``client.MAX_PAGE_SIZE``) no matter how wide a range is asked
  for, so "two years of history" does not mean more records in one call, it
  means the densest possible single page. Their worst-case fixture is one
  respx-mocked page of 25 SCORED records with every optional/nested field
  populated.
- The 4 analysis tools walk every page over the requested range via
  ``WhoopClient.paginate()``, so their worst case is a genuinely large
  collection -- over the 1000-record ``max_records`` cap, spanning years --
  not one page. Their fixture is 1,100+ records per collection.
"""

from __future__ import annotations

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

from whoopmcp.auth import TOKEN_URL, Authenticator, FileTokenStore, Token
from whoopmcp.client import BASE_URL, WhoopClient
from whoopmcp.config import Config
from whoopmcp.context_budget import TOOL_CEILINGS, estimate_tokens
from whoopmcp.server import AppContext, Principal, build_server
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

# -- fixture helpers, mirroring tests/test_server.py's own (kept separate so
# this file's worst-case fixtures can evolve independently of the happy-path
# ones) ----------------------------------------------------------------------


def fast_forwarding_clock() -> Callable[[], float]:
    """A clock that jumps far ahead on every call.

    Since issue #11, WhoopClient._get sits behind a RateLimiter that (against
    the default, real clock) genuinely waits out a per-minute/per-day window
    rollover once its budget is exhausted -- and the analysis-tool fixtures
    below page through 1,100+ records per collection, which is well past the
    default 100/minute budget in a single test. This clock makes any such
    wait resolve after one poll tick instead, exactly mirroring
    tests/test_server.py's own helper of the same name.
    """
    state = {"now": 0.0}

    def _clock() -> float:
        state["now"] += 3600.0
        return state["now"]

    return _clock


async def call_tool(
    server: MCPServer[AppContext], name: str, arguments: dict[str, Any], app_context: AppContext
) -> Any:
    """Call a tool with proper context wiring, and unwrap its return value.

    Same unwrap logic as tests/test_server.py's helper of the same name --
    see that module's docstring for why it is needed.
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
    client = WhoopClient(config, auth, clock=fast_forwarding_clock())
    # principal= matches test_server.py's own fixture and profile_fixture()'s
    # user_id (#8, merged after this file was first written) -- every tool
    # now gates on _ensure_principal, which raises without this.
    #
    # store_conn= plus the principal_members row (#29, merged after this file
    # was first written): every tool now resolves identity via
    # resolve_member_id, which requires a store and errors without a mapping
    # for the calling principal -- ("__local__", None, None) is
    # _principal_key's own sentinel for a request-less (stdio-shaped) Context,
    # exactly what call_tool's ServerRequestContext(session=None, ...) builds.
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


# -- regime 1: one densest-possible page, for the 8 data tools -------------

_DENSE_PAGE_SIZE = 25


def _dense_recovery(index: int) -> dict[str, Any]:
    """A SCORED recovery record with every optional field populated."""
    created_at = f"2026-08-{(index % 28) + 1:02d}T06:30:00Z"
    return {
        "cycle_id": index,
        "created_at": created_at,
        "score_state": "SCORED",
        "score": {
            "recovery_score": 65.0,
            "hrv_rmssd_milli": 48.5,
            "resting_heart_rate": 55,
            "user_calibrating": False,
            "spo2_percentage": 98.0,
            "skin_temp_celsius": 36.5,
        },
    }


def _dense_sleep(index: int) -> dict[str, Any]:
    """A SCORED sleep record with every optional field, including stages, populated."""
    created_at = f"2026-08-{(index % 28) + 1:02d}T22:00:00Z"
    return {
        "id": f"sleep-uuid-{index}",
        "created_at": created_at,
        "start": created_at,
        "end": created_at,
        "nap": False,
        "score_state": "SCORED",
        "score": {
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
        },
    }


def _dense_cycle(index: int) -> dict[str, Any]:
    """A SCORED cycle record with every optional field populated."""
    created_at = f"2026-08-{(index % 28) + 1:02d}T22:00:00Z"
    return {
        "id": index,
        "created_at": created_at,
        "start": created_at,
        "end": created_at,
        "score_state": "SCORED",
        "score": {
            "strain": 12.0,
            "kilojoule": 2850.0,
            "average_heart_rate": 78,
            "max_heart_rate": 155,
        },
    }


def _dense_workout(index: int) -> dict[str, Any]:
    """A SCORED workout record with every optional field, including zones, populated."""
    created_at = f"2026-08-{(index % 28) + 1:02d}T06:00:00Z"
    return {
        "id": f"workout-uuid-{index}",
        "sport_name": "running",
        "created_at": created_at,
        "start": created_at,
        "end": created_at,
        "score_state": "SCORED",
        "score": {
            "strain": 8.5,
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
        },
    }


def _dense_page(builder: Any, count: int = _DENSE_PAGE_SIZE) -> dict[str, Any]:
    """One respx-mocked page: WHOOP caps a page at 25 records regardless of range."""
    return {"records": [builder(i) for i in range(1, count + 1)], "next_token": None}


# -- regime 2: a >1000-record, >2-year collection, for the 4 analysis tools -

_ANALYSIS_RECORD_COUNT = 1100
_ANALYSIS_SPAN_DAYS = 800  # comfortably over 2 years (730 days)


def _spread_timestamp(index: int) -> str:
    base = datetime(2024, 1, 1, tzinfo=UTC)
    offset_days = (index * _ANALYSIS_SPAN_DAYS) / _ANALYSIS_RECORD_COUNT
    return (base + timedelta(days=offset_days)).isoformat()


def _analysis_recovery_records() -> list[dict[str, Any]]:
    records = []
    for i in range(1, _ANALYSIS_RECORD_COUNT + 1):
        record = _dense_recovery(i)
        record["created_at"] = _spread_timestamp(i)
        record["cycle_id"] = i  # matches _analysis_cycle_records' "id" for the join
        # _dense_recovery's recovery_score is a constant 65.0, fine for the
        # single-page data-tool fixtures above but not here: trend()/pearson()
        # refuse a zero-variance series (#22, #23), so a constant series
        # trivially short-circuits metric_trend/correlate_metrics into their
        # small insufficient-data/refused response instead of exercising the
        # real worst case these ceilings are meant to measure.
        record["score"]["recovery_score"] = 50.0 + (i % 40)
        records.append(record)
    return records


def _analysis_sleep_records() -> list[dict[str, Any]]:
    records = []
    for i in range(1, _ANALYSIS_RECORD_COUNT + 1):
        record = _dense_sleep(i)
        timestamp = _spread_timestamp(i)
        record["created_at"] = timestamp
        record["start"] = timestamp
        record["end"] = timestamp
        records.append(record)
    return records


def _analysis_cycle_records() -> list[dict[str, Any]]:
    records = []
    for i in range(1, _ANALYSIS_RECORD_COUNT + 1):
        record = _dense_cycle(i)
        timestamp = _spread_timestamp(i)
        record["id"] = i
        record["created_at"] = timestamp
        record["start"] = timestamp
        record["end"] = timestamp
        # Same reasoning as _analysis_recovery_records' recovery_score override:
        # _dense_cycle's strain is a constant 12.0, which makes correlate_metrics
        # refuse every lag (a constant series has no correlation) instead of
        # exercising its real worst-case response.
        record["score"]["strain"] = 5.0 + (i % 15)
        records.append(record)
    return records


def _mock_paginated_collection(
    path: str, records: list[dict[str, Any]], page_size: int = 25
) -> None:
    """Mock a WHOOP list endpoint so WhoopClient.paginate() walks it via nextToken.

    Ignores start/end filtering -- every test using this wants every record
    reachable regardless of the range passed -- and only the nextToken cursor
    selects the page, the same thing that actually drives client.paginate().
    """

    def _respond(request: httpx.Request) -> httpx.Response:
        params = parse_qs(urlparse(str(request.url)).query)
        offset = int(params.get("nextToken", ["0"])[0])
        page = records[offset : offset + page_size]
        next_offset = offset + page_size
        next_token = str(next_offset) if next_offset < len(records) else None
        return httpx.Response(200, json={"records": page, "next_token": next_token})

    respx.get(f"{BASE_URL}{path}").mock(side_effect=_respond)


def _seed(conn: Any, whoop_user_id: int, upsert: Any, records: list[dict[str, Any]]) -> None:
    """Bulk-seed the store for #16's own worst-case fixtures.

    Every one of the 12 repointed tools (and whoop_data_coverage) reads
    from the store, not the live API -- these fixtures no longer measure
    anything by mocking WHOOP; they have to actually be written here.
    """
    for record in records:
        upsert(conn, whoop_user_id, record)


# -- regime 3: #24's own worst cases -- dense outliers/warm-up for
# whoop_outliers, and a long alternating pass/fail/missing sweep for
# whoop_streaks. Both walk a full calendar range (unlike regime 2's
# record-count cap), so the fixture size below is driven by #24's own
# day-count caps, not _ANALYSIS_RECORD_COUNT. ------------------------------

_STREAK_SWEEP_DAYS = 1100


def _outliers_worst_case_records() -> list[dict[str, Any]]:
    """~1100 days with sparse isolated spikes -- worst case for
    whoop_outliers: sparse high-value spikes (every 15th day) have z-scores
    well above the default z=2.0 threshold when evaluated against the rolling
    14-day window (which sees mostly lower baseline values), maximizing the
    "outliers" list up to the internal _OUTLIERS_MAX_FLAGGED cap, each with
    full context_before/context_after and other_metrics payload. Contrasts
    with the alternating pattern (which produces zero outliers because
    alternation IS the local norm under a rolling z-score), demonstrating
    why a rolling rather than global baseline is needed."""
    records = []
    base = datetime(2024, 1, 1, tzinfo=UTC)
    for i in range(_STREAK_SWEEP_DAYS):
        created_at = (base + timedelta(days=i)).isoformat()
        # Sparse isolated spikes: mostly 50.0 baseline, 90.0 spikes every 15th day.
        value = 90.0 if i % 15 == 0 else 50.0
        records.append(
            {
                "cycle_id": i,
                "created_at": created_at,
                "score_state": "SCORED",
                "score": {
                    "recovery_score": value,
                    "hrv_rmssd_milli": 48.5,
                    "resting_heart_rate": 55,
                },
            }
        )
    return records


def _streaks_worst_case_records() -> list[dict[str, Any]]:
    """~1100 days, one in three deliberately missing entirely and the rest
    alternating pass/fail against a mid threshold -- worst case for
    whoop_streaks: the "days" list enumerates every calendar day up to its
    own internal cap, never collapsing missing/failing/passing runs."""
    records = []
    base = datetime(2024, 1, 1, tzinfo=UTC)
    for i in range(_STREAK_SWEEP_DAYS):
        if i % 3 == 0:
            continue  # deliberately missing: no record at all for this day.
        created_at = (base + timedelta(days=i)).isoformat()
        value = 80.0 if i % 2 == 0 else 20.0
        records.append(
            {
                "cycle_id": i,
                "created_at": created_at,
                "score_state": "SCORED",
                "score": {
                    "recovery_score": value,
                    "hrv_rmssd_milli": 48.5,
                    "resting_heart_rate": 55,
                },
            }
        )
    return records


# -- registry enumeration: every tool must have a ceiling -------------------


async def test_every_registered_tool_has_a_ceiling() -> None:
    """A 17th tool with no entry in TOOL_CEILINGS must fail this test, not ship unmeasured."""
    tools = await build_server().list_tools()

    missing = {tool.name for tool in tools} - set(TOOL_CEILINGS)

    assert missing == set()


# -- auth tools (no network worst case to speak of) -------------------------


@pytest.mark.parametrize("tool_name", ["whoop_auth_status", "whoop_logout"])
async def test_auth_tool_within_ceiling(
    tool_name: str, server: MCPServer[AppContext], app_context: AppContext
) -> None:
    result = await call_tool(server, tool_name, {}, app_context)

    assert estimate_tokens(result) <= TOOL_CEILINGS[tool_name]


async def test_whoop_login_within_ceiling(
    server: MCPServer[AppContext], app_context: AppContext
) -> None:
    result = await call_tool(server, "whoop_login", {}, app_context)

    assert estimate_tokens(result) <= TOOL_CEILINGS["whoop_login"]


@respx.mock
async def test_whoop_complete_login_within_ceiling(
    config: Config, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    login_result = await call_tool(server, "whoop_login", {}, app_context)
    login_text = str(login_result["result"])
    state = parse_qs(urlparse(login_text.splitlines()[-1]).query)["state"][0]

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
    result = await call_tool(
        server, "whoop_complete_login", {"code": "fake-auth-code", "state": state}, app_context
    )

    assert estimate_tokens(result) <= TOOL_CEILINGS["whoop_complete_login"]


# -- data tools: get_profile / get_body_measurement --------------------------


async def test_get_profile_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    fixture = {
        "user_id": 12345,
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe",
    }
    upsert_profile(app_context.store_conn, 12345, fixture)

    result = await call_tool(server, "get_profile", {}, app_context)

    assert estimate_tokens(result) <= TOOL_CEILINGS["get_profile"]


async def test_get_body_measurement_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    fixture = {"height_meter": 1.75, "weight_kilogram": 75.5, "max_heart_rate": 190}
    upsert_body_measurement(app_context.store_conn, 12345, fixture)

    result = await call_tool(server, "get_body_measurement", {}, app_context)

    assert estimate_tokens(result) <= TOOL_CEILINGS["get_body_measurement"]


# -- data tools: the 4 list tools, against one dense 25-record page ---------


async def test_list_recoveries_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed(
        app_context.store_conn,
        12345,
        upsert_recovery,
        [_dense_recovery(i) for i in range(1, _DENSE_PAGE_SIZE + 1)],
    )

    result = await call_tool(
        server,
        "list_recoveries",
        {"start": "2024-01-01T00:00:00Z", "end": "2026-08-30T00:00:00Z"},
        app_context,
    )

    assert result["count"] == _DENSE_PAGE_SIZE
    assert estimate_tokens(result) <= TOOL_CEILINGS["list_recoveries"]


async def test_list_sleeps_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Worst case for list_sleeps is detail="full" -- that's the larger of its two shapes."""
    assert app_context.store_conn is not None
    _seed(
        app_context.store_conn,
        12345,
        upsert_sleep,
        [_dense_sleep(i) for i in range(1, _DENSE_PAGE_SIZE + 1)],
    )

    result = await call_tool(
        server,
        "list_sleeps",
        {"start": "2024-01-01T00:00:00Z", "end": "2026-08-30T00:00:00Z", "detail": "full"},
        app_context,
    )

    assert result["count"] == _DENSE_PAGE_SIZE
    assert estimate_tokens(result) <= TOOL_CEILINGS["list_sleeps"]


async def test_list_cycles_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed(
        app_context.store_conn,
        12345,
        upsert_cycle,
        [_dense_cycle(i) for i in range(1, _DENSE_PAGE_SIZE + 1)],
    )

    result = await call_tool(
        server,
        "list_cycles",
        {"start": "2024-01-01T00:00:00Z", "end": "2026-08-30T00:00:00Z"},
        app_context,
    )

    assert result["count"] == _DENSE_PAGE_SIZE
    assert estimate_tokens(result) <= TOOL_CEILINGS["list_cycles"]


async def test_list_workouts_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Worst case for list_workouts is detail="full" -- that's the larger of its two shapes."""
    assert app_context.store_conn is not None
    _seed(
        app_context.store_conn,
        12345,
        upsert_workout,
        [_dense_workout(i) for i in range(1, _DENSE_PAGE_SIZE + 1)],
    )

    result = await call_tool(
        server,
        "list_workouts",
        {"start": "2024-01-01T00:00:00Z", "end": "2026-08-30T00:00:00Z", "detail": "full"},
        app_context,
    )

    assert result["count"] == _DENSE_PAGE_SIZE
    assert estimate_tokens(result) <= TOOL_CEILINGS["list_workouts"]


async def test_get_sleep_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    upsert_sleep(app_context.store_conn, 12345, _dense_sleep(1))

    result = await call_tool(server, "get_sleep", {"sleep_id": "sleep-uuid-1"}, app_context)

    assert estimate_tokens(result) <= TOOL_CEILINGS["get_sleep"]


async def test_get_workout_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    upsert_workout(app_context.store_conn, 12345, _dense_workout(1))

    result = await call_tool(server, "get_workout", {"workout_id": "workout-uuid-1"}, app_context)

    assert estimate_tokens(result) <= TOOL_CEILINGS["get_workout"]


async def test_whoop_data_coverage_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """whoop_data_coverage's response is 6 small fixed-size entity dicts --
    never echoed records -- so its worst case does not grow with history
    size; seeding a dense page is enough to exercise a populated, non-empty
    shape, not a true stress case."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    _seed(
        conn, 12345, upsert_recovery, [_dense_recovery(i) for i in range(1, _DENSE_PAGE_SIZE + 1)]
    )
    _seed(conn, 12345, upsert_sleep, [_dense_sleep(i) for i in range(1, _DENSE_PAGE_SIZE + 1)])
    _seed(conn, 12345, upsert_cycle, [_dense_cycle(i) for i in range(1, _DENSE_PAGE_SIZE + 1)])
    _seed(conn, 12345, upsert_workout, [_dense_workout(i) for i in range(1, _DENSE_PAGE_SIZE + 1)])
    upsert_profile(conn, 12345, {"user_id": 12345, "email": "user@example.com"})
    upsert_body_measurement(conn, 12345, {"height_meter": 1.75})

    result = await call_tool(server, "whoop_data_coverage", {}, app_context)

    assert estimate_tokens(result) <= TOOL_CEILINGS["whoop_data_coverage"]


# -- whoop_sync (#15): counts and a cursor per entity, never full records ---


@respx.mock
async def test_whoop_sync_within_ceiling(tmp_path: Path, server: MCPServer[AppContext]) -> None:
    """whoop_sync's response is four small per-entity dicts (count + cursor),
    never echoed records -- built on its own cache-enabled config/store
    rather than this file's shared ``app_context`` fixture, since that
    fixture's ``config`` leaves ``WHOOPMCP_CACHE`` unset and #15's tool
    refuses to write to a disabled store (see tests/test_sync.py for that
    contract in full)."""
    config = Config.from_env(
        {
            "WHOOP_CLIENT_ID": "cid",
            "WHOOP_CLIENT_SECRET": "csecret",
            "WHOOP_REDIRECT_URI": "https://localhost:8443/callback",
            "WHOOPMCP_STATE_DIR": str(tmp_path),
            "WHOOPMCP_CACHE": "true",
        }
    )
    FileTokenStore(config.token_path).save(
        Token("fake-access-token", expires_at=time.time() + 3600, refresh_token="fake-refresh")
    )
    auth = Authenticator(config)
    conn = open_store(":memory:")
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=12345
    )

    respx.get(f"{BASE_URL}/v2/recovery").mock(
        return_value=httpx.Response(200, json=_dense_page(_dense_recovery, count=1))
    )
    respx.get(f"{BASE_URL}/v2/activity/sleep").mock(
        return_value=httpx.Response(200, json=_dense_page(_dense_sleep, count=1))
    )
    respx.get(f"{BASE_URL}/v2/cycle").mock(
        return_value=httpx.Response(200, json=_dense_page(_dense_cycle, count=1))
    )
    respx.get(f"{BASE_URL}/v2/activity/workout").mock(
        return_value=httpx.Response(200, json=_dense_page(_dense_workout, count=1))
    )

    try:
        async with WhoopClient(config, auth, clock=fast_forwarding_clock()) as client:
            app_context = AppContext(
                config=config,
                auth=auth,
                client=client,
                principal=Principal(user_id=12345),
                store_conn=conn,
            )
            result = await call_tool(server, "whoop_sync", {}, app_context)

        assert set(result["entities"]) == {"recoveries", "sleeps", "cycles", "workouts"}
        assert estimate_tokens(result) <= TOOL_CEILINGS["whoop_sync"]
    finally:
        # A try/finally here (unlike this file's other tests, which are
        # already implemented and so never raise before their own
        # conn.close()) so this not-yet-implemented tool's ToolError
        # doesn't leak an unclosed sqlite connection into a later test's
        # ResourceWarning-as-error under this project's filterwarnings=error.
        conn.close()


# -- analysis tools, against a >1000-record, >2-year collection -------------


async def test_summarize_period_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    _seed(conn, 12345, upsert_recovery, _analysis_recovery_records())
    _seed(conn, 12345, upsert_sleep, _analysis_sleep_records())
    _seed(conn, 12345, upsert_cycle, _analysis_cycle_records())

    result = await call_tool(
        server,
        "summarize_period",
        {"start": "2024-01-01T00:00:00Z", "end": "2026-08-01T00:00:00Z"},
        app_context,
    )

    assert estimate_tokens(result) <= TOOL_CEILINGS["summarize_period"]


async def test_metric_trend_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed(app_context.store_conn, 12345, upsert_recovery, _analysis_recovery_records())

    result = await call_tool(
        server,
        "metric_trend",
        {
            "metric": "recovery_score",
            "start": "2024-01-01T00:00:00Z",
            "end": "2026-08-01T00:00:00Z",
        },
        app_context,
    )

    assert estimate_tokens(result) <= TOOL_CEILINGS["metric_trend"]


async def test_correlate_metrics_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    _seed(conn, 12345, upsert_recovery, _analysis_recovery_records())
    _seed(conn, 12345, upsert_cycle, _analysis_cycle_records())

    result = await call_tool(
        server,
        "correlate_metrics",
        {
            "metric_a": "strain",
            "metric_b": "recovery_score",
            "start": "2024-01-01T00:00:00Z",
            "end": "2026-08-01T00:00:00Z",
        },
        app_context,
    )

    assert estimate_tokens(result) <= TOOL_CEILINGS["correlate_metrics"]


async def test_compare_periods_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    _seed(conn, 12345, upsert_recovery, _analysis_recovery_records())
    _seed(conn, 12345, upsert_sleep, _analysis_sleep_records())
    _seed(conn, 12345, upsert_cycle, _analysis_cycle_records())

    result = await call_tool(
        server,
        "compare_periods",
        {
            "baseline_start": "2024-01-01T00:00:00Z",
            "baseline_end": "2025-01-01T00:00:00Z",
            "comparison_start": "2025-01-01T00:00:00Z",
            "comparison_end": "2026-08-01T00:00:00Z",
        },
        app_context,
    )

    assert estimate_tokens(result) <= TOOL_CEILINGS["compare_periods"]


# -- #24: whoop_outliers/whoop_streaks worst cases --------------------------


async def test_whoop_outliers_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed(app_context.store_conn, 12345, upsert_recovery, _outliers_worst_case_records())

    result = await call_tool(
        server,
        "whoop_outliers",
        {
            "metric": "recovery_score",
            "start": "2024-01-01T00:00:00Z",
            "end": "2027-02-05T00:00:00Z",
        },
        app_context,
    )

    assert "whoop_outliers" in TOOL_CEILINGS, (
        "context_budget.TOOL_CEILINGS needs a measured entry for whoop_outliers "
        "(test_every_registered_tool_has_a_ceiling otherwise fails CI)"
    )
    assert estimate_tokens(result) <= TOOL_CEILINGS["whoop_outliers"]


async def test_whoop_streaks_within_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed(app_context.store_conn, 12345, upsert_recovery, _streaks_worst_case_records())

    result = await call_tool(
        server,
        "whoop_streaks",
        {
            "metric": "recovery_score",
            "start": "2024-01-01T00:00:00Z",
            "end": "2027-02-05T00:00:00Z",
            "threshold": 50.0,
            "direction": "above",
        },
        app_context,
    )

    assert "whoop_streaks" in TOOL_CEILINGS, (
        "context_budget.TOOL_CEILINGS needs a measured entry for whoop_streaks "
        "(test_every_registered_tool_has_a_ceiling otherwise fails CI)"
    )
    assert estimate_tokens(result) <= TOOL_CEILINGS["whoop_streaks"]


# -- truncation surfaces on the tools that actually hit the cap -------------


async def test_truncation_appears_on_summarize_period_and_metric_trend(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    _seed(conn, 12345, upsert_recovery, _analysis_recovery_records())
    _seed(conn, 12345, upsert_sleep, _analysis_sleep_records())
    _seed(conn, 12345, upsert_cycle, _analysis_cycle_records())

    summary = await call_tool(
        server,
        "summarize_period",
        {"start": "2024-01-01T00:00:00Z", "end": "2026-08-01T00:00:00Z"},
        app_context,
    )
    trend_result = await call_tool(
        server,
        "metric_trend",
        {
            "metric": "recovery_score",
            "start": "2024-01-01T00:00:00Z",
            "end": "2026-08-01T00:00:00Z",
        },
        app_context,
    )

    assert summary["truncated"] is True
    assert "note" in summary
    assert trend_result["truncated"] is True
    assert "note" in trend_result


# -- detail="summary" (default) vs "full" --------------------------------


async def test_list_sleeps_detail_summary_is_smaller_than_full(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed(
        app_context.store_conn,
        12345,
        upsert_sleep,
        [_dense_sleep(i) for i in range(1, _DENSE_PAGE_SIZE + 1)],
    )

    summary_result = await call_tool(
        server,
        "list_sleeps",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-30T00:00:00Z"},
        app_context,
    )
    full_result = await call_tool(
        server,
        "list_sleeps",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-30T00:00:00Z", "detail": "full"},
        app_context,
    )

    assert estimate_tokens(summary_result) < estimate_tokens(full_result)
    assert "stage_durations" not in summary_result["records"][0]
    assert "units" not in summary_result
    assert "stage_durations" in full_result["records"][0]
    assert full_result["units"] == {"stage_durations": "milliseconds"}


async def test_list_workouts_detail_summary_is_smaller_than_full(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed(
        app_context.store_conn,
        12345,
        upsert_workout,
        [_dense_workout(i) for i in range(1, _DENSE_PAGE_SIZE + 1)],
    )

    summary_result = await call_tool(
        server,
        "list_workouts",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-30T00:00:00Z"},
        app_context,
    )
    full_result = await call_tool(
        server,
        "list_workouts",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-30T00:00:00Z", "detail": "full"},
        app_context,
    )

    assert estimate_tokens(summary_result) < estimate_tokens(full_result)
    assert "zone_durations" not in summary_result["records"][0]
    assert "units" not in summary_result
    assert "zone_durations" in full_result["records"][0]
    assert full_result["units"] == {"zone_durations": "milliseconds"}


# -- nulls are absent, not present-with-null --------------------------------


async def test_list_recoveries_nulls_are_absent_not_present_with_null(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    record = {
        "cycle_id": 1,
        "created_at": "2026-08-01T06:00:00Z",
        "score_state": "SCORED",
        "score": {
            "recovery_score": 65.0,
            "hrv_rmssd_milli": 48.5,
            "resting_heart_rate": None,  # forced null on an otherwise-normal field
        },
    }
    upsert_recovery(app_context.store_conn, 12345, record)

    result = await call_tool(
        server,
        "list_recoveries",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
        app_context,
    )

    trimmed = result["records"][0]
    assert "resting_heart_rate" not in trimmed
    # Sanity: the non-null fields are still there -- this isn't dropping the record.
    assert trimmed["recovery_score"] == 65.0
    assert trimmed["hrv_rmssd_milli"] == 48.5
