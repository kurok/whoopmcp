"""Tests for issue #16: data/analysis tools served from the store, not WHOOP.

Written before the implementation exists -- every test in this file is
expected to fail (ImportError, AttributeError, a raised ToolError from the
still-live-API tool body, or a plain assertion failure) until #16 lands.
Nothing here calls the real WHOOP API; every zero-API-call test wraps its
call in ``@respx.mock`` with no routes registered, so an accidental fetch
raises ``AllMockedAssertionError`` before the test's own assertion even runs
(mirroring tests/test_webhook_processing.py's own
``test_recovery_deleted_skips_fetch_and_sets_deleted_at``).

Response-shape convention this file assumes (a normal implementation detail
per the issue's own text, chosen and documented once, here, rather than
guessed at per test):

- Every repointed tool response carries a top-level ``"coverage"`` dict,
  keyed by the entity name(s) the tool drew from ("recoveries", "sleeps",
  "cycles", "workouts", "profile", "body_measurement" -- the same six names
  ``whoop_data_coverage`` itself reports). For the four collection entities,
  each value is
  ``{"earliest": iso|None, "latest": iso|None,
     "backfill": {"status": outcome|"never_run", "last_run_at": iso|None},
     "incremental_sync": {"status": outcome|"never_run",
                           "last_successful_at": iso|None}}``.
  ``last_successful_at`` is only populated when the incremental row's own
  outcome is "complete" -- an "in_progress" row's last_run_at is that run's
  own timestamp, not a prior completion's. For the two singletons (profile,
  body_measurement), the value is instead
  ``{"synced": bool, "last_updated_at": iso|None}`` -- a deliberately
  different, honest shape, since neither has an earliest/latest to report.
- The 4 list_* tools and the 4 analysis tools additionally carry a
  ``"range_coverage"`` dict, keyed the same way, each value
  ``{"status": "within_coverage" | "partly_outside_coverage" |
              "wholly_outside_coverage" | "no_data_synced_yet",
    "message": str}`` (``"message"`` present whenever ``status`` is not
  ``"within_coverage"``), comparing the tool's own resolved start/end against
  that entity's coverage window.
- get_sleep/get_workout/get_profile/get_body_measurement are point lookups,
  not ranges: they carry ``"coverage"`` but no ``"range_coverage"``. A miss
  is ``{"error": "not_synced", "coverage": {...}}`` when the entity's own
  coverage window is empty (nothing ever synced), or
  ``{"error": "not_found_in_store", "coverage": {...}}`` when the entity has
  *some* coverage but not this particular id/user -- never a live fetch.
- Metric-sourced analysis tools (metric_trend, correlate_metrics) key
  coverage/range_coverage by the underlying entity TABLE name ("recoveries"/
  "sleeps"/"cycles"), not the singular friendly collection name
  (_METRIC_COLLECTION's "recovery"/"sleep"/"cycle") -- consistent with every
  other tool's keys and with whoop_data_coverage's own.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
import respx
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context, MCPServer

from whoopmcp.auth import Authenticator, FileTokenStore, Token
from whoopmcp.client import WhoopClient
from whoopmcp.config import Config
from whoopmcp.server import AppContext, Principal, build_server
from whoopmcp.store import (
    link_principal_to_member,
    open_store,
    set_sync_state,
    upsert_body_measurement,
    upsert_cycle,
    upsert_profile,
    upsert_recovery,
    upsert_sleep,
    upsert_workout,
)

WHOOP_USER_ID = 12345

# -- shared fixture helpers, deliberately kept local rather than imported from
# tests/test_server.py / tests/test_context_budget.py -- same rationale
# test_context_budget.py already gives its own copy of these: this file's
# fixtures evolve with #16 independently of the happy-path/ceiling suites. ---


async def call_tool(
    server: MCPServer[AppContext], name: str, arguments: dict[str, Any], app_context: AppContext
) -> Any:
    """Call a tool with proper context wiring, and unwrap its return value."""
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
    conn = open_store(":memory:")
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=WHOOP_USER_ID
    )
    yield AppContext(
        config=config,
        auth=auth,
        client=client,
        principal=Principal(user_id=WHOOP_USER_ID),
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


# -- record builders (deliberately minimal -- store.py round-trips raw_json
# verbatim, so only the fields each entity's own upsert function reads for
# its extracted columns need to be realistic). --------------------------------


def recovery_record(cycle_id: int, created_at: str, recovery_score: float = 65.0) -> dict[str, Any]:
    return {
        "cycle_id": cycle_id,
        "created_at": created_at,
        "score_state": "SCORED",
        "score": {
            "recovery_score": recovery_score,
            "hrv_rmssd_milli": 48.5,
            "resting_heart_rate": 55,
        },
    }


def sleep_record(sleep_id: str, start: str, end: str) -> dict[str, Any]:
    return {
        "id": sleep_id,
        "start": start,
        "end": end,
        "nap": False,
        "score_state": "SCORED",
        "score": {"sleep_performance_percentage": 87.0, "sleep_efficiency_percentage": 90.5},
    }


def cycle_record(cycle_id: int, start: str, end: str, strain: float = 12.0) -> dict[str, Any]:
    return {
        "id": cycle_id,
        "start": start,
        "end": end,
        "score_state": "SCORED",
        "score": {"strain": strain, "average_heart_rate": 78, "max_heart_rate": 155},
    }


def workout_record(workout_id: str, start: str, end: str) -> dict[str, Any]:
    return {
        "id": workout_id,
        "sport_name": "running",
        "start": start,
        "end": end,
        "score_state": "SCORED",
        "score": {"strain": 8.5, "average_heart_rate": 145, "max_heart_rate": 180},
    }


def _soft_delete(conn: Any, table: str, resource_id: str) -> None:
    """Set deleted_at directly via raw SQL -- mirrors tests/test_store.py's
    own ``_soft_delete`` and tests/test_webhook_processing.py's rationale for
    not routing test setup through a store getter/setter."""
    conn.execute(
        f"UPDATE {table} SET deleted_at = ? WHERE whoop_user_id = ? AND resource_id = ?",  # noqa: S608
        ("2026-08-09T00:00:00Z", WHOOP_USER_ID, resource_id),
    )
    conn.commit()


def _seed_full_dataset(conn: Any) -> None:
    """One record (or two, where a pair is useful) per entity, all within
    2026-08-01..2026-08-08 -- the shared happy-path window every test in this
    file's TOOL_ARGS below queries. Also marks backfill+incremental sync
    state 'complete' for the 4 collection entities, since a repointed tool
    reporting coverage/sync-time honestly needs that state to exist."""
    upsert_recovery(conn, WHOOP_USER_ID, recovery_record(100, "2026-08-01T06:30:00Z"))
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(101, "2026-08-05T06:30:00Z", recovery_score=72.0)
    )
    upsert_sleep(
        conn, WHOOP_USER_ID, sleep_record("sleep-1", "2026-08-01T23:00:00Z", "2026-08-02T07:00:00Z")
    )
    upsert_sleep(
        conn, WHOOP_USER_ID, sleep_record("sleep-2", "2026-08-05T23:00:00Z", "2026-08-06T07:00:00Z")
    )
    upsert_cycle(
        conn, WHOOP_USER_ID, cycle_record(200, "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z")
    )
    upsert_cycle(
        conn,
        WHOOP_USER_ID,
        cycle_record(201, "2026-08-05T00:00:00Z", "2026-08-06T00:00:00Z", strain=15.0),
    )
    upsert_workout(
        conn, WHOOP_USER_ID, workout_record("wo-1", "2026-08-01T06:00:00Z", "2026-08-01T07:00:00Z")
    )
    upsert_profile(conn, WHOOP_USER_ID, {"user_id": WHOOP_USER_ID, "email": "a@example.com"})
    upsert_body_measurement(conn, WHOOP_USER_ID, {"height_meter": 1.8})
    for entity in ("recoveries", "sleeps", "cycles", "workouts"):
        set_sync_state(
            conn,
            WHOOP_USER_ID,
            entity,
            cursor=None,
            last_run_at="2026-08-07T00:00:00Z",
            outcome="complete",
        )
        set_sync_state(
            conn,
            WHOOP_USER_ID,
            f"{entity}:incremental",
            cursor="2026-08-07T00:00:00Z",
            last_run_at="2026-08-07T00:05:00Z",
            outcome="complete",
        )


#: Auth tools and whoop_sync are deliberately excluded: they either don't
#: touch the store's entity data at all, or (whoop_sync) is the one tool that
#: MUST still call the live API -- coverage reporting doesn't apply to it.
_AUTH_TOOLS = frozenset(
    {"whoop_auth_status", "whoop_login", "whoop_complete_login", "whoop_logout"}
)
_LIVE_API_TOOLS = frozenset({"whoop_sync"})
#: whoop_data_coverage's response IS the coverage report (per-entity dicts
#: at the top level) rather than a tool response carrying a "coverage" key
#: alongside its own payload, so it is deliberately exercised by its own
#: dedicated tests below (test_whoop_data_coverage_*) instead of through the
#: generic TOOL_ARGS loop -- excluded here for that reason, not overlooked.
#: whoop_timeseries (#20) is excluded for a related reason: it carries a
#: lightweight, single flat "range_coverage" entry (see its own docstring
#: in server.py) but deliberately NOT the fuller "coverage" envelope every
#: other range tool carries -- that envelope's fixed per-call cost is
#: exactly what this tool exists to avoid -- so it would fail
#: test_response_includes_coverage below by design, not by omission. It has
#: its own complete test file, tests/test_whoop_timeseries.py.
_SEPARATELY_TESTED_TOOLS = frozenset({"whoop_data_coverage", "whoop_timeseries"})

#: Every data/analysis tool this issue repoints, with a happy-path argument
#: set against `_seed_full_dataset`'s data. A tool added later without an
#: entry here fails `test_every_data_and_analysis_tool_is_enumerated_here`
#: rather than shipping silently uncovered.
TOOL_ARGS: dict[str, dict[str, Any]] = {
    "get_profile": {},
    "get_body_measurement": {},
    "list_recoveries": {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
    "list_sleeps": {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
    "list_cycles": {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
    "list_workouts": {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
    "get_sleep": {"sleep_id": "sleep-1"},
    "get_workout": {"workout_id": "wo-1"},
    "summarize_period": {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
    "metric_trend": {
        "metric": "recovery_score",
        "start": "2026-08-01T00:00:00Z",
        "end": "2026-08-08T00:00:00Z",
    },
    "correlate_metrics": {
        "metric_a": "strain",
        "metric_b": "recovery_score",
        "start": "2026-08-01T00:00:00Z",
        "end": "2026-08-08T00:00:00Z",
    },
    "compare_periods": {
        "baseline_start": "2026-08-01T00:00:00Z",
        "baseline_end": "2026-08-04T00:00:00Z",
        "comparison_start": "2026-08-04T00:00:00Z",
        "comparison_end": "2026-08-08T00:00:00Z",
    },
}


# -- registry enumeration: a new data/analysis tool must be added to
# TOOL_ARGS, or this fails -- mirrors test_context_budget.py's own
# test_every_registered_tool_has_a_ceiling. ----------------------------------


async def test_every_data_and_analysis_tool_is_enumerated_here() -> None:
    tools = await build_server().list_tools()
    non_gated = (
        {tool.name for tool in tools} - _AUTH_TOOLS - _LIVE_API_TOOLS - _SEPARATELY_TESTED_TOOLS
    )

    assert non_gated == set(TOOL_ARGS)


# -- acceptance criterion 1: zero API calls on the happy path ----------------


@pytest.mark.parametrize("tool_name", sorted(TOOL_ARGS))
@respx.mock
async def test_no_api_call_on_happy_path(
    tool_name: str, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """No route is registered above -- respx's own AllMockedAssertionError
    would already fail this test before the explicit assertion below runs if
    the tool issued any HTTP request at all; the explicit assertion is a
    readable, positive double-check, not the only guard."""
    assert app_context.store_conn is not None
    _seed_full_dataset(app_context.store_conn)

    await call_tool(server, tool_name, TOOL_ARGS[tool_name], app_context)

    assert len(respx.calls) == 0


# -- acceptance criterion 2: coverage metadata on every response ------------


@pytest.mark.parametrize("tool_name", sorted(TOOL_ARGS))
async def test_response_includes_coverage(
    tool_name: str, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed_full_dataset(app_context.store_conn)

    result = await call_tool(server, tool_name, TOOL_ARGS[tool_name], app_context)

    assert "coverage" in result, f"{tool_name} response is missing 'coverage': {result!r}"


_RANGE_TOOLS = frozenset(
    {
        "list_recoveries",
        "list_sleeps",
        "list_cycles",
        "list_workouts",
        "summarize_period",
        "metric_trend",
        "correlate_metrics",
        "compare_periods",
    }
)


@pytest.mark.parametrize("tool_name", sorted(_RANGE_TOOLS))
async def test_range_tool_response_includes_range_coverage(
    tool_name: str, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed_full_dataset(app_context.store_conn)

    result = await call_tool(server, tool_name, TOOL_ARGS[tool_name], app_context)

    assert "range_coverage" in result, (
        f"{tool_name} response is missing 'range_coverage': {result!r}"
    )


# -- acceptance criterion 3: wholly outside the coverage window -------------


async def test_list_sleeps_wholly_outside_coverage_window(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Sleeps exist only in August 2026; a January-2020 request must say so
    explicitly, not just return an empty list indistinguishable from 'you had
    no sleeps then'."""
    assert app_context.store_conn is not None
    upsert_sleep(
        app_context.store_conn,
        WHOOP_USER_ID,
        sleep_record("sleep-1", "2026-08-01T23:00:00Z", "2026-08-02T07:00:00Z"),
    )
    set_sync_state(
        app_context.store_conn,
        WHOOP_USER_ID,
        "sleeps",
        cursor=None,
        last_run_at="2026-08-07T00:00:00Z",
        outcome="complete",
    )

    result = await call_tool(
        server,
        "list_sleeps",
        {"start": "2020-01-01T00:00:00Z", "end": "2020-01-08T00:00:00Z"},
        app_context,
    )

    assert result["records"] == []
    assert result["range_coverage"]["sleeps"]["status"] == "wholly_outside_coverage"
    assert result["range_coverage"]["sleeps"]["message"]


async def test_metric_trend_wholly_outside_coverage_window(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn, WHOOP_USER_ID, recovery_record(100, "2026-08-01T06:30:00Z")
    )
    set_sync_state(
        app_context.store_conn,
        WHOOP_USER_ID,
        "recoveries",
        cursor=None,
        last_run_at="2026-08-07T00:00:00Z",
        outcome="complete",
    )

    result = await call_tool(
        server,
        "metric_trend",
        {
            "metric": "recovery_score",
            "start": "2020-01-01T00:00:00Z",
            "end": "2020-01-08T00:00:00Z",
        },
        app_context,
    )

    assert result["range_coverage"]["recoveries"]["status"] == "wholly_outside_coverage"
    assert result["range_coverage"]["recoveries"]["message"]


# -- acceptance criterion 4: partly outside the coverage window -------------


async def test_list_recoveries_partly_outside_coverage_window(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Recoveries exist on 08-01 and 08-05; a request for 08-03..08-10
    overlaps only the 08-05 record -- the response must return what exists
    AND flag the shortfall, not silently look complete."""
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn, WHOOP_USER_ID, recovery_record(100, "2026-08-01T06:30:00Z")
    )
    upsert_recovery(
        app_context.store_conn, WHOOP_USER_ID, recovery_record(101, "2026-08-05T06:30:00Z")
    )
    set_sync_state(
        app_context.store_conn,
        WHOOP_USER_ID,
        "recoveries",
        cursor=None,
        last_run_at="2026-08-07T00:00:00Z",
        outcome="complete",
    )

    result = await call_tool(
        server,
        "list_recoveries",
        {"start": "2026-08-03T00:00:00Z", "end": "2026-08-10T00:00:00Z"},
        app_context,
    )

    assert result["range_coverage"]["recoveries"]["status"] == "partly_outside_coverage"
    assert result["range_coverage"]["recoveries"]["message"]
    assert [r["cycle_id"] for r in result["records"]] == [101]


# -- acceptance criterion 5: an empty store answers coherently --------------


@pytest.mark.parametrize("tool_name", sorted(TOOL_ARGS))
async def test_empty_store_answers_coherently(
    tool_name: str, app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Nothing has ever been synced. Every tool must still answer -- no
    exception -- and every range tool's range_coverage (where applicable)
    must say 'no_data_synced_yet' rather than a bare empty result."""
    args = dict(TOOL_ARGS[tool_name])
    if tool_name == "get_sleep":
        args = {"sleep_id": "nonexistent"}
    elif tool_name == "get_workout":
        args = {"workout_id": "nonexistent"}

    result = await call_tool(server, tool_name, args, app_context)

    assert result is not None
    if tool_name in _RANGE_TOOLS:
        statuses = {entry["status"] for entry in result["range_coverage"].values()}
        assert statuses == {"no_data_synced_yet"}
    elif tool_name in ("get_sleep", "get_workout", "get_profile", "get_body_measurement"):
        assert result.get("error") == "not_synced"


async def test_whoop_data_coverage_on_empty_store(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    result = await call_tool(server, "whoop_data_coverage", {}, app_context)

    for entity in ("recoveries", "sleeps", "cycles", "workouts"):
        assert result[entity]["earliest"] is None
        assert result[entity]["latest"] is None
        assert result[entity]["backfill"]["status"] == "never_run"
        assert result[entity]["incremental_sync"]["status"] == "never_run"
    for singleton in ("profile", "body_measurement"):
        assert result[singleton]["synced"] is False
        assert result[singleton]["last_updated_at"] is None


# -- acceptance criterion 6: whoop_data_coverage matches what was written ---


async def test_whoop_data_coverage_matches_seeded_data(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    upsert_recovery(conn, WHOOP_USER_ID, recovery_record(100, "2026-08-01T06:30:00Z"))
    upsert_recovery(conn, WHOOP_USER_ID, recovery_record(101, "2026-08-05T06:30:00Z"))
    upsert_sleep(
        conn, WHOOP_USER_ID, sleep_record("sleep-1", "2026-08-01T23:00:00Z", "2026-08-02T07:00:00Z")
    )
    upsert_cycle(
        conn, WHOOP_USER_ID, cycle_record(200, "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z")
    )
    upsert_workout(
        conn, WHOOP_USER_ID, workout_record("wo-1", "2026-08-01T06:00:00Z", "2026-08-01T07:00:00Z")
    )
    upsert_profile(conn, WHOOP_USER_ID, {"user_id": WHOOP_USER_ID})
    upsert_body_measurement(conn, WHOOP_USER_ID, {"height_meter": 1.8})

    set_sync_state(
        conn,
        WHOOP_USER_ID,
        "recoveries",
        cursor=None,
        last_run_at="2026-08-06T00:00:00Z",
        outcome="complete",
    )
    set_sync_state(
        conn,
        WHOOP_USER_ID,
        "recoveries:incremental",
        cursor="2026-08-07T00:00:00Z",
        last_run_at="2026-08-07T00:05:00Z",
        outcome="complete",
    )
    # sleeps: backfill still in progress, no completed incremental sync yet --
    # last_successful_at must be None (an in_progress row's last_run_at is
    # this run's own timestamp, not a prior completion's), never guessed.
    set_sync_state(
        conn,
        WHOOP_USER_ID,
        "sleeps",
        cursor="opaque-cursor",
        last_run_at="2026-08-06T00:00:00Z",
        outcome="in_progress",
    )
    set_sync_state(
        conn,
        WHOOP_USER_ID,
        "sleeps:incremental",
        cursor="{}",
        last_run_at="2026-08-07T00:05:00Z",
        outcome="in_progress",
    )
    # cycles/workouts: never synced at all (no sync_state row).

    result = await call_tool(server, "whoop_data_coverage", {}, app_context)

    assert result["recoveries"]["earliest"] == "2026-08-01T06:30:00Z"
    assert result["recoveries"]["latest"] == "2026-08-05T06:30:00Z"
    assert result["recoveries"]["backfill"]["status"] == "complete"
    assert result["recoveries"]["backfill"]["last_run_at"] == "2026-08-06T00:00:00Z"
    assert result["recoveries"]["incremental_sync"]["status"] == "complete"
    assert result["recoveries"]["incremental_sync"]["last_successful_at"] == "2026-08-07T00:05:00Z"

    assert result["sleeps"]["earliest"] == "2026-08-01T23:00:00Z"
    assert result["sleeps"]["latest"] == "2026-08-02T07:00:00Z"
    assert result["sleeps"]["backfill"]["status"] == "in_progress"
    assert result["sleeps"]["incremental_sync"]["status"] == "in_progress"
    assert result["sleeps"]["incremental_sync"]["last_successful_at"] is None

    assert result["cycles"]["backfill"]["status"] == "never_run"
    assert result["cycles"]["incremental_sync"]["status"] == "never_run"
    assert (
        result["cycles"]["earliest"] == "2026-08-01T00:00:00Z"
    )  # data exists even though sync_state doesn't
    assert result["workouts"]["earliest"] == "2026-08-01T06:00:00Z"

    assert result["profile"]["synced"] is True
    assert result["profile"]["last_updated_at"] is not None
    assert result["body_measurement"]["synced"] is True


# -- acceptance criterion 7: deleted_at regression --------------------------


async def test_list_sleeps_does_not_resurrect_a_soft_deleted_sleep(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    upsert_sleep(
        conn,
        WHOOP_USER_ID,
        sleep_record("sleep-kept", "2026-08-01T23:00:00Z", "2026-08-02T07:00:00Z"),
    )
    upsert_sleep(
        conn,
        WHOOP_USER_ID,
        sleep_record("sleep-deleted", "2026-08-02T23:00:00Z", "2026-08-03T07:00:00Z"),
    )
    _soft_delete(conn, "sleeps", "sleep-deleted")

    result = await call_tool(
        server,
        "list_sleeps",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
        app_context,
    )

    ids = {r["id"] for r in result["records"]}
    assert ids == {"sleep-kept"}


async def test_get_sleep_does_not_resurrect_a_soft_deleted_sleep(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    # A second, still-live sleep so this entity's own coverage isn't empty --
    # the miss below must be "not_found_in_store", not "not_synced".
    upsert_sleep(
        conn,
        WHOOP_USER_ID,
        sleep_record("sleep-kept", "2026-08-01T23:00:00Z", "2026-08-02T07:00:00Z"),
    )
    upsert_sleep(
        conn,
        WHOOP_USER_ID,
        sleep_record("sleep-deleted", "2026-08-02T23:00:00Z", "2026-08-03T07:00:00Z"),
    )
    _soft_delete(conn, "sleeps", "sleep-deleted")

    result = await call_tool(server, "get_sleep", {"sleep_id": "sleep-deleted"}, app_context)

    assert result.get("error") == "not_found_in_store"


async def test_list_workouts_does_not_resurrect_a_soft_deleted_workout(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    upsert_workout(
        conn,
        WHOOP_USER_ID,
        workout_record("wo-kept", "2026-08-01T06:00:00Z", "2026-08-01T07:00:00Z"),
    )
    upsert_workout(
        conn,
        WHOOP_USER_ID,
        workout_record("wo-deleted", "2026-08-02T06:00:00Z", "2026-08-02T07:00:00Z"),
    )
    _soft_delete(conn, "workouts", "wo-deleted")

    result = await call_tool(
        server,
        "list_workouts",
        {"start": "2026-08-01T00:00:00Z", "end": "2026-08-08T00:00:00Z"},
        app_context,
    )

    ids = {r["id"] for r in result["records"]}
    assert ids == {"wo-kept"}


async def test_get_workout_does_not_resurrect_a_soft_deleted_workout(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    upsert_workout(
        conn,
        WHOOP_USER_ID,
        workout_record("wo-kept", "2026-08-01T06:00:00Z", "2026-08-01T07:00:00Z"),
    )
    upsert_workout(
        conn,
        WHOOP_USER_ID,
        workout_record("wo-deleted", "2026-08-02T06:00:00Z", "2026-08-02T07:00:00Z"),
    )
    _soft_delete(conn, "workouts", "wo-deleted")

    result = await call_tool(server, "get_workout", {"workout_id": "wo-deleted"}, app_context)

    assert result.get("error") == "not_found_in_store"


async def test_whoop_data_coverage_excludes_soft_deleted_from_the_window(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A soft-deleted row at the latest edge must not anchor the reported
    window -- the same 'inverted #15 bug' this issue's own pre-verified facts
    warn about."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    upsert_recovery(conn, WHOOP_USER_ID, recovery_record(100, "2026-08-01T06:30:00Z"))
    upsert_recovery(conn, WHOOP_USER_ID, recovery_record(101, "2026-08-10T06:30:00Z"))
    _soft_delete(conn, "recoveries", "101")

    result = await call_tool(server, "whoop_data_coverage", {}, app_context)

    assert result["recoveries"]["latest"] == "2026-08-01T06:30:00Z"
