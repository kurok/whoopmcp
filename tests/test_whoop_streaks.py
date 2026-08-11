"""Tests for issue #24's ``whoop_streaks``: consecutive-day runs above or
below a threshold, over the local store.

Written before the implementation exists -- every test in this file is
expected to fail (ImportError from the still-missing tool, a KeyError on
``context_budget.TOOL_CEILINGS["whoop_streaks"]`` in test_context_budget.py,
or a plain assertion failure) until #24 lands. Nothing here calls the real
WHOOP API; every happy-path test wraps its call in ``with respx.mock:`` with
no routes registered, mirroring tests/test_whoop_timeseries.py's own
convention.

Response shape assumed below:

    {
        "metric": str,
        "direction": "above" | "below",
        "threshold": float,
        "days": [{"date": ..., "status": "passing"|"failing"|"missing", "value": float|None}, ...],
        "streaks": [{"start": ..., "end": ..., "length": int, "mean": float}, ...],
        "period": {"start": ..., "end": ...},
        "truncated": bool,
        "note": str,  # present only when truncated
        "coverage": {...},        # full envelope, per #16/metric_trend
        "range_coverage": {...},  # full envelope, per #16/metric_trend
    }

Every calendar day in [start, end] is enumerated in "days", not just measured
ones -- a day absent from the store is "missing" (unmeasured), distinct from
a measured day that failed the threshold ("failing"). Per-streak entries
deliberately omit "direction" (constant across the whole response, stated
once at the top level).
"""

from __future__ import annotations

import time
from datetime import date, timedelta
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
from whoopmcp.store import link_principal_to_member, open_store, upsert_recovery

WHOOP_USER_ID = 12345


# -- fixture helpers, deliberately kept local -- same rationale
# test_whoop_timeseries.py already gives for its own copy of these. -------


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


def recovery_record(
    cycle_id: int,
    created_at: str,
    *,
    score_state: str = "SCORED",
    recovery_score: float = 65.0,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "cycle_id": cycle_id,
        "created_at": created_at,
        "score_state": score_state,
    }
    if score_state == "SCORED":
        record["score"] = {
            "recovery_score": recovery_score,
            "hrv_rmssd_milli": 48.5,
            "resting_heart_rate": 55.0,
        }
    return record


def _day(iso_date: str, hour: str = "06:00:00") -> str:
    return f"{iso_date}T{hour}Z"


def _seed_daily_recovery(
    conn: Any, start_date: date, values: list[float | None], *, id_offset: int = 0
) -> None:
    """One recovery record per day starting at ``start_date``, skipping any
    index whose value is ``None`` -- a deliberate calendar gap (missing,
    unmeasured), never a zero-valued record."""
    for i, value in enumerate(values):
        if value is None:
            continue
        day = start_date + timedelta(days=i)
        upsert_recovery(
            conn,
            WHOOP_USER_ID,
            recovery_record(id_offset + i, _day(day.isoformat()), recovery_score=value),
        )


# -- streaks found in both directions, correct start/end/length/mean -------


async def test_whoop_streaks_above_and_below_directions(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A clear high-run and low-run of known length/mean; direction="above"
    finds the high-run, direction="below" finds the low-run -- and neither
    streak entry carries a per-item "direction" key."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    start_date = date(2026, 2, 1)
    values: list[float | None] = [80.0] * 5 + [50.0] * 5 + [20.0] * 5 + [50.0] * 5
    _seed_daily_recovery(conn, start_date, values, id_offset=1000)
    end_date = start_date + timedelta(days=len(values) - 1)

    with respx.mock:
        above_result = await call_tool(
            server,
            "whoop_streaks",
            {
                "metric": "recovery_score",
                "start": f"{start_date.isoformat()}T00:00:00Z",
                "end": f"{end_date.isoformat()}T23:59:59Z",
                "threshold": 70.0,
                "direction": "above",
            },
            app_context,
        )

    assert above_result["direction"] == "above"
    assert above_result["threshold"] == pytest.approx(70.0)
    assert len(above_result["streaks"]) == 1
    high = above_result["streaks"][0]
    assert "direction" not in high
    assert high["start"] == start_date.isoformat()
    assert high["end"] == (start_date + timedelta(days=4)).isoformat()
    assert high["length"] == 5
    assert high["mean"] == pytest.approx(80.0)

    with respx.mock:
        below_result = await call_tool(
            server,
            "whoop_streaks",
            {
                "metric": "recovery_score",
                "start": f"{start_date.isoformat()}T00:00:00Z",
                "end": f"{end_date.isoformat()}T23:59:59Z",
                "threshold": 30.0,
                "direction": "below",
            },
            app_context,
        )

    assert below_result["direction"] == "below"
    assert len(below_result["streaks"]) == 1
    low = below_result["streaks"][0]
    assert "direction" not in low
    assert low["start"] == (start_date + timedelta(days=10)).isoformat()
    assert low["end"] == (start_date + timedelta(days=14)).isoformat()
    assert low["length"] == 5
    assert low["mean"] == pytest.approx(20.0)


# -- missing vs. failing: the literal acceptance-criterion test ------------


async def test_whoop_streaks_missing_vs_failing_distinguished(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """One calendar day genuinely unmeasured (no scored record at all) and
    one day measured but below threshold, both inside what would
    otherwise be one 8-day passing run. The "days" list's own "status"
    field must distinguish the two explicitly."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    start_date = date(2026, 4, 1)
    # Index 3 (2026-04-04): None -> deliberately no record at all (missing).
    # Index 4 (2026-04-05): measured, but fails the threshold.
    values: list[float | None] = [80.0, 80.0, 80.0, None, 50.0, 80.0, 80.0, 80.0]
    _seed_daily_recovery(conn, start_date, values, id_offset=2000)
    end_date = start_date + timedelta(days=len(values) - 1)

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_streaks",
            {
                "metric": "recovery_score",
                "start": f"{start_date.isoformat()}T00:00:00Z",
                "end": f"{end_date.isoformat()}T23:59:59Z",
                "threshold": 70.0,
                "direction": "above",
            },
            app_context,
        )

    days_by_date = {d["date"]: d for d in result["days"]}
    missing_date = (start_date + timedelta(days=3)).isoformat()
    failing_date = (start_date + timedelta(days=4)).isoformat()
    missing_day = days_by_date[missing_date]
    failing_day = days_by_date[failing_date]

    assert missing_day["status"] == "missing"
    assert missing_day["value"] is None
    assert failing_day["status"] == "failing"
    assert failing_day["value"] == pytest.approx(50.0)
    assert missing_day["status"] != failing_day["status"], (
        "a day with no strap data on and a day that was measured and failed the threshold "
        "must be distinguishable, per the issue's own acceptance criterion"
    )

    assert len(result["streaks"]) == 2
    first, second = result["streaks"]
    assert (first["start"], first["end"], first["length"]) == (
        start_date.isoformat(),
        (start_date + timedelta(days=2)).isoformat(),
        3,
    )
    assert (second["start"], second["end"], second["length"]) == (
        (start_date + timedelta(days=5)).isoformat(),
        (start_date + timedelta(days=7)).isoformat(),
        3,
    )


# -- a single-value range and an empty range both return coherently --------


async def test_whoop_streaks_empty_and_single_value_range(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None

    # Inverted range: start after end. No exception, coherent empty output,
    # for both directions.
    for direction in ("above", "below"):
        with respx.mock:
            result = await call_tool(
                server,
                "whoop_streaks",
                {
                    "metric": "recovery_score",
                    "start": "2026-08-10T00:00:00Z",
                    "end": "2026-08-01T00:00:00Z",
                    "threshold": 50.0,
                    "direction": direction,
                },
                app_context,
            )
        assert result["days"] == []
        assert result["streaks"] == []

    # Single-day range with one measured, passing point.
    conn = app_context.store_conn
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(3001, _day("2026-09-01"), recovery_score=80.0)
    )
    with respx.mock:
        single_result = await call_tool(
            server,
            "whoop_streaks",
            {
                "metric": "recovery_score",
                "start": "2026-09-01T00:00:00Z",
                "end": "2026-09-01T23:59:59Z",
                "threshold": 70.0,
                "direction": "above",
            },
            app_context,
        )
    assert len(single_result["days"]) == 1
    assert single_result["days"][0]["status"] == "passing"
    assert len(single_result["streaks"]) == 1
    assert single_result["streaks"][0]["length"] == 1

    # Single-day range with nothing measured at all: missing, not a crash.
    with respx.mock:
        single_missing_result = await call_tool(
            server,
            "whoop_streaks",
            {
                "metric": "recovery_score",
                "start": "2026-09-02T00:00:00Z",
                "end": "2026-09-02T23:59:59Z",
                "threshold": 70.0,
                "direction": "above",
            },
            app_context,
        )
    assert len(single_missing_result["days"]) == 1
    assert single_missing_result["days"][0]["status"] == "missing"
    assert single_missing_result["days"][0]["value"] is None
    assert single_missing_result["streaks"] == []


# -- zero API calls on the happy path ----------------------------------------


async def test_no_api_call_on_happy_path(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """No route is registered above -- respx's own AllMockedAssertionError
    would already fail this test before the explicit assertion below runs
    if the tool issued any HTTP request at all."""
    assert app_context.store_conn is not None
    _seed_daily_recovery(app_context.store_conn, date(2026, 5, 1), [80.0] * 10, id_offset=4000)

    with respx.mock:
        await call_tool(
            server,
            "whoop_streaks",
            {
                "metric": "recovery_score",
                "start": "2026-05-01T00:00:00Z",
                "end": "2026-05-10T23:59:59Z",
                "threshold": 70.0,
                "direction": "above",
            },
            app_context,
        )
        assert len(respx.calls) == 0


# -- registered as a real MCP tool -------------------------------------------


async def test_whoop_streaks_is_registered() -> None:
    tools = await build_server().list_tools()
    names = {tool.name for tool in tools}
    assert "whoop_streaks" in names
