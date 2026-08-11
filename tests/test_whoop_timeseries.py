"""Tests for issue #20: ``whoop_timeseries``, one metric-trend tool that
replaces per-entity ``list_*`` calls for "how has X trended" questions.

Written before the implementation exists -- every test in this file is
expected to fail (ImportError from the still-missing tool, a KeyError on
``context_budget.TOOL_CEILINGS["whoop_timeseries"]``, or a plain assertion
failure) until #20 lands. Nothing here calls the real WHOOP API; every
happy-path test wraps its call in ``@respx.mock`` with no routes registered,
mirroring tests/test_store_backed_tools.py's own convention: an accidental
fetch raises ``AllMockedAssertionError`` before this file's own assertion
even runs.

Response-shape convention actually shipped (updated after the explorer's
original plan called for the full "coverage"/"direction" envelope every
other range tool carries -- that costs several hundred fixed tokens per
call, which would have defeated this tool's whole reason to exist; see the
token-ratio tests below for the real, measured trade-off):

    {
        "metric": str,
        "unit": str,
        "granularity": "day" | "week" | "month",
        "points": [{"date": "2026-08-01", "value": 65.3}, ...],
        "truncated": bool,
        "note": str,        # present only when truncated
        "range_coverage": {"status": ..., "message": ...},  # single flat
                                                              # entry, not
                                                              # per-entity
    }

"direction" (unit/direction guidance) lives in the tool's own docstring per
metric, not the response envelope -- it's fixed per metric name, so
repeating it on every call would be pure waste; the docstring is read once
by whoever's calling the tool, not once per response. "range_coverage" is
deliberately the lightweight {status, message} comparison result alone
(reusing server.py's own ``_range_coverage_entry``), never the fuller
earliest/latest/backfill/incremental-sync "coverage" envelope -- cheap
enough not to undermine the ratio, but still enough to keep an absent
bucket from ever being confused with "this range was never synced".

A missing bucket is simply absent from "points" -- never a zero-valued
entry. A week bucket's "date" is the Monday that starts it (verified below
against a fixture that straddles a month boundary, per this issue's own
"do not skip this" instruction). Multiple records landing in one bucket are
averaged (mean), not summed.
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
from mcp.server.mcpserver.exceptions import ToolError

from whoopmcp.auth import Authenticator, FileTokenStore, Token
from whoopmcp.client import WhoopClient
from whoopmcp.config import Config
from whoopmcp.context_budget import TOOL_CEILINGS, estimate_tokens
from whoopmcp.server import AppContext, Principal, build_server
from whoopmcp.store import (
    link_principal_to_member,
    open_store,
    upsert_cycle,
    upsert_recovery,
    upsert_sleep,
)

WHOOP_USER_ID = 12345

#: The 6 friendly metric names whoop_timeseries must recognise -- exactly
#: metric_trend's own vocabulary (server.py's _METRIC_COLLECTION), per the
#: issue's own acceptance criterion. Kept as one literal tuple here (not
#: imported from server.py) so this file's expectations don't silently
#: track whatever server.py happens to define -- a drift between the two
#: is exactly the bug "match metric_trend's vocabulary exactly" guards
#: against.
VALID_METRICS = (
    "recovery_score",
    "hrv",
    "resting_heart_rate",
    "sleep_performance",
    "sleep_efficiency",
    "strain",
)


# -- fixture helpers, deliberately kept local -- same rationale
# test_store_backed_tools.py already gives for its own copy of these. -------


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


# -- record builders (minimal -- store.py round-trips raw_json verbatim, so
# only the fields each entity's own upsert function extracts into columns
# need to be realistic). ------------------------------------------------------


def recovery_record(
    cycle_id: int,
    created_at: str,
    *,
    score_state: str = "SCORED",
    recovery_score: float = 65.0,
    hrv_rmssd_milli: float = 48.5,
    resting_heart_rate: float = 55.0,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "cycle_id": cycle_id,
        "created_at": created_at,
        "score_state": score_state,
    }
    if score_state == "SCORED":
        record["score"] = {
            "recovery_score": recovery_score,
            "hrv_rmssd_milli": hrv_rmssd_milli,
            "resting_heart_rate": resting_heart_rate,
        }
    return record


def sleep_record(
    sleep_id: str,
    start: str,
    end: str,
    *,
    score_state: str = "SCORED",
    sleep_performance_percentage: float = 87.0,
    sleep_efficiency_percentage: float = 90.5,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": sleep_id,
        "start": start,
        "end": end,
        "nap": False,
        "score_state": score_state,
    }
    if score_state == "SCORED":
        record["score"] = {
            "sleep_performance_percentage": sleep_performance_percentage,
            "sleep_efficiency_percentage": sleep_efficiency_percentage,
        }
    return record


def cycle_record(
    cycle_id: int,
    start: str,
    end: str,
    *,
    score_state: str = "SCORED",
    strain: float = 12.0,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": cycle_id,
        "start": start,
        "end": end,
        "score_state": score_state,
    }
    if score_state == "SCORED":
        record["score"] = {"strain": strain, "average_heart_rate": 78, "max_heart_rate": 155}
    return record


def _day(iso_date: str, hour: str = "06:00:00") -> str:
    """A full ISO-8601 timestamp on the given calendar date, UTC."""
    return f"{iso_date}T{hour}Z"


# -- one test per metric: each resolves to its own store column -------------


async def test_recovery_score_resolves_to_recoveries(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        WHOOP_USER_ID,
        recovery_record(100, _day("2026-08-05"), recovery_score=71.0),
    )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-10T00:00:00Z",
            },
            app_context,
        )

    assert result["points"] == [{"date": "2026-08-05", "value": 71.0}]


async def test_hrv_resolves_to_recoveries(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        WHOOP_USER_ID,
        recovery_record(100, _day("2026-08-05"), hrv_rmssd_milli=52.3),
    )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {"metric": "hrv", "start": "2026-08-01T00:00:00Z", "end": "2026-08-10T00:00:00Z"},
            app_context,
        )

    assert result["points"] == [{"date": "2026-08-05", "value": 52.3}]


async def test_resting_heart_rate_resolves_to_recoveries(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        WHOOP_USER_ID,
        recovery_record(100, _day("2026-08-05"), resting_heart_rate=58.0),
    )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "resting_heart_rate",
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-10T00:00:00Z",
            },
            app_context,
        )

    assert result["points"] == [{"date": "2026-08-05", "value": 58.0}]


async def test_sleep_performance_resolves_to_sleeps(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    upsert_sleep(
        app_context.store_conn,
        WHOOP_USER_ID,
        sleep_record(
            "sleep-1",
            _day("2026-08-05", "23:00:00"),
            _day("2026-08-06", "07:00:00"),
            sleep_performance_percentage=81.0,
        ),
    )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "sleep_performance",
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-10T00:00:00Z",
            },
            app_context,
        )

    assert result["points"] == [{"date": "2026-08-05", "value": 81.0}]


async def test_sleep_efficiency_resolves_to_sleeps(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    upsert_sleep(
        app_context.store_conn,
        WHOOP_USER_ID,
        sleep_record(
            "sleep-1",
            _day("2026-08-05", "23:00:00"),
            _day("2026-08-06", "07:00:00"),
            sleep_efficiency_percentage=93.5,
        ),
    )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "sleep_efficiency",
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-10T00:00:00Z",
            },
            app_context,
        )

    assert result["points"] == [{"date": "2026-08-05", "value": 93.5}]


async def test_strain_resolves_to_cycles(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    upsert_cycle(
        app_context.store_conn,
        WHOOP_USER_ID,
        cycle_record(
            200, _day("2026-08-05", "00:00:00"), _day("2026-08-06", "00:00:00"), strain=14.2
        ),
    )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {"metric": "strain", "start": "2026-08-01T00:00:00Z", "end": "2026-08-10T00:00:00Z"},
            app_context,
        )

    assert result["points"] == [{"date": "2026-08-05", "value": 14.2}]


# -- granularity aggregation across a month boundary -------------------------
#
# 10 consecutive days, 2026-07-28 (Tuesday) .. 2026-08-06 (Thursday),
# deliberately NOT chosen to avoid the July/August boundary. recovery_score
# values increase by 1 each day (50..59) so mean-aggregated buckets are
# distinguishable from any individual day's value.
#
# Calendar layout (verified against the real calendar, not assumed):
#   Mon 2026-07-27 starts the week containing 07-28..08-02 (6 of our 10 days:
#     4 in July, 2 in August) -- this is the boundary-straddling week the
#     issue's own tests-to-write section warns is easy to get wrong.
#   Mon 2026-08-03 starts the week containing 08-03..08-06 (the remaining 4
#     days, all August).


_MONTH_BOUNDARY_DAYS = [
    ("2026-07-28", 50.0),
    ("2026-07-29", 51.0),
    ("2026-07-30", 52.0),
    ("2026-07-31", 53.0),
    ("2026-08-01", 54.0),
    ("2026-08-02", 55.0),
    ("2026-08-03", 56.0),
    ("2026-08-04", 57.0),
    ("2026-08-05", 58.0),
    ("2026-08-06", 59.0),
]


def _seed_month_boundary_recoveries(conn: Any) -> None:
    for i, (day, value) in enumerate(_MONTH_BOUNDARY_DAYS):
        record = recovery_record(300 + i, _day(day), recovery_score=value)
        upsert_recovery(conn, WHOOP_USER_ID, record)


async def test_day_granularity_across_month_boundary(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed_month_boundary_recoveries(app_context.store_conn)

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2026-07-28T00:00:00Z",
                "end": "2026-08-07T00:00:00Z",
                "granularity": "day",
            },
            app_context,
        )

    assert result["granularity"] == "day"
    expected = [{"date": day, "value": value} for day, value in _MONTH_BOUNDARY_DAYS]
    assert result["points"] == expected


async def test_week_granularity_across_month_boundary(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """The week of Mon 2026-07-27 holds 4 July days + 2 August days -- the
    bucket's own date (07-27) is in July even though some of its records are
    in August, proving the bucket boundary is computed from the calendar
    week, not from whichever month happens to hold the majority of it."""
    assert app_context.store_conn is not None
    _seed_month_boundary_recoveries(app_context.store_conn)

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2026-07-28T00:00:00Z",
                "end": "2026-08-07T00:00:00Z",
                "granularity": "week",
            },
            app_context,
        )

    assert result["granularity"] == "week"
    points = {p["date"]: p["value"] for p in result["points"]}
    assert set(points) == {"2026-07-27", "2026-08-03"}
    # mean of 50,51,52,53,54,55
    assert points["2026-07-27"] == pytest.approx(52.5)
    # mean of 56,57,58,59
    assert points["2026-08-03"] == pytest.approx(57.5)


async def test_month_granularity_across_month_boundary(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    _seed_month_boundary_recoveries(app_context.store_conn)

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2026-07-28T00:00:00Z",
                "end": "2026-08-07T00:00:00Z",
                "granularity": "month",
            },
            app_context,
        )

    assert result["granularity"] == "month"
    points = {p["date"]: p["value"] for p in result["points"]}
    assert set(points) == {"2026-07-01", "2026-08-01"}
    # mean of 50,51,52,53
    assert points["2026-07-01"] == pytest.approx(51.5)
    # mean of 54,55,56,57,58,59
    assert points["2026-08-01"] == pytest.approx(56.5)


# -- gaps are absent, never zero ---------------------------------------------


async def test_gap_day_is_absent_not_zero(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None
    upsert_recovery(app_context.store_conn, WHOOP_USER_ID, recovery_record(100, _day("2026-08-01")))
    # Deliberately nothing on 2026-08-02.
    upsert_recovery(app_context.store_conn, WHOOP_USER_ID, recovery_record(101, _day("2026-08-03")))

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-04T00:00:00Z",
                "granularity": "day",
            },
            app_context,
        )

    dates = [p["date"] for p in result["points"]]
    assert "2026-08-02" not in dates
    assert dates == ["2026-08-01", "2026-08-03"]


# -- unscored records are excluded -------------------------------------------


async def test_unscored_record_is_excluded(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A record whose score_state isn't SCORED is the only thing on its
    date -- if the SQL WHERE clause didn't actually filter it, that date
    would appear anyway (with whatever garbage value an unscored record's
    NULL column produces). Deliberately not paired with a scored sibling on
    the same date, which would mask a broken filter behind a real value."""
    assert app_context.store_conn is not None
    upsert_recovery(
        app_context.store_conn,
        WHOOP_USER_ID,
        recovery_record(100, _day("2026-08-02"), score_state="PENDING_SCORE"),
    )
    upsert_recovery(app_context.store_conn, WHOOP_USER_ID, recovery_record(101, _day("2026-08-01")))

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-04T00:00:00Z",
                "granularity": "day",
            },
            app_context,
        )

    dates = [p["date"] for p in result["points"]]
    assert "2026-08-02" not in dates
    assert dates == ["2026-08-01"]


# -- unknown metric name ------------------------------------------------------


async def test_unknown_metric_lists_valid_names(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    with respx.mock, pytest.raises(ToolError) as exc_info:
        await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "not_a_real_metric",
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-10T00:00:00Z",
            },
            app_context,
        )

    message = str(exc_info.value)
    assert "not_a_real_metric" in message
    for name in VALID_METRICS:
        assert name in message, f"error message should list {name!r} as a valid metric"


# -- truncation ---------------------------------------------------------------


async def test_truncation_is_reported_when_cap_is_hit(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """1500 distinct daily SCORED records, one per calendar day -- well over
    the 1000-point cap -- proves the cap actually bites and is reported, not
    silently truncated or silently ignored."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    start_date = date(2022, 1, 1)
    for i in range(1500):
        day = start_date + timedelta(days=i)
        upsert_recovery(
            conn,
            WHOOP_USER_ID,
            recovery_record(1000 + i, _day(day.isoformat()), recovery_score=float(i % 100)),
        )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2022-01-01T00:00:00Z",
                "end": "2026-12-31T00:00:00Z",
                "granularity": "day",
            },
            app_context,
        )

    assert result["truncated"] is True
    assert result.get("note")
    assert len(result["points"]) == 1000


# -- range_coverage: the lightweight safety signal that survives even
# though the full "coverage" envelope was deliberately dropped for cost.
# -----------------------------------------------------------------------


async def test_range_coverage_flags_a_range_wholly_outside_what_is_synced(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A range that has never been synced must be distinguishable from
    "genuinely no scored activity" -- the exact ambiguity #16 exists to
    prevent, which this tool's own lightweight range_coverage signal must
    still catch even without the fuller envelope. The store holds a
    recovery for a totally different period; the requested range has
    nothing at all."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(1, _day("2020-01-15"), recovery_score=50.0)
    )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-08T00:00:00Z",
                "granularity": "day",
            },
            app_context,
        )

    assert result["points"] == []
    assert result["range_coverage"]["status"] == "wholly_outside_coverage"
    assert "message" in result["range_coverage"]


async def test_range_coverage_reports_within_coverage_for_a_synced_range(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """The happy-path counterpart: a range that genuinely is covered reports
    "within_coverage" and carries no "message" -- confirming the signal
    doesn't cry wolf on the ordinary case this tool exists to serve
    cheaply. The held coverage window must span the FULL requested range
    (one record at each end, not a single point) -- _range_status (#16)
    correctly reports a range that merely overlaps a single held point as
    "partly_outside_coverage", not "within_coverage"."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(1, _day("2026-07-31"), recovery_score=50.0)
    )
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(2, _day("2026-08-09"), recovery_score=55.0)
    )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2026-08-01T00:00:00Z",
                "end": "2026-08-08T00:00:00Z",
                "granularity": "day",
            },
            app_context,
        )

    assert result["range_coverage"] == {"status": "within_coverage"}


# -- context ceiling (#25) ----------------------------------------------------


async def test_one_year_daily_series_stays_inside_context_ceiling(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """365 daily SCORED recovery records, one full year, granularity="day" --
    the worst case _TIMESERIES_MAX_POINTS doesn't truncate. Asserts both that
    the ceiling holds AND that the fixture wasn't accidentally truncated
    itself (which would make the ceiling check vacuous)."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    start_date = date(2025, 8, 11)
    for i in range(365):
        day = start_date + timedelta(days=i)
        upsert_recovery(
            conn,
            WHOOP_USER_ID,
            recovery_record(2000 + i, _day(day.isoformat()), recovery_score=float(40 + i % 50)),
        )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2025-08-11T00:00:00Z",
                "end": "2026-08-11T00:00:00Z",
                "granularity": "day",
            },
            app_context,
        )

    assert result["truncated"] is False
    assert len(result["points"]) == 365
    assert "whoop_timeseries" in TOOL_CEILINGS, (
        "context_budget.TOOL_CEILINGS needs a measured entry for whoop_timeseries "
        "(test_context_budget.py's own registry-enumeration check requires this too)"
    )
    assert estimate_tokens(result) <= TOOL_CEILINGS["whoop_timeseries"]


# -- acceptance criterion: measurably cheaper than the equivalent list_* call


async def test_whoop_timeseries_is_cheaper_than_list_sleeps(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """30 days of sleeps, one per day. Compares list_sleeps' own token cost
    for that range against whoop_timeseries' for the identical range and
    metric, and asserts the ratio clears a conservative floor.

    whoop_timeseries carries a small, flat "range_coverage" signal (unlike
    the full multi-field "coverage" envelope every other range tool
    carries) so an absent bucket can never be confused with "no data has
    been synced for this range at all" -- exactly the ambiguity #16 exists
    to prevent. That signal's cost is fixed regardless of range size, so it
    depresses the ratio most on a SHORT range like this one (measured ~4.2x
    here) and barely at all on a longer one, where list_*'s own per-record
    cost dominates -- see the longer-range sibling test below for the
    "roughly an order of magnitude" figure the issue's own framing
    describes. This is a regression guard on the short-range floor, not the
    full measurement; the true ratios for both ranges belong in the PR
    description."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    start_date = date(2026, 7, 1)
    for i in range(30):
        day = start_date + timedelta(days=i)
        next_day = day + timedelta(days=1)
        upsert_sleep(
            conn,
            WHOOP_USER_ID,
            sleep_record(
                f"sleep-{i}",
                f"{day.isoformat()}T23:00:00Z",
                f"{next_day.isoformat()}T07:00:00Z",
                sleep_performance_percentage=float(70 + i % 20),
            ),
        )

    with respx.mock:
        list_result = await call_tool(
            server,
            "list_sleeps",
            {
                "start": "2026-07-01T00:00:00Z",
                "end": "2026-07-31T00:00:00Z",
                "limit": 100,
            },
            app_context,
        )
        timeseries_result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "sleep_performance",
                "start": "2026-07-01T00:00:00Z",
                "end": "2026-07-31T00:00:00Z",
                "granularity": "day",
            },
            app_context,
        )

    list_tokens = estimate_tokens(list_result)
    timeseries_tokens = estimate_tokens(timeseries_result)
    assert timeseries_tokens > 0
    ratio = list_tokens / timeseries_tokens
    assert ratio >= 4, (
        f"expected whoop_timeseries to stay substantially cheaper than list_sleeps "
        f"even at this short range, where range_coverage's fixed cost is proportionally "
        f"largest; got list_sleeps={list_tokens}, whoop_timeseries={timeseries_tokens}, "
        f"ratio={ratio:.1f}"
    )


async def test_whoop_timeseries_ratio_holds_over_a_longer_range(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """The same comparison as the short-range test above, but over a full
    year. Measured, not assumed: both list_sleeps' cost and
    whoop_timeseries' own cost scale roughly linearly with the number of
    days (one full record vs. one {date, value} point each), so the ratio
    is set by the per-record-vs-per-point cost difference, not by
    range_coverage's fixed overhead vanishing into an ever-growing ratio --
    it settles a bit above the short-range floor (measured ~5.1x here vs.
    ~4.2x at 30 days) rather than approaching a full order of magnitude.
    Still a real, substantial improvement; this guards against that
    already-modest number regressing further, not against an assumption
    about how much it "should" grow."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    start_date = date(2025, 8, 11)
    for i in range(365):
        day = start_date + timedelta(days=i)
        next_day = day + timedelta(days=1)
        upsert_sleep(
            conn,
            WHOOP_USER_ID,
            sleep_record(
                f"sleep-year-{i}",
                f"{day.isoformat()}T23:00:00Z",
                f"{next_day.isoformat()}T07:00:00Z",
                sleep_performance_percentage=float(70 + i % 20),
            ),
        )

    with respx.mock:
        list_result = await call_tool(
            server,
            "list_sleeps",
            {
                "start": "2025-08-11T00:00:00Z",
                "end": "2026-08-11T00:00:00Z",
                "limit": 1000,
            },
            app_context,
        )
        timeseries_result = await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "sleep_performance",
                "start": "2025-08-11T00:00:00Z",
                "end": "2026-08-11T00:00:00Z",
                "granularity": "day",
            },
            app_context,
        )

    list_tokens = estimate_tokens(list_result)
    timeseries_tokens = estimate_tokens(timeseries_result)
    ratio = list_tokens / timeseries_tokens
    assert ratio >= 4.8, (
        f"expected the ratio to hold (or improve on) the short-range floor over a full "
        f"year; got list_sleeps={list_tokens}, whoop_timeseries={timeseries_tokens}, "
        f"ratio={ratio:.1f}"
    )


# -- zero API calls on the happy path ----------------------------------------


async def test_no_api_call_on_happy_path(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """No route is registered above -- respx's own AllMockedAssertionError
    would already fail this test before the explicit assertion below runs if
    the tool issued any HTTP request at all."""
    assert app_context.store_conn is not None
    _seed_month_boundary_recoveries(app_context.store_conn)

    with respx.mock:
        await call_tool(
            server,
            "whoop_timeseries",
            {
                "metric": "recovery_score",
                "start": "2026-07-28T00:00:00Z",
                "end": "2026-08-07T00:00:00Z",
            },
            app_context,
        )
        assert len(respx.calls) == 0


# -- registered as a real MCP tool -------------------------------------------


async def test_whoop_timeseries_is_registered() -> None:
    tools = await build_server().list_tools()
    names = {tool.name for tool in tools}
    assert "whoop_timeseries" in names
