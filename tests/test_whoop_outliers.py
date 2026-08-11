"""Tests for issue #24's ``whoop_outliers``: rolling-z-score anomaly
detection with context, over the local store.

Written before the implementation exists -- every test in this file is
expected to fail (ImportError from the still-missing tool, a KeyError on
``context_budget.TOOL_CEILINGS["whoop_outliers"]`` in test_context_budget.py,
or a plain assertion failure) until #24 lands. Nothing here calls the real
WHOOP API; every happy-path test wraps its call in ``@respx.mock`` (or a
bare ``with respx.mock:`` with no routes registered), mirroring
tests/test_whoop_timeseries.py's own convention: an accidental fetch raises
``AllMockedAssertionError`` before this file's own assertion even runs.

Response shape assumed below (see the issue's own explorer notes for the
full rationale -- not re-litigated here):

    {
        "metric": str,
        "window_days": int,
        "z_threshold": float,
        "scored_days_count": int,
        "outliers": [
            {
                "date": "2026-07-21", "value": 90.0, "z_score": 3.4,
                "baseline_mean": ..., "baseline_stdev": ...,
                "context_before": [{"date": ..., "value": ...}, ...],
                "context_after": [{"date": ..., "value": ...}, ...],
                "other_metrics": {"hrv": {"value": ..., "unit": ...}, ...},
            },
            ...
        ],
        "warmup_days": [{"date": ..., "value": ..., "reason": "warm_up"}, ...],
        "period": {"start": ..., "end": ...},
        "truncated": bool,
        "note": str,  # present only when truncated
        "coverage": {...},        # full envelope, per #16/metric_trend
        "range_coverage": {...},  # full envelope, per #16/metric_trend
    }

A day-deduplicated series sourced from ``store.get_metric_series`` (day
granularity, already SCORED-filtered) -- a day with no scored record is
simply absent, never a zero-valued entry. Context days are nearest
*measured* neighbours in that series, not literal calendar-adjacent days.
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
from whoopmcp.store import (
    link_principal_to_member,
    open_store,
    upsert_cycle,
    upsert_recovery,
    upsert_sleep,
)

WHOOP_USER_ID = 12345

#: The tool's own internal rolling-window size (14 calendar days -- see the
#: issue's own explorer notes for why 14, not 7 or 30). Duplicated here as a
#: literal, not imported from server.py, so a drift between this file's own
#: expectations and whatever server.py happens to define is a test failure,
#: not silently masked.
WINDOW_DAYS = 14


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


# -- record builders (minimal, matching tests/test_whoop_timeseries.py's
# own) --------------------------------------------------------------------


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


def _seed_daily_recovery(
    conn: Any, start_date: date, values: list[float], *, id_offset: int = 0
) -> None:
    """One recovery record per consecutive calendar day starting at
    ``start_date``, ``values`` taken in order."""
    for i, value in enumerate(values):
        day = start_date + timedelta(days=i)
        upsert_recovery(
            conn,
            WHOOP_USER_ID,
            recovery_record(id_offset + i, _day(day.isoformat()), recovery_score=value),
        )


# -- outliers found on a fixture with known anomalies, with context -------


async def test_whoop_outliers_finds_known_anomaly_with_context(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A 25-day flat recovery_score series with one deliberate spike, plus
    other metrics populated on the spike day -- "your HRV cratered on the
    14th" is only useful alongside what else happened that day."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    start_date = date(2026, 7, 1)
    spike_index = 20
    values = [50.0] * 25
    values[spike_index] = 90.0
    _seed_daily_recovery(conn, start_date, values, id_offset=3000)

    spike_day = (start_date + timedelta(days=spike_index)).isoformat()
    next_day = (start_date + timedelta(days=spike_index + 1)).isoformat()
    upsert_sleep(
        conn,
        WHOOP_USER_ID,
        sleep_record(
            "sleep-spike",
            _day(spike_day, "22:00:00"),
            _day(next_day, "06:00:00"),
            sleep_performance_percentage=60.0,
            sleep_efficiency_percentage=65.0,
        ),
    )
    upsert_cycle(
        conn,
        WHOOP_USER_ID,
        cycle_record(9000, _day(spike_day, "00:00:00"), _day(next_day, "00:00:00"), strain=18.5),
    )

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_outliers",
            {
                "metric": "recovery_score",
                "start": "2026-07-01T00:00:00Z",
                "end": "2026-07-26T00:00:00Z",
            },
            app_context,
        )

    outliers = result["outliers"]
    assert len(outliers) == 1, f"expected exactly one outlier, got {outliers!r}"
    outlier = outliers[0]
    assert outlier["date"] == spike_day
    assert outlier["value"] == pytest.approx(90.0)
    assert outlier["z_score"] is not None
    assert abs(outlier["z_score"]) >= 2.0

    before_dates = [c["date"] for c in outlier["context_before"]]
    after_dates = [c["date"] for c in outlier["context_after"]]
    assert before_dates == [
        (start_date + timedelta(days=spike_index - offset)).isoformat() for offset in (3, 2, 1)
    ]
    assert after_dates == [
        (start_date + timedelta(days=spike_index + offset)).isoformat() for offset in (1, 2, 3)
    ]
    assert all(c["value"] == pytest.approx(50.0) for c in outlier["context_before"])
    assert all(c["value"] == pytest.approx(50.0) for c in outlier["context_after"])

    other_metrics = outlier["other_metrics"]
    assert other_metrics["hrv"]["value"] == pytest.approx(48.5)
    assert other_metrics["resting_heart_rate"]["value"] == pytest.approx(55.0)
    assert other_metrics["sleep_performance"]["value"] == pytest.approx(60.0)
    assert other_metrics["sleep_efficiency"]["value"] == pytest.approx(65.0)
    assert other_metrics["strain"]["value"] == pytest.approx(18.5)
    for entry in other_metrics.values():
        assert "unit" in entry


# -- a slow seasonal drift does not flag every day -------------------------


async def test_whoop_outliers_seasonal_drift_does_not_flag_every_day(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """150 days at a stable baseline, then a genuine, sustained 30-day
    level shift ("a slow seasonal drift") -- the shifted month must not
    come back as a month of outliers; the rolling window re-adapts."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    start_date = date(2026, 1, 1)
    baseline_days = 150
    shift_days = 30
    values = [50.0] * baseline_days + [65.0] * shift_days
    _seed_daily_recovery(conn, start_date, values, id_offset=5000)

    end_date = start_date + timedelta(days=baseline_days + shift_days)

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_outliers",
            {
                "metric": "recovery_score",
                "start": f"{start_date.isoformat()}T00:00:00Z",
                "end": f"{end_date.isoformat()}T00:00:00Z",
            },
            app_context,
        )

    shift_dates = {
        (start_date + timedelta(days=baseline_days + j)).isoformat() for j in range(shift_days)
    }
    flagged_shift_dates = {o["date"] for o in result["outliers"] if o["date"] in shift_dates}
    assert len(flagged_shift_dates) < shift_days, (
        "a genuine seasonal shift must not flag every day of the shifted month"
    )
    assert len(flagged_shift_dates) <= 3

    deep_shift_date = (start_date + timedelta(days=baseline_days + 20)).isoformat()
    assert deep_shift_date not in flagged_shift_dates, (
        "well into the new regime the rolling window has re-adapted -- this day is simply "
        "the new normal, not an anomaly"
    )


# -- warm-up days are reported as unscored, not absent ---------------------


async def test_whoop_outliers_reports_warmup_days_not_absent(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A 20-day series with a 14-day rolling window: the first 13 days
    cannot be scored and must appear in "warmup_days", not be silently
    dropped from the response."""
    assert app_context.store_conn is not None
    conn = app_context.store_conn
    start_date = date(2026, 5, 1)
    total_days = 20
    _seed_daily_recovery(conn, start_date, [50.0] * total_days, id_offset=7000)
    end_date = start_date + timedelta(days=total_days)

    with respx.mock:
        result = await call_tool(
            server,
            "whoop_outliers",
            {
                "metric": "recovery_score",
                "start": f"{start_date.isoformat()}T00:00:00Z",
                "end": f"{end_date.isoformat()}T00:00:00Z",
            },
            app_context,
        )

    warmup_dates = {w["date"] for w in result["warmup_days"]}
    expected_warmup_dates = {
        (start_date + timedelta(days=i)).isoformat() for i in range(WINDOW_DAYS - 1)
    }
    assert warmup_dates, "warm-up days must not be absent from the response"
    assert warmup_dates == expected_warmup_dates
    for entry in result["warmup_days"]:
        assert entry["reason"]
    assert result["scored_days_count"] == total_days - (WINDOW_DAYS - 1)
    # None of the warm-up days should also appear as outliers -- they are
    # unscored, not "not an outlier".
    outlier_dates = {o["date"] for o in result["outliers"]}
    assert not (warmup_dates & outlier_dates)


# -- context truncated correctly at the range's own edges ------------------


async def test_whoop_outliers_context_truncated_at_range_edges(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """Context is nearest-measured-neighbours in the day-deduplicated
    series, not literal calendar days -- so it truncates whenever fewer
    than the fixed radius (3) of measured days exist on one side, which
    happens at the edge of what the store actually holds for the
    requested range. Two scenarios, deliberately on non-overlapping
    years so they cannot interact within the same store:

    (a) sparse early history: only 2 measured days precede the outlier
        within the requested range -- context_before comes back with 2
        entries, not 3, and not an error.
    (b) the outlier is the very last measured day the store holds within
        the requested range -- context_after comes back empty.
    """
    assert app_context.store_conn is not None
    conn = app_context.store_conn

    # (a) sparse before-history, truncated context_before.
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(8001, _day("2026-01-01"), recovery_score=50.0)
    )
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(8002, _day("2026-01-14"), recovery_score=50.0)
    )
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(8003, _day("2026-01-27"), recovery_score=90.0)
    )
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(8004, _day("2026-01-28"), recovery_score=50.0)
    )
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(8005, _day("2026-01-29"), recovery_score=50.0)
    )
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(8006, _day("2026-01-30"), recovery_score=50.0)
    )

    with respx.mock:
        result_a = await call_tool(
            server,
            "whoop_outliers",
            {
                "metric": "recovery_score",
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-01-31T00:00:00Z",
            },
            app_context,
        )

    outliers_a = [o for o in result_a["outliers"] if o["date"] == "2026-01-27"]
    assert len(outliers_a) == 1
    outlier_a = outliers_a[0]
    assert len(outlier_a["context_before"]) == 2, (
        f"expected a truncated (2-entry) context_before, got {outlier_a['context_before']!r}"
    )
    assert [c["date"] for c in outlier_a["context_before"]] == ["2026-01-01", "2026-01-14"]
    assert len(outlier_a["context_after"]) == 3

    # (b) dense history, outlier is the store's own last measured day
    # within the requested range -- truncated context_after.
    dense_start = date(2027, 3, 1)
    _seed_daily_recovery(conn, dense_start, [50.0] * 14, id_offset=8100)
    upsert_recovery(
        conn,
        WHOOP_USER_ID,
        recovery_record(
            8199, _day((dense_start + timedelta(days=14)).isoformat()), recovery_score=90.0
        ),
    )

    with respx.mock:
        result_b = await call_tool(
            server,
            "whoop_outliers",
            {
                "metric": "recovery_score",
                "start": "2027-03-01T00:00:00Z",
                "end": "2027-03-16T00:00:00Z",
            },
            app_context,
        )

    spike_date_b = (dense_start + timedelta(days=14)).isoformat()
    outliers_b = [o for o in result_b["outliers"] if o["date"] == spike_date_b]
    assert len(outliers_b) == 1
    outlier_b = outliers_b[0]
    assert len(outlier_b["context_before"]) == 3
    assert outlier_b["context_after"] == [], (
        f"expected an empty (truncated) context_after at the store's own last measured day, "
        f"got {outlier_b['context_after']!r}"
    )


# -- a single-value range and an empty range both return coherently --------


async def test_whoop_outliers_empty_and_single_day_range(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    assert app_context.store_conn is not None

    with respx.mock:
        empty_result = await call_tool(
            server,
            "whoop_outliers",
            {
                "metric": "recovery_score",
                "start": "2026-09-01T00:00:00Z",
                "end": "2026-09-10T00:00:00Z",
            },
            app_context,
        )
    assert empty_result["outliers"] == []
    assert empty_result["warmup_days"] == []
    assert empty_result["scored_days_count"] == 0

    conn = app_context.store_conn
    upsert_recovery(
        conn, WHOOP_USER_ID, recovery_record(9001, _day("2026-10-05"), recovery_score=65.0)
    )
    with respx.mock:
        single_result = await call_tool(
            server,
            "whoop_outliers",
            {
                "metric": "recovery_score",
                "start": "2026-10-05T00:00:00Z",
                "end": "2026-10-05T23:59:59Z",
            },
            app_context,
        )
    assert single_result["outliers"] == []
    assert single_result["scored_days_count"] == 0


# -- zero API calls on the happy path ----------------------------------------


async def test_no_api_call_on_happy_path(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """No route is registered above -- respx's own AllMockedAssertionError
    would already fail this test before the explicit assertion below runs
    if the tool issued any HTTP request at all."""
    assert app_context.store_conn is not None
    _seed_daily_recovery(app_context.store_conn, date(2026, 6, 1), [50.0] * 20, id_offset=6000)

    with respx.mock:
        await call_tool(
            server,
            "whoop_outliers",
            {
                "metric": "recovery_score",
                "start": "2026-06-01T00:00:00Z",
                "end": "2026-06-21T00:00:00Z",
            },
            app_context,
        )
        assert len(respx.calls) == 0


# -- registered as a real MCP tool -------------------------------------------


async def test_whoop_outliers_is_registered() -> None:
    tools = await build_server().list_tools()
    names = {tool.name for tool in tools}
    assert "whoop_outliers" in names
