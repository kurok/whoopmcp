"""Tests for issue #54: ``metric_trend`` downsamples its rolling series.

``analysis.trend()``'s ``rolling_7d``/``rolling_30d``/``rolling_90d`` return
one point per calendar day of coverage with no cap, so a multi-year range
measures ~20,760 tokens against peers of 700-1,300. #54's chosen fix is
*downsampling at the response layer*: pick the finest of ``daily`` (step 1
day) / ``weekly`` (7) / ``monthly`` (30) whose series fits within
``ROLLING_MAX_POINTS_PER_SERIES`` points, decimate to it, and say so in the
response.

Written before the implementation exists -- every test in this file is
expected to fail (a ``KeyError``/``AssertionError`` on the not-yet-present
``rolling_resolution``, or an ``ImportError`` on the not-yet-present
``context_budget`` helper) until #54 lands. Nothing here touches the network:
every tool call is served from the local store, exactly as
tests/test_store_backed_tools.py's own fixtures are.

The invariant this file exists to protect is #54's D1: **decimation, never
averaging**. Every value returned must be a rolling mean that
``analysis.trend()`` actually computed for that actual date. Averaging the
daily rolling means inside a bucket would produce a mean of means over
overlapping windows -- a number that is no window's mean at all -- so
``test_every_returned_point_is_a_real_computed_rolling_mean`` compares the
returned ``(date, value)`` pairs against the exact daily series rather than
merely counting points.

Response shape assumed below (on top of metric_trend's existing fields):

    {
        ...,
        "rolling_7d": [{"date": ..., "value": ...}, ...],   # decimated
        "rolling_30d": [...], "rolling_90d": [...],
        "rolling_resolution": "daily" | "weekly" | "monthly",  # always present
        "rolling_truncated": True,   # only in the monthly-overflow case
        "truncated": bool,           # pre-existing record-count cap (unrelated)
        "note": str,                 # pre-existing, record-count cap only
    }

The downsampling explanation (D4) is asserted loosely -- any top-level
``*note*`` string may carry it -- so that whether it lands in its own key or
alongside the record-count ``note`` stays an implementation choice, while
"both are legible when both apply" stays a test.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from math import ceil
from pathlib import Path
from statistics import mean
from typing import Any

import pytest
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context, MCPServer

from whoopmcp.analysis import trend
from whoopmcp.auth import Authenticator, FileTokenStore, Token
from whoopmcp.client import WhoopClient
from whoopmcp.config import Config
from whoopmcp.server import AppContext, Principal, build_server
from whoopmcp.store import link_principal_to_member, open_store, upsert_recovery

WHOOP_USER_ID = 12345

#: The three series metric_trend returns, in one place so every test below
#: checks all three rather than only the longest.
ROLLING_KEYS = ("rolling_7d", "rolling_30d", "rolling_90d")

#: #54's own step-in-days per resolution. Duplicated here as literals rather
#: than imported from context_budget, so a drift between this file's
#: expectations and the implementation is a test failure instead of being
#: silently absorbed -- the same convention tests/test_whoop_outliers.py uses
#: for its own WINDOW_DAYS.
RESOLUTION_STEPS = {"daily": 1, "weekly": 7, "monthly": 30}

#: server.py's own record-count cap, quoted in metric_trend's pre-existing
#: truncation note. Duplicated as a literal for the same reason.
ANALYSIS_MAX_RECORDS = 1000


# -- fixture helpers, deliberately kept local -- same rationale
# tests/test_whoop_outliers.py already gives for its own copy of these. ----


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
def app_context(config: Config) -> Any:
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


# -- the fixture series ----------------------------------------------------

#: Every fixture below starts here, so a range of "2020-01-01" to
#: "2030-01-01" covers all of them and the store read is never the thing
#: limiting coverage.
FIXTURE_START = datetime(2020, 1, 1, 6, 0, tzinfo=UTC)

RANGE_ARGS = {"start": "2020-01-01T00:00:00Z", "end": "2030-01-01T00:00:00Z"}


def daily_value(index: int) -> float:
    """A deliberately non-linear, non-repeating daily value.

    Non-linear on purpose: over a perfectly linear ramp the average of an
    odd-sized bucket of rolling means happens to *equal* the bucket's middle
    real value, which would let an averaging implementation slip past a
    value-only assertion. The ``index % 11`` sawtooth plus a slow drift keeps
    every bucket's average observably away from the real rolling mean for that
    bucket's own date, which
    ``test_every_returned_point_is_a_real_computed_rolling_mean`` asserts
    about this fixture directly rather than assuming.
    """
    return 45.0 + (index % 11) * 3.1 + index * 0.005


def daily_recoveries(days: int) -> list[dict[str, Any]]:
    """``days`` contiguous SCORED recovery records, one per calendar day.

    Contiguous (no gaps) so that decimation by index and decimation by
    calendar day coincide: a returned series can then be checked for an exact
    step-in-days spacing, which is what ``rolling_resolution`` claims.
    """
    return [
        {
            "cycle_id": index,
            "created_at": (FIXTURE_START + timedelta(days=index)).isoformat(),
            "score_state": "SCORED",
            "score": {
                "recovery_score": daily_value(index),
                "hrv_rmssd_milli": 48.5,
                "resting_heart_rate": 55.0,
            },
        }
        for index in range(days)
    ]


def exact_series(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """The undecimated rolling series, straight from ``analysis.trend()``.

    The analysis layer stays exact under #54 (fact #4), so this is both
    "what metric_trend returned before" and "the set of real computed
    values" a decimated response must be drawn from.
    """
    result = trend(records, "recovery_score")
    return {
        "rolling_7d": [{"date": p.date, "value": p.value} for p in result.rolling_7d],
        "rolling_30d": [{"date": p.date, "value": p.value} for p in result.rolling_30d],
        "rolling_90d": [{"date": p.date, "value": p.value} for p in result.rolling_90d],
    }


async def trend_over(
    server: MCPServer[AppContext], app_context: AppContext, records: list[dict[str, Any]]
) -> dict[str, Any]:
    """Seed ``records`` into the store and call metric_trend over all of them."""
    assert app_context.store_conn is not None
    for record in records:
        upsert_recovery(app_context.store_conn, WHOOP_USER_ID, record)
    result = await call_tool(
        server, "metric_trend", {"metric": "recovery_score", **RANGE_ARGS}, app_context
    )
    assert "error" not in result, result
    return dict(result)


def note_texts(response: dict[str, Any]) -> list[str]:
    """Every top-level note-ish string in a response.

    Deliberately key-name-agnostic: #54's D4 requires the downsampling
    explanation to be legible and distinguishable from the pre-existing
    record-count note, not to live under one particular key.
    """
    return [value for key, value in response.items() if "note" in key and isinstance(value, str)]


def dates_of(points: list[dict[str, Any]]) -> list[Any]:
    return [datetime.fromisoformat(point["date"]).date() for point in points]


# -- the common case is untouched -----------------------------------------


async def test_short_range_returns_daily_resolution_unchanged(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A short range is byte-for-byte what it was before #54.

    100 days of coverage puts the longest series (rolling_7d, 94 points)
    well inside the cap, so this change has to be invisible here: daily
    resolution, no downsampling note, no rolling_truncated flag, and exactly
    the same points ``analysis.trend()`` computes.
    """
    records = daily_recoveries(100)
    expected = exact_series(records)

    response = await trend_over(server, app_context, records)

    assert response["rolling_resolution"] == "daily"
    assert "rolling_truncated" not in response
    # The record-count note is the only "note" metric_trend has ever had, and
    # 100 records is nowhere near the cap, so there must be no note at all.
    assert "note" not in response
    assert note_texts(response) == []
    for key in ROLLING_KEYS:
        assert response[key] == expected[key], key
    # Sanity: the fixture really does exercise all three series.
    assert all(len(expected[key]) > 0 for key in ROLLING_KEYS)


# -- resolution boundaries ------------------------------------------------


async def test_range_past_the_daily_cap_becomes_weekly(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """200 days: too many daily points to return, few enough for weekly."""
    records = daily_recoveries(200)
    expected = exact_series(records)
    longest = max(len(points) for points in expected.values())

    response = await trend_over(server, app_context, records)

    # The fixture is past the daily cap and inside the weekly one, whichever
    # way round the cap is applied.
    assert longest > 120
    assert ceil(longest / RESOLUTION_STEPS["weekly"]) <= 120
    assert response["rolling_resolution"] == "weekly"
    assert "rolling_truncated" not in response
    for key in ROLLING_KEYS:
        assert len(response[key]) == ceil(len(expected[key]) / RESOLUTION_STEPS["weekly"]), key
    # D4: the response says what it did, and names the resolution.
    assert any("weekly" in text and "downsampl" in text.lower() for text in note_texts(response))


async def test_multi_year_range_becomes_monthly(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """950 days (~2.6 years): even weekly overflows the cap, so monthly."""
    records = daily_recoveries(950)
    expected = exact_series(records)
    longest = max(len(points) for points in expected.values())

    response = await trend_over(server, app_context, records)

    assert ceil(longest / RESOLUTION_STEPS["weekly"]) > 120
    assert ceil(longest / RESOLUTION_STEPS["monthly"]) <= 120
    assert response["rolling_resolution"] == "monthly"
    assert "rolling_truncated" not in response
    for key in ROLLING_KEYS:
        assert len(response[key]) == ceil(len(expected[key]) / RESOLUTION_STEPS["monthly"]), key
    assert any("monthly" in text and "downsampl" in text.lower() for text in note_texts(response))


# -- D1: decimate, never average ------------------------------------------


async def test_every_returned_point_is_a_real_computed_rolling_mean(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """#54's D1, the one mistake that would quietly misreport the metric.

    Every returned ``(date, value)`` pair must appear verbatim in the exact
    daily series -- i.e. be a rolling mean actually computed for that actual
    date. A bucket *average* would return a mean of means over overlapping
    windows: a number that is no window's mean at all.

    The assertion is only meaningful if averaging would in fact produce
    something different here, so this test proves that about its own fixture
    first, rather than assuming it.
    """
    records = daily_recoveries(200)
    expected = exact_series(records)

    response = await trend_over(server, app_context, records)

    assert response["rolling_resolution"] == "weekly"
    step = RESOLUTION_STEPS["weekly"]

    for key in ROLLING_KEYS:
        exact_points = expected[key]
        exact_pairs = {(point["date"], point["value"]) for point in exact_points}
        exact_values = [point["value"] for point in exact_points]

        # The fixture is discriminating: for *every* bucket alignment (hence
        # every offset, not only multiples of the step), averaging the bucket
        # would report, for the bucket's own date, a value observably
        # different from the real rolling mean for that date -- and one that
        # is not a real value for that date at all. Without this, a test that
        # only matched pairs could pass against an averaging implementation
        # by coincidence.
        for start in range(len(exact_values) - step + 1):
            bucket = exact_values[start : start + step]
            bucket_average = mean(bucket)
            bucket_date = exact_points[start + step - 1]["date"]
            assert abs(bucket_average - bucket[-1]) > 0.01, (
                f"{key}: fixture is too flat for averaging to be observably wrong"
            )
            assert (bucket_date, bucket_average) not in exact_pairs, (
                f"{key}: fixture is not discriminating -- a bucket average coincides "
                "with a real point"
            )

        # The guarantee itself.
        for point in response[key]:
            assert (point["date"], point["value"]) in exact_pairs, (
                f"{key}: {point} is not a rolling mean computed for that date"
            )


# -- D2: the most recent point survives, at every resolution ---------------


@pytest.mark.parametrize(
    ("days", "resolution"), [(100, "daily"), (200, "weekly"), (950, "monthly")]
)
async def test_most_recent_point_is_always_present(
    days: int,
    resolution: str,
    app_context: AppContext,
    server: MCPServer[AppContext],
) -> None:
    """The latest value is the one a caller most wants; bucket arithmetic
    must never be what drops it."""
    records = daily_recoveries(days)
    expected = exact_series(records)

    response = await trend_over(server, app_context, records)

    assert response["rolling_resolution"] == resolution
    for key in ROLLING_KEYS:
        assert response[key], key
        assert response[key][-1] == expected[key][-1], key


# -- D3: one resolution, applied to all three series ----------------------


async def test_all_three_series_share_one_resolution(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """``rolling_resolution`` describes the whole response, so all three
    series must actually be at that step -- not rolling_7d weekly beside
    rolling_90d daily.

    The fixture is contiguous, so the declared step in days is directly
    observable as the spacing between consecutive returned dates: every gap
    is that step, except that at most one may be shorter (whichever end an
    incomplete bucket falls on -- decimating from the most recent point
    backwards puts it at the start, aligning buckets to the calendar would
    put it at the end; #54 fixes neither, and this test does not either).
    """
    records = daily_recoveries(200)
    expected = exact_series(records)

    response = await trend_over(server, app_context, records)

    step = RESOLUTION_STEPS[response["rolling_resolution"]]
    assert step > 1  # otherwise this fixture proves nothing about D3
    for key in ROLLING_KEYS:
        points = response[key]
        assert len(points) == ceil(len(expected[key]) / step), key
        dates = dates_of(points)
        gaps = [(later - earlier).days for earlier, later in pairwise(dates)]
        assert all(gap <= step for gap in gaps), f"{key}: a gap exceeds {step} days: {gaps}"
        assert sum(1 for gap in gaps if gap != step) <= 1, (
            f"{key}: spacing {sorted(set(gaps))} does not match {step}-day buckets"
        )


# -- the monthly-overflow case --------------------------------------------


def test_monthly_overflow_truncates_and_keeps_the_most_recent_points() -> None:
    """Beyond ~10 years of daily points even monthly overflows the cap: keep
    the most recent points and flag it.

    Tested against the ``context_budget`` helper directly rather than through
    the tool, because it is unreachable through the tool: metric_trend's own
    1000-record store cap bounds a response at ~1000 daily points, which
    monthly resolution comfortably fits. The helper still has to be correct
    for it -- that is what makes the new ceiling hold for *any* input.
    """
    from whoopmcp.context_budget import (
        ROLLING_MAX_POINTS_PER_SERIES,
        shape_rolling_series,
    )

    assert ROLLING_MAX_POINTS_PER_SERIES == 120
    start = FIXTURE_START.date()
    series = {
        key: [
            {
                "date": (start + timedelta(days=index)).isoformat(),
                "value": daily_value(index),
            }
            for index in range(4000)
        ]
        for key in ROLLING_KEYS
    }

    shaped, resolution, rolling_truncated = shape_rolling_series(series)

    assert resolution == "monthly"
    assert rolling_truncated is True
    for key in ROLLING_KEYS:
        assert len(shaped[key]) == ROLLING_MAX_POINTS_PER_SERIES, key
        # Most recent kept, oldest dropped -- and still real values, in order.
        assert shaped[key][-1] == series[key][-1], key
        assert shaped[key][0] != series[key][0], key
        pairs = {(point["date"], point["value"]) for point in series[key]}
        assert all((point["date"], point["value"]) in pairs for point in shaped[key]), key
        dates = dates_of(shaped[key])
        assert dates == sorted(dates), key


# -- both caps at once, each still legible ---------------------------------


async def test_record_truncation_and_downsampling_announce_themselves_separately(
    app_context: AppContext, server: MCPServer[AppContext]
) -> None:
    """A response can be record-truncated *and* downsampled (fact #5).

    1,200 daily records is over the 1000-record store cap and long enough to
    need coarser-than-daily buckets, so both apply here. ``truncated`` keeps
    meaning "records were dropped before analysis" and must not be
    overloaded for the rolling cap; the two explanations must both be
    readable.
    """
    records = daily_recoveries(1200)

    response = await trend_over(server, app_context, records)

    assert response["truncated"] is True
    assert response["rolling_resolution"] in {"weekly", "monthly"}
    # The rolling cap did not overload the record-count flag, nor vice versa:
    # this response is downsampled but not monthly-overflowed.
    assert response.get("rolling_truncated") is None
    texts = note_texts(response)
    assert any(f"{ANALYSIS_MAX_RECORDS}-record cap" in text for text in texts), texts
    assert any(
        response["rolling_resolution"] in text and "downsampl" in text.lower() for text in texts
    ), texts
