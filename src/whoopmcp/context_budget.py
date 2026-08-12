"""Shared response-shaping and measurement helpers for context-budget control.

Not network (that's client.py), not statistics (that's analysis.py), and not
the MCP surface (that's server.py) -- this module holds the two small,
tool-agnostic pieces every tool response is measured and shaped by:
estimating how many tokens a payload costs, and dropping null noise from a
record before it goes out. server.py imports from here; nothing here imports
from server.py, client.py, or analysis.py.
"""

from __future__ import annotations

import json
from math import ceil
from typing import Any


def estimate_tokens(payload: Any) -> int:
    """Approximate the token cost of a JSON-shaped payload.

    Characters-divided-by-4, not bytes-divided-by-4: these payloads are
    dominated by repeated JSON key names (every record in a list repeats
    the same keys), and a character count captures that repetition
    directly, whereas a UTF-8 byte count would only add noise for the rare
    non-ASCII field without buying any extra accuracy for the common case.
    """
    return len(json.dumps(payload, default=str)) // 4


def strip_nulls(record: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``record`` with every ``None``-valued key removed.

    Recurses into nested dicts -- a nested dict that becomes empty after
    stripping is itself dropped, since an empty dict tells the model
    nothing a missing key wouldn't. Lists are left as-is: every caller of
    this function already runs a fully-formed, already-trimmed record
    through it (one level of dict-nesting is all that occurs in practice),
    but recursing into dicts generally, rather than only at the top level,
    costs nothing and stays correct if that ever changes.
    """
    result: dict[str, Any] = {}
    for key, value in record.items():
        if value is None:
            continue
        if isinstance(value, dict):
            nested = strip_nulls(value)
            if not nested:
                continue
            result[key] = nested
        else:
            result[key] = value
    return result


#: #54: the coarsest-that-fits cap on points per rolling series
#: (rolling_7d/30d/90d) that metric_trend returns. daily (step 1 calendar
#: day) is tried first, then weekly (step 7), then monthly (step 30); the
#: first of those whose series fits at or under this many points wins. If
#: even monthly overflows it, the series is truncated to the most recent
#: this-many points instead (see shape_rolling_series).
ROLLING_MAX_POINTS_PER_SERIES = 120

#: #54's per-resolution step, in calendar days, in coarsening order. Order
#: matters: shape_rolling_series tries each in turn and stops at the first
#: (finest) one whose decimated length fits ROLLING_MAX_POINTS_PER_SERIES.
_ROLLING_RESOLUTION_STEPS: dict[str, int] = {"daily": 1, "weekly": 7, "monthly": 30}


def _decimate(points: list[dict[str, Any]], step: int) -> list[dict[str, Any]]:
    """Keep every ``step``-th point, counting back from the most recent.

    Decimation, not averaging (#54's D1): every kept point is returned
    verbatim, so it stays exactly as real a computed value as it was before
    downsampling. Counting backwards from the last index (rather than
    forwards from the first) is what guarantees the final point is always
    kept (D2) -- any partial, less-than-``step``-wide leftover bucket falls
    at the *start* of the series instead, where it is the oldest, least-
    wanted point that ends up slightly closer to its neighbour than
    ``step``.
    """
    if step <= 1 or len(points) <= 1:
        return list(points)
    kept_indices: list[int] = []
    index = len(points) - 1
    while index >= 0:
        kept_indices.append(index)
        index -= step
    kept_indices.reverse()
    return [points[i] for i in kept_indices]


def shape_rolling_series(
    series: dict[str, list[dict[str, Any]]],
) -> tuple[dict[str, list[dict[str, Any]]], str, bool]:
    """Downsample metric_trend's rolling_7d/30d/90d series to a shared cap.

    Takes and returns plain ``{"date", "value"}`` dicts (fact #3 -- this
    module never imports ``analysis.py``); the caller is responsible for
    turning ``RollingPoint`` objects into that shape both before calling
    this and (implicitly) after, since this function only ever copies and
    reorders the dicts it is given.

    Picks one resolution for every series in ``series`` (D3), derived from
    the *longest* one, so a response never describes ``rolling_7d`` at one
    step and ``rolling_90d`` at another. Returns the shaped series (a new
    dict; each value a new, possibly-shorter list -- inputs are never
    mutated), the resolution name, and whether the monthly-overflow
    truncation branch fired.

    Real-world callers cannot reach the truncation branch through
    metric_trend today (its own record cap bounds the input well under what
    monthly resolution alone would need to overflow), but the branch has to
    be correct anyway -- that is what makes the ceiling this function exists
    to protect hold for *any* input, not just the ones metric_trend happens
    to produce right now.
    """
    longest = max((len(points) for points in series.values()), default=0)

    resolution = "monthly"
    step = _ROLLING_RESOLUTION_STEPS["monthly"]
    for candidate, candidate_step in _ROLLING_RESOLUTION_STEPS.items():
        if ceil(longest / candidate_step) <= ROLLING_MAX_POINTS_PER_SERIES:
            resolution = candidate
            step = candidate_step
            break

    shaped = {key: _decimate(points, step) for key, points in series.items()}

    rolling_truncated = False
    if resolution == "monthly":
        for key, points in shaped.items():
            if len(points) > ROLLING_MAX_POINTS_PER_SERIES:
                shaped[key] = points[-ROLLING_MAX_POINTS_PER_SERIES:]
                rolling_truncated = True

    return shaped, resolution, rolling_truncated


#: Per-tool context-budget ceiling, in estimated tokens (see estimate_tokens).
#: Measured against the worst-case fixtures in tests/test_context_budget.py --
#: a full page of 25 densely-populated records for the 8 data tools, and a
#: >1000-record, >2-year span for the 4 analysis tools -- then rounded up to
#: roughly 1.25x the measured worst case. tests/test_context_budget.py fails
#: if any registered tool is missing an entry here, so a 17th tool with no
#: ceiling breaks CI rather than shipping unmeasured.
#:
#: #16 repointed every data/analysis tool at the local store and gave each
#: response a "coverage" (and, for the range-taking ones, "range_coverage")
#: envelope -- every one of the 12 entries below was remeasured against this
#: file's own store-seeded fixtures, not carried over from the pre-#16
#: live-API measurement. ``whoop_data_coverage`` is new: 6 small per-entity
#: dicts, never echoed records, so its worst case does not grow with history
#: size the way the other 12 do.
TOOL_CEILINGS: dict[str, int] = {
    "whoop_auth_status": 50,
    "whoop_login": 300,
    "whoop_complete_login": 50,
    "whoop_logout": 100,
    "get_profile": 60,
    "get_body_measurement": 60,
    "list_recoveries": 1500,
    "list_sleeps": 2900,
    "list_cycles": 1700,
    "list_workouts": 3100,
    "get_sleep": 250,
    "get_workout": 250,
    "summarize_period": 850,
    # #54: rolling_7d/30d/90d are now decimated to whichever of daily/weekly/
    # monthly resolution keeps each series within
    # shape_rolling_series's own ROLLING_MAX_POINTS_PER_SERIES (120) --
    # replacing the old unbounded one-point-per-calendar-day series that made
    # this entry a genuinely-measured-but-unprotective 32000.
    #
    # The worst case reachable *through this tool* is ~4454, at roughly 846
    # contiguous days, where weekly resolution saturates all three series at
    # the cap at once. Note that is not the largest payload the helper can
    # produce in isolation: monthly saturation (~3660 days) yields marginally
    # more points (359 vs 346, since 30-day buckets divide a longer span more
    # evenly) but is unreachable here, because _ANALYSIS_MAX_RECORDS caps the
    # daily series at ~1000 points long before 3660 days of coverage exist.
    #
    # It is also not the >2-year fixture in tests/test_context_budget.py,
    # which measures 3969 because its record cap trips first -- quoting the
    # fixture would overstate the headroom. 5000 is ~1.12x the reachable
    # worst case, deliberately tighter than this file's usual ~1.25x: the cap
    # is absolute (three series x ROLLING_MAX_POINTS_PER_SERIES, whatever the
    # range), so unlike every other entry here there is no unbounded growth
    # left to leave room for. Verified by sweeping every coverage length from
    # 1 to 4000 days: the cap holds at each one and nothing exceeds 5000.
    "metric_trend": 5000,
    "correlate_metrics": 700,
    # #21 added effect_size/coverage_asymmetric per metric plus a top-level
    # period_length_note; #16 added coverage/range_coverage on top of that.
    "compare_periods": 1300,
    # #15: four small per-entity {count, cursor} dicts, never echoed records --
    # response size does not grow with the number of records synced, only
    # with the (fixed, small) number of entities, so one record per entity is
    # already the worst case. Measured at 74 against
    # tests/test_context_budget.py's own fixture; rounded up to roughly 1.25x.
    "whoop_sync": 100,
    # #16: 6 small per-entity coverage dicts, never echoed records -- same
    # "does not grow with history size" shape as whoop_sync above.
    "whoop_data_coverage": 340,
    # #20: a 365-point daily series (one full year, granularity="day") is
    # this tool's own worst case -- capped by _TIMESERIES_MAX_POINTS, and
    # deliberately carrying no "coverage"/"range_coverage" envelope (see the
    # tool's own docstring for why). Measured at 3582 against
    # tests/test_whoop_timeseries.py's own 365-day fixture; rounded up to
    # roughly 1.25x.
    "whoop_timeseries": 4500,
    # #24: measured against tests/test_context_budget.py's own worst-case
    # fixtures. whoop_outliers' response never echoes the day-series itself
    # (only detailed outliers, capped at _OUTLIERS_MAX_FLAGGED, plus
    # compact warm-up entries, capped at _OUTLIERS_MAX_WARMUP) -- the worst
    # case is sparse isolated spikes (e.g., baseline 50.0 with 90.0 spikes
    # every 15th day), which under a 14-day rolling window produces z-scores
    # well above the threshold and maximizes both the flagged-outliers and
    # per-outlier context payloads. Measured at 6990 against this fixture;
    # rounded up to roughly 1.25x. whoop_streaks' response DOES echo one
    # entry per calendar day swept (its own explicit "let the caller decide"
    # design, so every day's status/value has to be visible) -- measured at
    # 21293 against a _STREAKS_MAX_DAYS-day alternating pass/fail/missing
    # sweep; rounded up to roughly 1.25x.
    "whoop_outliers": 8800,
    "whoop_streaks": 27000,
}
