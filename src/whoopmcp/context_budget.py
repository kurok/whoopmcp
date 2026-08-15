"""Shared response-shaping and measurement helpers for context-budget control.

Two tool-agnostic pieces: estimating a payload's token cost, and dropping
null noise from a record. server.py imports from here; this module imports
from neither server.py, client.py, nor analysis.py.
"""

from __future__ import annotations

import json
from math import ceil
from typing import Any


def estimate_tokens(payload: Any) -> int:
    """Approximate the token cost of a JSON-shaped payload.

    chars/4, not bytes/4: payloads are dominated by repeated JSON key
    names, which a char count captures directly; a byte count would only
    add noise from rare non-ASCII fields.
    """
    return len(json.dumps(payload, default=str)) // 4


def strip_nulls(record: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``record`` with every ``None``-valued key removed.

    Recurses into nested dicts, dropping ones left empty after stripping.
    Lists are left as-is; current callers only nest one level deep, but
    recursing generally costs nothing and stays correct if that changes.
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


#: #54: cap on points per rolling series (rolling_7d/30d/90d). Tries
#: daily/weekly/monthly steps in order, first fit wins; overflow truncates.
ROLLING_MAX_POINTS_PER_SERIES = 120

#: #54's per-resolution step (days), coarsening order matters: first fit wins.
_ROLLING_RESOLUTION_STEPS: dict[str, int] = {"daily": 1, "weekly": 7, "monthly": 30}


def _decimate(points: list[dict[str, Any]], step: int) -> list[dict[str, Any]]:
    """Keep every ``step``-th point, counting back from the most recent.

    Decimation not averaging (#54 D1): kept points stay verbatim. Counting
    backward guarantees the final point is always kept (D2); any partial
    leftover bucket falls at the series' start instead.
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

    Takes/returns plain ``{"date", "value"}`` dicts; never imports analysis.py.
    Picks one resolution for all series (D3), from the longest one, so
    rolling_7d/90d never differ in step. Returns (shaped series, resolution
    name, whether monthly-overflow truncation fired); inputs are never mutated.
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


#: Per-tool context-budget ceiling, in tokens (see estimate_tokens). Measured
#: against tests/test_context_budget.py's worst-case fixtures, rounded to
#: ~1.25x; that test fails CI if any registered tool lacks an entry here.
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
    # #54: series decimated per shape_rolling_series (cap 120/series). Worst
    # case ~4454 tokens; 5000 is ~1.12x, tighter than usual since the cap is
    # absolute (no unbounded growth to leave headroom for).
    "metric_trend": 5000,
    "correlate_metrics": 700,
    # #21 added per-metric effect_size/coverage_asymmetric + period_length_note;
    # #16 added coverage/range_coverage.
    "compare_periods": 1300,
    # #15: 4 small per-entity {count, cursor} dicts; size doesn't grow with
    # records synced. Measured 74, rounded to ~1.25x.
    "whoop_sync": 100,
    # #16: 6 small per-entity coverage dicts; same "doesn't grow with
    # history size" shape as whoop_sync.
    "whoop_data_coverage": 340,
    # #20: worst case is a 365-point daily series, capped by
    # _TIMESERIES_MAX_POINTS. Measured 3582, rounded to ~1.25x.
    "whoop_timeseries": 4500,
    # #24: whoop_outliers never echoes the day-series, only capped
    # flagged/warm-up entries. Measured 6990, rounded to ~1.25x.
    "whoop_outliers": 8800,
    # whoop_streaks echoes one entry per swept day by design. Measured
    # 21293, rounded to ~1.25x.
    "whoop_streaks": 27000,
}
