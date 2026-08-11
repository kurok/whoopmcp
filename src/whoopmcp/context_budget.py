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
    # 32000, not 100: metric_trend's rolling_7d/30d/90d (#22) return one point
    # per calendar day of coverage with no cap, so a multi-year range's worst
    # case is genuinely this large -- measured, not designed. Tracked as a
    # follow-up (#54): the honest ceiling here defeats this file's own
    # purpose for long ranges, and the right fix (windowing, pagination, or a
    # rolling-point cap with a truncation note) is a product decision this
    # rebase should not make unasked.
    "metric_trend": 32000,
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
}
