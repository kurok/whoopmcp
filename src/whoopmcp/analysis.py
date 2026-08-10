"""Derived metrics over WHOOP records.

These are pure functions on already-fetched records, kept apart from the API
client so they can be tested without a network and reasoned about without an
access token.

A note on what belongs here: WHOOP data is health data, and a correlation
over 30 nights of sleep is not a medical finding. Functions in this module
return numbers and the sample size behind them; they do not return advice,
and the tool descriptions in ``server`` say so.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

#: Below this many paired observations a correlation is not worth reporting.
MIN_CORRELATION_SAMPLES = 8

#: Below this many observations, a trend/regression is not worth reporting --
#: mirrors MIN_CORRELATION_SAMPLES's philosophy for this module's other
#: "refuse below N" convention.
MIN_TREND_SAMPLES = 8

#: Friendly metric name -> key within record["score"].
_METRIC_PATHS: dict[str, str] = {
    "recovery_score": "recovery_score",
    "hrv": "hrv_rmssd_milli",
    "resting_heart_rate": "resting_heart_rate",
    "sleep_performance": "sleep_performance_percentage",
    "sleep_efficiency": "sleep_efficiency_percentage",
    "strain": "strain",
}

#: Metrics whose records are Cycle objects: a Cycle identifies itself via
#: "id" and never carries a "cycle_id" (that field is a foreign key that
#: Recovery/Sleep records use to point *at* the cycle they belong to).
_CYCLE_SOURCED_METRICS = frozenset({"strain"})


class InsufficientDataError(ValueError):
    """Not enough observations to compute the requested statistic."""


@dataclass(frozen=True, slots=True)
class Summary:
    """Descriptive statistics for one metric over one period."""

    metric: str
    count: int
    mean: float
    stdev: float
    minimum: float
    maximum: float
    median: float
    days_missing: int


@dataclass(frozen=True, slots=True)
class RollingPoint:
    """One point in a rolling-mean series: a calendar date and its mean."""

    date: str
    value: float


@dataclass(frozen=True, slots=True)
class Trend:
    """A least-squares trend, in metric units per day."""

    metric: str
    count: int
    slope_per_day: float
    first: float
    last: float
    r_squared: float
    fit_quality: str
    rolling_7d: list[RollingPoint]
    rolling_30d: list[RollingPoint]
    rolling_90d: list[RollingPoint]


@dataclass(frozen=True, slots=True)
class Correlation:
    """A Pearson correlation between two metrics, with its sample size."""

    metric_a: str
    metric_b: str
    count: int
    r: float


def mean(values: Sequence[float]) -> float:
    """Arithmetic mean.

    Raises:
        InsufficientDataError: on an empty sequence.
    """
    if not values:
        raise InsufficientDataError("mean of an empty sequence")
    return math.fsum(values) / len(values)


def stdev(values: Sequence[float]) -> float:
    """Sample standard deviation (n-1 denominator).

    Raises:
        InsufficientDataError: with fewer than two values.
    """
    if len(values) < 2:
        raise InsufficientDataError("standard deviation needs at least 2 values")
    mu = mean(values)
    return math.sqrt(math.fsum((v - mu) ** 2 for v in values) / (len(values) - 1))


def median(values: Sequence[float]) -> float:
    """Median: the middle value, or the average of the two middle values.

    Raises:
        InsufficientDataError: on an empty sequence.
    """
    if not values:
        raise InsufficientDataError("median of an empty sequence")
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def pearson(xs: Sequence[float], ys: Sequence[float]) -> float:
    """Pearson correlation coefficient.

    Raises:
        ValueError: if the sequences differ in length.
        InsufficientDataError: with fewer than two pairs, or when either
            series is constant (the coefficient is undefined, not zero).
    """
    if len(xs) != len(ys):
        raise ValueError(f"length mismatch: {len(xs)} vs {len(ys)}")
    if len(xs) < 2:
        raise InsufficientDataError("correlation needs at least 2 pairs")

    mx, my = mean(xs), mean(ys)
    dx = [x - mx for x in xs]
    dy = [y - my for y in ys]

    denom = math.sqrt(math.fsum(d * d for d in dx)) * math.sqrt(math.fsum(d * d for d in dy))
    if denom == 0.0:
        raise InsufficientDataError("correlation is undefined when a series is constant")

    return math.fsum(a * b for a, b in zip(dx, dy, strict=True)) / denom


def standardized_effect_size(
    mean_a: float,
    stdev_a: float,
    count_a: int,
    mean_b: float,
    stdev_b: float,
    count_b: int,
) -> float:
    """Cohen's d between two groups, via pooled standard deviation.

    Raises:
        InsufficientDataError: if either group has fewer than 2 observations,
            or when the pooled standard deviation is exactly 0 (both groups
            perfectly constant and identical -- undefined, not zero).
    """
    if count_a < 2 or count_b < 2:
        raise InsufficientDataError("effect size needs at least 2 observations per group")

    pooled_variance = ((count_a - 1) * stdev_a**2 + (count_b - 1) * stdev_b**2) / (
        count_a + count_b - 2
    )
    pooled_stdev = pooled_variance**0.5
    if pooled_stdev == 0.0:
        raise InsufficientDataError("effect size is undefined when pooled stdev is 0")

    return (mean_b - mean_a) / pooled_stdev


def linear_slope(xs: Sequence[float], ys: Sequence[float]) -> float:
    """Least-squares slope of ``ys`` against ``xs``.

    Raises:
        ValueError: if the sequences differ in length.
        InsufficientDataError: with fewer than two pairs or constant ``xs``.
    """
    if len(xs) != len(ys):
        raise ValueError(f"length mismatch: {len(xs)} vs {len(ys)}")
    if len(xs) < 2:
        raise InsufficientDataError("slope needs at least 2 pairs")

    mx, my = mean(xs), mean(ys)
    denom = math.fsum((x - mx) ** 2 for x in xs)
    if denom == 0.0:
        raise InsufficientDataError("slope is undefined when x is constant")

    return math.fsum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True)) / denom


# -- record shaping --------------------------------------------------------
#
# The functions below turn raw WHOOP records into the sequences the
# primitives above consume. They are the part that has to know WHOOP's
# response shapes, so they are the part most likely to break when the API
# changes -- keep the schema knowledge concentrated here.


def _metric_key(metric: str) -> str:
    """Resolve a friendly metric name to its key within record["score"]."""
    try:
        return _METRIC_PATHS[metric]
    except KeyError:
        raise ValueError(f"unknown metric: {metric!r}") from None


def _filtered_records(
    records: Sequence[dict[str, Any]], metric: str
) -> list[tuple[dict[str, Any], float]]:
    """Pair each SCORED record carrying ``metric`` with its extracted value.

    Shared by every function below so the SCORED-and-key-present filter is
    defined in exactly one place.
    """
    key = _metric_key(metric)
    pairs: list[tuple[dict[str, Any], float]] = []
    for record in records:
        if record.get("score_state") != "SCORED":
            continue
        score = record.get("score")
        if not score or key not in score:
            continue
        pairs.append((record, float(score[key])))
    return pairs


def _join_key(record: dict[str, Any], metric: str) -> Any:
    """The record's cycle_id if it has one, else its own id if it is a Cycle,
    else its UTC calendar date.

    A Recovery or Sleep record carries ``cycle_id`` as a foreign key to the
    cycle it belongs to, so that always wins. A Cycle record (e.g. the
    source of ``strain``) has no ``cycle_id`` of its own -- it identifies
    itself via ``id`` -- so metrics sourced from Cycle records join on their
    own ``id`` instead of falling through to calendar-day matching.
    """
    cycle_id = record.get("cycle_id")
    if cycle_id is not None:
        return cycle_id
    if metric in _CYCLE_SOURCED_METRICS:
        own_id = record.get("id")
        if own_id is not None:
            return own_id
    timestamp = datetime.fromisoformat(record["created_at"])
    return timestamp.astimezone(UTC).date().isoformat()


def _grouped_values(records: Sequence[dict[str, Any]], metric: str) -> dict[Any, list[float]]:
    """Filtered values for ``metric``, grouped by join key in encounter order."""
    groups: dict[Any, list[float]] = {}
    for record, value in _filtered_records(records, metric):
        groups.setdefault(_join_key(record, metric), []).append(value)
    return groups


def extract_metric(records: Sequence[dict[str, Any]], metric: str) -> list[float]:
    """Pull one named metric out of a list of records, skipping nulls."""
    return [value for _, value in _filtered_records(records, metric)]


def summarize(records: Sequence[dict[str, Any]], metric: str, *, expected_days: int) -> Summary:
    """Descriptive statistics for one metric across ``records``.

    Args:
        records: Raw WHOOP records to summarize.
        metric: Friendly metric name, as in ``extract_metric``.
        expected_days: How many calendar days the caller's window spans, used
            to compute ``days_missing`` -- the coverage gap, not a record
            count.
    """
    values = extract_metric(records, metric)
    result_mean = mean(values)
    result_stdev = stdev(values)
    unique_dates = {
        datetime.fromisoformat(record["created_at"]).astimezone(UTC).date().isoformat()
        for record, _ in _filtered_records(records, metric)
    }
    return Summary(
        metric=metric,
        count=len(values),
        mean=result_mean,
        stdev=result_stdev,
        minimum=min(values),
        maximum=max(values),
        median=median(values),
        days_missing=max(0, expected_days - len(unique_dates)),
    )


def _describe_fit(r_squared: float) -> str:
    """Describe a fit's strength in words, from its r-squared.

    A slope is not safe to narrate without knowing how much of the variance
    it actually explains -- this is the "describe the fit in words" half of
    that requirement, alongside the numeric r_squared field it never
    replaces. Bands are deliberately coarse and stated here rather than
    hidden behind the word: r_squared >= 0.7 "strong", >= 0.4 "moderate",
    >= 0.1 "weak", otherwise "negligible". These are common, not universal,
    conventions -- the numeric r_squared is always reported alongside this
    so nothing is lost if a caller judges the fit differently.
    """
    if r_squared >= 0.7:
        return "strong"
    if r_squared >= 0.4:
        return "moderate"
    if r_squared >= 0.1:
        return "weak"
    return "negligible"


def _daily_means(dated_values: Sequence[tuple[str, float]]) -> list[RollingPoint]:
    """Collapse same-date observations to one mean each, sorted by date."""
    groups: dict[str, list[float]] = {}
    for date, value in dated_values:
        groups.setdefault(date, []).append(value)
    return [RollingPoint(date=date, value=mean(values)) for date, values in sorted(groups.items())]


def _rolling_means(daily: Sequence[RollingPoint], window_days: int) -> list[RollingPoint]:
    """Rolling mean over a trailing window of ``window_days`` calendar days.

    ``daily`` must already be day-deduplicated and sorted by date. A date only
    gets a point once at least ``window_days`` calendar days have elapsed
    since the start of the *current run of coverage*; the window itself is
    every day-deduplicated point whose date falls within the trailing
    ``window_days``-day span, with no gap-filling for days that have no
    observation.

    "Current run of coverage" matters because a gap between two consecutive
    daily points that is itself >= ``window_days`` resets the minimum-periods
    clock: no point from before such a gap could ever land inside a window
    that only looks back ``window_days - 1`` days in the first place, so
    without the reset, the first point after a long gap would silently be
    reported as a full ``window_days``-day mean while actually being an
    average of whatever handful of points the gap happened to leave nearby --
    the exact "spurious swing" the leading-edge rule exists to prevent, just
    triggered mid-series instead of only at the very start. Each window size
    resets independently (a gap can be big enough to reset the 7-day window
    while leaving the 90-day window's own coverage intact), which falls out
    for free from this function being called once per window size.
    """
    dates = [datetime.fromisoformat(point.date).date() for point in daily]
    points: list[RollingPoint] = []
    window_start_idx = 0
    run_start = dates[0]
    for i, current_date in enumerate(dates):
        if i > 0 and (current_date - dates[i - 1]).days >= window_days:
            run_start = current_date
        if (current_date - run_start).days < window_days - 1:
            continue
        window_start = current_date - timedelta(days=window_days - 1)
        while dates[window_start_idx] < window_start:
            window_start_idx += 1
        window_values = [point.value for point in daily[window_start_idx : i + 1]]
        points.append(RollingPoint(date=daily[i].date, value=mean(window_values)))
    return points


def trend(records: Sequence[dict[str, Any]], metric: str) -> Trend:
    """Direction, rate of change and fit quality for one metric over time.

    Also returns 7/30/90-day rolling means computed on a day-deduplicated
    calendar series, independent of the per-record slope/r_squared figures.
    """
    filtered = _filtered_records(records, metric)
    if len(filtered) < MIN_TREND_SAMPLES:
        raise InsufficientDataError(
            f"trend needs at least {MIN_TREND_SAMPLES} observations, got {len(filtered)}"
        )

    pairs = [
        (datetime.fromisoformat(record["created_at"]).timestamp() / 86_400.0, value)
        for record, value in filtered
    ]
    pairs.sort(key=lambda pair: pair[0])
    xs = [day for day, _ in pairs]
    ys = [value for _, value in pairs]
    slope = linear_slope(xs, ys)
    r_squared = pearson(xs, ys) ** 2

    dated_values = [
        (datetime.fromisoformat(record["created_at"]).astimezone(UTC).date().isoformat(), value)
        for record, value in filtered
    ]
    daily = _daily_means(dated_values)

    return Trend(
        metric=metric,
        count=len(ys),
        slope_per_day=slope,
        first=ys[0],
        last=ys[-1],
        r_squared=r_squared,
        fit_quality=_describe_fit(r_squared),
        rolling_7d=_rolling_means(daily, 7),
        rolling_30d=_rolling_means(daily, 30),
        rolling_90d=_rolling_means(daily, 90),
    )


def correlate(
    records_a: Sequence[dict[str, Any]],
    metric_a: str,
    records_b: Sequence[dict[str, Any]],
    metric_b: str,
) -> Correlation:
    """Correlate two metrics that may come from different collections."""
    groups_a = _grouped_values(records_a, metric_a)
    groups_b = _grouped_values(records_b, metric_b)

    pairs: list[tuple[float, float]] = []
    for key, values_a in groups_a.items():
        values_b = groups_b.get(key)
        if values_b is None:
            continue
        pairs.extend(zip(values_a, values_b, strict=False))

    if len(pairs) < MIN_CORRELATION_SAMPLES:
        raise InsufficientDataError(
            f"correlate needs at least {MIN_CORRELATION_SAMPLES} matched pairs, got {len(pairs)}"
        )

    xs = [a for a, _ in pairs]
    ys = [b for _, b in pairs]
    return Correlation(metric_a=metric_a, metric_b=metric_b, count=len(pairs), r=pearson(xs, ys))
