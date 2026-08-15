"""Derived metrics over WHOOP records.

Pure functions on already-fetched records -- testable without network/token. WHOOP data is
health data: these return numbers and sample sizes, never advice (see ``server``'s tool text).
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

#: Below this many paired observations a correlation is not worth reporting.
MIN_CORRELATION_SAMPLES = 8

#: The default lag sweep for correlate_lag_sweep: +/- 3 days.
DEFAULT_LAG_SWEEP: tuple[int, ...] = tuple(range(-3, 4))

#: Below this many observations, a trend/regression is not worth reporting -- mirrors
#: MIN_CORRELATION_SAMPLES's "refuse below N" convention.
MIN_TREND_SAMPLES = 8

#: Below this many observations per group an effect size is not worth reporting (#183).
#: Checked per group, not the total -- 13/1 tells as little as 1/1 (a 2/2 split gave d=16.26).
MIN_EFFECT_SAMPLES = 8

#: Friendly metric name -> key within record["score"].
_METRIC_PATHS: dict[str, str] = {
    "recovery_score": "recovery_score",
    "hrv": "hrv_rmssd_milli",
    "resting_heart_rate": "resting_heart_rate",
    "sleep_performance": "sleep_performance_percentage",
    "sleep_efficiency": "sleep_efficiency_percentage",
    "strain": "strain",
}

#: Metrics whose records are Cycle objects: a Cycle has no "cycle_id" of its own (that's the
#: foreign key Recovery/Sleep use to point at their cycle) -- it identifies via "id" instead.
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
    """A Pearson and Spearman correlation between two metrics, with its sample size."""

    metric_a: str
    metric_b: str
    count: int
    r: float
    spearman_r: float


@dataclass(frozen=True, slots=True)
class LagResult:
    """One entry of a lag sweep: either a Correlation, or a refusal reason."""

    lag_days: int
    correlation: Correlation | None
    refused_reason: str | None


@dataclass(frozen=True, slots=True)
class RollingStat:
    """One day's rolling mean/stdev/z-score, or a reason it wasn't scored (``rolling_z_scores``).

    ``unscored_reason`` is ``None`` iff ``rolling_mean``/``rolling_stdev``/``z_score`` are all
    populated (the latter two may independently be ``None`` when the window has <2 points).
    """

    date: str
    value: float
    rolling_mean: float | None
    rolling_stdev: float | None
    z_score: float | None
    unscored_reason: str | None


@dataclass(frozen=True, slots=True)
class DayStatus:
    """One calendar day's streak status, per ``find_streaks``.

    ``status``: "missing" (no measurement), "failing" (measured, misses threshold), or
    "passing" (measured, meets it). ``value`` is ``None`` iff ``status == "missing"``.
    """

    date: str
    status: str
    value: float | None


@dataclass(frozen=True, slots=True)
class Streak:
    """A maximal run of consecutive "passing" days, per ``find_streaks``."""

    direction: str
    start: str
    end: str
    length: int
    mean: float


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
        InsufficientDataError: if either group has fewer than ``MIN_EFFECT_SAMPLES``
            observations, or pooled stdev is exactly 0 (both groups constant and identical).

    Floor is checked per group, not the total: a 13/1 split tells as little as 1/1 would.
    """
    if count_a < MIN_EFFECT_SAMPLES or count_b < MIN_EFFECT_SAMPLES:
        raise InsufficientDataError(
            f"effect size needs at least {MIN_EFFECT_SAMPLES} observations per group"
        )

    pooled_variance = ((count_a - 1) * stdev_a**2 + (count_b - 1) * stdev_b**2) / (
        count_a + count_b - 2
    )
    pooled_stdev = pooled_variance**0.5
    if pooled_stdev == 0.0:
        raise InsufficientDataError("effect size is undefined when pooled stdev is 0")

    return (mean_b - mean_a) / pooled_stdev


def _rank(values: Sequence[float]) -> list[float]:
    """1-indexed average (fractional) ranks of ``values``.

    Ties share the mean of the rank positions they occupy: values at sorted
    positions 2 and 3 (1-indexed) both get rank 2.5.
    """
    n = len(values)
    order = sorted(range(n), key=lambda i: values[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg_rank = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1
    return ranks


def spearman(xs: Sequence[float], ys: Sequence[float]) -> float:
    """Spearman's rank correlation coefficient.

    Pearson's r over each series' average ranks (ties resolved by mean rank).

    Raises:
        ValueError: if the sequences differ in length.
        InsufficientDataError: with fewer than two pairs, or zero rank-variance (raised by
            ``pearson`` on the ranked series).
    """
    if len(xs) != len(ys):
        raise ValueError(f"length mismatch: {len(xs)} vs {len(ys)}")
    if len(xs) < 2:
        raise InsufficientDataError("correlation needs at least 2 pairs")
    return pearson(_rank(xs), _rank(ys))


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
# Turns raw WHOOP records into sequences the primitives above consume; keep schema knowledge here.


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
        value = score[key]
        # Missing dict/key and a present-but-null value both fall through to the `float()`
        # guard below (#182) -- skipped, not raised, so one bad record can't break a window.
        try:
            pairs.append((record, float(value)))
        except (TypeError, ValueError):
            continue
    return pairs


def _join_key(record: dict[str, Any], metric: str) -> Any:
    """The record's cycle_id if it has one, else its own id if it's a Cycle, else its UTC date.

    Recovery/Sleep carry ``cycle_id`` pointing at their cycle (always wins). A Cycle record has
    no ``cycle_id`` of its own, so Cycle-sourced metrics join on ``id`` instead of calendar-day.
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
        expected_days: Calendar days the window spans, for ``days_missing`` (coverage gap,
            not a record count).
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

    Bands: >=0.7 "strong", >=0.4 "moderate", >=0.1 "weak", else "negligible" -- common, not
    universal conventions; the numeric r_squared is always reported alongside, never replaced.
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
    for day, value in dated_values:
        groups.setdefault(day, []).append(value)
    return [RollingPoint(date=day, value=mean(values)) for day, values in sorted(groups.items())]


def _rolling_means(daily: Sequence[RollingPoint], window_days: int) -> list[RollingPoint]:
    """Rolling mean over a trailing window of ``window_days`` calendar days.

    ``daily`` must be day-deduplicated and sorted. A date gets a point only once
    ``window_days`` have elapsed since the start of its *current run of coverage* -- a gap
    >= ``window_days`` between consecutive points resets that run's clock, so a point right
    after a long gap is never reported as a full-window mean built from a sparse handful of
    points. Each window size resets independently since this is called once per window size.
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


#: rolling_z_scores' warm-up reason: the current run of coverage hasn't reached window_days yet.
_UNSCORED_WARM_UP = "warm_up"

#: rolling_z_scores' other unscored reason: past warm-up but the trailing window still has
#: <2 points, so stdev/z-score are undefined. Only reachable for window_days <= 1.
_UNSCORED_INSUFFICIENT_VARIANCE = "insufficient_variance"


def rolling_z_scores(daily: Sequence[RollingPoint], window_days: int) -> list[RollingStat]:
    """One ``RollingStat`` per point in ``daily``, scored against a trailing ``window_days``-day
    rolling mean/stdev (a *rolling*, not global, z-score).

    Borrows ``_rolling_means``'s gap-reset rule. Never drops a day -- every input gets exactly
    one ``RollingStat``: tagged ``unscored_reason="warm_up"`` (all stats ``None``) or
    ``"insufficient_variance"`` (window has <2 points, only ``rolling_mean`` set) when unscored.
    A window with stdev exactly 0 defines ``z_score`` as ``0.0`` rather than raising or NaN/inf.
    """
    if not daily:
        return []
    dates = [datetime.fromisoformat(point.date).date() for point in daily]
    results: list[RollingStat] = []
    window_start_idx = 0
    run_start = dates[0]
    for i, current_date in enumerate(dates):
        if i > 0 and (current_date - dates[i - 1]).days >= window_days:
            run_start = current_date
        if (current_date - run_start).days < window_days - 1:
            results.append(
                RollingStat(
                    date=daily[i].date,
                    value=daily[i].value,
                    rolling_mean=None,
                    rolling_stdev=None,
                    z_score=None,
                    unscored_reason=_UNSCORED_WARM_UP,
                )
            )
            continue
        window_start = current_date - timedelta(days=window_days - 1)
        while dates[window_start_idx] < window_start:
            window_start_idx += 1
        window_values = [point.value for point in daily[window_start_idx : i + 1]]
        window_mean = mean(window_values)
        if len(window_values) < 2:
            results.append(
                RollingStat(
                    date=daily[i].date,
                    value=daily[i].value,
                    rolling_mean=window_mean,
                    rolling_stdev=None,
                    z_score=None,
                    unscored_reason=_UNSCORED_INSUFFICIENT_VARIANCE,
                )
            )
            continue
        window_stdev = stdev(window_values)
        z_score = 0.0 if window_stdev == 0.0 else (daily[i].value - window_mean) / window_stdev
        results.append(
            RollingStat(
                date=daily[i].date,
                value=daily[i].value,
                rolling_mean=window_mean,
                rolling_stdev=window_stdev,
                z_score=z_score,
                unscored_reason=None,
            )
        )
    return results


def context_window(
    daily: Sequence[RollingPoint], index: int, radius: int
) -> tuple[list[RollingPoint], list[RollingPoint]]:
    """The up-to-``radius`` measured points immediately before/after ``daily[index]``.

    Truncates at the range's own edges (fewer points near an edge, never an error/padding).
    "Before"/"after" are nearest *measured* neighbours, not calendar-adjacent days -- an
    unmeasured day is simply absent from ``daily`` (same contract as ``store.get_metric_series``).
    """
    before = list(daily[max(0, index - radius) : index])
    after = list(daily[index + 1 : index + 1 + radius])
    return before, after


#: find_streaks' only two valid ``direction`` values.
_STREAK_DIRECTIONS: tuple[str, str] = ("above", "below")


def _streak_from_run(run: Sequence[DayStatus], direction: str) -> Streak:
    """Build one ``Streak`` from a maximal run of consecutive passing days."""
    values = [day.value for day in run if day.value is not None]
    return Streak(
        direction=direction,
        start=run[0].date,
        end=run[-1].date,
        length=len(run),
        mean=mean(values),
    )


def find_streaks(
    daily: Sequence[RollingPoint],
    *,
    threshold: float,
    direction: str,
    range_start: str,
    range_end: str,
) -> tuple[list[DayStatus], list[Streak]]:
    """Classify every calendar day in ``[range_start, range_end]`` and find maximal
    above/below-threshold runs.

    Every day gets exactly one ``DayStatus``: "missing" (no point in ``daily``), "failing"
    (measured, misses threshold), or "passing" (measured, meets it). A streak is a maximal run
    of consecutive "passing" days; both "failing" and "missing" end a run, with no bridging --
    deliberately conservative, left to the caller to reinterpret via the full ``days`` list (#24).

    ``direction``: "above" (``value >= threshold``) or "below" (``value <= threshold``), both
    threshold-inclusive. ``range_start > range_end`` returns ``([], [])`` rather than raising.

    Raises:
        ValueError: if ``direction`` is not "above" or "below".
    """
    if direction not in _STREAK_DIRECTIONS:
        raise ValueError(f"direction must be one of {_STREAK_DIRECTIONS!r}, got {direction!r}")
    start = date.fromisoformat(range_start)
    end = date.fromisoformat(range_end)
    if start > end:
        return [], []

    values_by_date = {point.date: point.value for point in daily}
    days: list[DayStatus] = []
    current = start
    while current <= end:
        iso = current.isoformat()
        value = values_by_date.get(iso)
        if value is None:
            days.append(DayStatus(date=iso, status="missing", value=None))
        elif (value >= threshold) if direction == "above" else (value <= threshold):
            days.append(DayStatus(date=iso, status="passing", value=value))
        else:
            days.append(DayStatus(date=iso, status="failing", value=value))
        current += timedelta(days=1)

    streaks: list[Streak] = []
    run: list[DayStatus] = []
    for day in days:
        if day.status == "passing":
            run.append(day)
            continue
        if run:
            streaks.append(_streak_from_run(run, direction))
            run = []
    if run:
        streaks.append(_streak_from_run(run, direction))
    return days, streaks


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
    # A constant series has a defined slope (0) but undefined pearson r -- guard avoids
    # raising InsufficientDataError on a data-rich request (#199); r_squared=0.0 by convention.
    r_squared = 0.0 if all(y == ys[0] for y in ys) else pearson(xs, ys) ** 2

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


def _correlation_from_pairs(
    metric_a: str, metric_b: str, pairs: list[tuple[float, float]]
) -> Correlation:
    """Build a Correlation from already-matched pairs, refusing too few.

    Shared by ``correlate`` and ``correlate_lag_sweep`` so the refusal threshold is defined once.
    """
    if len(pairs) < MIN_CORRELATION_SAMPLES:
        raise InsufficientDataError(
            f"correlate needs at least {MIN_CORRELATION_SAMPLES} matched pairs, got {len(pairs)}"
        )

    xs = [a for a, _ in pairs]
    ys = [b for _, b in pairs]
    return Correlation(
        metric_a=metric_a,
        metric_b=metric_b,
        count=len(pairs),
        r=pearson(xs, ys),
        spearman_r=spearman(xs, ys),
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

    return _correlation_from_pairs(metric_a, metric_b, pairs)


def _dated_means(records: Sequence[dict[str, Any]], metric: str) -> dict[str, float]:
    """One value per unique UTC calendar date for ``metric``, averaging same-date duplicates.

    Same ``created_at``-based date derivation as ``_join_key``'s calendar-day fallback, applied
    uniformly (including cycle-sourced metrics). Same-date duplicates (e.g. a nap + main sleep)
    collapse to one mean, so downstream counts are distinct dates, not raw records.
    """
    groups: dict[str, list[float]] = {}
    for record, value in _filtered_records(records, metric):
        day = datetime.fromisoformat(record["created_at"]).astimezone(UTC).date().isoformat()
        groups.setdefault(day, []).append(value)
    return {day: mean(values) for day, values in groups.items()}


def correlate_lag_sweep(
    records_a: Sequence[dict[str, Any]],
    metric_a: str,
    records_b: Sequence[dict[str, Any]],
    metric_b: str,
    *,
    lags: Sequence[int] = DEFAULT_LAG_SWEEP,
) -> list[LagResult]:
    """Correlate two metrics at each of several day offsets ("lags").

    ``lag_days = L`` pairs metric_a's value on date D with metric_b's value on D + L (positive
    lag: metric_a "leads"). Joins on calendar date, not cycle_id like ``correlate()`` -- the two
    can disagree (a Recovery is created on the *next* calendar date after midnight), so a
    physiologically-aligned pairing at lag=0 in ``correlate()`` may show up here at lag=+1/+2.
    Treat a lag value as approximate day alignment, not physiological alignment.

    Never raises from pairing/correlation: each lag yields one ``LagResult``, with a refusal
    reason in place of a Correlation when too few pairs survive. Malformed input (missing/
    unparseable ``created_at``) still propagates.
    """
    dated_a = _dated_means(records_a, metric_a)
    dated_b = _dated_means(records_b, metric_b)

    results: list[LagResult] = []
    for lag in lags:
        pairs: list[tuple[float, float]] = []
        for day_str, value_a in dated_a.items():
            shifted_day = (date.fromisoformat(day_str) + timedelta(days=lag)).isoformat()
            value_b = dated_b.get(shifted_day)
            if value_b is None:
                continue
            pairs.append((value_a, value_b))

        try:
            correlation = _correlation_from_pairs(metric_a, metric_b, pairs)
        except InsufficientDataError as exc:
            results.append(LagResult(lag_days=lag, correlation=None, refused_reason=str(exc)))
        else:
            results.append(LagResult(lag_days=lag, correlation=correlation, refused_reason=None))
    return results
