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
from datetime import UTC, date, datetime, timedelta
from typing import Any

#: Below this many paired observations a correlation is not worth reporting.
MIN_CORRELATION_SAMPLES = 8

#: The default lag sweep for correlate_lag_sweep: +/- 3 days.
DEFAULT_LAG_SWEEP: tuple[int, ...] = tuple(range(-3, 4))

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


@dataclass(frozen=True, slots=True)
class Trend:
    """A least-squares trend, in metric units per day."""

    metric: str
    count: int
    slope_per_day: float
    first: float
    last: float


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

    Pearson's r computed over each series' average ranks (ties resolved by
    the mean of the tied positions' ranks).

    Raises:
        ValueError: if the sequences differ in length.
        InsufficientDataError: with fewer than two pairs, or when either
            series has zero rank-variance (all values tied) -- raised by
            ``pearson`` itself on the ranked series.
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


def summarize(records: Sequence[dict[str, Any]], metric: str) -> Summary:
    """Descriptive statistics for one metric across ``records``."""
    values = extract_metric(records, metric)
    return Summary(
        metric=metric,
        count=len(values),
        mean=mean(values),
        stdev=stdev(values),
        minimum=min(values),
        maximum=max(values),
    )


def trend(records: Sequence[dict[str, Any]], metric: str) -> Trend:
    """Direction and rate of change for one metric over time."""
    pairs = [
        (datetime.fromisoformat(record["created_at"]).timestamp() / 86_400.0, value)
        for record, value in _filtered_records(records, metric)
    ]
    pairs.sort(key=lambda pair: pair[0])
    xs = [day for day, _ in pairs]
    ys = [value for _, value in pairs]
    slope = linear_slope(xs, ys)
    return Trend(metric=metric, count=len(ys), slope_per_day=slope, first=ys[0], last=ys[-1])


def _correlation_from_pairs(
    metric_a: str, metric_b: str, pairs: list[tuple[float, float]]
) -> Correlation:
    """Build a Correlation from already-matched pairs, refusing too few.

    Shared by ``correlate`` (cycle_id-joined pairs) and
    ``correlate_lag_sweep`` (date-joined pairs) so the refusal threshold and
    message are defined in exactly one place.
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
    """One value per unique UTC calendar date for ``metric``, averaging
    same-date duplicates.

    Uses the same ``created_at``-based date derivation as ``_join_key``'s
    calendar-day fallback, uniformly for every record -- including
    cycle-sourced metrics like strain, which carry ``created_at`` too.

    A metric with more than one scored record on the same date (e.g. a nap
    alongside a main sleep) collapses to one averaged value for that date,
    so a ``LagResult.correlation.count`` downstream counts distinct dates,
    not raw records.
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

    ``lag_days = L`` pairs metric_a's value on calendar date D with
    metric_b's value on calendar date D + L: a positive lag means
    metric_a's date precedes metric_b's by that many days -- metric_a
    "leads".

    This joins purely on calendar date (derived from ``created_at``), which
    is a deliberate departure from ``correlate()``'s cycle_id-based join --
    lag arithmetic is fundamentally a date operation. The two do NOT
    coincide in general: a Recovery is created hours after the Cycle it
    belongs to (often after midnight, so on the *next* calendar date), so
    the "physiologically aligned" pairing that correlate()'s cycle_id join
    finds at lag=0 can show up here at lag=+1 (or +2) instead. Treat a lag
    value from this sweep as an approximate day-to-day alignment, not a
    physiological-cycle one -- callers reasoning about "yesterday's X vs
    today's Y" should expect the peak near the lag they'd predict, not
    necessarily at exactly that lag.

    Raises nothing from the pairing/correlation logic itself: every lag in
    ``lags`` produces exactly one ``LagResult``, with a refusal reason in
    place of a Correlation when too few pairs survive the shift. Malformed
    input (a record missing ``created_at``, or an unparseable timestamp)
    still propagates, same as every other function in this module.
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
