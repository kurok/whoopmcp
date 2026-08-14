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

#: Below this many observations, a trend/regression is not worth reporting --
#: mirrors MIN_CORRELATION_SAMPLES's philosophy for this module's other
#: "refuse below N" convention.
MIN_TREND_SAMPLES = 8

#: Below this many observations per group an effect size is not worth reporting
#: (#183). The same 8 as its two siblings above, reused rather than newly
#: invented: all three answer the same question -- how many observations before
#: a coefficient describes the member instead of the sample -- and a third
#: threshold would imply a distinction that does not exist.
#:
#: Cohen's d is the most misleading of the three when starved, which is why it
#: needed a floor rather than only a caveat: it divides by a pooled standard
#: deviation, and at two observations per group that denominator is nearly
#: arbitrary. Two 2-point groups measured here produced d = 16.26, a number that
#: reads as overwhelming evidence and is an artefact of the sample size.
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
    """One day's rolling mean/stdev/z-score, or an explicit reason it could
    not be scored -- see ``rolling_z_scores``. ``unscored_reason`` is
    ``None`` if and only if ``rolling_mean``/``rolling_stdev``/``z_score``
    are all populated (``rolling_stdev``/``z_score`` may still be ``None``
    on their own when the window has fewer than 2 points -- see
    ``rolling_z_scores`` -- in which case ``unscored_reason`` explains why).
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

    ``status`` is exactly one of "missing" (no measurement that day at
    all), "failing" (measured, does not meet the threshold/direction), or
    "passing" (measured, meets it). ``value`` is ``None`` if and only if
    ``status == "missing"`` -- the structural distinction the "missing day
    vs. failing day" acceptance criterion asks for.
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
        InsufficientDataError: if either group has fewer than
            ``MIN_EFFECT_SAMPLES`` observations, or when the pooled standard
            deviation is exactly 0 (both groups perfectly constant and
            identical -- undefined, not zero).

    Note the floor is checked per group, not on the total: 14 observations
    split 13/1 tells you as little about the second group as 1/1 does, and a
    check on the sum would let that through.
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
        value = score[key]
        # `not score` catches a missing or empty score dict and `key not in
        # score` catches an absent key, but neither catches the key being
        # present and null -- which is the one case `extract_metric`'s docstring
        # names, and the one that reached `float(None)` and raised (#182).
        #
        # One guard, not two: `float(None)` raises `TypeError`, so the null the
        # docstring promises to skip is handled by the same conversion guard
        # that handles every other unusable value -- a dict, a list, a
        # non-numeric string. An explicit `if value is None: continue` above
        # this reads well but is unreachable in effect; nothing can tell the two
        # versions apart, which is a good reason not to carry both.
        #
        # Skipping rather than raising keeps one malformed record from taking
        # down a whole window's analysis, and raising `TypeError`/`ValueError`
        # out of a filter every analysis path shares is the same opaque,
        # low-level failure #173 and #179 removed elsewhere. Numeric strings
        # still convert, so nothing that worked before stops working.
        try:
            pairs.append((record, float(value)))
        except (TypeError, ValueError):
            continue
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
    for day, value in dated_values:
        groups.setdefault(day, []).append(value)
    return [RollingPoint(date=day, value=mean(values)) for day, values in sorted(groups.items())]


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


#: rolling_z_scores' warm-up reason: the calendar clock for the current run
#: of coverage (see that function's docstring) has not yet reached
#: window_days.
_UNSCORED_WARM_UP = "warm_up"

#: rolling_z_scores' other unscored reason: past warm-up, but the trailing
#: window still contains fewer than 2 points, so a standard deviation (and
#: therefore a z-score) is undefined. Only reachable for window_days <= 1 --
#: a run's own "gap < window_days between consecutive points" invariant
#: otherwise guarantees the immediately preceding point falls in-window too.
_UNSCORED_INSUFFICIENT_VARIANCE = "insufficient_variance"


def rolling_z_scores(daily: Sequence[RollingPoint], window_days: int) -> list[RollingStat]:
    """One ``RollingStat`` per point in ``daily``, scored against a trailing
    ``window_days``-day rolling mean/stdev -- a *rolling*, not global,
    z-score, so a genuine sustained level shift ("a slow seasonal drift")
    re-adapts the baseline instead of reading as a month of anomalies.

    Borrows ``_rolling_means``'s own "current run of coverage" gap-reset
    rule verbatim (see that function's docstring for the full rationale): a
    gap between two consecutive daily points that is itself >= ``window_days``
    resets the warm-up clock. Unlike ``_rolling_means``, this function never
    drops a day from its own return value -- every input day gets exactly
    one ``RollingStat``, in the same order, whether or not it could be
    scored. A day still within warm-up is tagged ``unscored_reason ==
    "warm_up"`` with ``rolling_mean``/``rolling_stdev``/``z_score`` all
    ``None`` -- reported, never silently dropped (issue #24's own Notes: "a
    dropped day reads as a normal day"). A day past warm-up whose own
    trailing window still has fewer than 2 points is tagged
    ``"insufficient_variance"``: its ``rolling_mean`` is still reported (a
    mean of one point is well-defined), but ``rolling_stdev``/``z_score``
    stay ``None``.

    A window whose stdev is exactly 0 (every value in it identical) defines
    ``z_score`` as ``0.0`` -- no deviation to score against, not an outlier
    by construction -- rather than raising or producing inf/NaN.

    This project's own callers (server.py's ``whoop_outliers``) use a
    14-calendar-day window: short enough to re-adapt to a genuine level
    shift within roughly half that span, long enough to span a full
    weekday+weekend cadence twice over. That choice lives in server.py, not
    here -- this function takes ``window_days`` as a parameter and makes no
    assumption about its value.
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
    """The up-to-``radius`` measured points immediately before/after
    ``daily[index]``, via plain list slicing.

    Because ``daily`` is already scoped to the caller's own requested
    range, slicing truncates naturally at the range's own edges -- an
    outlier on the first or last day of the range comes back with fewer
    context points on that side, never an error and never padding.
    "Before"/"after" are nearest *measured* neighbours in this
    day-deduplicated series, not literal calendar-adjacent days: a day with
    no scored record is already simply absent from ``daily`` (the same
    "unmeasured, not zero" contract ``store.get_metric_series`` guarantees).
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
    """Classify every calendar day in ``[range_start, range_end]`` and find
    maximal above/below-threshold runs.

    Every calendar day in the inclusive range is enumerated -- not just
    measured ones -- as exactly one ``DayStatus``: "missing" when ``daily``
    has no point for that date, "failing" when it has one that does not
    meet the threshold, "passing" when it does. A streak is a maximal run of
    consecutive "passing" days; both "failing" and "missing" days end the
    current run, with no bridging logic -- the simplest, most conservative
    interpretation, and a deliberate one: whether an unmeasured day *should*
    break a streak (someone who didn't wear the strap did not fail a
    recovery streak; they stopped measuring) is a judgement call this
    function leaves to the caller, per issue #24's own Notes. The full
    ``days`` list is returned alongside ``streaks`` specifically so a
    caller who disagrees can reconstruct the alternate interpretation
    themselves -- e.g. by noticing two streaks are separated only by
    "missing" days, never "failing" ones.

    ``direction`` accepts exactly "above" (``value >= threshold``) or
    "below" (``value <= threshold``) -- both inclusive of the threshold
    itself, so a value exactly at the threshold is never silently excluded
    from both directions.

    ``range_start > range_end`` (an inverted range) returns ``([], [])``
    rather than raising; ``range_start == range_end`` is a normal one-day
    range. Neither ``daily`` nor the range being empty is an error.

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
