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
from typing import Any

#: Below this many paired observations a correlation is not worth reporting.
MIN_CORRELATION_SAMPLES = 8


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


def extract_metric(records: Sequence[dict[str, Any]], metric: str) -> list[float]:
    """Pull one named metric out of a list of records, skipping nulls.

    TODO(#3): map friendly names onto WHOOP's nested paths, e.g.
    "recovery_score" -> record["score"]["recovery_score"], "hrv" ->
    record["score"]["hrv_rmssd_milli"], "strain" -> record["score"]["strain"].
    Records with score_state != "SCORED" carry no score and must be dropped
    rather than read as zero.
    """
    raise NotImplementedError("extract_metric is not implemented yet -- see issue #3")


def summarize(records: Sequence[dict[str, Any]], metric: str) -> Summary:
    """Descriptive statistics for one metric across ``records``.

    TODO(#3): extract_metric, then fold into a Summary.
    """
    raise NotImplementedError("summarize is not implemented yet -- see issue #3")


def trend(records: Sequence[dict[str, Any]], metric: str) -> Trend:
    """Direction and rate of change for one metric over time.

    TODO(#3): pair each value with its record timestamp expressed in days,
    then linear_slope. Use the record's own timestamp, not its index --
    WHOOP records are not evenly spaced once a strap is taken off.
    """
    raise NotImplementedError("trend is not implemented yet -- see issue #3")


def correlate(
    records_a: Sequence[dict[str, Any]],
    metric_a: str,
    records_b: Sequence[dict[str, Any]],
    metric_b: str,
) -> Correlation:
    """Correlate two metrics that may come from different collections.

    TODO(#3): join on cycle_id where both sides have one, otherwise on
    calendar day, before correlating. Refuse below MIN_CORRELATION_SAMPLES.
    """
    raise NotImplementedError("correlate is not implemented yet -- see issue #3")
