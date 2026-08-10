from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from whoopmcp.analysis import (
    MIN_CORRELATION_SAMPLES,
    Correlation,
    InsufficientDataError,
    Summary,
    Trend,
    correlate,
    extract_metric,
    linear_slope,
    mean,
    median,
    pearson,
    standardized_effect_size,
    stdev,
    summarize,
    trend,
)


def test_mean() -> None:
    assert mean([1.0, 2.0, 6.0]) == 3.0


def test_mean_of_nothing_is_an_error_not_zero() -> None:
    with pytest.raises(InsufficientDataError):
        mean([])


def test_stdev_uses_the_sample_denominator() -> None:
    # n-1: population stdev of this series would be 2.0.
    assert stdev([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]) == pytest.approx(2.13809, rel=1e-4)


def test_stdev_needs_two_values() -> None:
    with pytest.raises(InsufficientDataError):
        stdev([1.0])


def test_median_odd_count() -> None:
    """Median of odd-length sequence returns the middle element."""
    assert median([1.0, 3.0, 5.0]) == 3.0
    assert median([10.0, 20.0, 30.0, 40.0, 50.0]) == 30.0


def test_median_even_count() -> None:
    """Median of even-length sequence returns average of two middle elements."""
    assert median([1.0, 2.0, 3.0, 4.0]) == 2.5
    assert median([10.0, 20.0, 30.0, 40.0]) == 25.0


def test_median_single_value() -> None:
    """Median of a single element is that element."""
    assert median([42.0]) == 42.0


def test_median_of_nothing_is_an_error() -> None:
    """Median of an empty sequence raises InsufficientDataError."""
    with pytest.raises(InsufficientDataError, match="median of an empty sequence"):
        median([])


def test_standardized_effect_size_happy_path() -> None:
    """Cohen's d between two normal distributions with known values."""
    # Group A: [1, 2, 3, 4, 5] -> mean=3, stdev^2 = 2.5
    # Group B: [5, 6, 7, 8, 9] -> mean=7, stdev^2 = 2.5
    # pooled_variance = ((5-1)*2.5 + (5-1)*2.5) / (5+5-2) = (10 + 10) / 8 = 2.5
    # pooled_stdev = sqrt(2.5) ~ 1.581
    # d = (7 - 3) / 1.581 ~ 2.53
    result = standardized_effect_size(
        mean_a=3.0,
        stdev_a=math.sqrt(2.5),
        count_a=5,
        mean_b=7.0,
        stdev_b=math.sqrt(2.5),
        count_b=5,
    )
    assert result == pytest.approx(2.53, abs=0.01)


def test_standardized_effect_size_insufficient_data_a() -> None:
    """Cohen's d raises InsufficientDataError when count_a < 2."""
    with pytest.raises(InsufficientDataError):
        standardized_effect_size(
            mean_a=5.0, stdev_a=1.0, count_a=1, mean_b=10.0, stdev_b=1.0, count_b=5
        )


def test_standardized_effect_size_insufficient_data_b() -> None:
    """Cohen's d raises InsufficientDataError when count_b < 2."""
    with pytest.raises(InsufficientDataError):
        standardized_effect_size(
            mean_a=5.0, stdev_a=1.0, count_a=5, mean_b=10.0, stdev_b=1.0, count_b=1
        )


def test_standardized_effect_size_zero_pooled_stdev() -> None:
    """Cohen's d raises InsufficientDataError when pooled stdev is exactly 0."""
    # Both groups are perfectly constant and identical: no variance at all
    with pytest.raises(InsufficientDataError):
        standardized_effect_size(
            mean_a=5.0, stdev_a=0.0, count_a=5, mean_b=5.0, stdev_b=0.0, count_b=5
        )


def test_pearson_detects_a_perfect_positive_relationship() -> None:
    assert pearson([1.0, 2.0, 3.0], [2.0, 4.0, 6.0]) == pytest.approx(1.0)


def test_pearson_detects_a_perfect_negative_relationship() -> None:
    assert pearson([1.0, 2.0, 3.0], [6.0, 4.0, 2.0]) == pytest.approx(-1.0)


def test_pearson_on_a_constant_series_is_undefined_not_zero() -> None:
    with pytest.raises(InsufficientDataError, match="constant"):
        pearson([1.0, 1.0, 1.0], [1.0, 2.0, 3.0])


def test_pearson_rejects_mismatched_lengths() -> None:
    with pytest.raises(ValueError, match="length mismatch"):
        pearson([1.0, 2.0], [1.0])


def test_linear_slope_recovers_a_known_gradient() -> None:
    assert linear_slope([0.0, 1.0, 2.0, 3.0], [1.0, 3.0, 5.0, 7.0]) == pytest.approx(2.0)


def test_linear_slope_of_a_flat_series_is_zero() -> None:
    assert linear_slope([0.0, 1.0, 2.0], [5.0, 5.0, 5.0]) == pytest.approx(0.0)


def test_linear_slope_needs_x_to_vary() -> None:
    with pytest.raises(InsufficientDataError, match="constant"):
        linear_slope([1.0, 1.0], [1.0, 2.0])


# -- extract_metric --------------------------------------------------------


def scored_record(
    created_at: str,
    recovery_score: float = 65.0,
    hrv: float = 48.5,
    resting_heart_rate: float = 55,
    sleep_performance: float = 87.0,
    sleep_efficiency: float = 90.5,
    strain: float = 12.0,
    cycle_id: int | None = 900,
) -> dict[str, Any]:
    """Construct a SCORED WHOOP record."""
    return {
        "id": 12345,
        "cycle_id": cycle_id,
        "created_at": created_at,
        "updated_at": created_at,
        "score_state": "SCORED",
        "score": {
            "recovery_score": recovery_score,
            "hrv_rmssd_milli": hrv,
            "resting_heart_rate": resting_heart_rate,
            "sleep_performance_percentage": sleep_performance,
            "sleep_efficiency_percentage": sleep_efficiency,
            "strain": strain,
        },
    }


def unscored_record(created_at: str) -> dict[str, Any]:
    """Construct an UNSCORED record (no valid score)."""
    return {
        "id": 12346,
        "created_at": created_at,
        "updated_at": created_at,
        "score_state": "PENDING_SCORE",
        "score": None,
    }


def test_extract_metric_happy_path() -> None:
    """Extract metric from a few records in order."""
    records = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        scored_record("2026-08-02T06:00:00Z", recovery_score=70.0),
        scored_record("2026-08-03T06:00:00Z", recovery_score=65.0),
    ]
    result = extract_metric(records, "recovery_score")
    assert result == [60.0, 70.0, 65.0]


def test_extract_metric_skips_unscored_records() -> None:
    """Records with score_state != 'SCORED' are excluded entirely."""
    records = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        unscored_record("2026-08-02T06:00:00Z"),
        scored_record("2026-08-03T06:00:00Z", recovery_score=65.0),
    ]
    result = extract_metric(records, "recovery_score")
    assert result == [60.0, 65.0]


def test_extract_metric_skips_missing_metric_key() -> None:
    """Records without the metric key in score dict are skipped, not an error."""
    records = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        {
            "id": 12347,
            "created_at": "2026-08-02T06:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": 70.0},  # has recovery_score
        },
        scored_record("2026-08-03T06:00:00Z", recovery_score=65.0),
    ]
    # Extract hrv, but the middle record doesn't have it (old API version)
    records[1]["score"].pop("hrv_rmssd_milli", None)
    result = extract_metric(records, "hrv")
    assert result == [48.5, 48.5]  # first and third, second skipped


def test_extract_metric_empty_records() -> None:
    """Empty records list returns empty list."""
    result = extract_metric([], "recovery_score")
    assert result == []


def test_extract_metric_all_metrics() -> None:
    """Test extraction of all supported metric names."""
    record = scored_record(
        "2026-08-01T06:00:00Z",
        recovery_score=62.0,
        hrv=45.3,
        resting_heart_rate=54,
        sleep_performance=88.0,
        sleep_efficiency=91.5,
        strain=11.2,
    )
    assert extract_metric([record], "recovery_score") == [62.0]
    assert extract_metric([record], "hrv") == [45.3]
    assert extract_metric([record], "resting_heart_rate") == [54.0]
    assert extract_metric([record], "sleep_performance") == [88.0]
    assert extract_metric([record], "sleep_efficiency") == [91.5]
    assert extract_metric([record], "strain") == [11.2]


# -- summarize --------------------------------------------------------


def test_summarize_happy_path() -> None:
    """Summarize 3+ records computes all statistics."""
    records = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        scored_record("2026-08-02T06:00:00Z", recovery_score=70.0),
        scored_record("2026-08-03T06:00:00Z", recovery_score=80.0),
    ]
    result = summarize(records, "recovery_score", expected_days=3)
    assert isinstance(result, Summary)
    assert result.metric == "recovery_score"
    assert result.count == 3
    assert result.mean == pytest.approx(70.0)
    assert result.minimum == 60.0
    assert result.maximum == 80.0
    # stdev of [60, 70, 80] with n-1: mean=70, sum of sq diffs = 200+0+100=200, div by 2
    # = 100, sqrt = 10
    assert result.stdev == pytest.approx(10.0)
    # Median of [60, 70, 80] is 70.0
    assert result.median == pytest.approx(70.0)
    # All 3 calendar dates covered out of 3 expected
    assert result.days_missing == 0


def test_summarize_excludes_unscored_records() -> None:
    """Unscored records do not contribute to summary count."""
    records = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        unscored_record("2026-08-02T06:00:00Z"),
        scored_record("2026-08-03T06:00:00Z", recovery_score=80.0),
        unscored_record("2026-08-04T06:00:00Z"),
        scored_record("2026-08-05T06:00:00Z", recovery_score=70.0),
    ]
    result = summarize(records, "recovery_score", expected_days=5)
    assert result.count == 3
    assert result.mean == pytest.approx(70.0)
    # Only 3 unique calendar dates (Aug 1, 3, 5) have SCORED records out of 5 expected
    assert result.days_missing == 2


def test_summarize_insufficient_data() -> None:
    """Only one SCORED record raises InsufficientDataError."""
    records = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        unscored_record("2026-08-02T06:00:00Z"),
    ]
    with pytest.raises(InsufficientDataError):
        summarize(records, "recovery_score", expected_days=2)


def test_summarize_days_missing_with_gap() -> None:
    """Days missing reflects gaps in calendar coverage, not record count."""
    # 5 SCORED records spanning 5 distinct calendar dates, but expected_days=10
    records = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        scored_record("2026-08-03T06:00:00Z", recovery_score=70.0),
        scored_record("2026-08-05T06:00:00Z", recovery_score=75.0),
        scored_record("2026-08-07T06:00:00Z", recovery_score=80.0),
        scored_record("2026-08-09T06:00:00Z", recovery_score=65.0),
    ]
    result = summarize(records, "recovery_score", expected_days=10)
    # 5 unique dates covered, 10 expected -> 5 days missing
    assert result.days_missing == 5
    assert result.count == 5


def test_summarize_days_missing_duplicate_dates() -> None:
    """Multiple SCORED records on same calendar date count as one date for coverage."""
    # Two records on 2026-08-01 (e.g., nap + main sleep), one each on Aug 2, 3
    records = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        scored_record("2026-08-01T20:00:00Z", recovery_score=65.0),  # Same day, different time
        scored_record("2026-08-02T06:00:00Z", recovery_score=70.0),
        scored_record("2026-08-03T06:00:00Z", recovery_score=75.0),
    ]
    result = summarize(records, "recovery_score", expected_days=4)
    # 3 unique calendar dates (Aug 1, 2, 3), 4 expected -> 1 day missing
    assert result.count == 4  # All 4 records contribute to the statistic
    assert result.days_missing == 1  # But only 3 unique dates for coverage


# -- trend --------------------------------------------------------


def test_trend_uses_timestamps_not_index() -> None:
    """Trend computes slope per day using actual timestamps, not record index.

    If the records are on days 0, 1, 5, 6 (unevenly spaced) with values
    increasing by 10 per day, an index-based slope would compute wrong.
    The timestamp-based slope should detect 10.0 per day.
    """
    # Day 0: value = 0
    # Day 1: value = 10 (day 1 - day 0 = 1 day, value changed by 10)
    # Day 5: value = 50 (day 5 - day 0 = 5 days, value changed by 50, so 10/day)
    # Day 6: value = 60 (day 6 - day 0 = 6 days, value changed by 60, so 10/day)
    # True slope per day = 10.0
    # Index-based would give (0+10+50+60) / 4 mean, then slope over index 0,1,2,3 = wrong
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=0)).isoformat().replace("+00:00", "Z"),
            recovery_score=0.0,
        ),
        scored_record(
            (base_date + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            recovery_score=10.0,
        ),
        scored_record(
            (base_date + timedelta(days=5)).isoformat().replace("+00:00", "Z"),
            recovery_score=50.0,
        ),
        scored_record(
            (base_date + timedelta(days=6)).isoformat().replace("+00:00", "Z"),
            recovery_score=60.0,
        ),
    ]
    result = trend(records, "recovery_score")
    assert isinstance(result, Trend)
    assert result.metric == "recovery_score"
    assert result.count == 4
    # Slope should be approximately 10.0 per day (timestamp-based)
    # Index-based would be different and wrong
    assert result.slope_per_day == pytest.approx(10.0, abs=0.1)


def test_trend_first_and_last() -> None:
    """Trend first and last reflect chronological values."""
    records = [
        scored_record("2026-08-03T06:00:00Z", recovery_score=75.0),
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        scored_record("2026-08-02T06:00:00Z", recovery_score=70.0),
    ]
    result = trend(records, "recovery_score")
    # Chronologically: day 1 (60), day 2 (70), day 3 (75)
    assert result.first == 60.0
    assert result.last == 75.0


def test_trend_excludes_unscored_records() -> None:
    """Unscored records are not included in trend computation."""
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=0)).isoformat().replace("+00:00", "Z"),
            recovery_score=60.0,
        ),
        unscored_record(
            (base_date + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        ),
        scored_record(
            (base_date + timedelta(days=2)).isoformat().replace("+00:00", "Z"),
            recovery_score=80.0,
        ),
    ]
    result = trend(records, "recovery_score")
    assert result.count == 2  # only the two SCORED records
    assert result.first == 60.0
    assert result.last == 80.0


# -- correlate --------------------------------------------------------


def test_correlate_joins_on_cycle_id() -> None:
    """Two record sets joined on cycle_id -> only matched pairs correlated.

    MIN_CORRELATION_SAMPLES=8, so this needs >=8 *matched* pairs to succeed
    at all -- a version of this test with only 2 or 3 matches would just be
    testing test_correlate_insufficient_samples over again. Cycle_id 9 (A)
    and 100 (B) are unmatched on the other side; if the join were actually a
    concatenation, count would be 9 or 10 instead of 8, and strain=999.0
    would drag the correlation toward zero.
    """
    records_a = [
        scored_record(f"2026-08-{i:02d}T06:00:00Z", recovery_score=float(i * 10), cycle_id=i)
        for i in range(1, 10)  # cycle_id 1..9
    ]
    records_b = [
        scored_record(f"2026-08-{i:02d}T07:00:00Z", strain=float(i * 2), cycle_id=i)
        for i in range(1, 9)  # cycle_id 1..8 -- no partner for A's cycle_id 9
    ] + [
        scored_record("2026-08-15T07:00:00Z", strain=999.0, cycle_id=100),  # no partner in A
    ]

    result = correlate(records_a, "recovery_score", records_b, "strain")

    assert isinstance(result, Correlation)
    assert result.metric_a == "recovery_score"
    assert result.metric_b == "strain"
    assert result.count == 8  # only cycle_id 1..8 matched on both sides
    assert result.r == pytest.approx(1.0, abs=0.01)  # a=10*i, b=2*i for i in 1..8: exact line


def test_correlate_insufficient_samples() -> None:
    """Fewer than MIN_CORRELATION_SAMPLES matched pairs raises InsufficientDataError."""
    # Only 3 matching pairs - below MIN_CORRELATION_SAMPLES (8)
    records_a = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0, cycle_id=1),
        scored_record("2026-08-02T06:00:00Z", recovery_score=70.0, cycle_id=2),
        scored_record("2026-08-03T06:00:00Z", recovery_score=80.0, cycle_id=3),
    ]
    records_b = [
        scored_record("2026-08-01T07:00:00Z", strain=10.0, cycle_id=1),
        scored_record("2026-08-02T07:00:00Z", strain=12.0, cycle_id=2),
        scored_record("2026-08-03T07:00:00Z", strain=15.0, cycle_id=3),
    ]
    with pytest.raises(InsufficientDataError):
        correlate(records_a, "recovery_score", records_b, "strain")


def test_correlate_falls_back_to_calendar_day() -> None:
    """Records without cycle_id join on calendar day from created_at.

    Uses "hrv" (not "strain") on the B side deliberately: "hrv" is not a
    cycle-sourced metric, so an own "id" on the record must NOT be used as a
    join key -- only the calendar-day fallback should apply here.
    """
    # Both records have no cycle_id, so they fall back to calendar day matching
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    # Create 8+ matching pairs on the same calendar day but different times
    records_a = [
        {
            "id": i,
            "created_at": (base_date + timedelta(hours=i)).isoformat().replace("+00:00", "Z"),
            "score_state": "SCORED",
            "score": {"recovery_score": 50.0 + i},
        }
        for i in range(10)
    ]
    records_b = [
        {
            "id": 100 + i,
            "created_at": (base_date + timedelta(hours=i + 1)).isoformat().replace("+00:00", "Z"),
            "score_state": "SCORED",
            "score": {"hrv_rmssd_milli": 10.0 + i},
        }
        for i in range(10)
    ]
    # All on the same calendar day (2026-08-01)
    result = correlate(records_a, "recovery_score", records_b, "hrv")
    assert isinstance(result, Correlation)
    assert result.count == 10  # all pairs matched on calendar day
    assert result.metric_a == "recovery_score"
    assert result.metric_b == "hrv"


def test_correlate_joins_strain_cycle_records_by_own_id() -> None:
    """Cycle records carry ``id``, not ``cycle_id`` -- calendar-day fallback must not catch this."""
    records_a = [
        {
            "id": i,
            "created_at": f"2026-08-{i:02d}T06:00:00Z",
            "score_state": "SCORED",
            "score": {"strain": float(i * 2)},
        }
        for i in range(1, MIN_CORRELATION_SAMPLES + 1)  # ids 1..8, no cycle_id key at all
    ]
    records_b = [
        scored_record(f"2026-08-{i:02d}T07:00:00Z", recovery_score=float(i * 10), cycle_id=i)
        for i in range(1, MIN_CORRELATION_SAMPLES + 1)  # cycle_id 1..8 matches A's id
    ]

    result = correlate(records_a, "strain", records_b, "recovery_score")

    assert isinstance(result, Correlation)
    assert result.count == MIN_CORRELATION_SAMPLES
    assert result.r == pytest.approx(1.0, abs=0.01)  # a=2*i, b=10*i for i in 1..8: exact line


def test_correlate_sufficient_matched_pairs() -> None:
    """With exactly MIN_CORRELATION_SAMPLES matched pairs, correlation succeeds."""
    # Create exactly MIN_CORRELATION_SAMPLES (8) matching pairs
    records_a = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=float(i * 10), cycle_id=i)
        for i in range(1, MIN_CORRELATION_SAMPLES + 1)
    ]
    records_b = [
        scored_record("2026-08-01T07:00:00Z", strain=float(i * 2), cycle_id=i)
        for i in range(1, MIN_CORRELATION_SAMPLES + 1)
    ]
    result = correlate(records_a, "recovery_score", records_b, "strain")
    assert result.count == MIN_CORRELATION_SAMPLES
    # Should be a strong positive correlation (both ascending linearly)
    assert result.r > 0.9
