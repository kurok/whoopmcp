from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from whoopmcp.analysis import (
    DEFAULT_LAG_SWEEP,
    MIN_CORRELATION_SAMPLES,
    Correlation,
    InsufficientDataError,
    LagResult,
    Summary,
    Trend,
    correlate,
    correlate_lag_sweep,
    extract_metric,
    linear_slope,
    mean,
    median,
    pearson,
    spearman,
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

    If the records are on days 0, 1, 5, 6, 7, 8, 9, 10 (unevenly spaced) with values
    increasing by 10 per day, an index-based slope would compute wrong.
    The timestamp-based slope should detect 10.0 per day.
    """
    # Days 0,1,5,6,7,8,9,10 with values 0,10,50,60,70,80,90,100 (all 10.0 per day)
    # True slope per day = 10.0
    # Index-based would give (0+10+50+60+70+80+90+100) / 8 mean, then slope over index 0-7 = wrong
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
        scored_record(
            (base_date + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
            recovery_score=70.0,
        ),
        scored_record(
            (base_date + timedelta(days=8)).isoformat().replace("+00:00", "Z"),
            recovery_score=80.0,
        ),
        scored_record(
            (base_date + timedelta(days=9)).isoformat().replace("+00:00", "Z"),
            recovery_score=90.0,
        ),
        scored_record(
            (base_date + timedelta(days=10)).isoformat().replace("+00:00", "Z"),
            recovery_score=100.0,
        ),
    ]
    result = trend(records, "recovery_score")
    assert isinstance(result, Trend)
    assert result.metric == "recovery_score"
    assert result.count == 8
    # Slope should be approximately 10.0 per day (timestamp-based)
    # Index-based would be different and wrong
    assert result.slope_per_day == pytest.approx(10.0, abs=0.1)


def test_trend_first_and_last() -> None:
    """Trend first and last reflect chronological values."""
    records = [
        scored_record("2026-08-03T06:00:00Z", recovery_score=75.0),
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        scored_record("2026-08-02T06:00:00Z", recovery_score=70.0),
        scored_record("2026-08-04T06:00:00Z", recovery_score=80.0),
        scored_record("2026-08-05T06:00:00Z", recovery_score=85.0),
        scored_record("2026-08-06T06:00:00Z", recovery_score=90.0),
        scored_record("2026-08-07T06:00:00Z", recovery_score=95.0),
        scored_record("2026-08-08T06:00:00Z", recovery_score=100.0),
    ]
    result = trend(records, "recovery_score")
    # Chronologically: day 1 (60), day 2 (70), ..., day 8 (100)
    assert result.first == 60.0
    assert result.last == 100.0


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
            recovery_score=65.0,
        ),
        scored_record(
            (base_date + timedelta(days=3)).isoformat().replace("+00:00", "Z"),
            recovery_score=70.0,
        ),
        scored_record(
            (base_date + timedelta(days=4)).isoformat().replace("+00:00", "Z"),
            recovery_score=75.0,
        ),
        scored_record(
            (base_date + timedelta(days=5)).isoformat().replace("+00:00", "Z"),
            recovery_score=80.0,
        ),
        scored_record(
            (base_date + timedelta(days=6)).isoformat().replace("+00:00", "Z"),
            recovery_score=85.0,
        ),
        scored_record(
            (base_date + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
            recovery_score=90.0,
        ),
        scored_record(
            (base_date + timedelta(days=8)).isoformat().replace("+00:00", "Z"),
            recovery_score=95.0,
        ),
    ]
    result = trend(records, "recovery_score")
    assert result.count == 8  # only the eight SCORED records (unscored is excluded)
    assert result.first == 60.0
    assert result.last == 95.0


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


def test_correlate_result_gains_spearman_r_unchanged_otherwise() -> None:
    """correlate() keeps every existing field's exact behavior; spearman_r is additive.

    Reuses test_correlate_joins_on_cycle_id's own fixture and assertions
    verbatim, then checks the one new field.
    """
    records_a = [
        scored_record(f"2026-08-{i:02d}T06:00:00Z", recovery_score=float(i * 10), cycle_id=i)
        for i in range(1, 10)
    ]
    records_b = [
        scored_record(f"2026-08-{i:02d}T07:00:00Z", strain=float(i * 2), cycle_id=i)
        for i in range(1, 9)
    ] + [
        scored_record("2026-08-15T07:00:00Z", strain=999.0, cycle_id=100),
    ]

    result = correlate(records_a, "recovery_score", records_b, "strain")

    # Unchanged: identical to test_correlate_joins_on_cycle_id.
    assert result.count == 8
    assert result.r == pytest.approx(1.0, abs=0.01)
    # New: additive field, same near-perfect value since the relationship
    # is both linear and monotonic (a=10*i, b=2*i).
    assert result.spearman_r == pytest.approx(1.0, abs=0.01)


# -- spearman ----------------------------------------------------------------


def test_spearman_perfect_positive_relationship() -> None:
    assert spearman([1.0, 2.0, 3.0], [10.0, 20.0, 30.0]) == pytest.approx(1.0)


def test_spearman_perfect_negative_relationship() -> None:
    assert spearman([1.0, 2.0, 3.0], [30.0, 20.0, 10.0]) == pytest.approx(-1.0)


def test_spearman_handles_tied_ranks() -> None:
    """Ties are resolved by average rank, matching a hand-computed value.

    xs = [1, 2, 2, 3] -> ranks [1, 2.5, 2.5, 4] (the two 2s share the average
    of positions 2 and 3). ys = [10, 20, 20, 40] -> ranks [1, 2.5, 2.5, 4],
    the identical rank pattern, so Spearman's rho is exactly 1.0.
    """
    xs = [1.0, 2.0, 2.0, 3.0]
    ys = [10.0, 20.0, 20.0, 40.0]
    assert spearman(xs, ys) == pytest.approx(1.0)


def test_spearman_ties_diverge_from_a_no_tie_series() -> None:
    """A hand-computed, non-trivial tied case: ranks differ from raw values.

    xs = [10, 20, 20, 30] -> ranks [1, 2.5, 2.5, 4] (the two 20s tie for
    positions 2 and 3, averaging to 2.5).
    ys = [5, 1, 9, 2]      -> ascending order is 1, 2, 5, 9, so ranks are
    [3, 1, 4, 2] (5 is 3rd-smallest, 1 is smallest, 9 is largest, 2 is
    2nd-smallest) -- ys has no ties of its own.
    Spearman = pearson([1, 2.5, 2.5, 4], [3, 1, 4, 2]).
    mean(rank_x) = 2.5, mean(rank_y) = 2.5.
    dx = [-1.5, 0, 0, 1.5]; dy = [0.5, -1.5, 1.5, -0.5]
    sum(dx*dy) = -0.75 + 0 + 0 - 0.75 = -1.5
    sum(dx^2) = 2.25+0+0+2.25 = 4.5; sum(dy^2) = 0.25+2.25+2.25+0.25 = 5.0
    rho = -1.5 / (sqrt(4.5) * sqrt(5.0)) = -1.5 / sqrt(22.5) ~= -0.31623
    """
    xs = [10.0, 20.0, 20.0, 30.0]
    ys = [5.0, 1.0, 9.0, 2.0]
    assert spearman(xs, ys) == pytest.approx(-1.5 / (4.5**0.5 * 5.0**0.5), rel=1e-6)


def test_spearman_constant_series_is_undefined_not_zero() -> None:
    """Every value tied means every rank is identical -- zero rank-variance,
    the same "undefined, not zero" contract pearson() already has."""
    with pytest.raises(InsufficientDataError):
        spearman([1.0, 1.0, 1.0], [1.0, 2.0, 3.0])
    with pytest.raises(InsufficientDataError):
        spearman([1.0, 2.0, 3.0], [5.0, 5.0, 5.0])


def test_spearman_rejects_mismatched_lengths() -> None:
    with pytest.raises(ValueError, match="length mismatch"):
        spearman([1.0, 2.0], [1.0])


def test_spearman_needs_at_least_two_pairs() -> None:
    with pytest.raises(InsufficientDataError):
        spearman([1.0], [1.0])


def test_spearman_diverges_from_pearson_on_nonlinear_monotonic_series() -> None:
    """y = x^3 is monotonic but not linear: Spearman stays at 1.0 (rank order
    is preserved exactly), Pearson is pulled down by the curvature."""
    xs = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]
    ys = [x**3 for x in xs]
    assert spearman(xs, ys) == pytest.approx(1.0)
    assert pearson(xs, ys) < 0.99


# -- correlate_lag_sweep ------------------------------------------------------


def test_lag_sweep_sign_convention_positive_lag_is_metric_a_leading() -> None:
    """THE SIGN TEST. Write this first; the sign is the easiest thing to get
    backwards (per the issue's own warning).

    `lag_days=L` must pair metric_a's value on date D with metric_b's value
    on date D+L -- a positive lag means metric_a's date precedes metric_b's.

    Fixture: a 14-value series with deliberately low self-similarity at
    every shift except 0 (verified by hand, chars below), so a correlation
    can only be strong at the ONE lag where metric_b is an exact date-
    shifted copy of metric_a -- unlike a plain monotonic series, whose
    autocorrelation is close to 1.0 at every lag and can't discriminate the
    sign at all.

    values = [18, 32, 4, 79, 58, 24, 90, 16, 95, 84, 45, 11, 30, 35]
    metric_a: dates 2026-08-01 .. 2026-08-14, value[i] on day i.
    metric_b: dates 2026-08-02 .. 2026-08-15, value[i] on day (i+1) -- i.e.
    metric_b's date D+1 carries metric_a's own value from date D, for every
    i. So metric_a[D] and metric_b[D+1] are IDENTICAL by construction: lag
    = +1 must be a perfect r = 1.0. Independently computed via Python's
    `statistics.correlation` outside this test (not reusing pearson/
    spearman under test): lag=+1 -> r=1.0 (n=14), lag=0 -> r~=-0.117 (n=13),
    lag=-1 -> r~=0.058 (n=12), lag=-2 -> r~=-0.095 (n=11), lag=+2 ->
    r~=-0.117 (n=13). Only lag=+1 is anywhere close to a real relationship.
    """
    values = [18.0, 32.0, 4.0, 79.0, 58.0, 24.0, 90.0, 16.0, 95.0, 84.0, 45.0, 11.0, 30.0, 35.0]
    base = datetime(2026, 8, 1, tzinfo=UTC)

    metric_a_records = [
        scored_record(
            (base + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=values[i],
            cycle_id=None,
        )
        for i in range(14)
    ]
    # metric_b's date (base + 1 + i) carries values[i] -- an exact one-day-
    # later copy of metric_a.
    metric_b_records = [
        scored_record(
            (base + timedelta(days=1 + i)).isoformat().replace("+00:00", "Z"),
            hrv=values[i],
            cycle_id=None,
        )
        for i in range(14)
    ]

    results = correlate_lag_sweep(
        metric_a_records, "recovery_score", metric_b_records, "hrv", lags=range(-2, 3)
    )
    assert all(isinstance(r, LagResult) for r in results)
    by_lag = {r.lag_days: r for r in results}

    assert by_lag[1].correlation is not None
    assert by_lag[1].correlation.count == 14
    assert by_lag[1].correlation.r == pytest.approx(1.0, abs=1e-9)

    # Every other lag in the sweep is decisively weaker -- not a close call.
    for lag in (-2, -1, 0, 2):
        entry = by_lag[lag]
        assert entry.correlation is not None, f"lag {lag} unexpectedly refused"
        assert abs(entry.correlation.r) < 0.2, (
            f"lag {lag} should be near-zero, got r={entry.correlation.r} "
            "-- the sign convention is likely backwards"
        )
    assert by_lag[-1].correlation.r < by_lag[1].correlation.r
    assert by_lag[0].correlation.r < by_lag[1].correlation.r


def test_lag_sweep_count_shrinks_as_lag_grows() -> None:
    """n (pairs matched) per lag shrinks as |lag_days| grows, and is reported
    per lag -- constructed from two series with only a partial date overlap
    that narrows further the more you shift.
    """
    base = datetime(2026, 8, 1, tzinfo=UTC)
    # metric_a: 20 consecutive days.
    metric_a_records = [
        scored_record(
            (base + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=50.0 + i,
            cycle_id=None,
        )
        for i in range(20)
    ]
    # metric_b: the same 20 consecutive days (full overlap at lag=0, shrinking
    # overlap as |lag| grows away from 0).
    metric_b_records = [
        scored_record(
            (base + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            hrv=30.0 + i,
            cycle_id=None,
        )
        for i in range(20)
    ]

    results = correlate_lag_sweep(
        metric_a_records, "recovery_score", metric_b_records, "hrv", lags=range(-5, 6)
    )
    by_lag = {r.lag_days: r for r in results}

    # None of these should be refused -- 20-day overlap, shrinking by |lag|
    # each time, always leaves >= 15 pairs, comfortably above the 8 floor.
    counts = {}
    for lag in range(-5, 6):
        entry = by_lag[lag]
        assert entry.correlation is not None, f"lag {lag} unexpectedly refused"
        counts[lag] = entry.correlation.count

    assert counts[0] == 20
    assert counts[5] == 15
    assert counts[-5] == 15
    assert counts[3] == 17
    assert counts[-3] == 17
    # Monotonically shrinking away from lag 0 in both directions.
    for lag in range(1, 5):
        assert counts[lag] > counts[lag + 1]
        assert counts[-lag] > counts[-(lag + 1)]


def test_lag_sweep_refused_lag_is_reported_not_omitted() -> None:
    """A lag whose surviving pairs fall below MIN_CORRELATION_SAMPLES is
    reported as refused, still present in the returned list -- not silently
    dropped."""
    base = datetime(2026, 8, 1, tzinfo=UTC)
    # Only 5 days of overlap at lag=0 -- below MIN_CORRELATION_SAMPLES (8).
    metric_a_records = [
        scored_record(
            (base + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=50.0 + i,
            cycle_id=None,
        )
        for i in range(5)
    ]
    metric_b_records = [
        scored_record(
            (base + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            hrv=30.0 + i,
            cycle_id=None,
        )
        for i in range(5)
    ]

    results = correlate_lag_sweep(
        metric_a_records, "recovery_score", metric_b_records, "hrv", lags=range(-1, 2)
    )
    assert len(results) == 3  # every requested lag is present
    by_lag = {r.lag_days: r for r in results}

    refused = by_lag[0]
    assert refused.correlation is None
    assert refused.refused_reason is not None
    assert "5" in refused.refused_reason  # mentions the actual count, like InsufficientDataError


def test_lag_sweep_never_raises_even_for_a_constant_metric() -> None:
    """A constant metric -- which raises InsufficientDataError from the base
    correlate() -- must never escape the sweep; it becomes a per-lag refusal
    for every lag, and the sweep still returns all of them.
    """
    base = datetime(2026, 8, 1, tzinfo=UTC)
    constant_a = [
        scored_record(
            (base + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=65.0,
            cycle_id=None,
        )
        for i in range(12)
    ]
    varying_b = [
        scored_record(
            (base + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            hrv=float(i),
            cycle_id=None,
        )
        for i in range(12)
    ]

    results = correlate_lag_sweep(constant_a, "recovery_score", varying_b, "hrv", lags=(-1, 0, 1))
    assert len(results) == 3
    for result in results:
        assert result.correlation is None
        assert result.refused_reason is not None


def test_lag_sweep_returns_every_requested_lag_not_just_the_best() -> None:
    base = datetime(2026, 8, 1, tzinfo=UTC)
    metric_a_records = [
        scored_record(
            (base + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=float(i),
            cycle_id=None,
        )
        for i in range(15)
    ]
    metric_b_records = [
        scored_record(
            (base + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            hrv=float(i * 2),
            cycle_id=None,
        )
        for i in range(15)
    ]

    requested = [-3, -1, 0, 1, 3]
    results = correlate_lag_sweep(
        metric_a_records, "recovery_score", metric_b_records, "hrv", lags=requested
    )
    assert sorted(r.lag_days for r in results) == sorted(requested)


def test_default_lag_sweep_is_plus_minus_three_days() -> None:
    assert tuple(DEFAULT_LAG_SWEEP) == tuple(range(-3, 4))


# -- trend: r_squared and rolling windows (issue #22) -----


def test_trend_computes_r_squared_on_synthetic_series() -> None:
    """r_squared, slope, and first/last all match hand-computed values.

    Series: day 0-7 with values 10,12,14,16,18,20,22,24 (exactly value = 2*day + 10).
    Expected slope: 2.0 per day (diff is always 2 per 1 day).
    Expected r_squared: 1.0 (perfect linear relationship).

    Hand computation for slope (least squares):
    xs = [0, 1, 2, 3, 4, 5, 6, 7], ys = [10, 12, 14, 16, 18, 20, 22, 24]
    mean(xs) = 3.5, mean(ys) = 17
    numerator = ((-3.5)*(-7) + (-2.5)*(-5) + (-1.5)*(-3) + (-0.5)*(-1)
               + (0.5)*(1) + (1.5)*(3) + (2.5)*(5) + (3.5)*(7))
              = 24.5 + 12.5 + 4.5 + 0.5 + 0.5 + 4.5 + 12.5 + 24.5 = 84
    denominator = 12.25 + 6.25 + 2.25 + 0.25 + 0.25 + 2.25 + 6.25 + 12.25 = 42
    slope = 84 / 42 = 2.0

    r_squared = pearson(xs, ys)^2 = 1.0^2 = 1.0 (since it's perfectly linear)
    """
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=10.0 + 2.0 * i,
        )
        for i in range(8)
    ]
    result = trend(records, "recovery_score")
    assert result.metric == "recovery_score"
    assert result.count == 8
    assert result.slope_per_day == pytest.approx(2.0, abs=0.01)
    assert result.r_squared == pytest.approx(1.0, abs=1e-6)
    assert result.first == 10.0
    assert result.last == 24.0


def test_trend_r_squared_is_one_on_perfectly_linear_series() -> None:
    """A perfectly linear series (value = 3*day + 5) yields r_squared = 1.0."""
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=5.0 + 3.0 * i,
        )
        for i in range(8)  # Days 0-7, values 5, 8, 11, 14, 17, 20, 23, 26
    ]
    result = trend(records, "recovery_score")
    assert result.r_squared == pytest.approx(1.0, abs=1e-6)


def test_trend_r_squared_is_low_on_pure_noise() -> None:
    """A deterministic no-correlation series gives low r_squared.

    Series: day 0-7 with values [1,2,1,2,1,2,1,2] (alternating).
    This has zero correlation with day index: mean(value) = 1.5, and the
    oscillation has no linear trend component even with 8 points.
    """
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    # Alternating pattern: no linear correlation with day
    values = [1.0, 2.0, 1.0, 2.0, 1.0, 2.0, 1.0, 2.0]
    records = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=values[i],
        )
        for i in range(8)
    ]
    result = trend(records, "recovery_score")
    # With no linear trend, r_squared should be very low
    assert result.r_squared < 0.1
    assert result.fit_quality == "negligible"


def test_trend_fit_quality_describes_r_squared_in_words() -> None:
    """fit_quality bands r_squared into a word, per the issue's explicit
    "describe the fit in words in the response" scope bullet -- r_squared
    alone is the number, fit_quality is the words, neither replaces the
    other.

    A perfectly linear series (r_squared == 1.0) must band to "strong".
    """
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=10.0 + 2.0 * i,
        )
        for i in range(8)
    ]
    result = trend(records, "recovery_score")
    assert result.r_squared == pytest.approx(1.0)
    assert result.fit_quality == "strong"


def test_trend_rolling_7d_respects_minimum_periods() -> None:
    """rolling_7d has no entry for the first 6 calendar days of the series.

    Create 10 consecutive daily records (days 0-9).
    rolling_7d should have no entry for days 0-5 (not yet 7 calendar days elapsed).
    The first rolling_7d entry should be for day 6 (dates show 7 calendar days have passed).
    """
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=50.0 + float(i),
        )
        for i in range(10)
    ]
    result = trend(records, "recovery_score")

    # rolling_7d should exist and have data
    assert result.rolling_7d is not None
    assert isinstance(result.rolling_7d, list)

    # First rolling point should be on day 6 (0-indexed)
    # because elapsed time from day 0 to day 6 = 6 days >= 7-1 days
    if result.rolling_7d:
        first_date_str = result.rolling_7d[0].date
        first_date = datetime.fromisoformat(first_date_str).date()
        expected_first = (base_date + timedelta(days=6)).date()
        assert first_date == expected_first

    # Verify no entries exist for days 0-5 (too few days elapsed)
    rolling_dates = {rp.date for rp in result.rolling_7d}
    for i in range(6):
        day_date = (base_date + timedelta(days=i)).date().isoformat()
        assert day_date not in rolling_dates


def test_trend_rolling_windows_computed_by_date_not_row_count() -> None:
    """Rolling windows use calendar date range, not row count -- and the
    minimum-periods clock restarts after a gap at least as long as the
    window itself, rather than staying pinned to the series' very first date.

    Records: days 0-4 (daily), a 19-day gap, then days 24-33 (daily). The
    gap (20 days between day 4 and day 24) is bigger than the 7-day window,
    so no point from before it could ever fall inside a post-gap window --
    which means the immediately-post-gap points (24-29) must get NO
    rolling_7d entry at all, exactly as if day 24 were itself the start of
    a new series. Only once 6 more calendar days have elapsed *within the
    post-gap run* (day 30) does a real, full 7-day window exist, and its
    value must come only from days 24-30 -- never from the pre-gap cluster.
    """
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = []

    # Days 0-4: first cluster (5 days -- never reaches a full 7-day window
    # on its own, so it should produce no rolling_7d points either).
    for i in range(5):
        records.append(
            scored_record(
                (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
                recovery_score=50.0 + float(i),
            )
        )

    # Gap: no records for days 5-23 (19 days -- exceeds the 7-day window).

    # Days 24-33: second cluster (after the gap), 10 days -- enough to reach
    # a full window post-reset.
    for i in range(24, 34):
        records.append(
            scored_record(
                (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
                recovery_score=50.0 + float(i - 24),
            )
        )

    result = trend(records, "recovery_score")
    points_by_date = {rp.date: rp.value for rp in result.rolling_7d}

    # The first 6 post-gap days (24-29) must have NO rolling_7d entry: the
    # gap reset the clock, and only 0-5 calendar days have elapsed since day
    # 24 at that point -- not the full 6 the 7-day window requires.
    for i in range(24, 30):
        day = (base_date + timedelta(days=i)).date().isoformat()
        assert day not in points_by_date, (
            f"day {i} got a rolling_7d point from only {i - 24 + 1} post-gap "
            "days of real history -- the minimum-periods clock did not reset "
            "after the gap"
        )

    # Day 30 is the first point with a genuine 7-day post-gap window
    # [24, 30], values 50..56 -- and must exclude every pre-gap value.
    day_30 = (base_date + timedelta(days=30)).date().isoformat()
    assert day_30 in points_by_date
    expected_value = mean([50.0 + float(i) for i in range(7)])
    assert points_by_date[day_30] == pytest.approx(expected_value, abs=0.01)

    # The pre-gap cluster (only 5 days) never reaches a full window either.
    for i in range(5):
        day = (base_date + timedelta(days=i)).date().isoformat()
        assert day not in points_by_date


def test_trend_below_min_samples_raises_insufficient_data_error() -> None:
    """A series with 7 or fewer SCORED records raises InsufficientDataError.

    Tests with exactly MIN_TREND_SAMPLES - 1 = 7 records.
    """
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=50.0 + float(i),
        )
        for i in range(7)  # Exactly 7 records
    ]
    with pytest.raises(InsufficientDataError) as exc_info:
        trend(records, "recovery_score")
    # Message should mention the actual count
    assert "7" in str(exc_info.value)


def test_trend_constant_value_series_raises_insufficient_data_error() -> None:
    """A constant-value metric series (all values identical) raises InsufficientDataError.

    Even with 10 SCORED records, if they all have the same metric value,
    pearson() will raise InsufficientDataError because the y series is constant.
    This is intentional: a flat metric has undefined r_squared.
    """
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    # All records have recovery_score = 65.0 (constant)
    records = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=65.0,  # Identical across all records
        )
        for i in range(10)  # Plenty of records, but constant values
    ]
    with pytest.raises(InsufficientDataError, match=r"constant|insufficient"):
        trend(records, "recovery_score")
