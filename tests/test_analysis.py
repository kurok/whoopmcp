from __future__ import annotations

import ast
import math
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from whoopmcp import analysis
from whoopmcp.analysis import (
    DEFAULT_LAG_SWEEP,
    MIN_CORRELATION_SAMPLES,
    Correlation,
    InsufficientDataError,
    LagResult,
    RollingPoint,
    Summary,
    Trend,
    context_window,
    correlate,
    correlate_lag_sweep,
    extract_metric,
    find_streaks,
    linear_slope,
    mean,
    median,
    pearson,
    rolling_z_scores,
    spearman,
    standardized_effect_size,
    stdev,
    summarize,
    trend,
)

#: Minimum sample count for effect size, matching the module's convention.
#: This will be defined in analysis.py as MIN_EFFECT_SAMPLES = 8.
_MIN_EFFECT_SAMPLES = 8


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
    # Both groups: stdev^2 = 2.5, means 3 and 7.
    # pooled_variance = ((8-1)*2.5 + (8-1)*2.5) / (8+8-2) = 35 / 14 = 2.5
    # pooled_stdev = sqrt(2.5) ~ 1.581
    # d = (7 - 3) / 1.581 ~ 2.53
    result = standardized_effect_size(
        mean_a=3.0,
        stdev_a=math.sqrt(2.5),
        count_a=8,
        mean_b=7.0,
        stdev_b=math.sqrt(2.5),
        count_b=8,
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


# -- issue #183: effect size floor tests -----------------------------------


def test_standardized_effect_size_rejects_two_per_group() -> None:
    """Cohen's d raises InsufficientDataError when count < MIN_EFFECT_SAMPLES per group."""
    with pytest.raises(
        InsufficientDataError, match="at least 8 observations per group"
    ) as exc_info:
        standardized_effect_size(
            mean_a=61.0, stdev_a=1.41, count_a=2, mean_b=84.0, stdev_b=1.41, count_b=2
        )
    assert "8" in str(exc_info.value) or "MIN_EFFECT_SAMPLES" in str(exc_info.value)


def test_standardized_effect_size_boundary_exactly_min_samples_per_group() -> None:
    """Cohen's d succeeds when BOTH groups have exactly MIN_EFFECT_SAMPLES observations."""
    result = standardized_effect_size(
        mean_a=61.0,
        stdev_a=1.5,
        count_a=_MIN_EFFECT_SAMPLES,
        mean_b=84.0,
        stdev_b=1.5,
        count_b=_MIN_EFFECT_SAMPLES,
    )
    assert isinstance(result, float)
    assert not math.isnan(result)


def test_standardized_effect_size_boundary_one_below_min_group_a() -> None:
    """Cohen's d raises when group A has fewer than MIN_EFFECT_SAMPLES observations."""
    with pytest.raises(InsufficientDataError):
        standardized_effect_size(
            mean_a=61.0,
            stdev_a=1.5,
            count_a=_MIN_EFFECT_SAMPLES - 1,
            mean_b=84.0,
            stdev_b=1.5,
            count_b=_MIN_EFFECT_SAMPLES,
        )


def test_standardized_effect_size_boundary_one_below_min_group_b() -> None:
    """Cohen's d raises when group B has fewer than MIN_EFFECT_SAMPLES observations."""
    with pytest.raises(InsufficientDataError):
        standardized_effect_size(
            mean_a=61.0,
            stdev_a=1.5,
            count_a=_MIN_EFFECT_SAMPLES,
            mean_b=84.0,
            stdev_b=1.5,
            count_b=_MIN_EFFECT_SAMPLES - 1,
        )


def test_standardized_effect_size_no_regression_above_floor() -> None:
    """Cohen's d still works correctly for reasonable sample sizes above the floor."""
    # Group A: mean=3, stdev=sqrt(2.5) (matches test_standardized_effect_size_happy_path)
    # Group B: mean=7, stdev=sqrt(2.5)
    # With n=10 per group, should compute the same d as the existing test
    result = standardized_effect_size(
        mean_a=3.0,
        stdev_a=math.sqrt(2.5),
        count_a=10,
        mean_b=7.0,
        stdev_b=math.sqrt(2.5),
        count_b=10,
    )
    # d = (7 - 3) / sqrt(2.5) ~ 2.53 (pooled stdev is sqrt(2.5) when n >> 1)
    assert result == pytest.approx(2.53, abs=0.01)


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


# -- Issue #182: handle null metric values gracefully -------------------


def test_extract_metric_skips_explicit_null_values() -> None:
    """A SCORED record with explicit null for the requested metric is skipped."""
    records = [
        scored_record("2026-08-01T06:00:00Z", hrv=48.5),
        # Middle record: SCORED state but explicit None for hrv
        {
            "id": 12347,
            "cycle_id": 900,
            "created_at": "2026-08-02T06:00:00Z",
            "updated_at": "2026-08-02T06:00:00Z",
            "score_state": "SCORED",
            "score": {
                "recovery_score": 65.0,
                "hrv_rmssd_milli": None,  # Explicit null
                "resting_heart_rate": 55,
                "sleep_performance_percentage": 87.0,
                "sleep_efficiency_percentage": 90.5,
                "strain": 12.0,
            },
        },
        scored_record("2026-08-03T06:00:00Z", hrv=52.0),
    ]
    result = extract_metric(records, "hrv")
    # Only the first and third records (48.5 and 52.0), skipping the null
    assert result == [48.5, 52.0]


def test_summarize_skips_records_with_null_metrics() -> None:
    """summarize() skips SCORED records with explicit null for the metric."""
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=0)).isoformat().replace("+00:00", "Z"),
            recovery_score=60.0,
        ),
        # Day 1: SCORED but null recovery_score
        {
            "id": 12348,
            "cycle_id": 901,
            "created_at": (base_date + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            "updated_at": (base_date + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            "score_state": "SCORED",
            "score": {"recovery_score": None},  # Explicit null
        },
        scored_record(
            (base_date + timedelta(days=2)).isoformat().replace("+00:00", "Z"),
            recovery_score=70.0,
        ),
        scored_record(
            (base_date + timedelta(days=3)).isoformat().replace("+00:00", "Z"),
            recovery_score=65.0,
        ),
    ]
    result = summarize(records, "recovery_score", expected_days=4)
    # Only 3 valid records: 60, 70, 65 (mean = 65, null is skipped)
    assert result.count == 3
    assert result.mean == pytest.approx(65.0)
    # 3 unique calendar dates (days 0, 2, 3), 4 expected -> 1 day missing
    assert result.days_missing == 1


def test_trend_skips_records_with_null_metrics() -> None:
    """trend() skips SCORED records with an explicit null for the metric."""
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=50.0 + float(i),
        )
        for i in range(9)
    ]
    # Replace day 3 with a null value
    records[3] = {
        "id": 12349,
        "cycle_id": 903,
        "created_at": (base_date + timedelta(days=3)).isoformat().replace("+00:00", "Z"),
        "updated_at": (base_date + timedelta(days=3)).isoformat().replace("+00:00", "Z"),
        "score_state": "SCORED",
        "score": {"recovery_score": None},  # Explicit null
    }
    result = trend(records, "recovery_score")
    # 8 valid records survive the skip, so trend has exactly its minimum.
    assert result.count == 8
    # Slope should be approximately 1.0 per day
    assert result.slope_per_day == pytest.approx(1.0, abs=0.1)


def test_correlate_skips_records_with_null_metrics() -> None:
    """correlate() skips SCORED records with explicit null for either metric."""
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    # Create 8+ pairs, but inject a null on the A side
    records_a = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=50.0 + float(i),
            cycle_id=i,
        )
        for i in range(9)
    ]
    # Day 2: SCORED but null recovery_score on A side
    records_a[2] = {
        "id": 12350,
        "cycle_id": 2,
        "created_at": (base_date + timedelta(days=2)).isoformat().replace("+00:00", "Z"),
        "updated_at": (base_date + timedelta(days=2)).isoformat().replace("+00:00", "Z"),
        "score_state": "SCORED",
        "score": {"recovery_score": None},
    }

    records_b = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            strain=10.0 + float(i * 2),
            cycle_id=i,
        )
        for i in range(9)
    ]

    result = correlate(records_a, "recovery_score", records_b, "strain")
    # 8 valid pairs (cycle_id 0,1,3,4,5,6,7,8 matched, 2 skipped due to null on A)
    assert result.count == 8


def test_correlate_lag_sweep_skips_records_with_null_metrics() -> None:
    """correlate_lag_sweep() skips records with explicit null for either metric."""
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records_a = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=50.0 + float(i),
            cycle_id=None,
        )
        for i in range(10)
    ]
    # Day 1: SCORED but null recovery_score
    records_a[1] = {
        "id": 12351,
        "created_at": (base_date + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "updated_at": (base_date + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "score_state": "SCORED",
        "score": {"recovery_score": None},
    }

    records_b = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            hrv=30.0 + float(i),
            cycle_id=None,
        )
        for i in range(10)
    ]

    results = correlate_lag_sweep(records_a, "recovery_score", records_b, "hrv", lags=(0,))
    assert len(results) == 1
    result = results[0]
    # 9 pairs at lag 0 (10 minus the 1 null on day 1)
    assert result.correlation is not None
    assert result.correlation.count == 9


def test_every_consumer_of_the_shared_filter_is_covered_above() -> None:
    """Pin which functions the null guard actually protects (#182)."""
    source = Path(analysis.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    consumers = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and any(
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Name)
            and inner.func.id == "_filtered_records"
            for inner in ast.walk(node)
        )
    }

    # `correlate` and `correlate_lag_sweep` are absent because they reach the
    # filter through `_dated_means`/`_grouped_values` rather than calling it
    # directly -- their null-value tests above exercise it transitively.
    assert consumers == {
        "_dated_means",
        "_grouped_values",
        "extract_metric",
        "summarize",
        "trend",
    }, (
        "the set of functions sharing the null guard changed; cover the new one "
        f"with a null-value test before updating this list. Found: {sorted(consumers)}"
    )


def test_extract_metric_all_null_raises_insufficient_data_error() -> None:
    """When every SCORED record has null for the metric, it behaves like an"""
    records = [
        {
            "id": 12353,
            "cycle_id": 905,
            "created_at": "2026-08-01T06:00:00Z",
            "updated_at": "2026-08-01T06:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": None},
        },
        {
            "id": 12354,
            "cycle_id": 906,
            "created_at": "2026-08-02T06:00:00Z",
            "updated_at": "2026-08-02T06:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": None},
        },
        {
            "id": 12355,
            "cycle_id": 907,
            "created_at": "2026-08-03T06:00:00Z",
            "updated_at": "2026-08-03T06:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": None},
        },
    ]
    # With all nulls, summarize should raise InsufficientDataError, not TypeError
    with pytest.raises(InsufficientDataError):
        summarize(records, "recovery_score", expected_days=3)

    # Same for trend
    with pytest.raises(InsufficientDataError):
        trend(records, "recovery_score")


def test_extract_metric_non_numeric_values_are_skipped() -> None:
    """Non-numeric non-null values (dict, list, non-numeric string) are skipped."""
    records = [
        scored_record("2026-08-01T06:00:00Z", hrv=48.5),
        # Non-numeric dict
        {
            "id": 12356,
            "cycle_id": 908,
            "created_at": "2026-08-02T06:00:00Z",
            "updated_at": "2026-08-02T06:00:00Z",
            "score_state": "SCORED",
            "score": {"hrv_rmssd_milli": {"nested": "dict"}},  # type: ignore[dict-item]
        },
        scored_record("2026-08-03T06:00:00Z", hrv=52.0),
        # Non-numeric list
        {
            "id": 12357,
            "cycle_id": 909,
            "created_at": "2026-08-04T06:00:00Z",
            "updated_at": "2026-08-04T06:00:00Z",
            "score_state": "SCORED",
            "score": {"hrv_rmssd_milli": ["list", "value"]},  # type: ignore[dict-item]
        },
        scored_record("2026-08-05T06:00:00Z", hrv=50.0),
        # Non-numeric string
        {
            "id": 12358,
            "cycle_id": 910,
            "created_at": "2026-08-06T06:00:00Z",
            "updated_at": "2026-08-06T06:00:00Z",
            "score_state": "SCORED",
            "score": {"hrv_rmssd_milli": "not_a_number"},
        },
        scored_record("2026-08-07T06:00:00Z", hrv=51.0),
    ]
    result = extract_metric(records, "hrv")
    # Only numeric values: 48.5, 52.0, 50.0, 51.0 (four total)
    assert result == [48.5, 52.0, 50.0, 51.0]
    assert len(result) == 4


def test_extract_metric_numeric_strings_are_still_accepted() -> None:
    """REGRESSION: numeric strings like "60."""
    records = [
        scored_record("2026-08-01T06:00:00Z", recovery_score=60.0),
        # Numeric string
        {
            "id": 12359,
            "cycle_id": 911,
            "created_at": "2026-08-02T06:00:00Z",
            "updated_at": "2026-08-02T06:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": "65.5"},  # type: ignore[dict-item]
        },
        scored_record("2026-08-03T06:00:00Z", recovery_score=70.0),
        # Another numeric string variant
        {
            "id": 12360,
            "cycle_id": 912,
            "created_at": "2026-08-04T06:00:00Z",
            "updated_at": "2026-08-04T06:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": "72"},  # type: ignore[dict-item]
        },
    ]
    result = extract_metric(records, "recovery_score")
    # All four should convert: 60.0, 65.5, 70.0, 72.0
    assert result == [60.0, 65.5, 70.0, 72.0]


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
    """Trend computes slope per day using actual timestamps, not record index."""
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
    """Two record sets joined on cycle_id -> only matched pairs correlated."""
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
    """Records without cycle_id join on calendar day from created_at."""
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
    """correlate() keeps every existing field's exact behavior; spearman_r is additive."""
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
    """Ties are resolved by average rank, matching a hand-computed value."""
    xs = [1.0, 2.0, 2.0, 3.0]
    ys = [10.0, 20.0, 20.0, 40.0]
    assert spearman(xs, ys) == pytest.approx(1.0)


def test_spearman_ties_diverge_from_a_no_tie_series() -> None:
    """A hand-computed, non-trivial tied case: ranks differ from raw values."""
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
    """THE SIGN TEST."""
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
    """r_squared, slope, and first/last all match hand-computed values."""
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
    """A deterministic no-correlation series gives low r_squared."""
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


def test_trend_of_a_constant_series_reports_zero_slope_not_a_refusal() -> None:
    """A perfectly constant series is a flat trend, not insufficient data."""
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=100.0,
        )
        for i in range(10)
    ]
    result = trend(records, "recovery_score")
    assert result.count == 10
    assert result.slope_per_day == 0.0
    assert result.r_squared == 0.0
    assert result.fit_quality == "negligible"
    assert result.first == 100.0
    assert result.last == 100.0
    # The rolling series never touched pearson and must still be present.
    assert result.rolling_7d, "rolling_7d must still be computed for a constant series"


def test_trend_fit_quality_describes_r_squared_in_words() -> None:
    """fit_quality bands r_squared into a word, per the issue's explicit"""
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
    """rolling_7d has no entry for the first 6 calendar days of the series."""
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
    """Rolling windows use calendar date range, not row count -- and the"""
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
    """A series with 7 or fewer SCORED records raises InsufficientDataError."""
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


def test_trend_constant_value_series_no_longer_raises() -> None:
    """The old contract inverted: a constant series used to be pinned as
    raising InsufficientDataError, on the claim that "a flat metric has
    undefined r_squared". #199 overrules that: only the correlation
    coefficient is undefined; the trend itself is a well-defined flat line,
    and refusing 10 good observations as "insufficient data" was the bug.
    Kept alongside the fuller assertion test above so the reversal is
    explicit in the history rather than a silently-deleted pin.
    """
    base_date = datetime(2026, 8, 1, tzinfo=UTC)
    records = [
        scored_record(
            (base_date + timedelta(days=i)).isoformat().replace("+00:00", "Z"),
            recovery_score=65.0,  # Identical across all records
        )
        for i in range(10)  # Plenty of records, but constant values
    ]
    result = trend(records, "recovery_score")  # must not raise
    assert result.slope_per_day == 0.0
    assert result.r_squared == 0.0


# ===========================================================================
# Issue #24: rolling_z_scores, context_window, find_streaks
#
# Written before the implementation exists -- every test below is expected
# to fail (ImportError on the names this file's own import block above now
# requests, or a plain assertion failure) until #24 lands. These are pure
# functions over already day-deduplicated ``RollingPoint`` sequences, same
# as ``_rolling_means`` -- no records, no store, no respx needed here (that
# lives in tests/test_whoop_outliers.py and tests/test_whoop_streaks.py).
# ===========================================================================


def _daily_points(start: date, values: list[float]) -> list[RollingPoint]:
    """A day-deduplicated RollingPoint series: one point per consecutive
    calendar day starting at ``start``, values taken in order."""
    return [
        RollingPoint(date=(start + timedelta(days=i)).isoformat(), value=v)
        for i, v in enumerate(values)
    ]


def _gapped_points(days: list[int], values: list[float], base: date) -> list[RollingPoint]:
    """A RollingPoint series at explicit (possibly non-consecutive) day
    offsets from ``base`` -- for building deliberate coverage gaps."""
    return [
        RollingPoint(date=(base + timedelta(days=d)).isoformat(), value=v)
        for d, v in zip(days, values, strict=True)
    ]


# -- rolling_z_scores: known anomaly on an otherwise-flat series -----------


def test_rolling_z_scores_flags_a_known_anomaly() -> None:
    """One deliberate spike inserted into an otherwise-flat 30-day series."""
    values = [50.0] * 30
    values[20] = 90.0
    daily = _daily_points(date(2026, 1, 1), values)

    result = rolling_z_scores(daily, window_days=7)
    assert len(result) == 30

    spike = result[20]
    assert spike.unscored_reason is None
    assert spike.z_score is not None
    assert abs(spike.z_score) >= 2.0

    # Neighbouring and distant normal days (all past the 6-day warm-up)
    # must not be flagged, even the ones whose own trailing window still
    # contains the spike value.
    for i in (10, 18, 19, 21, 22, 29):
        point = result[i]
        assert point.unscored_reason is None, f"index {i} unexpectedly unscored"
        assert point.z_score is not None
        assert abs(point.z_score) < 2.0, f"index {i} was flagged but is not the anomaly"


def test_rolling_z_scores_does_not_flag_a_slow_seasonal_drift() -> None:
    """A genuine, sustained level shift ("a slow seasonal drift") over the"""
    baseline = [50.0] * 150
    shifted = [65.0] * 30
    values = baseline + shifted
    daily = _daily_points(date(2026, 1, 1), values)

    # -- the naive, global comparison this test exists to discredit --
    global_mean = mean(values)
    global_stdev = stdev(values)
    global_z = [(v - global_mean) / global_stdev for v in values]
    shift_global_z = global_z[150:]
    flagged_global = sum(1 for z in shift_global_z if abs(z) >= 2.0)
    # The shifted month is a small, well-separated minority of the whole
    # series, so its global z-score sits above 2 for essentially all of it --
    # a global check would read the new, stable normal as a month-long
    # anomaly.
    assert flagged_global >= 25, (
        f"fixture is not actually discriminating: only {flagged_global}/30 shifted days "
        "would be flagged by a naive global z-score; the fixture needs a starker split"
    )

    # -- the rolling result this acceptance criterion is actually about --
    result = rolling_z_scores(daily, window_days=7)
    shift_rolling = result[150:]
    flagged_rolling = [r for r in shift_rolling if r.z_score is not None and abs(r.z_score) >= 2.0]
    # At most the single transition day (the window still mostly full of
    # the old baseline) may legitimately read as a change point -- the
    # other 29 days, once the window has re-adapted to the new normal,
    # must not be flagged. "Does not flag every day" is the literal
    # acceptance criterion; this asserts far fewer than "every day", and
    # far fewer than the global comparison above.
    assert len(flagged_rolling) <= 2
    assert len(flagged_rolling) < flagged_global

    # Deep into the shifted regime the rolling window has fully readjusted:
    # z should sit near zero, not near the global comparison's ~2.2.
    deep_shift = result[170]
    assert deep_shift.z_score is not None
    assert abs(deep_shift.z_score) < 1.0


def test_rolling_z_scores_tags_warmup_days_as_unscored_not_dropped() -> None:
    """The first (window_days - 1) days carry unscored_reason == "warm_up"
    with mean/stdev/z_score all None -- reported, never absent from the
    result at all."""
    window_days = 5
    values = [50.0 + i for i in range(10)]
    daily = _daily_points(date(2026, 2, 1), values)

    result = rolling_z_scores(daily, window_days=window_days)
    assert len(result) == len(daily) == 10

    for i in range(window_days - 1):
        point = result[i]
        assert point.unscored_reason == "warm_up", f"index {i} should be tagged warm_up"
        assert point.rolling_mean is None
        assert point.rolling_stdev is None
        assert point.z_score is None

    for i in range(window_days - 1, 10):
        point = result[i]
        assert point.unscored_reason is None
        assert point.z_score is not None


def test_rolling_z_scores_resets_warmup_after_a_long_gap() -> None:
    """Mirrors _rolling_means' own gap-reset test (tests/test_analysis.py's
    test_trend_rolling_windows_computed_by_date_not_row_count) but for this
    new function: a gap >= window_days resets the warm-up clock, and every
    day the old function would have silently DROPPED for still being
    within a post-gap warm-up must instead appear here, tagged "warm_up".
    """
    base_date = date(2026, 8, 1)
    days = list(range(5)) + list(range(24, 34))
    values = [50.0 + i for i in range(5)] + [50.0 + (i - 24) for i in range(24, 34)]
    daily = _gapped_points(days, values, base_date)

    result = rolling_z_scores(daily, window_days=7)
    assert len(result) == len(daily) == 15

    # Pre-gap cluster (indices 0-4, days 0-4): only 5 days, never reaches a
    # full 7-day window on its own.
    for i in range(5):
        assert result[i].unscored_reason == "warm_up", f"pre-gap index {i} should be warm_up"

    # Post-gap indices 5-10 (days 24-29): the gap (19 days, >= window_days)
    # resets the clock, so these must be tagged warm_up rather than either
    # silently dropped (the old _rolling_means behaviour) or scored from
    # pre-gap history that could never legitimately reach them.
    for i in range(5, 11):
        assert result[i].unscored_reason == "warm_up", (
            f"post-gap index {i} (day {days[i]}) should be warm_up -- the gap must reset the clock"
        )

    # Index 11 (day 30) is the first point with a genuine 7-day post-gap
    # window [24, 30], values 50..56 -- computed only from post-gap history.
    first_scored = result[11]
    assert first_scored.unscored_reason is None
    assert first_scored.rolling_mean == pytest.approx(mean([50.0 + i for i in range(7)]), abs=0.01)
    assert first_scored.z_score is not None


def test_rolling_z_scores_zero_variance_window_is_not_an_outlier() -> None:
    """A perfectly flat window (rolling_stdev == 0) defines z_score as 0.0
    -- "no deviation to score against, not an outlier by construction" --
    rather than raising or producing inf/NaN."""
    daily = _daily_points(date(2026, 3, 1), [50.0] * 10)
    result = rolling_z_scores(daily, window_days=5)
    for point in result[4:]:
        assert point.unscored_reason is None
        assert point.rolling_stdev == 0.0
        assert point.z_score == 0.0


# -- context_window: nearest-measured-neighbours, truncated at the edges ---


def test_context_window_truncates_at_sequence_edges() -> None:
    """index=0 and index=len-1 on a short series: context comes back
    shorter than the radius on the side that runs off the sequence,
    rather than raising or padding."""
    daily = _daily_points(date(2026, 3, 1), [10.0, 20.0, 30.0, 40.0, 50.0])

    before, after = context_window(daily, index=0, radius=3)
    assert before == []
    assert [p.value for p in after] == [20.0, 30.0, 40.0]

    before, after = context_window(daily, index=4, radius=3)
    assert [p.value for p in before] == [20.0, 30.0, 40.0]
    assert after == []


def test_context_window_middle_of_range_returns_full_radius() -> None:
    """Control case: radius genuinely available on both sides."""
    daily = _daily_points(date(2026, 3, 1), [float(i) for i in range(10)])

    before, after = context_window(daily, index=5, radius=3)
    assert [p.value for p in before] == [2.0, 3.0, 4.0]
    assert [p.value for p in after] == [6.0, 7.0, 8.0]


# -- find_streaks: both directions, and missing vs. failing ----------------


def test_find_streaks_above_and_below() -> None:
    """A fixture with one clear high-run and one clear low-run of known
    length/mean; direction="above" finds the high-run, direction="below"
    finds the low-run."""
    daily = (
        _daily_points(date(2026, 1, 1), [80.0] * 5)
        + _daily_points(date(2026, 1, 6), [50.0] * 5)
        + _daily_points(date(2026, 1, 11), [20.0] * 5)
        + _daily_points(date(2026, 1, 16), [50.0] * 5)
    )

    _, above_streaks = find_streaks(
        daily,
        threshold=70.0,
        direction="above",
        range_start="2026-01-01",
        range_end="2026-01-20",
    )
    assert len(above_streaks) == 1
    high = above_streaks[0]
    assert high.direction == "above"
    assert high.start == "2026-01-01"
    assert high.end == "2026-01-05"
    assert high.length == 5
    assert high.mean == pytest.approx(80.0)

    _, below_streaks = find_streaks(
        daily,
        threshold=30.0,
        direction="below",
        range_start="2026-01-01",
        range_end="2026-01-20",
    )
    assert len(below_streaks) == 1
    low = below_streaks[0]
    assert low.direction == "below"
    assert low.start == "2026-01-11"
    assert low.end == "2026-01-15"
    assert low.length == 5
    assert low.mean == pytest.approx(20.0)


def test_find_streaks_distinguishes_missing_from_failing() -> None:
    """One calendar day genuinely absent from ``daily`` (missing) and one
    present-but-failing day, both inside what would otherwise be one
    8-day passing run. Asserts DayStatus.status differs ("missing" vs
    "failing"), DayStatus.value differs (None vs not-None), and both
    correctly terminate the streak -- the literal acceptance-criterion
    test."""
    daily = (
        _daily_points(date(2026, 4, 1), [80.0] * 3)  # 04-01..04-03: passing
        # 2026-04-04 deliberately absent: missing, not measured.
        + _daily_points(date(2026, 4, 5), [50.0])  # 04-05: measured, failing
        + _daily_points(date(2026, 4, 6), [80.0] * 3)  # 04-06..04-08: passing
    )

    days, streaks = find_streaks(
        daily,
        threshold=70.0,
        direction="above",
        range_start="2026-04-01",
        range_end="2026-04-08",
    )
    assert len(days) == 8
    by_date = {d.date: d for d in days}

    missing_day = by_date["2026-04-04"]
    failing_day = by_date["2026-04-05"]
    assert missing_day.status == "missing"
    assert missing_day.value is None
    assert failing_day.status == "failing"
    assert failing_day.value == pytest.approx(50.0)
    assert missing_day.status != failing_day.status

    assert len(streaks) == 2
    first, second = streaks
    assert (first.start, first.end, first.length) == ("2026-04-01", "2026-04-03", 3)
    assert first.mean == pytest.approx(80.0)
    assert (second.start, second.end, second.length) == ("2026-04-06", "2026-04-08", 3)
    assert second.mean == pytest.approx(80.0)


def test_find_streaks_empty_and_single_day_ranges_do_not_raise() -> None:
    """range_start > range_end, and range_start == range_end, in both
    directions -- no exception, coherent (possibly empty) days/streaks."""
    # Inverted range, no data at all.
    for direction in ("above", "below"):
        days, streaks = find_streaks(
            [],
            threshold=50.0,
            direction=direction,
            range_start="2026-05-10",
            range_end="2026-05-01",
        )
        assert days == []
        assert streaks == []

    # Single-day range, one passing measured point.
    daily = _daily_points(date(2026, 6, 1), [80.0])
    days, streaks = find_streaks(
        daily,
        threshold=70.0,
        direction="above",
        range_start="2026-06-01",
        range_end="2026-06-01",
    )
    assert len(days) == 1
    assert days[0].status == "passing"
    assert days[0].value == pytest.approx(80.0)
    assert len(streaks) == 1
    assert (streaks[0].start, streaks[0].end, streaks[0].length) == (
        "2026-06-01",
        "2026-06-01",
        1,
    )

    # Single-day range, nothing measured at all: missing, not a crash.
    days, streaks = find_streaks(
        [],
        threshold=70.0,
        direction="above",
        range_start="2026-06-02",
        range_end="2026-06-02",
    )
    assert len(days) == 1
    assert days[0].status == "missing"
    assert days[0].value is None
    assert streaks == []


def test_find_streaks_rejects_invalid_direction() -> None:
    """direction accepts exactly "above"/"below" -- anything else is a
    ValueError that names both valid options, not a silent misinterpretation."""
    with pytest.raises(ValueError, match="above") as exc_info:
        find_streaks(
            [],
            threshold=50.0,
            direction="sideways",  # type: ignore[arg-type]
            range_start="2026-01-01",
            range_end="2026-01-02",
        )
    assert "below" in str(exc_info.value)
