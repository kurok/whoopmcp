"""Test suite for src/whoopmcp/store.py (persistent data layer).

This module tests a sqlite3-backed store for WHOOP data with forward migration
support and per-user data isolation. All tests use :memory: databases unless
file persistence is required for the test itself.
"""

from __future__ import annotations

import inspect
import sqlite3
from pathlib import Path

import pytest
from whoopmcp.store import (
    CURRENT_SCHEMA_VERSION,
    get_body_measurement,
    get_cycles,
    get_profile,
    get_recoveries,
    get_sleeps,
    get_sync_state,
    get_workouts,
    open_store,
    set_sync_state,
    upsert_body_measurement,
    upsert_cycle,
    upsert_profile,
    upsert_recovery,
    upsert_sleep,
    upsert_workout,
)

# -- Schema and version tests ------------------------------------------------


def test_schema_is_created_on_first_open() -> None:
    """On first open of a fresh database, the full schema is applied and
    PRAGMA user_version is set to CURRENT_SCHEMA_VERSION."""
    conn = open_store(":memory:")

    version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == CURRENT_SCHEMA_VERSION

    # Check that all 7 required tables exist
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    table_names = {t[0] for t in tables}

    expected_tables = {
        "body_measurements",
        "cycles",
        "profiles",
        "recoveries",
        "sleeps",
        "sync_state",
        "workouts",
    }
    assert expected_tables.issubset(table_names), f"Missing tables: {expected_tables - table_names}"

    conn.close()


def test_forward_migration_increments_version(tmp_path: Path) -> None:
    """Opening a database with an older schema version applies forward
    migration and increments the version. Opening an already-current
    database is a no-op."""
    db_path = tmp_path / "test.db"

    # Create a "old version" database by opening a fresh connection directly
    # and manually setting the user_version to 0 (simulating an old schema).
    old_conn = sqlite3.connect(str(db_path))
    old_conn.execute("PRAGMA user_version = 0")
    old_conn.close()

    # Now open with open_store(), which should detect the old version and
    # migrate it forward to CURRENT_SCHEMA_VERSION.
    conn = open_store(str(db_path))
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == CURRENT_SCHEMA_VERSION
    conn.close()

    # Opening again should be a no-op: version stays the same.
    conn = open_store(str(db_path))
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == CURRENT_SCHEMA_VERSION
    conn.close()


# -- Upsert tests --------------------------------------------------------


def test_upsert_recovery_is_idempotent() -> None:
    """Writing the same recovery record twice leaves exactly one row."""
    conn = open_store(":memory:")
    whoop_user_id = 1
    record = {
        "cycle_id": 12345,
        "created_at": "2026-08-01T10:00:00Z",
        "score_state": "SCORED",
        "score": {
            "recovery_score": 75,
            "hrv_rmssd_milli": 45.2,
            "resting_heart_rate": 62,
        },
    }

    upsert_recovery(conn, whoop_user_id, record)
    upsert_recovery(conn, whoop_user_id, record)

    count = conn.execute(
        "SELECT COUNT(*) FROM recoveries WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()[0]
    assert count == 1

    conn.close()


def test_upsert_recovery_updates_changed_record() -> None:
    """Upserting a record with the same resource_id but different data
    updates the row in place rather than duplicating it."""
    conn = open_store(":memory:")
    whoop_user_id = 1
    cycle_id = 12345

    record_v1 = {
        "cycle_id": cycle_id,
        "created_at": "2026-08-01T10:00:00Z",
        "score_state": "SCORED",
        "score": {"recovery_score": 75, "hrv_rmssd_milli": 45.2, "resting_heart_rate": 62},
    }

    record_v2 = {
        "cycle_id": cycle_id,
        "created_at": "2026-08-01T10:00:00Z",
        "score_state": "SCORED",
        "score": {"recovery_score": 82, "hrv_rmssd_milli": 50.1, "resting_heart_rate": 60},
    }

    upsert_recovery(conn, whoop_user_id, record_v1)
    upsert_recovery(conn, whoop_user_id, record_v2)

    # Still only one row
    count = conn.execute(
        "SELECT COUNT(*) FROM recoveries WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()[0]
    assert count == 1

    # The retrieved record reflects the new score
    results = get_recoveries(conn, whoop_user_id)
    assert len(results) == 1
    assert results[0]["score"]["recovery_score"] == 82

    conn.close()


def test_upsert_sleep_is_idempotent() -> None:
    """Writing the same sleep record twice leaves exactly one row."""
    conn = open_store(":memory:")
    whoop_user_id = 2
    record = {
        "id": "uuid-1234",
        "start": "2026-08-01T23:00:00Z",
        "end": "2026-08-02T07:00:00Z",
        "state": "VALID",
        "nap": False,
    }

    upsert_sleep(conn, whoop_user_id, record)
    upsert_sleep(conn, whoop_user_id, record)

    count = conn.execute(
        "SELECT COUNT(*) FROM sleeps WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()[0]
    assert count == 1

    conn.close()


def test_upsert_cycle_is_idempotent() -> None:
    """Writing the same cycle record twice leaves exactly one row."""
    conn = open_store(":memory:")
    whoop_user_id = 3
    record = {
        "id": 100001,
        "start": "2026-08-01T00:00:00Z",
        "end": "2026-08-02T00:00:00Z",
        "days": 1,
    }

    upsert_cycle(conn, whoop_user_id, record)
    upsert_cycle(conn, whoop_user_id, record)

    count = conn.execute(
        "SELECT COUNT(*) FROM cycles WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()[0]
    assert count == 1

    conn.close()


def test_upsert_workout_is_idempotent() -> None:
    """Writing the same workout record twice leaves exactly one row."""
    conn = open_store(":memory:")
    whoop_user_id = 4
    record = {
        "id": "workout-uuid-1",
        "start": "2026-08-02T08:00:00Z",
        "end": "2026-08-02T09:00:00Z",
        "sport_id": 1,
        "score_state": "SCORED",
    }

    upsert_workout(conn, whoop_user_id, record)
    upsert_workout(conn, whoop_user_id, record)

    count = conn.execute(
        "SELECT COUNT(*) FROM workouts WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()[0]
    assert count == 1

    conn.close()


def test_upsert_body_measurement_is_idempotent() -> None:
    """Writing the same body_measurement record twice leaves exactly one row."""
    conn = open_store(":memory:")
    whoop_user_id = 5
    record = {
        "measured_at": "2026-08-01T08:00:00Z",
        "weight_kg": 75.5,
        "body_fat_percentage": 15.2,
    }

    upsert_body_measurement(conn, whoop_user_id, record)
    upsert_body_measurement(conn, whoop_user_id, record)

    count = conn.execute(
        "SELECT COUNT(*) FROM body_measurements WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()[0]
    assert count == 1

    conn.close()


def test_upsert_profile_is_idempotent() -> None:
    """Writing the same profile record twice leaves exactly one row."""
    conn = open_store(":memory:")
    whoop_user_id = 6
    record = {
        "user_id": whoop_user_id,
        "email": "test@example.com",
        "first_name": "John",
    }

    upsert_profile(conn, whoop_user_id, record)
    upsert_profile(conn, whoop_user_id, record)

    count = conn.execute(
        "SELECT COUNT(*) FROM profiles WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()[0]
    assert count == 1

    conn.close()


# -- Read function signature tests -------------------------------------------


def test_all_read_functions_require_whoop_user_id_positional() -> None:
    """All read functions (get_*) must have whoop_user_id as a required
    positional argument with no default value. This is a signature-level check
    using inspect."""
    read_functions = [
        get_recoveries,
        get_sleeps,
        get_cycles,
        get_workouts,
        get_body_measurement,
        get_profile,
        get_sync_state,
    ]

    for func in read_functions:
        sig = inspect.signature(func)
        params = sig.parameters
        assert "whoop_user_id" in params, f"{func.__name__} missing whoop_user_id parameter"
        param = params["whoop_user_id"]
        assert param.default is inspect.Parameter.empty, (
            f"{func.__name__}'s whoop_user_id has a default value, but should be required"
        )


def test_read_function_raises_without_user_id() -> None:
    """Calling a read function without whoop_user_id raises TypeError
    at runtime. Uses get_recoveries as the representative test."""
    conn = open_store(":memory:")

    with pytest.raises(TypeError, match=r"missing.*required.*positional.*argument"):
        get_recoveries(conn)  # type: ignore[call-arg]

    conn.close()


def test_read_function_rejects_explicit_none_user_id() -> None:
    """Calling a read function with whoop_user_id=None explicitly raises
    either TypeError or ValueError at runtime. Tests defensive programming
    against the type hint (which mypy would catch, but runtime code may bypass)."""
    conn = open_store(":memory:")

    # At least one of these should raise an exception for None user_id
    with pytest.raises((TypeError, ValueError)):
        get_recoveries(conn, whoop_user_id=None)  # type: ignore[arg-type]

    conn.close()


# -- Round-trip payload tests -----------------------------------------------


def test_recovery_payload_round_trips_byte_identical() -> None:
    """Write a recovery with nested data, read it back, and verify the
    retrieved dict equals the original exactly (deep equality)."""
    conn = open_store(":memory:")
    whoop_user_id = 7
    original_record = {
        "cycle_id": 54321,
        "created_at": "2026-08-02T14:30:00Z",
        "score_state": "SCORED",
        "score": {
            "recovery_score": 68,
            "hrv_rmssd_milli": 42.8,
            "resting_heart_rate": 65,
            "spo2_percentage": 96.5,
        },
        "metrics": [
            {"type": "hrv", "value": 42.8},
            {"type": "rhr", "value": 65},
        ],
    }

    upsert_recovery(conn, whoop_user_id, original_record)
    results = get_recoveries(conn, whoop_user_id)

    assert len(results) == 1
    assert results[0] == original_record

    conn.close()


def test_sleep_payload_round_trips_byte_identical() -> None:
    """Write a sleep with nested data, read it back, and verify deep equality."""
    conn = open_store(":memory:")
    whoop_user_id = 8
    original_record = {
        "id": "uuid-sleep-123",
        "start": "2026-08-02T22:30:00Z",
        "end": "2026-08-03T07:15:00Z",
        "state": "VALID",
        "nap": False,
        "score_state": "SCORED",
        "score": {
            "sleep_score": 82,
            "sleep_performance_percentage": 91,
            "recovery_percentage": 75,
        },
        "data": {"calories": 450, "mood": 8},
    }

    upsert_sleep(conn, whoop_user_id, original_record)
    results = get_sleeps(conn, whoop_user_id)

    assert len(results) == 1
    assert results[0] == original_record

    conn.close()


def test_profile_payload_round_trips_byte_identical() -> None:
    """Write a profile record, read it back, verify deep equality."""
    conn = open_store(":memory:")
    whoop_user_id = 9
    original_record = {
        "user_id": whoop_user_id,
        "email": "user@example.com",
        "first_name": "Jane",
        "last_name": "Doe",
        "birth_date": "1990-03-15",
        "sex": "FEMALE",
        "updated_at": "2026-08-01T12:00:00Z",
    }

    upsert_profile(conn, whoop_user_id, original_record)
    result = get_profile(conn, whoop_user_id)

    assert result == original_record

    conn.close()


# -- User scoping isolation tests -------------------------------------------


def test_user_scoping_isolates_data() -> None:
    """Data for whoop_user_id=1 and whoop_user_id=2 are isolated: reading
    user 1's recoveries returns only user 1's records, not user 2's."""
    conn = open_store(":memory:")

    user1_record = {
        "cycle_id": 1001,
        "created_at": "2026-08-01T10:00:00Z",
        "score_state": "SCORED",
        "score": {"recovery_score": 75},
    }
    user2_record = {
        "cycle_id": 2001,
        "created_at": "2026-08-01T11:00:00Z",
        "score_state": "SCORED",
        "score": {"recovery_score": 65},
    }

    upsert_recovery(conn, whoop_user_id=1, record=user1_record)
    upsert_recovery(conn, whoop_user_id=2, record=user2_record)

    user1_results = get_recoveries(conn, whoop_user_id=1)
    user2_results = get_recoveries(conn, whoop_user_id=2)

    assert len(user1_results) == 1
    assert user1_results[0]["cycle_id"] == 1001

    assert len(user2_results) == 1
    assert user2_results[0]["cycle_id"] == 2001

    conn.close()


# -- sync_state tests -------------------------------------------------------


def test_sync_state_round_trips() -> None:
    """set_sync_state followed by get_sync_state returns the same values."""
    conn = open_store(":memory:")
    whoop_user_id = 10
    entity = "recoveries"

    sync_data = {
        "cursor": "abc-123-def",
        "last_run_at": "2026-08-02T15:30:00Z",
        "outcome": "success",
    }

    set_sync_state(
        conn,
        whoop_user_id,
        entity,
        cursor=sync_data["cursor"],
        last_run_at=sync_data["last_run_at"],
        outcome=sync_data["outcome"],
    )

    retrieved = get_sync_state(conn, whoop_user_id, entity)

    assert retrieved is not None
    assert retrieved["cursor"] == sync_data["cursor"]
    assert retrieved["last_run_at"] == sync_data["last_run_at"]
    assert retrieved["outcome"] == sync_data["outcome"]

    conn.close()


def test_sync_state_returns_none_for_unseen_entity() -> None:
    """get_sync_state returns None when no sync has ever been performed for
    a (user, entity) pair."""
    conn = open_store(":memory:")
    whoop_user_id = 11
    entity = "sleeps"

    result = get_sync_state(conn, whoop_user_id, entity)

    assert result is None

    conn.close()


def test_sync_state_overwrites_on_set() -> None:
    """Calling set_sync_state twice overwrites the first value."""
    conn = open_store(":memory:")
    whoop_user_id = 12
    entity = "cycles"

    set_sync_state(
        conn,
        whoop_user_id,
        entity,
        cursor="old-cursor",
        last_run_at="2026-08-01T00:00:00Z",
        outcome="success",
    )

    set_sync_state(
        conn,
        whoop_user_id,
        entity,
        cursor="new-cursor",
        last_run_at="2026-08-02T00:00:00Z",
        outcome="partial",
    )

    retrieved = get_sync_state(conn, whoop_user_id, entity)

    assert retrieved is not None
    assert retrieved["cursor"] == "new-cursor"
    assert retrieved["last_run_at"] == "2026-08-02T00:00:00Z"
    assert retrieved["outcome"] == "partial"

    conn.close()


def test_sync_state_can_store_none_cursor() -> None:
    """sync_state allows cursor=None for entities that don't use cursor-based
    pagination (e.g., a full-sync result)."""
    conn = open_store(":memory:")
    whoop_user_id = 13
    entity = "profiles"

    set_sync_state(
        conn,
        whoop_user_id,
        entity,
        cursor=None,
        last_run_at="2026-08-02T10:00:00Z",
        outcome="success",
    )

    retrieved = get_sync_state(conn, whoop_user_id, entity)

    assert retrieved is not None
    assert retrieved["cursor"] is None
    assert retrieved["last_run_at"] == "2026-08-02T10:00:00Z"
    assert retrieved["outcome"] == "success"

    conn.close()


# -- Date-range filtering tests -------------------------------------------


def test_recovery_date_range_filtering() -> None:
    """get_recoveries(start=..., end=...) filters results by created_at.
    Write 3 recoveries at different timestamps; query a sub-range; assert
    only the matching one(s) come back."""
    conn = open_store(":memory:")
    whoop_user_id = 14

    # Create 3 records at different times
    records = [
        {
            "cycle_id": 3001,
            "created_at": "2026-08-01T08:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": 70},
        },
        {
            "cycle_id": 3002,
            "created_at": "2026-08-02T12:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": 75},
        },
        {
            "cycle_id": 3003,
            "created_at": "2026-08-03T16:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": 80},
        },
    ]

    for record in records:
        upsert_recovery(conn, whoop_user_id, record)

    # Query only the middle one
    results = get_recoveries(
        conn,
        whoop_user_id,
        start="2026-08-02T00:00:00Z",
        end="2026-08-03T00:00:00Z",
    )

    assert len(results) == 1
    assert results[0]["cycle_id"] == 3002

    conn.close()


def test_sleep_date_range_filtering() -> None:
    """get_sleeps with start/end filters by the sleep's start timestamp."""
    conn = open_store(":memory:")
    whoop_user_id = 15

    sleeps = [
        {
            "id": "uuid-sleep-1",
            "start": "2026-08-01T23:00:00Z",
            "end": "2026-08-02T07:00:00Z",
            "state": "VALID",
            "nap": False,
        },
        {
            "id": "uuid-sleep-2",
            "start": "2026-08-02T23:00:00Z",
            "end": "2026-08-03T07:00:00Z",
            "state": "VALID",
            "nap": False,
        },
        {
            "id": "uuid-sleep-3",
            "start": "2026-08-03T23:00:00Z",
            "end": "2026-08-04T07:00:00Z",
            "state": "VALID",
            "nap": False,
        },
    ]

    for sleep in sleeps:
        upsert_sleep(conn, whoop_user_id, sleep)

    # Query for sleeps starting on 2026-08-02
    results = get_sleeps(
        conn,
        whoop_user_id,
        start="2026-08-02T00:00:00Z",
        end="2026-08-03T00:00:00Z",
    )

    assert len(results) == 1
    assert results[0]["id"] == "uuid-sleep-2"

    conn.close()


def test_cycle_date_range_filtering() -> None:
    """get_cycles with start/end filters by the cycle's start timestamp."""
    conn = open_store(":memory:")
    whoop_user_id = 16

    cycles = [
        {
            "id": 4001,
            "start": "2026-08-01T00:00:00Z",
            "end": "2026-08-02T00:00:00Z",
            "days": 1,
        },
        {
            "id": 4002,
            "start": "2026-08-02T00:00:00Z",
            "end": "2026-08-03T00:00:00Z",
            "days": 1,
        },
        {
            "id": 4003,
            "start": "2026-08-03T00:00:00Z",
            "end": "2026-08-04T00:00:00Z",
            "days": 1,
        },
    ]

    for cycle in cycles:
        upsert_cycle(conn, whoop_user_id, cycle)

    # Query for cycles starting between 2026-08-02 and 2026-08-04
    results = get_cycles(
        conn,
        whoop_user_id,
        start="2026-08-02T00:00:00Z",
        end="2026-08-04T00:00:00Z",
    )

    # Should get cycles 4002 and 4003 (their starts are in the range)
    assert len(results) == 2
    cycle_ids = {c["id"] for c in results}
    assert cycle_ids == {4002, 4003}

    conn.close()


def test_workout_date_range_filtering() -> None:
    """get_workouts with start/end filters by the workout's start timestamp."""
    conn = open_store(":memory:")
    whoop_user_id = 17

    workouts = [
        {
            "id": "uuid-wo-1",
            "start": "2026-08-01T06:00:00Z",
            "end": "2026-08-01T07:00:00Z",
            "sport_id": 1,
            "score_state": "SCORED",
        },
        {
            "id": "uuid-wo-2",
            "start": "2026-08-02T06:00:00Z",
            "end": "2026-08-02T07:30:00Z",
            "sport_id": 2,
            "score_state": "SCORED",
        },
        {
            "id": "uuid-wo-3",
            "start": "2026-08-03T06:00:00Z",
            "end": "2026-08-03T08:00:00Z",
            "sport_id": 1,
            "score_state": "SCORED",
        },
    ]

    for workout in workouts:
        upsert_workout(conn, whoop_user_id, workout)

    # Query for workouts on 2026-08-02
    results = get_workouts(
        conn,
        whoop_user_id,
        start="2026-08-02T00:00:00Z",
        end="2026-08-03T00:00:00Z",
    )

    assert len(results) == 1
    assert results[0]["id"] == "uuid-wo-2"

    conn.close()
