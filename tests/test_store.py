"""Test suite for src/whoopmcp/store.py (persistent data layer).

This module tests a sqlite3-backed store for WHOOP data with forward migration
support and per-user data isolation. All tests use :memory: databases unless
file persistence is required for the test itself.
"""

from __future__ import annotations

import inspect
import os
import sqlite3
import stat
import tempfile
from pathlib import Path
from typing import Any

import pytest

from whoopmcp.store import (
    CURRENT_SCHEMA_VERSION,
    export_member_data,
    get_body_measurement,
    get_body_measurement_updated_at,
    get_cycle_coverage,
    get_cycles,
    get_profile,
    get_profile_updated_at,
    get_recoveries,
    get_recovery_coverage,
    get_sleep_by_id,
    get_sleep_coverage,
    get_sleeps,
    get_sync_state,
    get_workout_by_id,
    get_workout_coverage,
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

# -- #16: names this module's new tests below require, but that do not yet
# exist on store.py -- get_recovery_coverage, get_sleep_coverage,
# get_cycle_coverage, get_workout_coverage, get_sleep_by_id, get_workout_by_id,
# get_profile_updated_at, get_body_measurement_updated_at, and the
# include_deleted/limit/offset parameters on get_recoveries/get_sleeps/
# get_cycles/get_workouts. The import above deliberately fails (ImportError)
# until #16 adds them -- this file's whole new "#16" section is written
# test-first, before that implementation exists.

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

    # *args rather than a literal get_recoveries(conn) call: the missing
    # argument is deliberate here (that's the point of the test), but a
    # static analyzer can't tell that apart from a real call-site bug --
    # CodeQL's wrong-number-of-arguments query flagged the literal form.
    args: tuple[Any, ...] = (conn,)
    with pytest.raises(TypeError, match=r"missing.*required.*positional.*argument"):
        get_recoveries(*args)

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


# -- #16: include_deleted on the 4 collection getters -------------------------
#
# Pre-#16, get_recoveries/get_sleeps/get_cycles/get_workouts do not filter on
# deleted_at at all (see the module's own comment on deleted_at being
# "reserved for #18; never written or filtered on in this issue"). #16 adds a
# deleted_at IS NULL filter by default, with include_deleted=True as the
# explicit opt-out export_member_data needs (a soft-delete is not erasure).


def _soft_delete(conn: Any, table: str, whoop_user_id: int, resource_id: str) -> None:
    """Set deleted_at directly via raw SQL, bypassing store.py's own upsert
    functions entirely -- mirrors tests/test_webhook_processing.py's own
    comment about avoiding a store getter/setter that "could itself filter
    member data" for this kind of test setup."""
    conn.execute(
        f"UPDATE {table} SET deleted_at = ? WHERE whoop_user_id = ? AND resource_id = ?",  # noqa: S608
        ("2026-08-05T00:00:00Z", whoop_user_id, resource_id),
    )
    conn.commit()


def test_get_recoveries_excludes_soft_deleted_by_default() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 20
    upsert_recovery(
        conn,
        whoop_user_id,
        {"cycle_id": 5001, "created_at": "2026-08-01T08:00:00Z", "score_state": "SCORED"},
    )
    upsert_recovery(
        conn,
        whoop_user_id,
        {"cycle_id": 5002, "created_at": "2026-08-02T08:00:00Z", "score_state": "SCORED"},
    )
    _soft_delete(conn, "recoveries", whoop_user_id, "5002")

    results = get_recoveries(conn, whoop_user_id)

    assert {r["cycle_id"] for r in results} == {5001}
    conn.close()


def test_get_recoveries_include_deleted_true_still_returns_soft_deleted() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 21
    upsert_recovery(
        conn,
        whoop_user_id,
        {"cycle_id": 5003, "created_at": "2026-08-01T08:00:00Z", "score_state": "SCORED"},
    )
    _soft_delete(conn, "recoveries", whoop_user_id, "5003")

    results = get_recoveries(conn, whoop_user_id, include_deleted=True)

    assert {r["cycle_id"] for r in results} == {5003}
    conn.close()


def test_get_sleeps_excludes_soft_deleted_by_default() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 22
    upsert_sleep(
        conn,
        whoop_user_id,
        {"id": "sleep-a", "start": "2026-08-01T23:00:00Z", "end": "2026-08-02T07:00:00Z"},
    )
    upsert_sleep(
        conn,
        whoop_user_id,
        {"id": "sleep-b", "start": "2026-08-02T23:00:00Z", "end": "2026-08-03T07:00:00Z"},
    )
    _soft_delete(conn, "sleeps", whoop_user_id, "sleep-b")

    results = get_sleeps(conn, whoop_user_id)

    assert {r["id"] for r in results} == {"sleep-a"}
    conn.close()


def test_get_cycles_excludes_soft_deleted_by_default() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 23
    upsert_cycle(
        conn,
        whoop_user_id,
        {"id": 6001, "start": "2026-08-01T00:00:00Z", "end": "2026-08-02T00:00:00Z"},
    )
    upsert_cycle(
        conn,
        whoop_user_id,
        {"id": 6002, "start": "2026-08-02T00:00:00Z", "end": "2026-08-03T00:00:00Z"},
    )
    _soft_delete(conn, "cycles", whoop_user_id, "6002")

    results = get_cycles(conn, whoop_user_id)

    assert {r["id"] for r in results} == {6001}
    conn.close()


def test_get_workouts_excludes_soft_deleted_by_default() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 24
    upsert_workout(
        conn,
        whoop_user_id,
        {"id": "wo-a", "start": "2026-08-01T06:00:00Z", "end": "2026-08-01T07:00:00Z"},
    )
    upsert_workout(
        conn,
        whoop_user_id,
        {"id": "wo-b", "start": "2026-08-02T06:00:00Z", "end": "2026-08-02T07:00:00Z"},
    )
    _soft_delete(conn, "workouts", whoop_user_id, "wo-b")

    results = get_workouts(conn, whoop_user_id)

    assert {r["id"] for r in results} == {"wo-a"}
    conn.close()


def test_export_member_data_still_includes_soft_deleted_rows() -> None:
    """export_member_data (#32's data-subject export) must keep showing a
    record WHOOP told this server was deleted, until an operator actually
    erases it -- a soft-delete is not erasure. Its 4 getter calls must pass
    include_deleted=True even though the default flipped to False."""
    conn = open_store(":memory:")
    whoop_user_id = 25
    upsert_sleep(
        conn,
        whoop_user_id,
        {"id": "sleep-export", "start": "2026-08-01T23:00:00Z", "end": "2026-08-02T07:00:00Z"},
    )
    _soft_delete(conn, "sleeps", whoop_user_id, "sleep-export")

    export = export_member_data(conn, whoop_user_id)

    assert {r["id"] for r in export["sleeps"]} == {"sleep-export"}
    conn.close()


# -- #16: single-record lookups by id -----------------------------------------


def test_get_sleep_by_id_returns_none_for_unknown_id() -> None:
    conn = open_store(":memory:")
    assert get_sleep_by_id(conn, 30, "nonexistent") is None
    conn.close()


def test_get_sleep_by_id_returns_the_record() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 31
    upsert_sleep(
        conn,
        whoop_user_id,
        {"id": "sleep-x", "start": "2026-08-01T23:00:00Z", "end": "2026-08-02T07:00:00Z"},
    )

    result = get_sleep_by_id(conn, whoop_user_id, "sleep-x")

    assert result is not None
    assert result["id"] == "sleep-x"
    conn.close()


def test_get_sleep_by_id_excludes_soft_deleted_by_default() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 32
    upsert_sleep(
        conn,
        whoop_user_id,
        {"id": "sleep-y", "start": "2026-08-01T23:00:00Z", "end": "2026-08-02T07:00:00Z"},
    )
    _soft_delete(conn, "sleeps", whoop_user_id, "sleep-y")

    assert get_sleep_by_id(conn, whoop_user_id, "sleep-y") is None
    assert get_sleep_by_id(conn, whoop_user_id, "sleep-y", include_deleted=True) is not None
    conn.close()


def test_get_workout_by_id_returns_none_for_unknown_id() -> None:
    conn = open_store(":memory:")
    assert get_workout_by_id(conn, 33, "nonexistent") is None
    conn.close()


def test_get_workout_by_id_returns_the_record() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 34
    upsert_workout(
        conn,
        whoop_user_id,
        {"id": "wo-x", "start": "2026-08-01T06:00:00Z", "end": "2026-08-01T07:00:00Z"},
    )

    result = get_workout_by_id(conn, whoop_user_id, "wo-x")

    assert result is not None
    assert result["id"] == "wo-x"
    conn.close()


def test_get_workout_by_id_excludes_soft_deleted_by_default() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 35
    upsert_workout(
        conn,
        whoop_user_id,
        {"id": "wo-y", "start": "2026-08-01T06:00:00Z", "end": "2026-08-01T07:00:00Z"},
    )
    _soft_delete(conn, "workouts", whoop_user_id, "wo-y")

    assert get_workout_by_id(conn, whoop_user_id, "wo-y") is None
    assert get_workout_by_id(conn, whoop_user_id, "wo-y", include_deleted=True) is not None
    conn.close()


# -- #16: per-entity coverage (earliest/latest) queries -----------------------
#
# Per the module's own date-column mapping: recoveries key their activity
# date on created_at; sleeps/cycles/workouts key theirs on start/end (the
# record's full span, latest = MAX(end), not MAX(start)) -- never updated_at,
# which is sync/rescore bookkeeping, not an activity date.


def test_get_recovery_coverage_empty_table_returns_none_none() -> None:
    conn = open_store(":memory:")
    assert get_recovery_coverage(conn, 40) == (None, None)
    conn.close()


def test_get_recovery_coverage_returns_min_max_created_at() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 41
    for cycle_id, created_at in (
        (1, "2026-08-01T08:00:00Z"),
        (2, "2026-08-05T08:00:00Z"),
        (3, "2026-08-03T08:00:00Z"),
    ):
        upsert_recovery(
            conn,
            whoop_user_id,
            {"cycle_id": cycle_id, "created_at": created_at, "score_state": "SCORED"},
        )

    earliest, latest = get_recovery_coverage(conn, whoop_user_id)

    assert earliest == "2026-08-01T08:00:00Z"
    assert latest == "2026-08-05T08:00:00Z"
    conn.close()


def test_get_recovery_coverage_excludes_soft_deleted_from_the_window() -> None:
    """A soft-deleted row at either edge must not anchor the reported window."""
    conn = open_store(":memory:")
    whoop_user_id = 42
    upsert_recovery(
        conn,
        whoop_user_id,
        {"cycle_id": 1, "created_at": "2026-08-01T08:00:00Z", "score_state": "SCORED"},
    )
    upsert_recovery(
        conn,
        whoop_user_id,
        {"cycle_id": 2, "created_at": "2026-08-10T08:00:00Z", "score_state": "SCORED"},
    )
    _soft_delete(conn, "recoveries", whoop_user_id, "2")

    earliest, latest = get_recovery_coverage(conn, whoop_user_id)

    assert earliest == "2026-08-01T08:00:00Z"
    assert latest == "2026-08-01T08:00:00Z"
    conn.close()


def test_get_sleep_coverage_uses_start_and_end() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 43
    upsert_sleep(
        conn,
        whoop_user_id,
        {"id": "s1", "start": "2026-08-01T23:00:00Z", "end": "2026-08-02T07:00:00Z"},
    )
    upsert_sleep(
        conn,
        whoop_user_id,
        {"id": "s2", "start": "2026-08-05T23:00:00Z", "end": "2026-08-06T07:00:00Z"},
    )

    earliest, latest = get_sleep_coverage(conn, whoop_user_id)

    assert earliest == "2026-08-01T23:00:00Z"
    assert latest == "2026-08-06T07:00:00Z"
    conn.close()


def test_get_cycle_coverage_empty_table_returns_none_none() -> None:
    conn = open_store(":memory:")
    assert get_cycle_coverage(conn, 44) == (None, None)
    conn.close()


def test_get_cycle_coverage_uses_start_and_end() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 45
    upsert_cycle(
        conn,
        whoop_user_id,
        {"id": 1, "start": "2026-08-01T00:00:00Z", "end": "2026-08-02T00:00:00Z"},
    )
    upsert_cycle(
        conn,
        whoop_user_id,
        {"id": 2, "start": "2026-08-05T00:00:00Z", "end": "2026-08-06T00:00:00Z"},
    )

    earliest, latest = get_cycle_coverage(conn, whoop_user_id)

    assert earliest == "2026-08-01T00:00:00Z"
    assert latest == "2026-08-06T00:00:00Z"
    conn.close()


def test_get_workout_coverage_uses_start_and_end() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 46
    upsert_workout(
        conn,
        whoop_user_id,
        {"id": "w1", "start": "2026-08-01T06:00:00Z", "end": "2026-08-01T07:00:00Z"},
    )
    upsert_workout(
        conn,
        whoop_user_id,
        {"id": "w2", "start": "2026-08-05T06:00:00Z", "end": "2026-08-05T08:00:00Z"},
    )

    earliest, latest = get_workout_coverage(conn, whoop_user_id)

    assert earliest == "2026-08-01T06:00:00Z"
    assert latest == "2026-08-05T08:00:00Z"
    conn.close()


def test_get_workout_coverage_empty_table_returns_none_none() -> None:
    conn = open_store(":memory:")
    assert get_workout_coverage(conn, 47) == (None, None)
    conn.close()


# -- #16: singleton (profile / body_measurement) freshness -------------------


def test_get_profile_updated_at_none_when_never_synced() -> None:
    conn = open_store(":memory:")
    assert get_profile_updated_at(conn, 50) is None
    conn.close()


def test_get_profile_updated_at_returns_the_stored_updated_at() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 51
    upsert_profile(conn, whoop_user_id, {"user_id": whoop_user_id, "email": "a@example.com"})

    updated_at = get_profile_updated_at(conn, whoop_user_id)

    assert updated_at is not None
    # Round-trips as an ISO 8601 string, same shape store._now() writes.
    from datetime import datetime

    datetime.fromisoformat(updated_at)
    conn.close()


def test_get_body_measurement_updated_at_none_when_never_synced() -> None:
    conn = open_store(":memory:")
    assert get_body_measurement_updated_at(conn, 52) is None
    conn.close()


def test_get_body_measurement_updated_at_returns_the_stored_updated_at() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 53
    upsert_body_measurement(conn, whoop_user_id, {"height_meter": 1.8})

    updated_at = get_body_measurement_updated_at(conn, whoop_user_id)

    assert updated_at is not None
    conn.close()


# -- #16: limit/offset pagination on the 4 collection getters ----------------


def test_get_sleeps_limit_returns_the_oldest_n() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 60
    for i, day in enumerate((1, 2, 3), start=1):
        upsert_sleep(
            conn,
            whoop_user_id,
            {
                "id": f"sleep-{i}",
                "start": f"2026-08-0{day}T23:00:00Z",
                "end": f"2026-08-0{day + 1}T07:00:00Z",
            },
        )

    results = get_sleeps(conn, whoop_user_id, limit=2)

    assert [r["id"] for r in results] == ["sleep-1", "sleep-2"]
    conn.close()


def test_get_sleeps_offset_skips_the_first_n() -> None:
    conn = open_store(":memory:")
    whoop_user_id = 61
    for i, day in enumerate((1, 2, 3), start=1):
        upsert_sleep(
            conn,
            whoop_user_id,
            {
                "id": f"sleep-{i}",
                "start": f"2026-08-0{day}T23:00:00Z",
                "end": f"2026-08-0{day + 1}T07:00:00Z",
            },
        )

    results = get_sleeps(conn, whoop_user_id, limit=2, offset=2)

    assert [r["id"] for r in results] == ["sleep-3"]
    conn.close()


# -- #68: file modes on the database, its parent directory and its sidecars --
#
# All mode assertions below follow tests/test_auth.py:136-143 exactly: they are
# skipped on Windows (POSIX modes are advisory there at best) and they assert
# the security property -- "no group or other access" -- rather than an exact
# 0o600, which would be brittle against a legitimately stricter mode.

_GROUP_OR_OTHER = stat.S_IRWXG | stat.S_IRWXO


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_fresh_store_file_is_not_readable_by_other_users(tmp_path: Path) -> None:
    """A database created by open_store holds every member's profile, body
    measurements and raw payloads -- the same class of data the token file
    goes out of its way to protect. It must not land at the umask default."""
    db_path = tmp_path / "state" / "cache.sqlite3"

    conn = open_store(db_path)
    conn.close()

    mode = stat.S_IMODE(db_path.stat().st_mode)

    assert mode & _GROUP_OR_OTHER == 0, f"database file is mode {mode:o}"


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_fresh_store_creates_its_parent_directory_without_group_or_other_access(
    tmp_path: Path,
) -> None:
    """open_store currently does no directory creation at all: it fails
    outright when the parent is absent. It must create the parent instead,
    and create it 0700 -- that directory mode is what actually protects the
    transient sidecars (see the sidecar test below)."""
    db_path = tmp_path / "state" / "nested" / "cache.sqlite3"

    conn = open_store(db_path)
    conn.close()

    assert db_path.parent.is_dir()
    mode = stat.S_IMODE(db_path.parent.stat().st_mode)

    assert mode & _GROUP_OR_OTHER == 0, f"state directory is mode {mode:o}"


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_pre_existing_world_readable_store_file_is_tightened(tmp_path: Path) -> None:
    """Every store already on disk was created at the umask default by an
    earlier version, so creating new files 0600 is not enough on its own: an
    existing file has to be chmod'd on open, not left as it was found."""
    db_path = tmp_path / "state" / "cache.sqlite3"
    db_path.parent.mkdir(parents=True)
    db_path.touch()
    db_path.chmod(0o644)

    conn = open_store(db_path)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    conn.close()

    assert version == CURRENT_SCHEMA_VERSION, "tightening the mode must not break migration"
    mode = stat.S_IMODE(db_path.stat().st_mode)

    assert mode & _GROUP_OR_OTHER == 0, f"pre-existing database file is mode {mode:o}"


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_no_file_in_the_state_directory_is_group_or_other_accessible_after_writes(
    tmp_path: Path,
) -> None:
    """The sidecar case, stated honestly.

    Issue #68 asks for ``-wal``/``-shm`` to be protected. Those files do not
    exist in this codebase: ``store.py`` sets no ``PRAGMA journal_mode``, so
    SQLite runs in its default ``delete`` mode (asserted below, so this test
    fails loudly if that ever changes). The sidecar that *is* created is a
    transient ``<db>-journal``, written and unlinked inside a single
    ``execute`` -- far too short-lived to chmod without the chmod itself
    being a race.

    The real protection for any sidecar, present or future, is the 0700
    parent directory: no other user can traverse into it to open a journal
    regardless of that journal's own mode. So this asserts the directory
    mode, and that nothing left in the directory after a burst of writes
    carries group or other bits.
    """
    state_dir = tmp_path / "state"
    db_path = state_dir / "cache.sqlite3"

    conn = open_store(db_path)
    journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    for i in range(25):
        upsert_sleep(
            conn,
            70,
            {
                "id": f"sleep-{i}",
                "start": "2026-08-01T23:00:00Z",
                "end": "2026-08-02T07:00:00Z",
            },
        )
    conn.close()

    assert journal_mode == "delete", (
        f"journal_mode is {journal_mode!r}, not 'delete' -- this test's premise "
        "(no -wal/-shm files exist here) no longer holds"
    )

    dir_mode = stat.S_IMODE(state_dir.stat().st_mode)
    assert dir_mode & _GROUP_OR_OTHER == 0, f"state directory is mode {dir_mode:o}"

    loose = {
        str(child.relative_to(state_dir)): f"{stat.S_IMODE(child.stat().st_mode):o}"
        for child in sorted(state_dir.rglob("*"))
        if stat.S_IMODE(child.stat().st_mode) & _GROUP_OR_OTHER
    }
    assert loose == {}, f"files in the state directory are group/other accessible: {loose}"


def test_an_unchmoddable_directory_does_not_prevent_the_store_opening(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D3: an operator who deliberately placed the state directory somewhere
    this process cannot re-permission must not find the server refusing to
    start. Every chmod is refused here; open_store must still return a
    migrated, usable connection.

    No mode is asserted, so this runs on Windows too.
    """
    refused: list[str] = []

    def refuse(path: object, mode: int, *args: object, **kwargs: object) -> None:
        refused.append(str(path))
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(os, "chmod", refuse)
    monkeypatch.setattr(Path, "chmod", lambda self, mode, **kwargs: refuse(self, mode))

    state_dir = tmp_path / "shared"
    state_dir.mkdir()
    db_path = state_dir / "cache.sqlite3"
    db_path.touch()

    conn = open_store(db_path)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    upsert_profile(conn, 71, {"first_name": "A", "last_name": "B"})
    stored = get_profile(conn, 71)
    conn.close()

    assert version == CURRENT_SCHEMA_VERSION
    assert stored is not None
    assert refused, "no chmod was even attempted -- the D3 tolerance path is untested"


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_a_str_path_containing_a_question_mark_is_still_secured() -> None:
    """``?`` is a legal POSIX filename character, so a state directory
    containing one must not be mistaken for a sqlite URI and skipped.

    This is the fail-open direction, which is the one that matters: a
    security fix that quietly declines to apply to some real paths is worse
    than one that tightens a path it needn't have. Only the ``file:`` prefix
    marks a genuine URI, and this path has none.
    """
    with tempfile.TemporaryDirectory() as raw:
        weird_dir = Path(raw) / "state?v=1"
        weird_dir.mkdir(mode=0o755)
        db_path = weird_dir / "cache.sqlite3"

        conn = open_store(str(db_path))
        upsert_profile(conn, 72, {"first_name": "A", "last_name": "B"})
        conn.close()

        file_mode = stat.S_IMODE(db_path.stat().st_mode)
        dir_mode = stat.S_IMODE(weird_dir.stat().st_mode)

    assert file_mode & (stat.S_IRWXG | stat.S_IRWXO) == 0, f"db is mode {file_mode:o}"
    assert dir_mode & (stat.S_IRWXG | stat.S_IRWXO) == 0, f"dir is mode {dir_mode:o}"


@pytest.mark.parametrize("special_path", [":memory:", "file::memory:?cache=shared"])
def test_special_sqlite_paths_are_left_entirely_alone(
    special_path: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D4: ``":memory:"`` and URI forms are not filesystem paths. They must
    reach ``sqlite3.connect`` with no mkdir, touch or chmod performed on
    them, and ``":memory:"`` must leave no file behind at all.

    (Only the ``":memory:"`` case can assert an empty directory: a URI string
    passed to ``sqlite3.connect`` without ``uri=True`` is treated as a
    literal filename by sqlite itself, which is sqlite's business and not
    open_store's.)
    """
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)

    calls: list[str] = []
    real_chmod = os.chmod
    real_touch = Path.touch
    real_mkdir = Path.mkdir

    def record_chmod(path: object, mode: int, *args: object, **kwargs: object) -> None:
        calls.append(f"os.chmod({path!s})")
        real_chmod(path, mode, *args, **kwargs)  # type: ignore[arg-type]

    def record_path_chmod(self: Path, mode: int, **kwargs: object) -> None:
        calls.append(f"Path.chmod({self!s})")
        real_chmod(self, mode)

    def record_touch(self: Path, mode: int = 0o666, exist_ok: bool = True) -> None:
        calls.append(f"Path.touch({self!s})")
        real_touch(self, mode=mode, exist_ok=exist_ok)

    def record_mkdir(
        self: Path, mode: int = 0o777, parents: bool = False, exist_ok: bool = False
    ) -> None:
        calls.append(f"Path.mkdir({self!s})")
        real_mkdir(self, mode=mode, parents=parents, exist_ok=exist_ok)

    monkeypatch.setattr(os, "chmod", record_chmod)
    monkeypatch.setattr(Path, "chmod", record_path_chmod)
    monkeypatch.setattr(Path, "touch", record_touch)
    monkeypatch.setattr(Path, "mkdir", record_mkdir)

    conn = open_store(special_path)
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    conn.close()

    assert version == CURRENT_SCHEMA_VERSION
    assert calls == [], f"a special path touched the filesystem: {calls}"

    if special_path == ":memory:":
        assert list(cwd.iterdir()) == [], "an in-memory store created a file on disk"
