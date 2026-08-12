"""Tests for issue #105: webhook_events.whoop_user_id NOT NULL constraint migration.

Tests the schema migration that makes whoop_user_id NOT NULL, preventing invisible
rows in export and erasure operations, plus the pre-flight check and signature
tightening. These tests are written before the migration is implemented.
"""

from __future__ import annotations

import sqlite3
import typing

import pytest

from whoopmcp.store import (
    _MIGRATIONS,
    erase_member_data,
    export_member_data,
    insert_webhook_event,
    open_store,
)


# Test 1: A fresh store has the NOT NULL constraint
def test_fresh_store_webhook_events_whoop_user_id_has_not_null_constraint() -> None:
    """PRAGMA table_info(webhook_events) reports notnull=1 for whoop_user_id.

    This test will FAIL on current main (where the column is nullable).
    """
    conn = open_store(":memory:")

    try:
        # Get column info for webhook_events table
        pragma_result = conn.execute("PRAGMA table_info(webhook_events)").fetchall()

        # pragma_result format: (cid, name, type, notnull, dflt_value, pk)
        # Find the whoop_user_id column
        whoop_user_id_col = None
        for row in pragma_result:
            if row[1] == "whoop_user_id":  # row[1] is the column name
                whoop_user_id_col = row
                break

        assert whoop_user_id_col is not None, "whoop_user_id column not found"
        notnull_flag = whoop_user_id_col[3]  # row[3] is the notnull flag
        assert notnull_flag == 1, (
            f"whoop_user_id should have notnull=1, but got {notnull_flag}. "
            "Column is still nullable."
        )
    finally:
        conn.close()


# Test 2: Inserting NULL into whoop_user_id raises an error
def test_inserting_null_whoop_user_id_raises() -> None:
    """After the migration, attempting to insert a NULL whoop_user_id
    should raise sqlite3.IntegrityError at the database level.

    This test will FAIL on current main (where NULL is allowed).
    """
    conn = open_store(":memory:")

    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO webhook_events (
                    trace_id, whoop_user_id, event_type, event_body, status,
                    attempt_count, created_at
                ) VALUES (?, ?, ?, ?, 'pending', 0, ?)
                """,
                (
                    "test-trace-id",
                    None,
                    "sleep.updated",
                    '{"data": "test"}',
                    "2026-08-10T00:00:00Z",
                ),
            )
    finally:
        conn.close()


# Test 3: The upgrade path preserves all data
def test_migration_v4_to_v5_preserves_all_webhook_events_data() -> None:
    """Build a v4-shaped store by running migrations 1-4 manually, populate it
    with webhook_events and other table data for multiple members, then run
    open_store() which will apply the v5 migration. Assert that every row
    survives with identical values and the version is 5.

    This test builds the v4 fixture from the committed migration strings,
    not hand-written DDL, so it cannot drift from the real schema.
    """
    # A file-based db is needed (an in-memory one can't be reopened), so
    # this builds a v4 fixture from the committed migration strings inside
    # a tempfile, then reopens it via ``open_store`` to trigger v5.
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = f"{tmpdir}/test.db"

        # Step 1: Create and populate a v4 database
        conn = sqlite3.connect(db_path)
        for version in range(1, 5):
            conn.executescript(_MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()

        # Seed data
        member_a = 910001
        member_b = 910002

        conn.execute(
            """
            INSERT INTO webhook_events (
                trace_id, whoop_user_id, event_type, event_body, status,
                attempt_count, created_at, processed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "trace-a-1",
                member_a,
                "sleep.updated",
                '{"sleep_id": "s1"}',
                "success",
                1,
                "2026-08-01T10:00:00Z",
                "2026-08-01T10:05:00Z",
            ),
        )

        conn.execute(
            """
            INSERT INTO webhook_events (
                trace_id, whoop_user_id, event_type, event_body, status,
                attempt_count, created_at, processed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "trace-b-1",
                member_b,
                "recovery.updated",
                '{"recovery_id": "r1"}',
                "pending",
                0,
                "2026-08-02T11:00:00Z",
                None,
            ),
        )

        # Seed other tables
        conn.execute(
            """
            INSERT INTO recoveries (
                whoop_user_id, resource_id, created_at, score_state,
                recovery_score, raw_json, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                member_a,
                "c1",
                "2026-08-01T00:00:00Z",
                "SCORED",
                75.5,
                '{"cid": "c1"}',
                "2026-08-01T10:00:00Z",
            ),
        )

        conn.commit()

        # Capture v4 state
        v4_webhook_rows = conn.execute(
            "SELECT trace_id, whoop_user_id, event_type, event_body, status, "
            "attempt_count, created_at, processed_at FROM webhook_events ORDER BY trace_id"
        ).fetchall()

        v4_recovery_rows = conn.execute(
            "SELECT whoop_user_id, resource_id, created_at, score_state, "
            "recovery_score, raw_json, updated_at FROM recoveries ORDER BY whoop_user_id"
        ).fetchall()

        conn.close()

        # Step 2: Open with open_store() which applies v5 migration
        conn = open_store(db_path)

        # Verify version is now 5
        v5_version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert v5_version == 5, f"After migration, expected v5, got v{v5_version}"

        # Verify all rows survive identically
        v5_webhook_rows = conn.execute(
            "SELECT trace_id, whoop_user_id, event_type, event_body, status, "
            "attempt_count, created_at, processed_at FROM webhook_events ORDER BY trace_id"
        ).fetchall()

        v5_recovery_rows = conn.execute(
            "SELECT whoop_user_id, resource_id, created_at, score_state, "
            "recovery_score, raw_json, updated_at FROM recoveries ORDER BY whoop_user_id"
        ).fetchall()

        assert v5_webhook_rows == v4_webhook_rows, (
            f"webhook_events rows changed after migration: "
            f"v4={v4_webhook_rows}, v5={v5_webhook_rows}"
        )
        assert v5_recovery_rows == v4_recovery_rows, (
            f"recoveries rows changed after migration: v4={v4_recovery_rows}, v5={v5_recovery_rows}"
        )

        # Verify the index ix_webhook_events_status exists
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='webhook_events'"
        ).fetchall()
        index_names = {idx[0] for idx in indexes}
        assert "ix_webhook_events_status" in index_names, (
            f"Index ix_webhook_events_status missing. Found: {index_names}"
        )

        conn.close()


# Test 4: D2 pre-flight check - database unchanged if NULL rows exist
def test_migration_v4_to_v5_pre_flight_fails_without_changing_database() -> None:
    """A v4 store containing one NULL-user row should trigger open_store()
    to raise an error naming the count, and the database must remain completely
    unchanged: still version 4, the NULL row still present, column still nullable.

    This test verifies the pre-flight check works correctly and does not
    partially migrate.

    This test will FAIL on current main (no pre-flight check exists yet).
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = f"{tmpdir}/test.db"

        # Create a v4 database with a NULL-user row
        conn = sqlite3.connect(db_path)
        for version in range(1, 5):
            conn.executescript(_MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()

        # Insert one NULL-user row
        conn.execute(
            """
            INSERT INTO webhook_events (
                trace_id, whoop_user_id, event_type, event_body, status,
                attempt_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "trace-null-1",
                None,
                "test.event",
                '{"test": "data"}',
                "pending",
                0,
                "2026-08-01T00:00:00Z",
            ),
        )

        conn.commit()

        # Verify the NULL row exists
        null_count = conn.execute(
            "SELECT COUNT(*) FROM webhook_events WHERE whoop_user_id IS NULL"
        ).fetchone()[0]
        assert null_count == 1, "Failed to insert NULL-user row"

        v4_version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert v4_version == 4

        # Verify column is still nullable
        pragma_result = conn.execute("PRAGMA table_info(webhook_events)").fetchall()
        whoop_user_id_col = next(r for r in pragma_result if r[1] == "whoop_user_id")
        v4_notnull = whoop_user_id_col[3]

        conn.close()

        # Step 2: Try to open_store() which should fail in pre-flight
        # (test will FAIL if no pre-flight check is implemented)
        with pytest.raises(Exception) as exc_info:
            open_store(db_path)

        # Verify the error message names the count
        error_msg = str(exc_info.value)
        assert "1" in error_msg, f"Error message should name the NULL-row count. Got: {error_msg}"

        # Step 3: Verify database is completely unchanged
        conn = sqlite3.connect(db_path)

        # Still v4
        after_version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert after_version == 4, (
            f"Database version changed during pre-flight check! Expected v4, got v{after_version}"
        )

        # NULL row still exists
        null_count_after = conn.execute(
            "SELECT COUNT(*) FROM webhook_events WHERE whoop_user_id IS NULL"
        ).fetchone()[0]
        assert null_count_after == 1, "NULL row was removed during pre-flight check!"

        # Column still nullable
        pragma_result_after = conn.execute("PRAGMA table_info(webhook_events)").fetchall()
        whoop_user_id_col_after = next(r for r in pragma_result_after if r[1] == "whoop_user_id")
        notnull_after = whoop_user_id_col_after[3]
        assert notnull_after == v4_notnull, "Column nullability changed during pre-flight check!"

        conn.close()


# Test 5: Schema equivalence - rebuilt table matches fact #3 DDL (except constraint)
def test_migration_v5_schema_matches_v4_except_not_null() -> None:
    """The v5 table definition must be identical to v4 except for the
    NOT NULL constraint on whoop_user_id. This ensures no column order,
    type, or default was accidentally changed.

    Compares PRAGMA table_info and sqlite_master DDL against fact #3.
    """
    conn = open_store(":memory:")

    try:
        # Fact #3's exact v4 DDL for webhook_events was:
        #   CREATE TABLE webhook_events (
        #       trace_id TEXT NOT NULL PRIMARY KEY,
        #       whoop_user_id INTEGER,
        #       event_type TEXT NOT NULL,
        #       event_body TEXT NOT NULL,
        #       status TEXT NOT NULL DEFAULT 'pending',
        #       attempt_count INTEGER NOT NULL DEFAULT 0,
        #       created_at TEXT NOT NULL,
        #       processed_at TEXT
        #   )

        # Expected v5 DDL (same but whoop_user_id NOT NULL)
        expected_v5_ddl_pattern = """CREATE TABLE webhook_events (
    trace_id TEXT NOT NULL PRIMARY KEY,
    whoop_user_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    event_body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    processed_at TEXT
)"""

        # Get the actual DDL from sqlite_master
        actual_ddl = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='webhook_events'"
        ).fetchone()[0]

        # Normalize whitespace for comparison
        def normalize_ddl(ddl: str) -> str:
            return " ".join(ddl.split())

        expected_normalized = normalize_ddl(expected_v5_ddl_pattern)
        actual_normalized = normalize_ddl(actual_ddl)

        assert actual_normalized == expected_normalized, (
            f"Schema mismatch:\nExpected: {expected_normalized}\nActual:   {actual_normalized}"
        )

        # Also verify via PRAGMA table_info
        pragma_result = conn.execute("PRAGMA table_info(webhook_events)").fetchall()

        expected_columns = [
            ("trace_id", "TEXT", 1),  # (name, type, notnull)
            ("whoop_user_id", "INTEGER", 1),
            ("event_type", "TEXT", 1),
            ("event_body", "TEXT", 1),
            ("status", "TEXT", 1),
            ("attempt_count", "INTEGER", 1),
            ("created_at", "TEXT", 1),
            ("processed_at", "TEXT", 0),
        ]

        actual_columns = [(r[1], r[2], r[3]) for r in pragma_result]

        assert actual_columns == expected_columns, (
            f"Column structure mismatch:\nExpected: {expected_columns}\nActual: {actual_columns}"
        )
    finally:
        conn.close()


# Test 6: No regression - export and erasure still work for normal rows
def test_migration_v5_export_and_erasure_unchanged_for_normal_rows() -> None:
    """After migration to v5, export_member_data and erase_member_data
    should still work correctly for normal (non-NULL) webhook_events rows.

    Tests that the migration did not break existing export/erasure functionality.
    """
    conn = open_store(":memory:")

    try:
        member_id = 900001

        # Insert some webhook events using the store function
        # (using direct SQL since insert_webhook_event may be under test too)
        conn.execute(
            """
            INSERT INTO webhook_events (
                trace_id, whoop_user_id, event_type, event_body, status,
                attempt_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "trace-1",
                member_id,
                "sleep.updated",
                '{"data": "test1"}',
                "success",
                0,
                "2026-08-01T00:00:00Z",
            ),
        )

        conn.execute(
            """
            INSERT INTO webhook_events (
                trace_id, whoop_user_id, event_type, event_body, status,
                attempt_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "trace-2",
                member_id,
                "recovery.updated",
                '{"data": "test2"}',
                "pending",
                1,
                "2026-08-02T00:00:00Z",
            ),
        )

        conn.commit()

        # Test export
        exported = export_member_data(conn, member_id)
        assert exported["whoop_user_id"] == member_id
        got = len(exported["webhook_events"])
        assert got == 2, f"export_member_data should find 2 webhook events, got {got}"

        # Verify exact row data
        traces = {e["trace_id"] for e in exported["webhook_events"]}
        assert traces == {"trace-1", "trace-2"}, f"Exported traces don't match: {traces}"

        # Test erasure
        erase_member_data(conn, member_id)

        # Verify all webhook_events for member are gone
        remaining = conn.execute(
            "SELECT COUNT(*) FROM webhook_events WHERE whoop_user_id = ?",
            (member_id,),
        ).fetchone()[0]
        assert remaining == 0, (
            f"erase_member_data should remove all webhook events, but {remaining} remain"
        )
    finally:
        conn.close()


# Test 7: Re-running migration is safe
def test_migration_v5_is_idempotent_and_handles_leftover_temp_table() -> None:
    """Re-running _migrate on an already-v5 store is a no-op.
    A leftover temp table from an aborted run does not block a retry.

    This ensures the migration can be safely retried without corruption.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = f"{tmpdir}/test.db"

        # Create and migrate to v5
        conn = open_store(db_path)
        v5_version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert v5_version == 5
        conn.close()

        # Re-open and verify it's still v5 (idempotent)
        conn = open_store(db_path)
        still_v5_version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert still_v5_version == 5, (
            f"Re-opening v5 store should stay at v5, got v{still_v5_version}"
        )
        conn.close()

        # Now the case the `DROP TABLE IF EXISTS` in _SCHEMA_V5 exists for: a
        # leftover `webhook_events_old` from a run that aborted mid-rebuild.
        # This has to be set up on a **v4** store, because on an already-v5
        # store migration 5 never runs and the guard is never reached -- and
        # it has to use the migration's real temp-table name, or it collides
        # with nothing and proves nothing.
        v4_path = f"{tmpdir}/leftover.db"
        raw = sqlite3.connect(v4_path)
        for version in range(1, 5):
            raw.executescript(_MIGRATIONS[version])
            raw.execute(f"PRAGMA user_version = {version}")
        raw.execute(
            "INSERT INTO webhook_events (trace_id, whoop_user_id, event_type, "
            "event_body, status, attempt_count, created_at) "
            "VALUES ('leftover-1', 4242, 'recovery.updated', '{}', 'pending', 0, "
            "'2026-01-01T00:00:00Z')"
        )
        raw.execute("CREATE TABLE webhook_events_old (junk TEXT)")
        raw.execute("INSERT INTO webhook_events_old (junk) VALUES ('debris')")
        raw.commit()
        raw.close()

        conn = open_store(v4_path)
        try:
            final_version = conn.execute("PRAGMA user_version").fetchone()[0]
            assert final_version == 5, (
                f"a leftover webhook_events_old must not block the retry; got v{final_version}"
            )
            # The real row survived, and the debris table is gone.
            assert conn.execute(
                "SELECT trace_id, whoop_user_id FROM webhook_events"
            ).fetchall() == [("leftover-1", 4242)]
            assert not conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'webhook_events_old'"
            ).fetchall(), "the migration must not leave its temp table behind"
        finally:
            conn.close()


# Test 8: Function signature tightening - insert_webhook_event parameter is int
def test_insert_webhook_event_signature_requires_int_not_optional() -> None:
    """Verify that insert_webhook_event's whoop_user_id parameter annotation
    is now `int`, not `int | None`, so mypy can catch attempts to pass None.

    store.py has `from __future__ import annotations` (PEP 563), so raw
    `inspect.signature(...).parameters[...].annotation` is always the
    unevaluated string `"int"` / `"int | None"` -- comparing it to the
    actual `int` type would never hold regardless of the real signature.
    `typing.get_type_hints` resolves the string against the function's
    module globals, giving back the real evaluated type.
    """
    hints = typing.get_type_hints(insert_webhook_event)
    annotation = hints["whoop_user_id"]

    assert annotation is int, f"whoop_user_id should be annotated as `int`, but got {annotation!r}"
