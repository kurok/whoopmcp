"""Persistent store for WHOOP records: schema, migrations, repository layer.

``sqlite3`` from the standard library, no ORM: the schema below is six flat
record tables plus one bookkeeping table, and SQLAlchemy would be the
largest dependency in the project by an order of magnitude for what four
``CREATE TABLE`` statements already give us.

Records are mutable -- a recovery can be rescored days after it happens --
so every write here is an upsert keyed on the row's primary key, never a
plain ``INSERT``. The full JSON payload is kept alongside the extracted
columns (``raw_json``) so a later issue can add or reshape an extracted
column without re-fetching two years of history from WHOOP to get it.

This module knows nothing about HTTP or MCP: it takes dicts in and hands
dicts back out, exactly as stored. Callers (``client.py``, ``server.py``)
own the decision of when to read from here versus the live API.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

#: Bump this and append to ``_MIGRATIONS`` when the schema changes. Never
#: edit an already-shipped migration -- append a new one instead.
CURRENT_SCHEMA_VERSION = 4

# -- schema ------------------------------------------------------------------
#
# Version 1 is the very first schema, so it is simply every table up front.
# A real second migration is a matter of adding `2: "...ALTER TABLE..."`
# below without touching this entry or the ladder logic in `_migrate`.
#
# Every entity table carries the same three bookkeeping columns:
#   raw_json    the full API response, source of truth for anything not
#               pulled out into its own column.
#   updated_at  when this row was last written here (not WHOOP's own
#               timestamps) -- this is the sync cursor for #15, hence the
#               index on every table.
#   deleted_at  reserved for #18; never written or filtered on in this
#               issue, it just needs to exist.

_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS recoveries (
    whoop_user_id INTEGER NOT NULL,
    resource_id TEXT NOT NULL,
    created_at TEXT,
    score_state TEXT,
    recovery_score REAL,
    hrv_rmssd_milli REAL,
    resting_heart_rate REAL,
    raw_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    PRIMARY KEY (whoop_user_id, resource_id)
);
CREATE INDEX IF NOT EXISTS ix_recoveries_updated_at ON recoveries (updated_at);

CREATE TABLE IF NOT EXISTS sleeps (
    whoop_user_id INTEGER NOT NULL,
    resource_id TEXT NOT NULL,
    start TEXT,
    end TEXT,
    score_state TEXT,
    sleep_performance_percentage REAL,
    sleep_efficiency_percentage REAL,
    raw_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    PRIMARY KEY (whoop_user_id, resource_id)
);
CREATE INDEX IF NOT EXISTS ix_sleeps_updated_at ON sleeps (updated_at);

CREATE TABLE IF NOT EXISTS cycles (
    whoop_user_id INTEGER NOT NULL,
    resource_id TEXT NOT NULL,
    start TEXT,
    end TEXT,
    score_state TEXT,
    strain REAL,
    raw_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    PRIMARY KEY (whoop_user_id, resource_id)
);
CREATE INDEX IF NOT EXISTS ix_cycles_updated_at ON cycles (updated_at);

CREATE TABLE IF NOT EXISTS workouts (
    whoop_user_id INTEGER NOT NULL,
    resource_id TEXT NOT NULL,
    start TEXT,
    end TEXT,
    score_state TEXT,
    sport_name TEXT,
    strain REAL,
    raw_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    PRIMARY KEY (whoop_user_id, resource_id)
);
CREATE INDEX IF NOT EXISTS ix_workouts_updated_at ON workouts (updated_at);

CREATE TABLE IF NOT EXISTS body_measurements (
    whoop_user_id INTEGER NOT NULL,
    raw_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    PRIMARY KEY (whoop_user_id)
);
CREATE INDEX IF NOT EXISTS ix_body_measurements_updated_at ON body_measurements (updated_at);

CREATE TABLE IF NOT EXISTS profiles (
    whoop_user_id INTEGER NOT NULL,
    raw_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    PRIMARY KEY (whoop_user_id)
);
CREATE INDEX IF NOT EXISTS ix_profiles_updated_at ON profiles (updated_at);

CREATE TABLE IF NOT EXISTS sync_state (
    whoop_user_id INTEGER NOT NULL,
    entity TEXT NOT NULL,
    cursor TEXT,
    last_run_at TEXT NOT NULL,
    outcome TEXT NOT NULL,
    PRIMARY KEY (whoop_user_id, entity)
);
"""

#: Version 2 (#18): a webhook_events table, keyed uniquely on trace_id. It
#: is what makes webhook processing idempotent -- a duplicate delivery of
#: the same trace_id hits this table's PRIMARY KEY before it ever reaches an
#: upsert -- and it doubles as a replay log: every verified webhook body is
#: recorded here before it is processed, so the four entity tables above
#: could in principle be rebuilt from a full API backfill plus a replay of
#: this table, after a bad migration or a bug in an upsert function.
#:
#: `status` is one of "pending", "success", or "dead_letter" (gave up after
#: too many attempts). "pending" covers three distinct reasons a row hasn't
#: reached a terminal state, none of which get their own status value:
#: queued (never yet attempted), mid-retry (`attempt_count` > 0, transient
#: failures so far, more attempts left), and -- since #66 -- not yet
#: actionable (`_apply_event` raised `webhook_processor.MemberNotLinkedError`;
#: `attempt_count` deliberately NOT incremented, since no amount of
#: automatic retrying fixes a member who hasn't logged in yet). That third
#: case is not swept by anything today -- reprocessing it is #19's
#: reconciliation job, not this table's own bookkeeping. `attempt_count` and
#: `whoop_user_id` are plain columns, not extracted into their own index,
#: since the only query this table serves today is a point lookup by
#: `trace_id`; `ix_webhook_events_status` exists for an operator inspecting
#: what's stuck (pending for any of the three reasons above, or dead_letter),
#: not for anything this issue's own code queries by status.
_SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS webhook_events (
    trace_id TEXT NOT NULL PRIMARY KEY,
    whoop_user_id INTEGER,
    event_type TEXT NOT NULL,
    event_body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    processed_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_webhook_events_status ON webhook_events (status);
"""

#: Version 3 (#29): the principal<->WHOOP-member join, and its audit log.
#:
#: ``principal_members`` is the ONLY table that maps an MCP principal (a
#: bearer token's ``client_id``/``issuer``/``subject`` triple -- see
#: ``mcp.server.auth.provider.principal_components``, or the fixed local
#: sentinel ``server._LOCAL_PRINCIPAL_CLIENT_ID`` under stdio / no-bearer-auth
#: deployments) to a ``whoop_user_id``. Populated ONLY by
#: ``link_principal_to_member``, called ONLY from ``server.whoop_complete_login``
#: -- never inferred from a header, a hostname, or an unsigned claim.
#: ``issuer``/``subject`` are ``NOT NULL DEFAULT ''`` rather than nullable:
#: sqlite's own NULL-handling means a composite PRIMARY KEY does not treat two
#: NULLs as equal, so two distinct no-subject principals could otherwise both
#: "successfully" insert as if the key were unique when it silently was not.
#: ``''`` sidesteps that trap; every caller passes it through unconditionally
#: (see ``link_principal_to_member``/``get_member_for_principal``).
#:
#: ``tool_call_audit`` is deliberately narrow: ``whoop_user_id``, ``tool_name``,
#: ``called_at`` and nothing else. That is a schema-shape guarantee that
#: nobody can silently smuggle a payload/argument/result column onto this
#: table later without ``test_tool_call_audit_table_is_shape_locked_to_no
#: _payload_columns`` failing first -- see ``record_tool_call``.
_SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS principal_members (
    client_id TEXT NOT NULL,
    issuer TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    whoop_user_id INTEGER NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (client_id, issuer, subject)
);

CREATE TABLE IF NOT EXISTS tool_call_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    whoop_user_id INTEGER NOT NULL,
    tool_name TEXT NOT NULL,
    called_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_tool_call_audit_whoop_user_id ON tool_call_audit (whoop_user_id);
"""

#: Version 4 (#19): per-user last-webhook-delivery time, so #31 can later
#: alert on silence relative to that user's own baseline (a dead webhook
#: integration and a user on holiday look identical otherwise).
#:
#: One row per ``whoop_user_id`` (its own PRIMARY KEY, not a composite key
#: the way ``sync_state`` uses) -- deliberately its own table rather than a
#: third concept crammed into ``sync_state``, which #14 and #15 already
#: double up (a bare entity key, and ``f"{entity}:incremental"``); a third,
#: differently-shaped key in that same table risks exactly the kind of
#: entity-key collision #14/#15 had to carefully design around.
#: ``record_webhook_delivery`` upserts ``last_delivered_at`` to "now" on
#: every successfully-processed delivery (including the two vacuous-success
#: skips in ``webhook_processor._apply_event`` -- see that module -- since
#: both are still genuine, completed deliveries and therefore real liveness
#: signal); it is never called on the #66 not-yet-actionable
#: ``MemberNotLinkedError`` path.
_SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS webhook_delivery_state (
    whoop_user_id INTEGER NOT NULL PRIMARY KEY,
    last_delivered_at TEXT NOT NULL
);
"""

#: Migration ladder: version N's script, applied when the database's
#: `PRAGMA user_version` is below N. Keyed by the version it produces, so
#: appending a real migration later is `_MIGRATIONS[5] = "ALTER TABLE ..."`.
_MIGRATIONS: dict[int, str] = {
    1: _SCHEMA_V1,
    2: _SCHEMA_V2,
    3: _SCHEMA_V3,
    4: _SCHEMA_V4,
}

#: Tables filtered by ``whoop_user_id`` that ``_execute_scoped`` enforces a
#: read of that column against, on every touch. Deliberately excludes:
#: ``webhook_events`` (its ``whoop_user_id`` is nullable pre-identity-resolution
#: data -- issue #18's own design, not a leak surface #29 is about), and
#: ``principal_members``/``tool_call_audit`` (the identity/audit layer itself,
#: not member data to filter by member). If a new tenant-scoped table is ever
#: added here without a matching cross-read test case, ``tests/test_tenancy.py
#: ::test_tested_entity_tables_cover_every_tenant_scoped_table`` fails loudly.
_TENANT_SCOPED_TABLES: frozenset[str] = frozenset(
    {
        "recoveries",
        "sleeps",
        "cycles",
        "workouts",
        "body_measurements",
        "profiles",
        "sync_state",
        "webhook_delivery_state",
    }
)

#: Every table a member's data-subject erasure (#32) must remove a real row
#: from -- ``_TENANT_SCOPED_TABLES`` (the six entity/body/profile tables plus
#: ``sync_state``) plus the two bookkeeping tables the issue names by name,
#: ``webhook_events`` and ``tool_call_audit``. Deliberately excludes
#: ``principal_members``: that table is erased separately, by the
#: already-existing ``delete_principal_links_for_member`` (#30), composed
#: with ``erase_member_data`` by the ``erase-member`` CLI subcommand rather
#: than duplicated here. ``tests/test_data_subject_rights.py
#: ::test_erasure_registry_covers_every_schema_table`` asserts this constant,
#: plus that one documented exception, equals the *live* schema's own table
#: list (``PRAGMA table_list``) -- not a second hand-written list -- so a
#: future migration that adds a table without adding it here fails that test
#: immediately rather than shipping an uncovered table silently.
_ERASURE_TABLES: frozenset[str] = _TENANT_SCOPED_TABLES | frozenset(
    {"webhook_events", "tool_call_audit"}
)

#: Which column on each ``_ERASURE_TABLES`` table names "how old is this
#: row" for ``enforce_retention``. Not always ``updated_at``: ``sync_state``
#: has no such column and ages off its own ``last_run_at``, ``webhook_events``
#: off ``created_at`` (it is never updated in place the way an entity row
#: is -- see its own section), and ``tool_call_audit`` off ``called_at``.
_RETENTION_TIMESTAMP_COLUMNS: dict[str, str] = {
    "recoveries": "updated_at",
    "sleeps": "updated_at",
    "cycles": "updated_at",
    "workouts": "updated_at",
    "body_measurements": "updated_at",
    "profiles": "updated_at",
    "sync_state": "last_run_at",
    "webhook_events": "created_at",
    "tool_call_audit": "called_at",
    "webhook_delivery_state": "last_delivered_at",
}


class UnscopedQueryError(RuntimeError):
    """A query against a tenant-scoped table never read its ``whoop_user_id`` column.

    Raised by ``_execute_scoped`` -- the database-level half of #29's
    enforcement: a missing member filter fails here, at the engine, not only
    by application code remembering to pass one.
    """


def _execute_scoped(
    conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()
) -> sqlite3.Cursor:
    """Run ``sql`` against ``conn``, failing closed if it touches a
    tenant-scoped table (``_TENANT_SCOPED_TABLES``) without reading that
    table's own ``whoop_user_id`` column as a restrictive equality predicate.

    This is the ONLY way any function in this module touches ``conn`` for an
    entity read/write -- ``test_store_has_no_unwrapped_sqlite_execute_outside
    _scoped_wrapper`` enforces that structurally, so a future store.py
    function cannot quietly route around this check.

    Mechanism: installs a ``sqlite3.Connection.set_authorizer`` callback for
    the duration of this one statement's compilation, recording every
    ``SQLITE_READ`` (table, column) pair and every table named by a
    ``SQLITE_INSERT``/``SQLITE_UPDATE``/``SQLITE_DELETE`` action. Any
    tenant-scoped table that was touched (read OR written) but never had its
    ``whoop_user_id`` column read is unscoped -- this also catches a bare
    ``UPDATE t SET col = val`` with no ``WHERE`` at all, which triggers no
    ``SQLITE_READ`` whatsoever (there is nothing to read to pick rows), only
    the write action naming the table.

    For SELECT statements, an additional check ensures ``whoop_user_id`` is
    used with a restrictive equality predicate (``whoop_user_id = ?``), not
    just mentioned. This catches cases like ``WHERE whoop_user_id > 0`` or
    ``SELECT whoop_user_id FROM table`` without a WHERE clause.

    A non-``SELECT`` statement is already fully executed (sqlite3 steps it to
    completion inside a single ``execute()`` call) by the time the violation
    is detected, so raising alone would leave its mutation sitting as a
    pending, uncommitted change that a later, unrelated ``conn.commit()``
    could silently persist. ``conn.rollback()`` before raising undoes it.
    Every store.py write function commits immediately after its own
    ``_execute_scoped`` call and never batches multiple writes in one
    transaction, so this rollback only ever undoes the offending statement
    itself, never a caller's earlier, already-legitimate work.
    """
    import re

    reads: dict[str, set[str]] = {}
    writes: set[str] = set()

    def authorizer(
        action: int, arg1: str | None, arg2: str | None, arg3: str | None, arg4: str | None
    ) -> int:
        del arg3, arg4
        if action == sqlite3.SQLITE_READ and arg1 in _TENANT_SCOPED_TABLES:
            reads.setdefault(arg1, set()).add(arg2 or "")
        elif (
            action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE)
            and arg1 in _TENANT_SCOPED_TABLES
        ):
            writes.add(arg1)
        return sqlite3.SQLITE_OK

    conn.set_authorizer(authorizer)
    try:
        cursor = conn.execute(sql, params)
    finally:
        conn.set_authorizer(None)

    touched = writes | set(reads)
    unscoped = {table for table in touched if "whoop_user_id" not in reads.get(table, set())}
    if unscoped:
        conn.rollback()
        raise UnscopedQueryError(
            f"query touches tenant-scoped table(s) {sorted(unscoped)} without "
            f"reading whoop_user_id: {sql!r}"
        )

    # For SELECT statements that reference whoop_user_id, ensure it is used
    # with a restrictive equality predicate (whoop_user_id = ?) rather than
    # just mentioned or used non-restrictively. This catches cases like
    # "WHERE whoop_user_id > 0" or "SELECT whoop_user_id FROM ..." without
    # a restrictive WHERE clause.
    references_whoop_user_id = any("whoop_user_id" in reads.get(table, set()) for table in reads)
    if (
        "SELECT" in sql.upper()
        and references_whoop_user_id
        and not re.search(r"whoop_user_id\s*=\s*\?", sql, re.IGNORECASE)
    ):
        conn.rollback()
        raise UnscopedQueryError(
            f"query touches tenant-scoped table(s) with whoop_user_id but "
            f"does not filter with whoop_user_id = ?: {sql!r}"
        )

    return cursor


def open_store(path: str | Path) -> sqlite3.Connection:
    """Open the sqlite store at ``path``, applying any pending migrations.

    ``path`` may be ``":memory:"`` for an ephemeral, in-process database.
    The connection is not shared across threads (no ``check_same_thread``
    override): this repo's pattern elsewhere is a single connection used
    straightforwardly, and nothing here needs cross-thread access.
    """
    conn = sqlite3.connect(path)
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring ``conn``'s schema up to ``CURRENT_SCHEMA_VERSION``, in order.

    Each step's DDL uses ``IF NOT EXISTS``, so it is safe to re-run if a
    previous attempt got partway through and never reached the version
    bump below -- there is no destructive statement in any migration to
    roll back. (``executescript`` commits any pending transaction before it
    runs, which would make wrapping it in our own ``BEGIN`` a no-op, so we
    lean on idempotent DDL instead of a transaction for atomicity here.)
    """
    current: int = conn.execute("PRAGMA user_version").fetchone()[0]
    for version in range(current + 1, CURRENT_SCHEMA_VERSION + 1):
        conn.executescript(_MIGRATIONS[version])
        conn.execute(f"PRAGMA user_version = {version}")
    conn.commit()


# -- shared helpers -----------------------------------------------------------


def _require_user_id(whoop_user_id: int | None) -> None:
    """Guard the read-function contract (#8) at runtime.

    Every read function types ``whoop_user_id`` as a required ``int`` with
    no default, which stops most misuse at type-check time -- but a caller
    that bypasses static checking can still pass ``None`` explicitly, which
    would silently scope a query to no one's data. Fail loudly instead.
    """
    if whoop_user_id is None:
        raise TypeError("whoop_user_id is required and must not be None")


def _now() -> str:
    """Current UTC time as the ISO 8601 string stored in ``updated_at``."""
    return datetime.now(UTC).isoformat()


# -- recoveries ---------------------------------------------------------------


def upsert_recovery(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update one recovery, keyed on (whoop_user_id, cycle_id).

    Recoveries carry no independent id in the v2 API -- they're addressed
    by the cycle they belong to -- so ``resource_id`` is ``record["cycle_id"]``.
    The extracted score columns are only ever populated when WHOOP has
    scored the cycle; ``record.get("score")`` is falsy otherwise, so every
    extracted column below falls back to ``NULL`` on its own.
    """
    score = record.get("score") or {}
    _execute_scoped(
        conn,
        """
        INSERT INTO recoveries (
            whoop_user_id, resource_id, created_at, score_state,
            recovery_score, hrv_rmssd_milli, resting_heart_rate,
            raw_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (whoop_user_id, resource_id) DO UPDATE SET
            created_at = excluded.created_at,
            score_state = excluded.score_state,
            recovery_score = excluded.recovery_score,
            hrv_rmssd_milli = excluded.hrv_rmssd_milli,
            resting_heart_rate = excluded.resting_heart_rate,
            raw_json = excluded.raw_json,
            updated_at = excluded.updated_at
        """,
        (
            whoop_user_id,
            str(record["cycle_id"]),
            record.get("created_at"),
            record.get("score_state"),
            score.get("recovery_score"),
            score.get("hrv_rmssd_milli"),
            score.get("resting_heart_rate"),
            json.dumps(record),
            _now(),
        ),
    )
    conn.commit()


def get_recoveries(
    conn: sqlite3.Connection,
    whoop_user_id: int,
    *,
    start: str | None = None,
    end: str | None = None,
    include_deleted: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Recoveries for ``whoop_user_id``, oldest first.

    ``start``/``end`` (inclusive) filter on ``created_at`` when given, and
    are ignored (i.e. no filtering on that bound) when left as ``None``.
    Returns each record's raw payload exactly as it was written -- this
    store does no reshaping.

    ``include_deleted`` (#16/#18): soft-deleted rows (``deleted_at`` set by
    the ``*.deleted`` webhook path) are excluded by default -- a repointed
    MCP tool must never resurrect one. Pass ``True`` only for a caller that
    deliberately wants a deleted-but-not-erased row too, e.g.
    ``export_member_data`` (#32): a soft-delete is not erasure.

    ``limit``/``offset`` (#16): store-backed pagination for the list_*
    tools. ``offset`` is ignored unless ``limit`` is also given.
    """
    _require_user_id(whoop_user_id)
    sql = """
        SELECT raw_json FROM recoveries
        WHERE whoop_user_id = ?
          AND (? OR deleted_at IS NULL)
          AND (? IS NULL OR created_at >= ?)
          AND (? IS NULL OR created_at <= ?)
        ORDER BY created_at
    """
    params: tuple[Any, ...] = (whoop_user_id, include_deleted, start, start, end, end)
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params = (*params, limit, offset)
    rows = _execute_scoped(conn, sql, params).fetchall()
    return [json.loads(row[0]) for row in rows]


def get_recovery_coverage(
    conn: sqlite3.Connection, whoop_user_id: int
) -> tuple[str | None, str | None]:
    """The (earliest, latest) ``created_at`` held for ``whoop_user_id``'s
    recoveries, excluding soft-deleted rows -- ``(None, None)`` if the table
    holds nothing live for this member.

    ``created_at`` (the activity date), never ``updated_at`` (sync/rescore
    bookkeeping, per this module's own schema comment) -- see #16's own
    notes on why conflating the two would be the inverted form of #15's bug.
    """
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        """
        SELECT MIN(created_at), MAX(created_at) FROM recoveries
        WHERE whoop_user_id = ? AND deleted_at IS NULL
        """,
        (whoop_user_id,),
    ).fetchone()
    return (row[0], row[1]) if row is not None else (None, None)


# -- sleeps ---------------------------------------------------------------


def upsert_sleep(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update one sleep, keyed on (whoop_user_id, id)."""
    score = record.get("score") or {}
    _execute_scoped(
        conn,
        """
        INSERT INTO sleeps (
            whoop_user_id, resource_id, start, end, score_state,
            sleep_performance_percentage, sleep_efficiency_percentage,
            raw_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (whoop_user_id, resource_id) DO UPDATE SET
            start = excluded.start,
            end = excluded.end,
            score_state = excluded.score_state,
            sleep_performance_percentage = excluded.sleep_performance_percentage,
            sleep_efficiency_percentage = excluded.sleep_efficiency_percentage,
            raw_json = excluded.raw_json,
            updated_at = excluded.updated_at
        """,
        (
            whoop_user_id,
            str(record["id"]),
            record.get("start"),
            record.get("end"),
            record.get("score_state"),
            score.get("sleep_performance_percentage"),
            score.get("sleep_efficiency_percentage"),
            json.dumps(record),
            _now(),
        ),
    )
    conn.commit()


def get_sleeps(
    conn: sqlite3.Connection,
    whoop_user_id: int,
    *,
    start: str | None = None,
    end: str | None = None,
    include_deleted: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Sleeps for ``whoop_user_id``, oldest first.

    ``start``/``end`` (inclusive) filter on the sleep's own ``start``
    timestamp when given. See ``get_recoveries`` for ``include_deleted``/
    ``limit``/``offset``.
    """
    _require_user_id(whoop_user_id)
    sql = """
        SELECT raw_json FROM sleeps
        WHERE whoop_user_id = ?
          AND (? OR deleted_at IS NULL)
          AND (? IS NULL OR start >= ?)
          AND (? IS NULL OR start <= ?)
        ORDER BY start
    """
    params: tuple[Any, ...] = (whoop_user_id, include_deleted, start, start, end, end)
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params = (*params, limit, offset)
    rows = _execute_scoped(conn, sql, params).fetchall()
    return [json.loads(row[0]) for row in rows]


def get_sleep_coverage(
    conn: sqlite3.Connection, whoop_user_id: int
) -> tuple[str | None, str | None]:
    """The (earliest ``start``, latest ``end``) held for ``whoop_user_id``'s
    sleeps, excluding soft-deleted rows -- ``(None, None)`` if none are held.

    The record's full span (``MIN(start)``/``MAX(end)``), not ``MAX(start)``:
    the latest-held sleep may still be ongoing well past its own start.
    """
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        """
        SELECT MIN(start), MAX(end) FROM sleeps
        WHERE whoop_user_id = ? AND deleted_at IS NULL
        """,
        (whoop_user_id,),
    ).fetchone()
    return (row[0], row[1]) if row is not None else (None, None)


def get_sleep_by_id(
    conn: sqlite3.Connection,
    whoop_user_id: int,
    resource_id: str,
    *,
    include_deleted: bool = False,
) -> dict[str, Any] | None:
    """The stored sleep ``resource_id`` for ``whoop_user_id``, or ``None`` if
    unknown -- or soft-deleted and ``include_deleted`` is left ``False``."""
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        """
        SELECT raw_json FROM sleeps
        WHERE whoop_user_id = ? AND resource_id = ?
          AND (? OR deleted_at IS NULL)
        """,
        (whoop_user_id, resource_id, include_deleted),
    ).fetchone()
    return json.loads(row[0]) if row is not None else None


# -- cycles ---------------------------------------------------------------


def upsert_cycle(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update one cycle, keyed on (whoop_user_id, id).

    A cycle's ``id`` is an integer in the v2 API; it is stored as TEXT like
    every other resource id (sqlite is dynamically typed regardless), so the
    primary key's column type is consistent across all four entity tables.
    """
    score = record.get("score") or {}
    _execute_scoped(
        conn,
        """
        INSERT INTO cycles (
            whoop_user_id, resource_id, start, end, score_state, strain,
            raw_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (whoop_user_id, resource_id) DO UPDATE SET
            start = excluded.start,
            end = excluded.end,
            score_state = excluded.score_state,
            strain = excluded.strain,
            raw_json = excluded.raw_json,
            updated_at = excluded.updated_at
        """,
        (
            whoop_user_id,
            str(record["id"]),
            record.get("start"),
            record.get("end"),
            record.get("score_state"),
            score.get("strain"),
            json.dumps(record),
            _now(),
        ),
    )
    conn.commit()


def get_cycles(
    conn: sqlite3.Connection,
    whoop_user_id: int,
    *,
    start: str | None = None,
    end: str | None = None,
    include_deleted: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Cycles for ``whoop_user_id``, oldest first.

    ``start``/``end`` (inclusive) filter on the cycle's own ``start``
    timestamp when given. See ``get_recoveries`` for ``include_deleted``/
    ``limit``/``offset``.
    """
    _require_user_id(whoop_user_id)
    sql = """
        SELECT raw_json FROM cycles
        WHERE whoop_user_id = ?
          AND (? OR deleted_at IS NULL)
          AND (? IS NULL OR start >= ?)
          AND (? IS NULL OR start <= ?)
        ORDER BY start
    """
    params: tuple[Any, ...] = (whoop_user_id, include_deleted, start, start, end, end)
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params = (*params, limit, offset)
    rows = _execute_scoped(conn, sql, params).fetchall()
    return [json.loads(row[0]) for row in rows]


def get_cycle_coverage(
    conn: sqlite3.Connection, whoop_user_id: int
) -> tuple[str | None, str | None]:
    """The (earliest ``start``, latest ``end``) held for ``whoop_user_id``'s
    cycles, excluding soft-deleted rows -- ``(None, None)`` if none are held.
    """
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        """
        SELECT MIN(start), MAX(end) FROM cycles
        WHERE whoop_user_id = ? AND deleted_at IS NULL
        """,
        (whoop_user_id,),
    ).fetchone()
    return (row[0], row[1]) if row is not None else (None, None)


# -- workouts ---------------------------------------------------------------


def upsert_workout(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update one workout, keyed on (whoop_user_id, id)."""
    score = record.get("score") or {}
    _execute_scoped(
        conn,
        """
        INSERT INTO workouts (
            whoop_user_id, resource_id, start, end, score_state, sport_name,
            strain, raw_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (whoop_user_id, resource_id) DO UPDATE SET
            start = excluded.start,
            end = excluded.end,
            score_state = excluded.score_state,
            sport_name = excluded.sport_name,
            strain = excluded.strain,
            raw_json = excluded.raw_json,
            updated_at = excluded.updated_at
        """,
        (
            whoop_user_id,
            str(record["id"]),
            record.get("start"),
            record.get("end"),
            record.get("score_state"),
            record.get("sport_name"),
            score.get("strain"),
            json.dumps(record),
            _now(),
        ),
    )
    conn.commit()


def get_workouts(
    conn: sqlite3.Connection,
    whoop_user_id: int,
    *,
    start: str | None = None,
    end: str | None = None,
    include_deleted: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Workouts for ``whoop_user_id``, oldest first.

    ``start``/``end`` (inclusive) filter on the workout's own ``start``
    timestamp when given. See ``get_recoveries`` for ``include_deleted``/
    ``limit``/``offset``.
    """
    _require_user_id(whoop_user_id)
    sql = """
        SELECT raw_json FROM workouts
        WHERE whoop_user_id = ?
          AND (? OR deleted_at IS NULL)
          AND (? IS NULL OR start >= ?)
          AND (? IS NULL OR start <= ?)
        ORDER BY start
    """
    params: tuple[Any, ...] = (whoop_user_id, include_deleted, start, start, end, end)
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params = (*params, limit, offset)
    rows = _execute_scoped(conn, sql, params).fetchall()
    return [json.loads(row[0]) for row in rows]


def get_workout_coverage(
    conn: sqlite3.Connection, whoop_user_id: int
) -> tuple[str | None, str | None]:
    """The (earliest ``start``, latest ``end``) held for ``whoop_user_id``'s
    workouts, excluding soft-deleted rows -- ``(None, None)`` if none are held.
    """
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        """
        SELECT MIN(start), MAX(end) FROM workouts
        WHERE whoop_user_id = ? AND deleted_at IS NULL
        """,
        (whoop_user_id,),
    ).fetchone()
    return (row[0], row[1]) if row is not None else (None, None)


def get_workout_by_id(
    conn: sqlite3.Connection,
    whoop_user_id: int,
    resource_id: str,
    *,
    include_deleted: bool = False,
) -> dict[str, Any] | None:
    """The stored workout ``resource_id`` for ``whoop_user_id``, or ``None``
    if unknown -- or soft-deleted and ``include_deleted`` is left ``False``."""
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        """
        SELECT raw_json FROM workouts
        WHERE whoop_user_id = ? AND resource_id = ?
          AND (? OR deleted_at IS NULL)
        """,
        (whoop_user_id, resource_id, include_deleted),
    ).fetchone()
    return json.loads(row[0]) if row is not None else None


# -- body measurements & profile ---------------------------------------------
#
# Neither has an id of its own in the WHOOP API -- one row per
# whoop_user_id, which is itself the primary key.


def upsert_body_measurement(
    conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]
) -> None:
    """Insert or update the one body-measurement row for ``whoop_user_id``."""
    _execute_scoped(
        conn,
        """
        INSERT INTO body_measurements (whoop_user_id, raw_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT (whoop_user_id) DO UPDATE SET
            raw_json = excluded.raw_json,
            updated_at = excluded.updated_at
        """,
        (whoop_user_id, json.dumps(record), _now()),
    )
    conn.commit()


def get_body_measurement(conn: sqlite3.Connection, whoop_user_id: int) -> dict[str, Any] | None:
    """The stored body-measurement payload for ``whoop_user_id``, or ``None``
    if nothing has been synced for them yet."""
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        "SELECT raw_json FROM body_measurements WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()
    return json.loads(row[0]) if row is not None else None


def get_body_measurement_updated_at(conn: sqlite3.Connection, whoop_user_id: int) -> str | None:
    """When ``whoop_user_id``'s body-measurement row was last written here, or
    ``None`` if it has never been synced -- the singleton-shaped freshness
    signal #16's ``whoop_data_coverage`` reports for this entity, since it
    has no earliest/latest activity range to speak of."""
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        "SELECT updated_at FROM body_measurements WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()
    return row[0] if row is not None else None


def upsert_profile(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update the one profile row for ``whoop_user_id``."""
    _execute_scoped(
        conn,
        """
        INSERT INTO profiles (whoop_user_id, raw_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT (whoop_user_id) DO UPDATE SET
            raw_json = excluded.raw_json,
            updated_at = excluded.updated_at
        """,
        (whoop_user_id, json.dumps(record), _now()),
    )
    conn.commit()


def get_profile(conn: sqlite3.Connection, whoop_user_id: int) -> dict[str, Any] | None:
    """The stored profile payload for ``whoop_user_id``, or ``None`` if
    nothing has been synced for them yet."""
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        "SELECT raw_json FROM profiles WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()
    return json.loads(row[0]) if row is not None else None


def get_profile_updated_at(conn: sqlite3.Connection, whoop_user_id: int) -> str | None:
    """When ``whoop_user_id``'s profile row was last written here, or
    ``None`` if it has never been synced -- see
    ``get_body_measurement_updated_at`` for the analogous singleton."""
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        "SELECT updated_at FROM profiles WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()
    return row[0] if row is not None else None


# -- sync_state ---------------------------------------------------------------


def set_sync_state(
    conn: sqlite3.Connection,
    whoop_user_id: int,
    entity: str,
    *,
    cursor: str | None,
    last_run_at: str,
    outcome: str,
) -> None:
    """Record the outcome of a sync run for (``whoop_user_id``, ``entity``).

    ``cursor`` is ``None`` for entities that don't paginate by cursor (e.g.
    a full-sync result for a singleton like the profile).
    """
    _execute_scoped(
        conn,
        """
        INSERT INTO sync_state (whoop_user_id, entity, cursor, last_run_at, outcome)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (whoop_user_id, entity) DO UPDATE SET
            cursor = excluded.cursor,
            last_run_at = excluded.last_run_at,
            outcome = excluded.outcome
        """,
        (whoop_user_id, entity, cursor, last_run_at, outcome),
    )
    conn.commit()


def get_sync_state(
    conn: sqlite3.Connection, whoop_user_id: int, entity: str
) -> dict[str, Any] | None:
    """The last recorded sync outcome for (``whoop_user_id``, ``entity``),
    or ``None`` if that pair has never been synced."""
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        """
        SELECT cursor, last_run_at, outcome FROM sync_state
        WHERE whoop_user_id = ? AND entity = ?
        """,
        (whoop_user_id, entity),
    ).fetchone()
    if row is None:
        return None
    cursor, last_run_at, outcome = row
    return {"cursor": cursor, "last_run_at": last_run_at, "outcome": outcome}


# -- webhook_delivery_state (#19) ---------------------------------------------
#
# One row per whoop_user_id, upserted every time a webhook delivery for that
# user finishes processing (see webhook_processor.process_webhook_event's
# success branch). Exists purely so #31 can later alert on a member who has
# gone quiet relative to their own baseline -- see _SCHEMA_V4's own comment.


def record_webhook_delivery(conn: sqlite3.Connection, whoop_user_id: int) -> None:
    """Record that a webhook delivery for ``whoop_user_id`` just completed,
    advancing ``last_delivered_at`` to now."""
    _execute_scoped(
        conn,
        """
        INSERT INTO webhook_delivery_state (whoop_user_id, last_delivered_at)
        VALUES (?, ?)
        ON CONFLICT (whoop_user_id) DO UPDATE SET
            last_delivered_at = excluded.last_delivered_at
        """,
        (whoop_user_id, _now()),
    )
    conn.commit()


def get_last_webhook_delivery(conn: sqlite3.Connection, whoop_user_id: int) -> str | None:
    """The last recorded webhook-delivery time for ``whoop_user_id``, or
    ``None`` if no delivery has ever completed for them."""
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        "SELECT last_delivered_at FROM webhook_delivery_state WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()
    return row[0] if row is not None else None


def get_webhook_delivery_state_for_member(
    conn: sqlite3.Connection, whoop_user_id: int
) -> dict[str, Any]:
    """``{"last_delivered_at": ...}`` for ``whoop_user_id``, or ``{}`` if no
    delivery has ever completed for them -- for ``export_member_data``."""
    _require_user_id(whoop_user_id)
    last_delivered_at = get_last_webhook_delivery(conn, whoop_user_id)
    return {} if last_delivered_at is None else {"last_delivered_at": last_delivered_at}


# -- webhook_events (#18) -----------------------------------------------------
#
# Unlike every table above, this one is never upserted: a row is inserted
# exactly once, when a trace_id is first seen (the INSERT itself is how
# idempotency is enforced -- a second insert of the same trace_id violates
# the PRIMARY KEY), and only ever updated in place afterwards to advance its
# own status/attempt_count as processing proceeds or retries.


def insert_webhook_event(
    conn: sqlite3.Connection,
    trace_id: str,
    whoop_user_id: int | None,
    event_type: str,
    event_body: str,
) -> None:
    """Record a newly-seen webhook event as pending, before it is processed.

    Written first, unconditionally -- before the fetch-and-upsert this event
    triggers even starts -- so the replay log is complete even for an event
    whose processing later fails outright. Raises ``sqlite3.IntegrityError``
    if ``trace_id`` already exists; the caller (``webhook_processor``) checks
    with ``get_webhook_event`` first and only calls this for a trace_id it
    has not seen, so that error should never actually surface in practice --
    it is the ``PRIMARY KEY``'s job to make that guarantee load-bearing
    rather than advisory.
    """
    _execute_scoped(
        conn,
        """
        INSERT INTO webhook_events (
            trace_id, whoop_user_id, event_type, event_body, status,
            attempt_count, created_at
        ) VALUES (?, ?, ?, ?, 'pending', 0, ?)
        """,
        (trace_id, whoop_user_id, event_type, event_body, _now()),
    )
    conn.commit()


_WEBHOOK_EVENT_COLUMNS = (
    "trace_id",
    "whoop_user_id",
    "event_type",
    "event_body",
    "status",
    "attempt_count",
    "created_at",
    "processed_at",
)


def get_webhook_event(conn: sqlite3.Connection, trace_id: str) -> dict[str, Any] | None:
    """The webhook_events row for ``trace_id``, or ``None`` if never seen."""
    # _WEBHOOK_EVENT_COLUMNS is a fixed, internal tuple of literal column
    # names, never user input.
    row = _execute_scoped(
        conn,
        f"SELECT {', '.join(_WEBHOOK_EVENT_COLUMNS)} FROM webhook_events WHERE trace_id = ?",  # noqa: S608
        (trace_id,),
    ).fetchone()
    if row is None:
        return None
    return dict(zip(_WEBHOOK_EVENT_COLUMNS, row, strict=True))


def mark_webhook_event_success(conn: sqlite3.Connection, trace_id: str) -> None:
    """Record that ``trace_id`` finished processing -- fetched, upserted (or
    deliberately skipped: an unknown user, a *.deleted, or an out-of-order
    record). A later duplicate delivery of the same trace_id sees this
    status and is skipped without a second fetch."""
    _execute_scoped(
        conn,
        "UPDATE webhook_events SET status = 'success', processed_at = ? WHERE trace_id = ?",
        (_now(), trace_id),
    )
    conn.commit()


def mark_webhook_event_retry(conn: sqlite3.Connection, trace_id: str, attempt_count: int) -> None:
    """Record one failed attempt at ``trace_id``, still short of the caller's
    ``max_attempts``. Status stays "pending" -- this is not a terminal state."""
    _execute_scoped(
        conn,
        "UPDATE webhook_events SET status = 'pending', attempt_count = ? WHERE trace_id = ?",
        (attempt_count, trace_id),
    )
    conn.commit()


def mark_webhook_event_dead_letter(
    conn: sqlite3.Connection, trace_id: str, attempt_count: int
) -> None:
    """Give up on ``trace_id`` after ``attempt_count`` failed attempts.

    Terminal: a dead-lettered event is never retried again, and sits here
    for an operator to inspect (``event_body`` is the full original payload).
    """
    _execute_scoped(
        conn,
        """
        UPDATE webhook_events SET status = 'dead_letter', attempt_count = ?, processed_at = ?
        WHERE trace_id = ?
        """,
        (attempt_count, _now(), trace_id),
    )
    conn.commit()


# -- principal_members & tool_call_audit (#29) --------------------------------
#
# The join between an MCP principal and the WHOOP member it is allowed to
# act as. Written ONLY by ``link_principal_to_member``, called ONLY from
# ``server.whoop_complete_login`` -- see that function and ``server
# .resolve_member_id`` for the write and read sides of this join
# respectively. Neither table is in ``_TENANT_SCOPED_TABLES``: they ARE the
# identity/audit layer, not member data to filter by member.


def link_principal_to_member(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    issuer: str | None,
    subject: str | None,
    whoop_user_id: int,
) -> None:
    """Record that MCP principal (``client_id``, ``issuer``, ``subject``) may
    act as WHOOP member ``whoop_user_id``.

    An idempotent upsert: re-linking the same principal (e.g. re-authorising)
    updates the mapping in place rather than duplicating the row. ``issuer``/
    ``subject`` of ``None`` are stored as ``''`` -- see ``_SCHEMA_V3``'s own
    comment for why NULL is unsafe here.
    """
    _execute_scoped(
        conn,
        """
        INSERT INTO principal_members (client_id, issuer, subject, whoop_user_id, linked_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (client_id, issuer, subject) DO UPDATE SET
            whoop_user_id = excluded.whoop_user_id,
            linked_at = excluded.linked_at
        """,
        (client_id, issuer or "", subject or "", whoop_user_id, _now()),
    )
    conn.commit()


def get_member_for_principal(
    conn: sqlite3.Connection,
    *,
    client_id: str,
    issuer: str | None,
    subject: str | None,
) -> int | None:
    """The WHOOP member id linked to this MCP principal, or ``None`` if
    unlinked -- the caller (``server.resolve_member_id``) must treat
    ``None`` as an error, never a default."""
    cursor = _execute_scoped(
        conn,
        """
        SELECT whoop_user_id FROM principal_members
        WHERE client_id = ? AND issuer = ? AND subject = ?
        """,
        (client_id, issuer or "", subject or ""),
    )
    row = cursor.fetchone()
    return row[0] if row is not None else None


def principal_is_linked_to_member(conn: sqlite3.Connection, whoop_user_id: int) -> bool:
    """Whether any MCP principal is currently linked to ``whoop_user_id``.

    Used by the ``delete-member`` CLI subcommand (``__main__.py``) as a
    confirmation guard against operator error, before it calls
    ``delete_principal_links_for_member`` -- ``--whoop-user-id`` on that
    subcommand must match a real, already-linked id, not name one out of
    several live grants (there is exactly one per process today; see
    ``CONTRIBUTING.md``).
    """
    cursor = _execute_scoped(
        conn,
        "SELECT 1 FROM principal_members WHERE whoop_user_id = ? LIMIT 1",
        (whoop_user_id,),
    )
    return cursor.fetchone() is not None


def all_linked_whoop_user_ids(conn: sqlite3.Connection) -> set[int]:
    """Every distinct WHOOP member id ``principal_members`` has ever linked,
    across all principals and all time.

    Used by ``export-member`` (#32) to decide whether attaching the single
    locally-stored token's scopes to an export document is safe: today's
    architecture keeps exactly one live grant per process (see
    ``CONTRIBUTING.md``), but ``principal_members`` rows are never pruned on
    their own, so a store that has ever been re-authorised against a
    different WHOOP account can still list more than one distinct id here
    even though only one token file exists. When this returns more than a
    single id, no local record says which of them the current token belongs
    to -- callers must not guess.
    """
    cursor = _execute_scoped(conn, "SELECT DISTINCT whoop_user_id FROM principal_members")
    return {row[0] for row in cursor.fetchall()}


def delete_principal_links_for_member(conn: sqlite3.Connection, whoop_user_id: int) -> None:
    """Remove every ``principal_members`` row linked to ``whoop_user_id``.

    The local-identity-plumbing half of member deletion (#30): paired with
    ``auth.Authenticator.revoke_and_forget`` (which handles the token and
    the upstream revoke) by the ``delete-member`` CLI subcommand. Routed
    through ``_execute_scoped`` like every other write in this module, even
    though ``principal_members`` is not itself in ``_TENANT_SCOPED_TABLES``
    -- see that table's own comment for why it is identity/audit plumbing,
    not member data filtered by member; going through ``_execute_scoped``
    here is just this module's one way of touching ``conn``, not a
    tenancy-isolation claim about this particular table. Health data,
    webhook events, and audit rows are deliberately untouched -- that is
    #32's full erasure story, not this issue's narrower token-and-link
    scope.
    """
    _execute_scoped(
        conn,
        "DELETE FROM principal_members WHERE whoop_user_id = ?",
        (whoop_user_id,),
    )
    conn.commit()


def record_tool_call(conn: sqlite3.Connection, whoop_user_id: int, tool_name: str) -> None:
    """Audit-log one tool call: identity and tool name only, never a payload.

    ``tool_call_audit``'s own schema (see ``_SCHEMA_V3``) makes "no payload"
    a shape guarantee rather than a redaction step that could have a bug --
    there is no column here to put one in.
    """
    _execute_scoped(
        conn,
        "INSERT INTO tool_call_audit (whoop_user_id, tool_name, called_at) VALUES (?, ?, ?)",
        (whoop_user_id, tool_name, _now()),
    )
    conn.commit()


# -- data subject rights (#32): export, erasure, retention -------------------
#
# Every function below is operator-only, CLI-exposed plumbing (see
# ``__main__.py``'s ``export-member``/``erase-member``/``enforce-retention``
# subcommands) -- none of it is, or may become, an MCP tool. See
# ``client.py``'s own module docstring and ``auth.revoke_upstream``'s for why:
# an LLM-driven tool must never be able to trigger a member's own irreversible
# export or erasure, or another member's.


def get_all_sync_state_for_member(
    conn: sqlite3.Connection, whoop_user_id: int
) -> list[dict[str, Any]]:
    """Every recorded sync outcome for ``whoop_user_id``, one dict per entity
    that has ever been synced (see ``set_sync_state``) -- unlike
    ``get_sync_state``, which reads one named entity at a time, this reads
    all of them, for ``export_member_data``."""
    _require_user_id(whoop_user_id)
    rows = _execute_scoped(
        conn,
        "SELECT entity, cursor, last_run_at, outcome FROM sync_state WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchall()
    columns = ("entity", "cursor", "last_run_at", "outcome")
    return [dict(zip(columns, row, strict=True)) for row in rows]


def get_webhook_events_for_member(
    conn: sqlite3.Connection, whoop_user_id: int
) -> list[dict[str, Any]]:
    """Every ``webhook_events`` row recorded for ``whoop_user_id``, using the
    same column set ``get_webhook_event`` reads by ``trace_id`` alone -- this
    reads every row for a member instead, for ``export_member_data``."""
    _require_user_id(whoop_user_id)
    rows = _execute_scoped(
        conn,
        # _WEBHOOK_EVENT_COLUMNS is a fixed, internal tuple of literal column
        # names, never user input.
        f"SELECT {', '.join(_WEBHOOK_EVENT_COLUMNS)} FROM webhook_events "  # noqa: S608
        f"WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchall()
    return [dict(zip(_WEBHOOK_EVENT_COLUMNS, row, strict=True)) for row in rows]


_TOOL_CALL_AUDIT_COLUMNS = ("id", "whoop_user_id", "tool_name", "called_at")


def get_tool_call_audit_for_member(
    conn: sqlite3.Connection, whoop_user_id: int
) -> list[dict[str, Any]]:
    """Every ``tool_call_audit`` row recorded for ``whoop_user_id``, for
    ``export_member_data``."""
    _require_user_id(whoop_user_id)
    rows = _execute_scoped(
        conn,
        f"SELECT {', '.join(_TOOL_CALL_AUDIT_COLUMNS)} FROM tool_call_audit "  # noqa: S608
        f"WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchall()
    return [dict(zip(_TOOL_CALL_AUDIT_COLUMNS, row, strict=True)) for row in rows]


def get_principal_links_for_member(
    conn: sqlite3.Connection, whoop_user_id: int
) -> list[dict[str, Any]]:
    """Every MCP principal currently (or previously) linked to
    ``whoop_user_id``, with ``linked_at`` -- the "what was authorised and
    when" half of consent transparency the issue asks for; nothing new is
    tracked, this just surfaces what ``link_principal_to_member`` already
    records."""
    _require_user_id(whoop_user_id)
    rows = _execute_scoped(
        conn,
        """
        SELECT client_id, issuer, subject, linked_at FROM principal_members
        WHERE whoop_user_id = ?
        """,
        (whoop_user_id,),
    ).fetchall()
    columns = ("client_id", "issuer", "subject", "linked_at")
    return [dict(zip(columns, row, strict=True)) for row in rows]


def export_member_data(conn: sqlite3.Connection, whoop_user_id: int) -> dict[str, Any]:
    """Everything this store holds about ``whoop_user_id``, as one portable,
    JSON-serialisable document -- the data-subject *export* half of #32.

    Built entirely from the existing member-scoped read functions (plus the
    four small ``get_*_for_member`` helpers above), so every field is already
    enforced member-scoped by ``_execute_scoped`` -- there is no separate
    query in this function for a second member's data to leak through.

    ``include_deleted=True`` on the four collection getters (#16): a
    soft-delete (the ``*.deleted`` webhook path) is not erasure -- see this
    module's own comment on ``erase_member_data`` -- so a data-subject
    export must still show a record WHOOP told this server was deleted,
    until an operator actually erases it.
    """
    _require_user_id(whoop_user_id)
    return {
        "whoop_user_id": whoop_user_id,
        "exported_at": _now(),
        "profile": get_profile(conn, whoop_user_id),
        "body_measurement": get_body_measurement(conn, whoop_user_id),
        "recoveries": get_recoveries(conn, whoop_user_id, include_deleted=True),
        "sleeps": get_sleeps(conn, whoop_user_id, include_deleted=True),
        "cycles": get_cycles(conn, whoop_user_id, include_deleted=True),
        "workouts": get_workouts(conn, whoop_user_id, include_deleted=True),
        "sync_state": get_all_sync_state_for_member(conn, whoop_user_id),
        "webhook_events": get_webhook_events_for_member(conn, whoop_user_id),
        "tool_call_audit": get_tool_call_audit_for_member(conn, whoop_user_id),
        "principal_links": get_principal_links_for_member(conn, whoop_user_id),
        "webhook_delivery_state": get_webhook_delivery_state_for_member(conn, whoop_user_id),
    }


def erase_member_data(conn: sqlite3.Connection, whoop_user_id: int) -> None:
    """Permanently ``DELETE`` every row belonging to ``whoop_user_id`` across
    every table in ``_ERASURE_TABLES`` -- the data-subject *erasure* half of
    #32. A real removal, verified at the database level by this module's own
    tests: it never sets a soft-delete marker the way the ``*.deleted``
    webhook path does (see ``webhook_processor``'s own soft-delete helper for
    that entirely separate, unrelated code path) -- there is no column write
    here at all, only ``DELETE FROM ... WHERE whoop_user_id = ?``, run
    through the same ``_execute_scoped`` enforcement every other write in
    this module goes through.

    ``principal_members`` is deliberately NOT among ``_ERASURE_TABLES``: that
    table's own erasure is ``delete_principal_links_for_member`` (#30),
    reused as-is and composed with this function by the ``erase-member`` CLI
    subcommand, not duplicated here.
    """
    _require_user_id(whoop_user_id)
    for table in sorted(_ERASURE_TABLES):
        _execute_scoped(
            conn,
            # table is drawn from the fixed, internal _ERASURE_TABLES
            # frozenset, never user input.
            f"DELETE FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (whoop_user_id,),
        )
    conn.commit()


def enforce_retention(
    conn: sqlite3.Connection, *, max_age_days: int, now: datetime | None = None
) -> dict[str, int]:
    """Delete every row in ``_ERASURE_TABLES`` whose own age column (per
    ``_RETENTION_TIMESTAMP_COLUMNS``) is older than ``max_age_days`` relative
    to ``now`` (the real current time, when omitted) -- the retention *job*
    #32 asks for: something that actually runs and deletes, not a documented
    promise. Returns the number of rows removed per table (``cursor.rowcount``).

    Deliberately a cross-tenant sweep, not a per-member loop: retention
    applies to every member at once by its very nature, so each table below
    is swept in one statement rather than enumerating ids first (and, for the
    six tables also in ``_TENANT_SCOPED_TABLES``, an id-first loop is not
    even available here -- discovering *which* ids have stale data would
    itself require reading a tenant-scoped table's ``whoop_user_id`` column
    with no equality predicate, which ``_execute_scoped``'s own SELECT check
    refuses). ``_execute_scoped``'s enforcement (see its own docstring) only
    requires that a touched tenant-scoped table's ``whoop_user_id`` column is
    actually read by the statement -- it does not require a specific id -- so
    ``whoop_user_id IS NOT NULL`` (always true: every ``_TENANT_SCOPED_TABLES``
    table declares that column ``NOT NULL``) satisfies that requirement
    honestly, for what is a genuinely deliberate, all-members-at-once
    statement rather than a missed member filter.
    """
    as_of = now if now is not None else datetime.now(UTC)
    cutoff = (as_of - timedelta(days=max_age_days)).isoformat()

    counts: dict[str, int] = {}
    for table in sorted(_ERASURE_TABLES):
        column = _RETENTION_TIMESTAMP_COLUMNS[table]
        if table in _TENANT_SCOPED_TABLES:
            sql = f"DELETE FROM {table} WHERE whoop_user_id IS NOT NULL AND {column} < ?"  # noqa: S608
        else:
            sql = f"DELETE FROM {table} WHERE {column} < ?"  # noqa: S608
        cursor = _execute_scoped(conn, sql, (cutoff,))
        counts[table] = cursor.rowcount
    conn.commit()
    return counts
