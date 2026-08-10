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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: Bump this and append to ``_MIGRATIONS`` when the schema changes. Never
#: edit an already-shipped migration -- append a new one instead.
CURRENT_SCHEMA_VERSION = 1

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

#: Migration ladder: version N's script, applied when the database's
#: `PRAGMA user_version` is below N. Keyed by the version it produces, so
#: appending a real migration later is `_MIGRATIONS[2] = "ALTER TABLE ..."`.
_MIGRATIONS: dict[int, str] = {
    1: _SCHEMA_V1,
}


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
    conn.execute(
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
) -> list[dict[str, Any]]:
    """Recoveries for ``whoop_user_id``, oldest first.

    ``start``/``end`` (inclusive) filter on ``created_at`` when given, and
    are ignored (i.e. no filtering on that bound) when left as ``None``.
    Returns each record's raw payload exactly as it was written -- this
    store does no reshaping.
    """
    _require_user_id(whoop_user_id)
    rows = conn.execute(
        """
        SELECT raw_json FROM recoveries
        WHERE whoop_user_id = ?
          AND (? IS NULL OR created_at >= ?)
          AND (? IS NULL OR created_at <= ?)
        ORDER BY created_at
        """,
        (whoop_user_id, start, start, end, end),
    ).fetchall()
    return [json.loads(row[0]) for row in rows]


# -- sleeps ---------------------------------------------------------------


def upsert_sleep(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update one sleep, keyed on (whoop_user_id, id)."""
    score = record.get("score") or {}
    conn.execute(
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
) -> list[dict[str, Any]]:
    """Sleeps for ``whoop_user_id``, oldest first.

    ``start``/``end`` (inclusive) filter on the sleep's own ``start``
    timestamp when given.
    """
    _require_user_id(whoop_user_id)
    rows = conn.execute(
        """
        SELECT raw_json FROM sleeps
        WHERE whoop_user_id = ?
          AND (? IS NULL OR start >= ?)
          AND (? IS NULL OR start <= ?)
        ORDER BY start
        """,
        (whoop_user_id, start, start, end, end),
    ).fetchall()
    return [json.loads(row[0]) for row in rows]


# -- cycles ---------------------------------------------------------------


def upsert_cycle(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update one cycle, keyed on (whoop_user_id, id).

    A cycle's ``id`` is an integer in the v2 API; it is stored as TEXT like
    every other resource id (sqlite is dynamically typed regardless), so the
    primary key's column type is consistent across all four entity tables.
    """
    score = record.get("score") or {}
    conn.execute(
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
) -> list[dict[str, Any]]:
    """Cycles for ``whoop_user_id``, oldest first.

    ``start``/``end`` (inclusive) filter on the cycle's own ``start``
    timestamp when given.
    """
    _require_user_id(whoop_user_id)
    rows = conn.execute(
        """
        SELECT raw_json FROM cycles
        WHERE whoop_user_id = ?
          AND (? IS NULL OR start >= ?)
          AND (? IS NULL OR start <= ?)
        ORDER BY start
        """,
        (whoop_user_id, start, start, end, end),
    ).fetchall()
    return [json.loads(row[0]) for row in rows]


# -- workouts ---------------------------------------------------------------


def upsert_workout(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update one workout, keyed on (whoop_user_id, id)."""
    score = record.get("score") or {}
    conn.execute(
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
) -> list[dict[str, Any]]:
    """Workouts for ``whoop_user_id``, oldest first.

    ``start``/``end`` (inclusive) filter on the workout's own ``start``
    timestamp when given.
    """
    _require_user_id(whoop_user_id)
    rows = conn.execute(
        """
        SELECT raw_json FROM workouts
        WHERE whoop_user_id = ?
          AND (? IS NULL OR start >= ?)
          AND (? IS NULL OR start <= ?)
        ORDER BY start
        """,
        (whoop_user_id, start, start, end, end),
    ).fetchall()
    return [json.loads(row[0]) for row in rows]


# -- body measurements & profile ---------------------------------------------
#
# Neither has an id of its own in the WHOOP API -- one row per
# whoop_user_id, which is itself the primary key.


def upsert_body_measurement(
    conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]
) -> None:
    """Insert or update the one body-measurement row for ``whoop_user_id``."""
    conn.execute(
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
    row = conn.execute(
        "SELECT raw_json FROM body_measurements WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()
    return json.loads(row[0]) if row is not None else None


def upsert_profile(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update the one profile row for ``whoop_user_id``."""
    conn.execute(
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
    row = conn.execute(
        "SELECT raw_json FROM profiles WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchone()
    return json.loads(row[0]) if row is not None else None


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
    conn.execute(
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
    row = conn.execute(
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
