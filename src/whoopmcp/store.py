"""Persistent store for WHOOP records: schema, migrations, repository layer.

Plain ``sqlite3``, no ORM. Writes are upserts (records are mutable, e.g.
rescored recoveries); ``raw_json`` sits alongside extracted columns. Knows
nothing about HTTP/MCP -- callers decide when to read here vs. the live API.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NamedTuple

logger = logging.getLogger(__name__)

#: POSIX modes are advisory on Windows; mirrors ``auth.FileTokenStore``'s same-named constant.
_MODES_ENFORCED = os.name != "nt"

#: True once the Windows-permissions warning has been logged once per process.
_warned_about_unenforced_modes = False

#: Bump and append to ``_MIGRATIONS`` on schema change. Never edit a shipped migration.
CURRENT_SCHEMA_VERSION = 5

# -- schema ------------------------------------------------------------------
# Every entity table has raw_json (full payload), updated_at (write time,
# sync cursor for #15), deleted_at (reserved for #18, unused here).

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

#: Version 2 (#18): webhook_events table, keyed on trace_id for idempotent
#: delivery processing (a duplicate hits the PRIMARY KEY before any upsert)
#: and as a replay log. status is 'pending' (queued, mid-retry, or -- since
#: #66 -- not yet actionable because the member isn't linked), 'success', or
#: 'dead_letter'. Idempotent DDL (CREATE TABLE IF NOT EXISTS) -- safe to retry.
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

#: Version 3 (#29): principal_members (MCP principal -> whoop_user_id link,
#: written only by link_principal_to_member) and tool_call_audit (shape-locked
#: to no payload columns, see record_tool_call). issuer/subject default to ''
#: not NULL, since sqlite treats distinct NULLs as non-equal in a composite
#: key, which would let two no-subject principals both "successfully" insert.
#: Idempotent DDL -- safe to retry.
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

#: Version 4 (#19): webhook_delivery_state, one row per whoop_user_id tracking
#: last_delivered_at, so #31 can alert on silence relative to a user's own
#: baseline. Its own table (not folded into sync_state's already-doubled-up
#: key shape). record_webhook_delivery upserts it on every completed
#: delivery, never on the #66 not-yet-actionable path. Idempotent DDL --
#: safe to retry.
_SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS webhook_delivery_state (
    whoop_user_id INTEGER NOT NULL PRIMARY KEY,
    last_delivered_at TEXT NOT NULL
);
"""

#: Version 5 (#105): webhook_events.whoop_user_id -> NOT NULL (a NULL row was
#: invisible to export/erasure, which filter by whoop_user_id). No ALTER
#: COLUMN in sqlite, so this rebuilds via a second table, not ALTER TABLE...
#: RENAME TO (quotes the identifier, touches a temp db). NOT idempotent:
#: wrapped in BEGIN/COMMIT with DROP TABLE IF EXISTS up front for safe retry.
#: _migrate pre-flights and refuses on any NULL whoop_user_id row first.
_SCHEMA_V5 = """
BEGIN;

DROP TABLE IF EXISTS webhook_events_old;

CREATE TABLE webhook_events_old (
    trace_id TEXT NOT NULL PRIMARY KEY,
    whoop_user_id INTEGER,
    event_type TEXT NOT NULL,
    event_body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    processed_at TEXT
);

INSERT INTO webhook_events_old (
    trace_id, whoop_user_id, event_type, event_body, status,
    attempt_count, created_at, processed_at
)
SELECT trace_id, whoop_user_id, event_type, event_body, status,
       attempt_count, created_at, processed_at
FROM webhook_events;

DROP TABLE webhook_events;

CREATE TABLE webhook_events (
    trace_id TEXT NOT NULL PRIMARY KEY,
    whoop_user_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    event_body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    processed_at TEXT
);

INSERT INTO webhook_events (
    trace_id, whoop_user_id, event_type, event_body, status,
    attempt_count, created_at, processed_at
)
SELECT trace_id, whoop_user_id, event_type, event_body, status,
       attempt_count, created_at, processed_at
FROM webhook_events_old;

DROP TABLE webhook_events_old;

CREATE INDEX IF NOT EXISTS ix_webhook_events_status ON webhook_events (status);

COMMIT;
"""

#: Migration ladder keyed by version; applied when PRAGMA user_version is
#: below that key. Append new migrations as _MIGRATIONS[N] = "...".
_MIGRATIONS: dict[int, str] = {
    1: _SCHEMA_V1,
    2: _SCHEMA_V2,
    3: _SCHEMA_V3,
    4: _SCHEMA_V4,
    5: _SCHEMA_V5,
}

#: Tables _execute_scoped requires a whoop_user_id read on. Excludes
#: webhook_events (callers enforce the boundary themselves; still in
#: _ERASURE_TABLES since it holds member data) and principal_members/
#: tool_call_audit (identity/audit layer, not member data). Adding a
#: tenant-scoped table here without a matching test fails
#: tests/test_tenancy.py::test_tested_entity_tables_cover_every_tenant_scoped_table.
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

#: Every table member erasure (#32) must remove a row from: the tenant-scoped
#: tables plus webhook_events and tool_call_audit. Excludes principal_members,
#: erased separately by delete_principal_links_for_member (#30). Asserted
#: against the live schema's own table list by
#: tests/test_data_subject_rights.py::test_erasure_registry_covers_every_schema_table.
_ERASURE_TABLES: frozenset[str] = _TENANT_SCOPED_TABLES | frozenset(
    {"webhook_events", "tool_call_audit"}
)

#: Age column per _ERASURE_TABLES table, for enforce_retention. Not always
#: updated_at: sync_state uses last_run_at, webhook_events uses created_at
#: (never updated in place), tool_call_audit uses called_at.
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

#: Webhook resource name -> table it's stored in. Recoveries key on
#: cycle_id (this module's own convention); sleeps/workouts on their UUID.
_TABLE_BY_RESOURCE: dict[str, str] = {
    "recovery": "recoveries",
    "sleep": "sleeps",
    "workout": "workouts",
}


class UnscopedQueryError(RuntimeError):
    """A tenant-scoped query never read its ``whoop_user_id`` column.

    Raised by ``_execute_scoped``, the engine-level half of #29's enforcement.
    """


#: The one predicate shape that pins a statement to a single member:
#: ``whoop_user_id`` compared for equality against a bound parameter, after
#: the first top-level ``WHERE`` and at parenthesis depth zero, in a copy of
#: the statement with comments, string literals and quoted identifiers
#: stripped. See ``_statement_restricts_to_one_member`` for the stripping
#: and position check; this regex is only the fragment it searches for.
#:
#: A presence check, not a SQL parser (#99/#109 deliberately kept it that
#: way, for shapes no caller here exhibits). What it does and does not catch:
#:
#: * CAUGHT -- no equality on the column at all: ``!=``, ``>``, ``IS NOT
#:   NULL``, ``IN (?, ?)``, or the column merely in a select list (#99).
#: * CAUGHT -- equality against an interpolated literal (``= 42``); the
#:   ``?`` requirement is deliberate, since every real caller binds the id.
#: * CAUGHT, since #109 -- a fragment outside a predicate: a ``SET``
#:   assignment, a comment, or a string literal.
#: * CAUGHT, since #109 -- a subquery in ``SET`` supplying the fragment
#:   while the outer statement stays unfiltered.
#: * CAUGHT, since #129 -- the mirror image: a subquery or parenthesised
#:   group *after* the top-level ``WHERE`` supplying the fragment while the
#:   top-level predicate itself spans every member.
#: * CAUGHT, and a deliberate false positive -- a genuine restriction that
#:   sits inside parentheses is rejected too (no caller here writes that
#:   shape; failing closed is the survivable direction).
#: * NOT CAUGHT -- a matching fragment after the top-level ``WHERE`` that
#:   still widens its own reach, e.g. ``whoop_user_id = ? OR 1 = 1``.
#: * NOT CAUGHT -- *which* table the fragment applies to when a statement
#:   names two tenant-scoped tables; this check is per-statement, not per-table.
#: * CAUGHT, since #154 -- a compound statement where one top-level arm
#:   fails to restrict to the member while another arm carries the fragment.
#: * CAUGHT, since #131 -- a bracket- or backtick-quoted identifier with an
#:   unbalanced parenthesis, which used to desync the depth counter.
#:
#: The universal check (backed by sqlite's own authorizer) remains
#: load-bearing; this regex is the second layer. When this list changes,
#: change it in the same commit as the code and add the shape to
#: ``tests/test_tenancy.py``.
_MEMBER_EQUALITY_PREDICATE = re.compile(r"whoop_user_id\s*=\s*\?", re.IGNORECASE)

_TOP_LEVEL_WHERE = re.compile(r"\bWHERE\b", re.IGNORECASE)

#: sqlite's compound-SELECT operators, used to split a statement into arms
#: at depth zero (#154): each arm must restrict to the member independently,
#: since an arm with no WHERE at all spans its whole table.
_TOP_LEVEL_COMPOUND_OPERATOR = re.compile(
    r"\b(?:UNION\s+ALL|UNION|INTERSECT|EXCEPT)\b", re.IGNORECASE
)


def _statement_restricts_to_one_member(sql: str) -> bool:
    """Whether ``sql`` carries a ``whoop_user_id = ?`` predicate that actually
    restricts to one member -- not merely a matching fragment anywhere in the
    text (#109).

    Never modifies ``sql`` itself; searches a sanitised copy only.
    ``_execute_scoped`` always passes the original text to sqlite unchanged.

    Two refinements over a bare ``_MEMBER_EQUALITY_PREDICATE.search(sql)``:

    1. Six region kinds are stripped before searching, each replaced with a
       **space** (not deleted, since deleting would fuse tokens and could
       hide or forge a keyword/fragment match): ``--`` and ``/* */``
       comments, single/double-quoted string literals, and backtick-/
       bracket-quoted identifiers (doubled-quote escape honoured for the
       first three; brackets have no escape, per sqlite's own tokeniser).
    2. Every top-level (depth-zero) ``WHERE`` must be followed, before the
       next top-level ``WHERE``, by a fragment that itself sits at depth
       zero -- required per compound-statement *arm*, not per ``WHERE``,
       since an arm with no ``WHERE`` at all has no anchor to walk to and
       spans its whole table (#154). Three defects fixed this in stages:
       requiring the match after a ``WHERE`` at all (#109, catches a ``SET``
       fragment or a subquery-in-``SET``); requiring it at depth zero (#129,
       catches a parenthesised group after ``WHERE`` widening the reach);
       requiring every compound arm to have one (#154, catches a ``UNION``
       arm with no ``WHERE`` spanning its table).

    Still a presence check on text, not a parser -- see
    ``_MEMBER_EQUALITY_PREDICATE`` for what it does and does not catch.
    """
    # Every stripped region is replaced by a SPACE, never deleted. To sqlite a
    # comment and a quoted region are token *separators*, so deleting one fuses
    # the tokens it stood between, and fusion breaks both searches below, in
    # opposite directions:
    #
    # * It HIDES a keyword from the ``\b``-anchored searches (``WHERE``, the
    #   compound operators). ``UNION/**/ALL`` collapsed to ``UNIONALL`` and
    #   ``recoveries/**/UNION`` to ``recoveriesUNION``, so the arm split
    #   silently did not happen and an unfiltered arm was accepted --
    #   reproduced as ``SELECT raw_json FROM recoveries EXCEPT/**/SELECT
    #   raw_json FROM recoveries WHERE whoop_user_id = ?`` returning exactly
    #   the *other* members' rows. It can also hide a legitimate ``WHERE``
    #   (``FROM recoveries/**/WHERE ...``), which is a false rejection.
    # * It FORGES a match for ``_MEMBER_EQUALITY_PREDICATE``, which has no word
    #   boundaries: ``WHERE whoop_user/**/_id = ?`` fused into a predicate the
    #   statement never wrote. Not exploitable on its own -- such a statement
    #   never reads ``whoop_user_id``, so the universal authorizer check
    #   rejects it -- but the layer was forgeable, not merely suppressible.
    #
    # A separator can only split a token, never join two, so it closes both:
    # it cannot spell any character of a keyword or of the thirteen-character
    # fragment token, and a keyword it reveals is bordered by separators on
    # both sides, which is exactly when sqlite tokenises it as that keyword.
    chars: list[str] = []
    i, n = 0, len(sql)
    while i < n:
        if sql[i : i + 2] == "--":
            newline = sql.find("\n", i)
            chars.append(" ")
            i = n if newline == -1 else newline
            continue
        if sql[i : i + 2] == "/*":
            end = sql.find("*/", i + 2)
            chars.append(" ")
            i = n if end == -1 else end + 2
            continue
        ch = sql[i]
        if ch in ("'", '"', "`"):
            # Backticks double to escape, exactly as ' and " do -- sqlite
            # accepts ``a``b`` as the single identifier a`b (measured, #131).
            j = i + 1
            while j < n:
                if sql[j] == ch:
                    if sql[j : j + 2] == ch * 2:
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            else:
                j = n
            chars.append(" ")
            i = j
            continue
        if ch == "[":
            # Bracket-quoted identifiers have NO escape mechanism: the first
            # ``]`` ends the identifier, and sqlite rejects ``[a]]b]`` as an
            # unrecognised token rather than reading a doubled ``]`` (measured,
            # #131). So this cannot share the doubling branch above -- doing so
            # would consume past the real terminator and swallow live SQL.
            end = sql.find("]", i + 1)
            chars.append(" ")
            i = n if end == -1 else end + 1
            continue
        chars.append(ch)
        i += 1
    sanitized = "".join(chars)

    # Depth is computed once, for every index, rather than re-walked per
    # search. #109 tracked it incrementally to find one anchor and #129 added
    # a second incremental walk for the fragment; #154 needs a fragment check
    # per anchor, and a third hand-rolled counter would be the bug waiting to
    # happen. With this, "is this token at depth zero" is an index lookup.
    depths: list[int] = []
    depth = 0
    for ch in sanitized:
        if ch == "(":
            depth += 1
            depths.append(depth)
        elif ch == ")":
            depths.append(depth)
            depth -= 1
        else:
            depths.append(depth)

    # Split into top-level compound ARMS first, and require every arm to
    # restrict to the member (#154).
    #
    # The obvious formulation -- "every top-level WHERE must carry a fragment"
    # -- is the wrong invariant, and I wrote it before catching this: an arm
    # with no ``WHERE`` at all has no anchor, so a WHERE-counting loop never
    # sees it. ``SELECT raw_json FROM recoveries UNION SELECT raw_json FROM
    # recoveries WHERE whoop_user_id = ?`` has exactly one top-level ``WHERE``,
    # which does carry a fragment, and returns every member's payload. The
    # thing that must be true is a property of each arm, not of each ``WHERE``.
    arm_bounds = [0]
    for match in _TOP_LEVEL_COMPOUND_OPERATOR.finditer(sanitized):
        if depths[match.start()] == 0:
            arm_bounds.append(match.start())
            arm_bounds.append(match.end())
    arm_bounds.append(len(sanitized))
    arms = [(arm_bounds[i], arm_bounds[i + 1]) for i in range(0, len(arm_bounds) - 1, 2)]

    for arm_start, arm_end in arms:
        anchors = [
            m
            for m in _TOP_LEVEL_WHERE.finditer(sanitized, arm_start, arm_end)
            if depths[m.start()] == 0
        ]
        # No top-level WHERE in this arm means the arm spans the whole table.
        if not anchors:
            return False
        # And every top-level WHERE it does have must carry its own depth-zero
        # fragment, so a second WHERE cannot widen what the first pinned.
        for index, anchor in enumerate(anchors):
            segment_start = anchor.end()
            segment_end = anchors[index + 1].start() if index + 1 < len(anchors) else arm_end
            if not any(
                depths[found.start()] == 0
                for found in _MEMBER_EQUALITY_PREDICATE.finditer(
                    sanitized, segment_start, segment_end
                )
            ):
                return False
    return True


class _TenancyFindings(NamedTuple):
    """What sqlite's authorizer saw after the universal read-check passed.

    Returned by ``_execute_with_tenancy_authorizer`` so its two callers --
    ``_execute_scoped`` and ``_execute_all_tenant_sweep`` -- can each decide
    what else, if anything, to require of the statement.
    """

    #: The executed statement's cursor.
    cursor: sqlite3.Cursor
    #: Whether any tenant-scoped table had its ``whoop_user_id`` column read.
    reads_member_column: bool
    #: Tenant-scoped tables UPDATEd/DELETEd without also being INSERTed into
    #: -- must be pinned to one member (#99 D1). Excluding INSERTed tables
    #: exempts upserts (sqlite reports them as both SQLITE_INSERT and
    #: SQLITE_UPDATE, with no WHERE clause to carry a predicate).
    needs_member_predicate: frozenset[str]


class UnrollbackableStatementError(RuntimeError):
    """Rejected before execution because a post-execution rejection couldn't
    be undone by rollback. Not an ``UnscopedQueryError`` -- tenancy scoping
    isn't the problem; see ``_require_rollbackable_statement``.
    """


#: Leading keywords Python's sqlite3 auto-opens a transaction for -- the only
#: ones a ``conn.rollback()`` can undo (measured, not from docs). A CTE-prefixed
#: write (``WITH ... DELETE``) leaves ``in_transaction`` False and isn't undone.
_LEADING_KEYWORDS_THE_DRIVER_CAN_ROLL_BACK = frozenset(
    {"SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE"}
)

_LEADING_KEYWORD = re.compile(r"[A-Za-z]+")


def _leading_keyword(sql: str) -> str:
    """``sql``'s first keyword, upper-cased, skipping whitespace/comments.
    ``""`` if there is none.

    Comments are skipped so ``/* c */ WITH ...`` isn't bypassed. Nothing
    else is skipped deliberately: a BOM or other non-alphabetic leading byte
    yields ``""``, which ``_require_rollbackable_statement`` refuses -- a
    BOM-prefixed ``DELETE`` would otherwise run in autocommit and survive a
    rollback. Does not reuse ``_statement_restricts_to_one_member``'s
    sanitiser, which strips quoted regions too (wrong here: a leading quoted
    identifier isn't a keyword).
    """
    index, length = 0, len(sql)
    while index < length:
        if sql[index].isspace():
            index += 1
            continue
        if sql[index : index + 2] == "--":
            newline = sql.find("\n", index)
            index = length if newline == -1 else newline + 1
            continue
        if sql[index : index + 2] == "/*":
            end = sql.find("*/", index + 2)
            index = length if end == -1 else end + 2
            continue
        break
    match = _LEADING_KEYWORD.match(sql, index)
    return match.group(0).upper() if match else ""


def _require_rollbackable_statement(sql: str) -> None:
    """Fail closed on a statement whose mutation a rollback could not undo.

    Python's ``sqlite3`` only auto-opens a transaction for keywords in
    ``_LEADING_KEYWORDS_THE_DRIVER_CAN_ROLL_BACK``; anything else runs in
    autocommit, making ``_execute_scoped``'s rollback-before-raise a no-op
    (#155: a CTE-prefixed ``DELETE`` bypassed the check and stayed deleted).

    Deliberately over-rejects read-only CTEs/``EXPLAIN``/``VALUES`` too,
    since telling them from writes needs a parser (see
    ``test_read_only_cte_is_over_rejected_deliberately``). Also refuses a
    UTF-8 BOM prefix, which sqlite skips but the driver's DML check doesn't
    (``test_bom_prefixed_write_is_rejected``).

    Assumes ``open_store``'s default ``isolation_level``; autocommit mode
    would defeat this guard.
    """
    keyword = _leading_keyword(sql)
    if keyword not in _LEADING_KEYWORDS_THE_DRIVER_CAN_ROLL_BACK:
        raise UnrollbackableStatementError(
            f"statement leads with {keyword or '<no keyword>'!r}, outside the set Python's "
            "sqlite3 auto-opens a transaction for, so a tenancy check that rejected it could "
            "not undo any mutation it made. Statements outside that set are refused whether "
            "or not they actually write, because telling those apart needs a SQL parser -- see "
            f"_require_rollbackable_statement: {sql!r}"
        )


def _execute_with_tenancy_authorizer(
    conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]
) -> _TenancyFindings:
    """Execute one statement under sqlite's authorizer, enforcing the
    **universal** check: any tenant-scoped table touched (read or written)
    must have had its own ``whoop_user_id`` column read, or
    ``UnscopedQueryError`` is raised after rolling back.

    Shared machinery behind ``_execute_scoped`` and
    ``_execute_all_tenant_sweep`` -- lives here once so the check cannot
    drift between them
    (``test_only_the_two_named_guard_entry_points_execute_sql`` pins that).

    Rolls back before raising, since a non-``SELECT`` statement has already
    run by the time the authorizer's findings can be inspected; see
    ``_execute_scoped`` for why that is safe. Calls
    ``_require_rollbackable_statement`` first (#155) so that precondition
    always holds.
    """
    _require_rollbackable_statement(sql)
    reads: dict[str, set[str]] = {}
    inserted: set[str] = set()
    mutated: set[str] = set()

    def authorizer(
        action: int, arg1: str | None, arg2: str | None, arg3: str | None, arg4: str | None
    ) -> int:
        del arg3, arg4
        if action == sqlite3.SQLITE_READ and arg1 in _TENANT_SCOPED_TABLES:
            reads.setdefault(arg1, set()).add(arg2 or "")
        elif action == sqlite3.SQLITE_INSERT and arg1 in _TENANT_SCOPED_TABLES:
            inserted.add(arg1)
        elif (
            action in (sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE)
            and arg1 in _TENANT_SCOPED_TABLES
        ):
            mutated.add(arg1)
        return sqlite3.SQLITE_OK

    conn.set_authorizer(authorizer)
    try:
        cursor = conn.execute(sql, params)
    finally:
        conn.set_authorizer(None)

    touched = inserted | mutated | set(reads)
    unscoped = {table for table in touched if "whoop_user_id" not in reads.get(table, set())}
    if unscoped:
        conn.rollback()
        raise UnscopedQueryError(
            f"query touches tenant-scoped table(s) {sorted(unscoped)} without "
            f"reading whoop_user_id: {sql!r}"
        )

    return _TenancyFindings(
        cursor=cursor,
        reads_member_column=any("whoop_user_id" in columns for columns in reads.values()),
        needs_member_predicate=frozenset(mutated - inserted),
    )


def _execute_scoped(
    conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()
) -> sqlite3.Cursor:
    """Run ``sql`` against ``conn``, failing closed if it touches a
    tenant-scoped table without reading its ``whoop_user_id`` column, or --
    for a ``SELECT``, ``UPDATE`` or ``DELETE`` -- without a
    ``whoop_user_id = ?`` equality predicate pinning it to one member.

    The way every function in this module touches ``conn``, except
    ``_execute_all_tenant_sweep`` (``enforce_retention``'s all-members sweep).
    Both execute through ``_execute_with_tenancy_authorizer``, so neither can
    skip the universal check
    (``test_store_has_no_unwrapped_sqlite_execute_outside_scoped_wrapper``).

    Two checks, in order: (1) the universal column-read check, backed by
    sqlite's own authorizer; (2) the member-equality-predicate check
    (``_statement_restricts_to_one_member``), since reading the column isn't
    the same as restricting to one member (``!=``, ``>``, ``IS NOT NULL`` all
    read it while spanning every row). Applied to ``SELECT`` (#29) and, since
    #99, to ``UPDATE``/``DELETE``.

    ``INSERT`` is exempt from check 2, permanently: it has no ``WHERE``
    clause to carry a predicate, since it supplies ``whoop_user_id`` as a
    *value* -- every write here is an ``INSERT ... ON CONFLICT ... DO
    UPDATE`` upsert, which sqlite reports as both ``SQLITE_INSERT`` and
    ``SQLITE_UPDATE`` on the same table.

    A non-``SELECT`` statement has already fully executed by the time a
    violation is detected, so ``conn.rollback()`` runs before raising, to
    undo a mutation that would otherwise sit pending for an unrelated later
    ``conn.commit()`` to persist. The erasure path (#104) and
    ``enforce_retention`` both rely on this rollback covering a batch of
    several statements under one commit.
    """
    found = _execute_with_tenancy_authorizer(conn, sql, params)

    # #99: an UPDATE/DELETE that reads whoop_user_id may still span every member.
    if found.needs_member_predicate and not _statement_restricts_to_one_member(sql):
        conn.rollback()
        raise UnscopedQueryError(
            f"statement mutates tenant-scoped table(s) "
            f"{sorted(found.needs_member_predicate)} but does not restrict itself to one "
            f"member with whoop_user_id = ?: {sql!r}"
        )

    # A SELECT that reads whoop_user_id must restrict with it, not just mention it.
    if (
        "SELECT" in sql.upper()
        and found.reads_member_column
        and not _statement_restricts_to_one_member(sql)
    ):
        conn.rollback()
        raise UnscopedQueryError(
            f"query touches tenant-scoped table(s) with whoop_user_id but "
            f"does not filter with whoop_user_id = ?: {sql!r}"
        )

    return found.cursor


def _execute_all_tenant_sweep(
    conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()
) -> sqlite3.Cursor:
    """Run one deliberately all-members statement: like ``_execute_scoped``
    but without requiring a ``whoop_user_id = ?`` equality predicate.

    The universal read-check still applies unchanged, via the same
    ``_execute_with_tenancy_authorizer`` machinery
    (``test_all_tenant_sweep_path_still_enforces_the_universal_check``).

    Exactly one caller: ``enforce_retention``, whose per-table
    ``DELETE ... WHERE whoop_user_id IS NOT NULL AND <age> < ?`` is honestly
    all-members (``test_all_tenant_sweep_path_has_exactly_one_caller``).

    A named function rather than an ``_execute_scoped(...,
    allow_all_tenants=True)`` flag on purpose (#99 D2): a bypass that is a
    distinct, greppable name is harder to reach for than a keyword at every
    call site.
    """
    return _execute_with_tenancy_authorizer(conn, sql, params).cursor


def _is_special_sqlite_path(path: str | Path) -> bool:
    """True for a sqlite ``path`` that isn't a real file: the ``":memory:"``
    sentinel or a URI form (``file:...``). Only a ``str`` can be one of
    these -- a ``Path`` is never a URI here (#68 D4).

    Keyed on the ``file:`` prefix alone, not on a ``?`` query string, since
    ``?`` is a legal POSIX filename character.
    """
    if not isinstance(path, str):
        return False
    return path == ":memory:" or path.startswith("file:")


def _warn_once_about_unenforced_modes(path: Path) -> None:
    """Log once per process that ``path``'s permissions aren't enforced here.
    Mirrors ``auth.FileTokenStore``'s identically-shaped one-time warning."""
    global _warned_about_unenforced_modes
    if _warned_about_unenforced_modes:
        return
    _warned_about_unenforced_modes = True
    logger.warning(
        "%s cannot be protected by file permissions on Windows; the database "
        "-- every linked member's profile, body measurements and raw "
        "payloads -- is readable by any process running as you. See "
        "PRIVACY.md.",
        path,
    )


def _secure_db_path(path: Path) -> None:
    """Best-effort: make ``path``'s parent 0700 (creating it if absent) and
    ``path`` itself 0600, tightening either if looser.

    Protects sqlite sidecars too (e.g. ``-journal``) by locking the parent
    directory, since a sidecar is unreachable if another user can't traverse
    into it. Never raises -- every step is wrapped so an unchangeable mode is
    logged, not fatal.

    **No protection on Windows**: it uses ACLs, not POSIX modes, so
    ``os.chmod``/``touch(mode=...)`` are attempted but ignored by the OS.
    """
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        logger.debug("could not create state directory %s: %s", parent, exc)

    try:
        if parent.is_dir():
            current = stat.S_IMODE(parent.stat().st_mode)
            if current & 0o077:
                os.chmod(parent, current & ~0o077)
    except OSError as exc:
        logger.debug("could not tighten permissions on %s: %s", parent, exc)

    try:
        if not path.exists():
            path.touch(mode=0o600)
        elif path.is_file():
            current = stat.S_IMODE(path.stat().st_mode)
            if current & 0o077:
                os.chmod(path, current & ~0o077)
    except OSError as exc:
        logger.debug("could not secure permissions on %s: %s", path, exc)

    if not _MODES_ENFORCED:
        _warn_once_about_unenforced_modes(path)


def open_store(path: str | Path) -> sqlite3.Connection:
    """Open the sqlite store at ``path``, applying any pending migrations.

    ``path`` may be ``":memory:"`` or a sqlite URI -- neither is touched by
    the permissions step (#68 D4; see ``_is_special_sqlite_path``). A real
    path's parent/file are secured to 0700/0600 before ``sqlite3.connect``
    touches them (#68; see ``_secure_db_path``, PRIVACY.md). No
    ``check_same_thread`` override: this connection is used single-threaded.

    If ``_migrate`` raises, the connection opened here is closed before the
    exception propagates.
    """
    if not _is_special_sqlite_path(path):
        _secure_db_path(Path(path))
    conn = sqlite3.connect(path)
    try:
        _migrate(conn)
    except Exception:
        conn.close()
        raise
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring ``conn``'s schema up to ``CURRENT_SCHEMA_VERSION``, in order.

    Versions 1-4 use idempotent DDL (``IF NOT EXISTS``), safe to re-run if a
    prior attempt got partway through. Version 5's script wraps its own
    ``BEGIN``/``COMMIT`` since it isn't idempotent (a table rebuild); that is
    a real transaction sqlite rolls back on a mid-script failure, distinct
    from ``executescript`` committing any already-pending transaction first.

    Version 5's NULL pre-flight (#105 D2) runs here in Python, immediately
    before its DDL, so a bad row is reported before the rebuild starts rather
    than surfacing as a bare ``IntegrityError`` partway through.
    """
    current: int = conn.execute("PRAGMA user_version").fetchone()[0]
    for version in range(current + 1, CURRENT_SCHEMA_VERSION + 1):
        if version == 5:
            (null_count,) = conn.execute(
                "SELECT COUNT(*) FROM webhook_events WHERE whoop_user_id IS NULL"
            ).fetchone()
            if null_count:
                raise ValueError(
                    "Cannot migrate webhook_events.whoop_user_id to NOT "
                    f"NULL: {null_count} row(s) still have a NULL "
                    "whoop_user_id. Resolve or remove those rows before "
                    "retrying (see issue #105)."
                )
        conn.executescript(_MIGRATIONS[version])
        conn.execute(f"PRAGMA user_version = {version}")
    conn.commit()


# -- shared helpers -----------------------------------------------------------


def _require_user_id(whoop_user_id: int | None) -> None:
    """Guard the read-function contract (#8): fail loudly on an explicit
    ``None`` that bypassed static typing, rather than silently scoping a
    query to no one's data.
    """
    if whoop_user_id is None:
        raise TypeError("whoop_user_id is required and must not be None")


def _now() -> str:
    """Current UTC time as the ISO 8601 string stored in ``updated_at``."""
    return datetime.now(UTC).isoformat()


# -- recoveries ---------------------------------------------------------------


def upsert_recovery(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update one recovery, keyed on (whoop_user_id, cycle_id).

    Recoveries have no independent id in the v2 API -- addressed by their
    cycle, so ``resource_id`` is ``record["cycle_id"]``. Extracted score
    columns fall back to ``NULL`` when WHOOP hasn't scored the cycle yet.
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

    Args:
        start/end: inclusive filter on ``created_at``; ``None`` is unbounded.
        include_deleted: include soft-deleted rows (default excludes them; a
            soft delete is not erasure, so e.g. ``export_member_data`` wants
            ``True``).
        limit/offset: store-backed pagination; ``offset`` is ignored unless
            ``limit`` is given.
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
    live recoveries, or ``(None, None)`` if none.

    Uses ``created_at`` (activity date), never ``updated_at`` (sync
    bookkeeping) -- see #16.
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


def get_latest_recovery(conn: sqlite3.Connection, whoop_user_id: int) -> dict[str, Any] | None:
    """The most recently created live recovery for ``whoop_user_id``, or
    ``None``. See ``get_recoveries`` for why ``created_at``, not ``updated_at``.
    """
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        """
        SELECT raw_json FROM recoveries
        WHERE whoop_user_id = ? AND deleted_at IS NULL
        ORDER BY created_at DESC LIMIT 1
        """,
        (whoop_user_id,),
    ).fetchone()
    return json.loads(row[0]) if row is not None else None


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
    """Sleeps for ``whoop_user_id``, oldest first, filtered on ``start``.
    See ``get_recoveries`` for ``include_deleted``/``limit``/``offset``.
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
    """The (earliest ``start``, latest ``end``) for ``whoop_user_id``'s live
    sleeps, or ``(None, None)`` if none. Uses the full span, not
    ``MAX(start)``, since the latest sleep may still be ongoing.
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


def get_sleep_cycle_id(conn: sqlite3.Connection, whoop_user_id: int, sleep_id: str) -> int | None:
    """The ``cycle_id`` on a locally-stored sleep record, if any.

    Used by ``webhook_processor`` to resolve ``recovery.deleted`` without a
    fetch, from an already-synced sleep record (#15).
    """
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        "SELECT raw_json FROM sleeps WHERE whoop_user_id = ? AND resource_id = ?",
        (whoop_user_id, sleep_id),
    ).fetchone()
    if row is None:
        return None
    cycle_id = json.loads(row[0]).get("cycle_id")
    return int(cycle_id) if cycle_id is not None else None


def get_latest_sleep(conn: sqlite3.Connection, whoop_user_id: int) -> dict[str, Any] | None:
    """The most recently started live sleep for ``whoop_user_id``, or
    ``None`` if none held.
    """
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        """
        SELECT raw_json FROM sleeps
        WHERE whoop_user_id = ? AND deleted_at IS NULL
        ORDER BY start DESC LIMIT 1
        """,
        (whoop_user_id,),
    ).fetchone()
    return json.loads(row[0]) if row is not None else None


# -- cycles ---------------------------------------------------------------


def upsert_cycle(conn: sqlite3.Connection, whoop_user_id: int, record: dict[str, Any]) -> None:
    """Insert or update one cycle, keyed on (whoop_user_id, id).

    Stored as TEXT like every other resource id, for column-type consistency
    across the four entity tables (sqlite is dynamically typed regardless).
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
    """Cycles for ``whoop_user_id``, oldest first, filtered on ``start``.
    See ``get_recoveries`` for ``include_deleted``/``limit``/``offset``.
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
    """The (earliest ``start``, latest ``end``) for ``whoop_user_id``'s live
    cycles, or ``(None, None)`` if none.
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


def get_latest_cycle(conn: sqlite3.Connection, whoop_user_id: int) -> dict[str, Any] | None:
    """The most recently started live cycle for ``whoop_user_id``, or
    ``None`` if none held.
    """
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        """
        SELECT raw_json FROM cycles
        WHERE whoop_user_id = ? AND deleted_at IS NULL
        ORDER BY start DESC LIMIT 1
        """,
        (whoop_user_id,),
    ).fetchone()
    return json.loads(row[0]) if row is not None else None


# -- metric time series (#20) -------------------------------------------------
# One generic aggregator: table/value_column/date_column are interpolated,
# not bound, so they must come from the fixed allow-lists below, never raw
# caller input (defense in depth on top of server.py's own resolution).

#: Tables ``get_metric_series`` is allowed to aggregate over.
_METRIC_TIMESERIES_TABLES: frozenset[str] = frozenset({"recoveries", "sleeps", "cycles"})

#: Value columns ``get_metric_series`` is allowed to aggregate, per table.
_METRIC_TIMESERIES_COLUMNS: dict[str, frozenset[str]] = {
    "recoveries": frozenset({"recovery_score", "hrv_rmssd_milli", "resting_heart_rate"}),
    "sleeps": frozenset({"sleep_performance_percentage", "sleep_efficiency_percentage"}),
    "cycles": frozenset({"strain"}),
}

#: Activity-date column to bucket by, per table -- created_at for
#: recoveries, start for sleeps/cycles, never updated_at (sync bookkeeping).
_METRIC_TIMESERIES_DATE_COLUMNS: dict[str, str] = {
    "recoveries": "created_at",
    "sleeps": "start",
    "cycles": "start",
}

#: SQLite bucket-boundary expression per granularity, keyed against
#: {date_column} at format time. day: calendar date verbatim. month: the
#: 1st of the record's calendar month (a real date, not "YYYY-MM"). week:
#: the Monday starting the record's week (strftime %w gives 0=Sun..6=Sat;
#: (w+6)%7 = days since the last Monday) -- a real date, not a week number,
#: since this is read by a model, not a spreadsheet.
_BUCKET_EXPR: dict[str, str] = {
    "day": "strftime('%Y-%m-%d', {date_column})",
    "week": (
        "date({date_column}, '-' || "
        "((CAST(strftime('%w', {date_column}) AS INTEGER) + 6) % 7) || ' days')"
    ),
    "month": "strftime('%Y-%m-01', {date_column})",
}


def get_metric_series(
    conn: sqlite3.Connection,
    whoop_user_id: int,
    *,
    table: str,
    value_column: str,
    date_column: str,
    granularity: str,
    start: str | None,
    end: str | None,
    limit: int,
) -> list[tuple[str, float]]:
    """One metric's ``[(bucket_date, mean_value), ...]`` series, aggregated
    in SQL at ``granularity`` ("day"/"week"/"month"), ordered by date,
    filtered to ``score_state = 'SCORED'``, and gap-free (an empty bucket
    produces no row, never a zero). Multiple records in one bucket are
    averaged, not summed.

    ``table``/``value_column``/``date_column`` must come from this module's
    own allow-lists -- never raw caller input, since they're interpolated.

    Over-fetches by one row (pass ``limit + 1``) so the caller can detect
    truncation without a second query (matches server.py's
    ``_fetch_collection`` convention).
    """
    _require_user_id(whoop_user_id)
    if table not in _METRIC_TIMESERIES_TABLES:
        raise ValueError(f"unknown metric-timeseries table: {table!r}")
    if value_column not in _METRIC_TIMESERIES_COLUMNS[table]:
        raise ValueError(f"unknown metric-timeseries column {value_column!r} for table {table!r}")
    if date_column not in (_METRIC_TIMESERIES_DATE_COLUMNS[table],):
        raise ValueError(
            f"unknown metric-timeseries date column {date_column!r} for table {table!r}"
        )
    if granularity not in _BUCKET_EXPR:
        raise ValueError(f"unknown granularity: {granularity!r}")

    bucket_expr = _BUCKET_EXPR[granularity].format(date_column=date_column)
    sql = f"""
        SELECT {bucket_expr} AS bucket, AVG({value_column}) AS value
        FROM {table}
        WHERE whoop_user_id = ?
          AND deleted_at IS NULL
          AND score_state = 'SCORED'
          AND {value_column} IS NOT NULL
          AND {date_column} IS NOT NULL
          AND (? IS NULL OR {date_column} >= ?)
          AND (? IS NULL OR {date_column} <= ?)
        GROUP BY bucket
        ORDER BY bucket
        LIMIT ?
    """  # noqa: S608 -- fixed allow-lists only, never caller input  # nosec B608
    rows = _execute_scoped(conn, sql, (whoop_user_id, start, start, end, end, limit)).fetchall()
    return [(row[0], row[1]) for row in rows]


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
    """Workouts for ``whoop_user_id``, oldest first, filtered on ``start``.
    See ``get_recoveries`` for ``include_deleted``/``limit``/``offset``.
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
    """The (earliest ``start``, latest ``end``) for ``whoop_user_id``'s live
    workouts, or ``(None, None)`` if none.
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


# -- webhook-driven cross-entity accessors (#18/#19) --------------------------
# Backs webhook_processor.py's event processing; #67 moved this SQL here so
# it runs through _execute_scoped too. (get_sleep_cycle_id, the third
# relocated read, lives above with this module's other sleep accessors.)


def get_resource_updated_at(
    conn: sqlite3.Connection, resource: str, whoop_user_id: int, resource_id: str
) -> str | None:
    """The stored record's own ``updated_at`` (from ``raw_json``), if a row
    for ``(whoop_user_id, resource_id)`` exists in ``resource``'s table.

    WHOOP's own ``updated_at``, not this store's bookkeeping column of the
    same name (contrast ``get_profile_updated_at``) -- only WHOOP's tells
    ``webhook_processor`` whether an incoming record is actually newer.
    """
    table = _TABLE_BY_RESOURCE[resource]
    _require_user_id(whoop_user_id)
    row = _execute_scoped(
        conn,
        f"SELECT raw_json FROM {table} WHERE whoop_user_id = ? AND resource_id = ?",  # noqa: S608 -- fixed internal literal, never user input  # nosec B608
        (whoop_user_id, resource_id),
    ).fetchone()
    if row is None:
        return None
    updated_at = json.loads(row[0]).get("updated_at")
    return str(updated_at) if updated_at is not None else None


def set_deleted_at(
    conn: sqlite3.Connection, resource: str, whoop_user_id: int, resource_id: str
) -> None:
    """Soft-delete one row: set its ``deleted_at`` to now.

    Public (unlike most helpers here) because #19's ``reconciliation.py``
    reuses it directly; also re-exported as
    ``webhook_processor.set_deleted_at`` for the ``*.deleted`` webhook path.
    """
    table = _TABLE_BY_RESOURCE[resource]
    _execute_scoped(
        conn,
        f"UPDATE {table} SET deleted_at = ? WHERE whoop_user_id = ? AND resource_id = ?",  # noqa: S608 -- fixed internal literal, never user input  # nosec B608
        (_now(), whoop_user_id, resource_id),
    )
    conn.commit()


# -- body measurements & profile ---------------------------------------------
# Neither has its own id in the WHOOP API -- one row per whoop_user_id,
# which is itself the primary key.


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
    """When ``whoop_user_id``'s body-measurement row was last written, or
    ``None`` if never synced -- the freshness signal #16's
    ``whoop_data_coverage`` reports for this singleton entity."""
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
    """When ``whoop_user_id``'s profile row was last written, or ``None`` if
    never synced -- see ``get_body_measurement_updated_at`` for the
    analogous singleton."""
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
# One row per whoop_user_id, upserted on every completed delivery, so #31
# can alert on a member gone quiet relative to their own baseline.


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
# Never upserted: a row is inserted once per trace_id (the PRIMARY KEY
# enforces idempotency), then only updated in place as processing proceeds.


def insert_webhook_event(
    conn: sqlite3.Connection,
    trace_id: str,
    whoop_user_id: int,
    event_type: str,
    event_body: str,
) -> None:
    """Record a newly-seen webhook event as pending, before processing.

    Written first and unconditionally, so the replay log is complete even
    if processing later fails. Raises ``sqlite3.IntegrityError`` if
    ``trace_id`` already exists; the caller checks with
    ``get_webhook_event`` first, so this should not surface in practice.
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
    # Fixed internal column names, never user input.
    row = _execute_scoped(
        conn,
        f"SELECT {', '.join(_WEBHOOK_EVENT_COLUMNS)} FROM webhook_events WHERE trace_id = ?",  # noqa: S608 -- fixed internal tuple, never user input  # nosec B608
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
    Terminal -- never retried again; sits for an operator to inspect.
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
# The MCP-principal <-> WHOOP-member join, written only by
# link_principal_to_member (called only from server.whoop_complete_login).
# Neither table is in _TENANT_SCOPED_TABLES: they ARE the identity layer.


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

    Idempotent upsert. ``issuer``/``subject`` of ``None`` are stored as
    ``''`` -- see ``_SCHEMA_V3`` for why NULL is unsafe here.
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

    Used by the ``delete-member`` CLI subcommand as a confirmation guard
    before ``delete_principal_links_for_member``.
    """
    cursor = _execute_scoped(
        conn,
        "SELECT 1 FROM principal_members WHERE whoop_user_id = ? LIMIT 1",
        (whoop_user_id,),
    )
    return cursor.fetchone() is not None


def all_linked_whoop_user_ids(conn: sqlite3.Connection) -> set[int]:
    """Every distinct WHOOP member id ``principal_members`` has ever linked.

    Used by ``export-member`` (#32) to check it's safe to attach the one
    locally-stored token's scopes to an export -- if this returns more than
    one id, no local record says which one the current token belongs to.
    """
    cursor = _execute_scoped(conn, "SELECT DISTINCT whoop_user_id FROM principal_members")
    return {row[0] for row in cursor.fetchall()}


def _delete_principal_links_for_member_impl(conn: sqlite3.Connection, whoop_user_id: int) -> None:
    """Delete principal_members rows for ``whoop_user_id`` without
    committing, so #104's erase_member_and_links_atomically can batch it.
    """
    _execute_scoped(
        conn,
        "DELETE FROM principal_members WHERE whoop_user_id = ?",
        (whoop_user_id,),
    )


def delete_principal_links_for_member(conn: sqlite3.Connection, whoop_user_id: int) -> None:
    """Remove every ``principal_members`` row linked to ``whoop_user_id``.

    The identity half of member deletion (#30), paired with
    ``auth.Authenticator.revoke_and_forget`` by the ``delete-member`` CLI
    subcommand. Health data, webhook events and audit rows are untouched --
    that's #32's separate erasure scope.
    """
    _delete_principal_links_for_member_impl(conn, whoop_user_id)
    conn.commit()


def record_tool_call(conn: sqlite3.Connection, whoop_user_id: int, tool_name: str) -> None:
    """Audit-log one tool call: identity and tool name only, never a payload.

    ``tool_call_audit``'s schema (see ``_SCHEMA_V3``) makes that a shape
    guarantee, not a redaction step that could have a bug.
    """
    _execute_scoped(
        conn,
        "INSERT INTO tool_call_audit (whoop_user_id, tool_name, called_at) VALUES (?, ?, ?)",
        (whoop_user_id, tool_name, _now()),
    )
    conn.commit()


# -- data subject rights (#32): export, erasure, retention -------------------
# Operator-only CLI plumbing (__main__.py); none of this is or may become
# an MCP tool -- an LLM-driven tool must never trigger irreversible
# export/erasure for any member.


def get_all_sync_state_for_member(
    conn: sqlite3.Connection, whoop_user_id: int
) -> list[dict[str, Any]]:
    """Every recorded sync outcome for ``whoop_user_id``, one dict per entity
    -- unlike ``get_sync_state``, which reads one named entity, this reads
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
    """Every ``webhook_events`` row for ``whoop_user_id`` (same columns as
    ``get_webhook_event``, but every row for a member), for
    ``export_member_data``."""
    _require_user_id(whoop_user_id)
    rows = _execute_scoped(
        conn,
        # Fixed internal column names, never user input.
        f"SELECT {', '.join(_WEBHOOK_EVENT_COLUMNS)} FROM webhook_events "  # noqa: S608 -- fixed internal tuple, never user input  # nosec B608
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
        f"SELECT {', '.join(_TOOL_CALL_AUDIT_COLUMNS)} FROM tool_call_audit "  # noqa: S608 -- fixed internal tuple, never user input  # nosec B608
        f"WHERE whoop_user_id = ?",
        (whoop_user_id,),
    ).fetchall()
    return [dict(zip(_TOOL_CALL_AUDIT_COLUMNS, row, strict=True)) for row in rows]


def get_principal_links_for_member(
    conn: sqlite3.Connection, whoop_user_id: int
) -> list[dict[str, Any]]:
    """Every MCP principal linked (currently or previously) to
    ``whoop_user_id``, with ``linked_at`` -- for consent transparency.
    """
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
    """Everything this store holds about ``whoop_user_id``, as one portable
    JSON document -- the export half of #32.

    Built from existing member-scoped read functions, so every field is
    already enforced member-scoped by ``_execute_scoped``.
    ``include_deleted=True`` on the collection getters, since a soft-delete
    is not erasure.
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


def _erase_member_data_impl(conn: sqlite3.Connection, whoop_user_id: int) -> None:
    """Delete all _ERASURE_TABLES rows for ``whoop_user_id`` without
    committing, so #104's erase_member_and_links_atomically can batch it.
    """
    _require_user_id(whoop_user_id)
    for table in sorted(_ERASURE_TABLES):
        _execute_scoped(
            conn,
            # Fixed internal frozenset, never user input.
            f"DELETE FROM {table} WHERE whoop_user_id = ?",  # noqa: S608 -- fixed internal frozenset, never user input  # nosec B608
            (whoop_user_id,),
        )


def erase_member_data(conn: sqlite3.Connection, whoop_user_id: int) -> None:
    """Permanently ``DELETE`` every row for ``whoop_user_id`` across
    ``_ERASURE_TABLES`` -- the erasure half of #32. A real removal, not the
    soft-delete marker the ``*.deleted`` webhook path sets.

    ``principal_members`` is deliberately excluded -- its own erasure is
    ``delete_principal_links_for_member`` (#30), composed separately by the
    ``erase-member`` CLI subcommand.
    """
    _erase_member_data_impl(conn, whoop_user_id)
    conn.commit()


def erase_member_and_links_atomically(conn: sqlite3.Connection, whoop_user_id: int) -> None:
    """#104: atomically erase both health data and the principal link for
    ``whoop_user_id`` in one transaction, so neither is left half-erased.

    Used by ``erase-member`` instead of calling the two deletes separately.
    ``conn.in_transaction`` is ``False`` on return either way (D5, allows a
    following ``VACUUM``): any exception is caught, rolled back, re-raised.
    """
    try:
        _erase_member_data_impl(conn, whoop_user_id)
        _delete_principal_links_for_member_impl(conn, whoop_user_id)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def enforce_retention(
    conn: sqlite3.Connection, *, max_age_days: int, now: datetime | None = None
) -> dict[str, int]:
    """Delete every row in ``_ERASURE_TABLES`` older than ``max_age_days``
    (per ``_RETENTION_TIMESTAMP_COLUMNS``), relative to ``now`` (real time if
    omitted) -- the retention *job* #32 asks for. Returns rows removed per
    table.

    A cross-tenant sweep, not a per-member loop, since retention applies to
    every member at once -- and, for tenant-scoped tables, an id-first loop
    isn't even available (``_execute_scoped``'s SELECT check refuses an
    unfiltered read of ``whoop_user_id``).

    The only caller of ``_execute_all_tenant_sweep`` (since #99); the two
    non-tenant-scoped tables keep going through ``_execute_scoped``
    unchanged. Deletes exactly what it deleted before #99 -- only the check
    faced changed, not the rows matched
    (``test_enforce_retention_deletes_exactly_what_it_deleted_before``).
    """
    as_of = now if now is not None else datetime.now(UTC)
    cutoff = (as_of - timedelta(days=max_age_days)).isoformat()

    counts: dict[str, int] = {}
    for table in sorted(_ERASURE_TABLES):
        column = _RETENTION_TIMESTAMP_COLUMNS[table]
        if table in _TENANT_SCOPED_TABLES:
            sql = f"DELETE FROM {table} WHERE whoop_user_id IS NOT NULL AND {column} < ?"  # noqa: S608 -- fixed internal mappings, never user input  # nosec B608
            cursor = _execute_all_tenant_sweep(conn, sql, (cutoff,))
        else:
            sql = f"DELETE FROM {table} WHERE {column} < ?"  # noqa: S608 -- fixed internal mappings, never user input  # nosec B608
            cursor = _execute_scoped(conn, sql, (cutoff,))
        counts[table] = cursor.rowcount
    conn.commit()
    return counts


def compact_database(conn: sqlite3.Connection) -> None:
    """#100: compact the database file with ``VACUUM`` to reclaim and
    overwrite freed pages left by deleted rows (``secure_delete`` is 0 by
    design -- see PRIVACY.md).

    Can't go through ``_execute_scoped``/``_execute_all_tenant_sweep``
    (``VACUUM`` has no ``WHERE`` and touches every table). Called only from
    ``__main__._erase_member`` after an erasure commits. A failed ``VACUUM``
    (e.g. full disk) must not be reported as erasure failure, since the
    deletes are already committed; the caller catches
    ``sqlite3.OperationalError`` and returns non-zero.
    """
    conn.execute("VACUUM")
