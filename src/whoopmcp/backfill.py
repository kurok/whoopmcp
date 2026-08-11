"""Resumable, throttled history import (#14).

A newly authorised user has years of history and none of it locally.
``run_backfill`` walks every paginated collection (recoveries, sleeps,
cycles, workouts) newest-first -- WHOOP's v2 collection endpoints return
records descending by start when unbounded, so a plain ``nextToken`` walk
already delivers the last week first while the rest is still arriving --
upserts every record through the store, and checkpoints the API's own
opaque cursor into ``sync_state`` only after a page has fully committed.
An interrupted run resumes exactly where it stopped and never re-requests
an already-committed page.

Every page fetch is issued at ``RequestPriority.BACKFILL``, the low-priority
class #11 built and nothing consumed until now: the import never starves an
interactive question, and it can never bypass the rate limiter because it
only ever talks to WHOOP through ``WhoopClient``'s own list methods.

The whole thing is gated on ``Config.cache_enabled`` -- PRIVACY.md promises
the persistent store is "off by default; only written if you set
WHOOPMCP_CACHE=true", and backfill is the first bulk writer that would
otherwise break that promise.

Deliberately CLI-only (``whoopmcp backfill``, see ``__main__.py``), never an
MCP tool -- a tool call that blocks for a minute is a broken tool call, and
#30/#32 already established that operator-only capabilities live on the CLI.
Progress needs no mechanism of its own: ``sync_state``'s (cursor,
last_run_at, outcome) rows are the queryable progress surface, and record
enough for #16 to later say what range the store holds.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from whoopmcp.client import MAX_PAGE_SIZE, Page, RequestPriority, WhoopClient
from whoopmcp.config import Config
from whoopmcp.store import (
    get_sync_state,
    set_sync_state,
    upsert_cycle,
    upsert_recovery,
    upsert_sleep,
    upsert_workout,
)


class BackfillDisabledError(RuntimeError):
    """Backfill was invoked without the persistent store enabled."""


@dataclass(frozen=True, slots=True)
class _EntitySpec:
    """One paginated collection the backfill walks.

    ``name`` doubles as the ``sync_state`` entity key and is the store's own
    table name, so #15/#16 can consume the same rows without translation.
    ``list_method`` names the ``WhoopClient`` method rather than binding it,
    since the client instance only exists at run time.
    """

    name: str
    list_method: str
    upsert: Callable[[sqlite3.Connection, int, dict[str, Any]], None]


#: The four paginated collections, in the order they are walked. The
#: profile/body-measurement singletons are deliberately absent: they are not
#: paginated collections, and the profile is already written at login.
BACKFILL_ENTITIES: tuple[_EntitySpec, ...] = (
    _EntitySpec("recoveries", "list_recoveries", upsert_recovery),
    _EntitySpec("sleeps", "list_sleeps", upsert_sleep),
    _EntitySpec("cycles", "list_cycles", upsert_cycle),
    _EntitySpec("workouts", "list_workouts", upsert_workout),
)


def _now() -> str:
    """Current UTC time, same ISO 8601 format ``store._now`` writes."""
    return datetime.now(UTC).isoformat()


async def run_backfill(
    conn: sqlite3.Connection,
    client: WhoopClient,
    config: Config,
    whoop_user_id: int,
) -> dict[str, int]:
    """Import ``whoop_user_id``'s full history into the persistent store.

    Returns the number of records imported per entity. Raises
    ``BackfillDisabledError`` -- before touching the network or the store --
    unless ``config.cache_enabled`` is set. Any fetch or upsert failure
    propagates without advancing the interrupted entity's checkpoint, so a
    re-run resumes from the last fully-committed page.
    """
    if not config.cache_enabled:
        raise BackfillDisabledError(
            "backfill requires the persistent store, which is off by default; "
            "set WHOOPMCP_CACHE=true to enable it (see PRIVACY.md)"
        )
    imported: dict[str, int] = {}
    for spec in BACKFILL_ENTITIES:
        imported[spec.name] = await _backfill_entity(
            conn, client, whoop_user_id, spec, config.backfill_floor_date
        )
    return imported


async def _backfill_entity(
    conn: sqlite3.Connection,
    client: WhoopClient,
    whoop_user_id: int,
    spec: _EntitySpec,
    floor: str | None,
) -> int:
    """Walk one collection to exhaustion (or ``floor``), checkpointing.

    Per page: fetch (at BACKFILL priority, resuming from any stored cursor),
    upsert every record (idempotent, each self-committing through the store),
    and only then advance ``sync_state`` to the page's own ``next_token``.
    A failure mid-page leaves the previous checkpoint in place -- the
    interrupted page is re-fetched and re-upserted on the next run, which is
    safe precisely because every write is an upsert.
    """
    state = get_sync_state(conn, whoop_user_id, spec.name)
    if state is not None and state["outcome"] == "complete":
        # One-shot import: refreshing already-completed history is #15's job.
        return 0
    cursor: str | None = state["cursor"] if state is not None else None

    fetch = getattr(client, spec.list_method)
    imported = 0
    while True:
        page: Page = await fetch(
            start=floor,
            limit=MAX_PAGE_SIZE,
            next_token=cursor,
            priority=RequestPriority.BACKFILL,
        )
        for record in page.records:
            spec.upsert(conn, whoop_user_id, record)
            imported += 1
        cursor = page.next_token
        set_sync_state(
            conn,
            whoop_user_id,
            spec.name,
            cursor=cursor,
            last_run_at=_now(),
            outcome="complete" if cursor is None else "in_progress",
        )
        if cursor is None:
            return imported
