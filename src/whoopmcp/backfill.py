"""Resumable, throttled history import (#14).

Walks collections newest-first, checkpointing ``sync_state`` only after a
page fully commits (retries never redo a committed page). Gated on
``cache_enabled``; CLI-only, never an MCP tool (blocking calls are broken).
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

    ``name`` is also the ``sync_state`` key and store table name (shared with
    #15/#16). ``list_method`` names the client method since the client only
    exists at run time.
    """

    name: str
    list_method: str
    upsert: Callable[[sqlite3.Connection, int, dict[str, Any]], None]


#: The four paginated collections, walked in this order. Profile/body-
#: measurement are excluded: not paginated, and profile is written at login.
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

    Returns records imported per entity. Raises ``BackfillDisabledError``
    before any I/O unless ``cache_enabled`` is set. A failure mid-entity
    leaves its checkpoint unadvanced, so a re-run resumes from the last
    committed page.
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

    Per page: fetch (BACKFILL priority, resuming from stored cursor), upsert
    every record, then advance ``sync_state``. A failure mid-page leaves the
    prior checkpoint in place; safe to retry since every write is an upsert.
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
