"""Periodic full reconciliation: the webhook backstop (#19). Diffs a fresh
listing (recoveries/sleeps/workouts) against the store, soft-deleting records
the listing omits -- catches drops that updated_at-based sync can't see.
CLI-only; BACKFILL priority; margin-widens fresh-fetch start past the window.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from whoopmcp.client import MAX_PAGE_SIZE, Page, RequestPriority, WhoopClient
from whoopmcp.config import Config
from whoopmcp.store import (
    get_cycles,
    get_recoveries,
    get_sleeps,
    get_workouts,
    upsert_cycle,
    upsert_recovery,
    upsert_sleep,
    upsert_workout,
)
from whoopmcp.webhook_processor import set_deleted_at

#: Reconciliation window in days; comfortably exceeds any cron schedule while
#: keeping a full re-listing cheap.
DEFAULT_WINDOW_DAYS = 30

#: How many locally-held records one run may close (soft-delete).
#:
#: Distinguishes a real dropped-deletion hole (a handful of records) from an
#: incomplete/truncated fetch (which would wipe most of the window) -- a
#: soft-delete is permanent, nothing ever clears `deleted_at`. Applies to what
#: would be CLOSED, not to whether the listing was empty (#175, #197).
CLOSE_LIMIT_PER_RUN = 5

#: Extra days subtracted from the fresh fetch's own `start` bound (never the
#: local window) -- WHOOP's `/v2/recovery` filters on the related sleep's
#: timeframe, not the recovery's own `created_at`, so without this margin a
#: recovery just inside the window can be falsely reported missing and
#: permanently soft-deleted. 3 days is a generous multiple of the
#: sleep->recovery creation gap.
_FRESH_FETCH_MARGIN_DAYS = 3


class ReconciliationDisabledError(RuntimeError):
    """Reconciliation was invoked without the persistent store enabled."""


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    """One collection's reconciliation outcome: fetched count and holes closed."""

    resource: str
    fetched: int
    #: Records whose stored copy was replaced by a newer fresh `updated_at` (#185).
    updated: int
    closed: int
    #: Why nothing closed, when it was a refusal not "nothing to close" (#175,
    #: #197); None on a normal run.
    withheld: str | None = None


@dataclass(frozen=True, slots=True)
class _ReconcileSpec:
    """One collection reconciliation walks.

    `entity` is the plural table/result-key name; `resource` is the singular
    form `set_deleted_at` expects. `list_method` names (not binds) the
    `WhoopClient` method since the client only exists at run time.
    """

    entity: str
    resource: str
    list_method: str
    get_local: Callable[..., list[dict[str, Any]]]
    id_field: str
    #: Writes a fresh record back over the stored one, for update detection.
    upsert: Callable[..., Any]
    #: Whether a locally-live id missing from the fresh listing is soft-deleted.
    #: False for cycles (#185): corrections still apply, but soft-delete is
    #: irreversible and cycle listing bounds are unvalidated, so cycles get
    #: updates without being enrolled in deletion.
    soft_deletes: bool = True


#: The four entities sync covers, for update detection (#185); deletion still
#: applies only to #18's webhook set (see `soft_deletes`). WHOOP has no
#: query-by-modification-time, so re-listing is the only way to see a rescore.
_RECONCILE_SPECS: tuple[_ReconcileSpec, ...] = (
    _ReconcileSpec(
        "recoveries", "recovery", "list_recoveries", get_recoveries, "cycle_id", upsert_recovery
    ),
    _ReconcileSpec("sleeps", "sleep", "list_sleeps", get_sleeps, "id", upsert_sleep),
    _ReconcileSpec("workouts", "workout", "list_workouts", get_workouts, "id", upsert_workout),
    _ReconcileSpec(
        "cycles", "cycle", "list_cycles", get_cycles, "id", upsert_cycle, soft_deletes=False
    ),
)


def _window_start_str(window_days: int, now: datetime) -> str:
    """Window lower bound, formatted like stored WHOOP timestamps so string
    comparison against `start`/`created_at` columns is meaningful."""
    window_start = now - timedelta(days=window_days)
    return window_start.strftime("%Y-%m-%dT%H:%M:%SZ")


async def _reconcile_entity(
    conn: sqlite3.Connection,
    client: WhoopClient,
    whoop_user_id: int,
    spec: _ReconcileSpec,
    window_start: str,
    fresh_fetch_start: str,
) -> ReconciliationResult:
    """Diff a fresh listing of `spec.entity` against the store for
    `whoop_user_id` in `[window_start, now)`, soft-deleting ids the fresh
    listing no longer mentions.

    `fresh_fetch_start` is earlier than `window_start` by
    `_FRESH_FETCH_MARGIN_DAYS` (see that constant); the local comparison itself
    still uses unwidened `window_start`.
    """
    fetch = getattr(client, spec.list_method)

    # Read local set BEFORE the fresh fetch (#175): reading after would let a
    # row written mid-fetch (webhook processor / concurrent sync) appear only
    # in local_ids and get soft-deleted at birth. Missing one cycle's deletion
    # is recoverable; a wrong soft-delete is not.
    local_records = spec.get_local(conn, whoop_user_id, start=window_start, include_deleted=False)
    local_ids = {str(record[spec.id_field]) for record in local_records}
    # Stored updated_at per id, so a fresh record can be recognised as a
    # correction rather than merely present (#185).
    local_updated_at = {
        str(record[spec.id_field]): record.get("updated_at") for record in local_records
    }

    fresh_ids: set[str] = set()
    fetched = 0
    updated = 0
    cursor: str | None = None
    while True:
        page: Page = await fetch(
            start=fresh_fetch_start,
            limit=MAX_PAGE_SIZE,
            next_token=cursor,
            priority=RequestPriority.BACKFILL,
        )
        for record in page.records:
            resource_id = str(record[spec.id_field])
            fresh_ids.add(resource_id)
            fetched += 1
            # Only re-listing can see a rescore: sync's forward walk sends its
            # mark as `start`, which WHOOP applies to occurrence time, not
            # modification time. Strictly-newer + already-held only: a new id
            # is sync/backfill's job, not this one's.
            stored = local_updated_at.get(resource_id)
            incoming = record.get("updated_at")
            if stored is not None and incoming is not None and str(incoming) > str(stored):
                spec.upsert(conn, whoop_user_id, record)
                updated += 1
        cursor = page.next_token
        if cursor is None:
            break

    # An incomplete listing (empty body, or truncated pagination via a missing
    # next_token) looks identical to a genuinely empty one (#175, #197).
    # Soft-delete is permanent -- nothing clears `deleted_at` -- so this fails
    # closed rather than trust an ambiguous response.
    if not spec.soft_deletes:
        # Cycles: corrected above, never closed (see soft_deletes).
        return ReconciliationResult(
            resource=spec.entity, fetched=fetched, updated=updated, closed=0
        )

    # Limit applies to what would be CLOSED (see CLOSE_LIMIT_PER_RUN); closing
    # nothing rather than the first few, since a partial close picks survivors
    # arbitrarily.
    missing = local_ids - fresh_ids
    if len(missing) > CLOSE_LIMIT_PER_RUN:
        return ReconciliationResult(
            resource=spec.entity,
            fetched=fetched,
            updated=updated,
            closed=0,
            withheld=(
                f"the fresh listing omits {len(missing)} of {len(local_ids)} locally-live "
                f"{spec.entity} for the window (more than {CLOSE_LIMIT_PER_RUN}); declining to "
                "close them, since a truncated or empty listing and a failed one look "
                "identical here and a soft-delete cannot be undone"
            ),
        )

    for resource_id in missing:
        set_deleted_at(conn, spec.resource, whoop_user_id, resource_id)

    return ReconciliationResult(
        resource=spec.entity, fetched=fetched, updated=updated, closed=len(missing)
    )


async def run_reconciliation(
    conn: sqlite3.Connection,
    client: WhoopClient,
    config: Config,
    whoop_user_id: int,
    *,
    window_days: int = DEFAULT_WINDOW_DAYS,
    now: datetime | None = None,
) -> dict[str, ReconciliationResult]:
    """Reconcile recoveries/sleeps/workouts against a fresh WHOOP listing of
    the last `window_days` days, closing dropped-deletion holes (#19).

    Raises `ReconciliationDisabledError` before touching network/store unless
    `config.cache_enabled` is set (PRIVACY.md: persistent store is off by
    default).
    """
    if not config.cache_enabled:
        raise ReconciliationDisabledError(
            "reconciliation requires the persistent store, which is off by "
            "default; set WHOOPMCP_CACHE=true to enable it (see PRIVACY.md)"
        )
    as_of = now if now is not None else datetime.now(UTC)
    window_start = _window_start_str(window_days, as_of)
    fresh_fetch_start = _window_start_str(window_days + _FRESH_FETCH_MARGIN_DAYS, as_of)

    results: dict[str, ReconciliationResult] = {}
    for spec in _RECONCILE_SPECS:
        results[spec.entity] = await _reconcile_entity(
            conn, client, whoop_user_id, spec, window_start, fresh_fetch_start
        )
    return results
