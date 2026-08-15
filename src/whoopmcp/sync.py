"""Incremental sync from an `updated_at` high-water mark (#15). Walks
backfill's four collections forward from each one's own mark (not
`created_at` -- records get rescored), under its own `sync_state` key
namespace (`f"{name}:incremental"`) so it never collides with backfill's row.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from whoopmcp.backfill import BACKFILL_ENTITIES, _EntitySpec
from whoopmcp.client import MAX_PAGE_SIZE, Page, RequestPriority, WhoopAPIError, WhoopClient
from whoopmcp.config import Config
from whoopmcp.store import get_sync_state, set_sync_state

#: Overlap subtracted from the prior high-water mark before each request --
#: exact-boundary comparison can drop a record to clock skew; idempotent
#: upsert makes re-fetching a minute of already-seen records free.
_OVERLAP_SECONDS = 60.0

#: `since` bound for a first-ever sync (no prior mark): idempotent upsert
#: makes a full-history walk safe, and a concrete epoch value (not `None`)
#: lets an interrupted first run resume with the exact same bound.
_EPOCH_SINCE = "1970-01-01T00:00:00+00:00"


class SyncDisabledError(RuntimeError):
    """Incremental sync was invoked without the persistent store enabled."""


@dataclass(frozen=True, slots=True)
class EntitySyncResult:
    """One entity's outcome from a single `run_sync` call."""

    #: Records upserted this call (0 in steady state).
    count: int
    #: High-water `updated_at` mark on record, or None if never synced.
    high_water_mark: str | None
    #: Records stored but refused as mark candidates -- unparseable or
    #: implausibly future-dated (#186); distinguishes a refusal from a clean run.
    skipped_implausible: int = 0
    #: Why this entity didn't sync, or None if it did (#187); cursor is untouched.
    error: str | None = None
    #: Whether a stale stored resume token was dropped and re-walked (#201).
    dropped_stale_cursor: bool = False


def _incremental_entity_key(name: str) -> str:
    """The `sync_state` key this module owns for collection `name` --
    deliberately distinct from the bare name, which `backfill.py` owns."""
    return f"{name}:incremental"


def _now() -> str:
    """Current UTC time, the same ISO 8601 shape ``store._now``/``backfill._now`` write."""
    return datetime.now(UTC).isoformat()


#: How far ahead of local time an `updated_at` may sit and still advance the
#: high-water mark. Some skew is normal (independent clocks); 5 min is wide
#: enough to allow it but tight enough that a bogus far-future value (#186)
#: can't poison the mark -- costs a few minutes of progress, not everything.
_MAX_CLOCK_SKEW_SECONDS = 300


def _is_plausible_mark(value: str, *, now: datetime) -> bool:
    """Whether `value` may advance the high-water mark.

    Fails if unparseable (guarded, never raises) or implausibly future-dated --
    a poisoned mark would make every later run request a future window forever.
    A refused record is still stored; only its claim on the cursor is denied.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed <= now + timedelta(seconds=_MAX_CLOCK_SKEW_SECONDS)


def _usable_resume_mark(mark: str, *, now: datetime) -> str | None:
    """`mark` if usable, else None -- the read-side recovery half of #186.

    Discarding (not clamping to now) a poisoned mark on read is what lets an
    already-poisoned installation heal: `None` re-walks from `_EPOCH_SINCE`,
    lossless since upserts are idempotent. Clamping to now would silently skip
    records that arrived while the mark was wrong.
    """
    if _is_plausible_mark(mark, now=now):
        return mark
    return None


def _apply_overlap(high_water_mark: str, overlap_seconds: float) -> str:
    """`high_water_mark` shifted back by `overlap_seconds`, same ISO 8601 shape.

    `fromisoformat` accepts both WHOOP's trailing `Z` and this store's `+00:00`
    (Python 3.11+), so either stored shape round-trips correctly.
    """
    parsed = datetime.fromisoformat(high_water_mark)
    return (parsed - timedelta(seconds=overlap_seconds)).isoformat()


async def run_sync(
    conn: sqlite3.Connection,
    client: WhoopClient,
    config: Config,
    whoop_user_id: int,
) -> dict[str, EntitySyncResult]:
    """Sync recoveries, sleeps, cycles and workouts forward.

    Raises `SyncDisabledError` before touching network/store unless
    `config.cache_enabled` is set. A fetch/upsert failure propagates without
    advancing that entity's mark, so a re-run resumes from the last committed
    page.
    """
    if not config.cache_enabled:
        raise SyncDisabledError(
            "incremental sync requires the persistent store, which is off by default; "
            "set WHOOPMCP_CACHE=true to enable it (see PRIVACY.md)"
        )
    results: dict[str, EntitySyncResult] = {}
    for spec in BACKFILL_ENTITIES:
        try:
            results[spec.name] = await _sync_entity(conn, client, whoop_user_id, spec)
        except Exception as exc:
            # Isolated per entity (#187): one failing must not deny sync to
            # entities after it in the list. Broad on purpose -- an unlisted
            # failure mode must not take down healthy entities either.
            # `CancelledError` is a BaseException and still propagates: a
            # cancelled run is not a partial success.
            results[spec.name] = EntitySyncResult(
                count=0, high_water_mark=None, error=f"{type(exc).__name__}: {exc}"
            )
    return results


async def _sync_entity(
    conn: sqlite3.Connection,
    client: WhoopClient,
    whoop_user_id: int,
    spec: _EntitySpec,
    *,
    overlap_seconds: float = _OVERLAP_SECONDS,
) -> EntitySyncResult:
    """Walk one collection forward from its high-water `updated_at` mark.

    Per page: fetch, upsert, track max observed `updated_at`, then commit
    `sync_state` (JSON blob mid-walk, bare ISO mark once exhausted). A failure
    mid-page leaves the prior checkpoint in place, so it is re-fetched next run.
    """
    key = _incremental_entity_key(spec.name)
    state = get_sync_state(conn, whoop_user_id, key)
    # One clock reading for the whole run, so all plausibility checks use the
    # same `now`.
    now = datetime.now(UTC)

    if state is not None and state["outcome"] == "in_progress":
        # Resume verbatim: same `since`, max `updated_at` already committed.
        # `fallback_mark` != `high_water_seen`: an empty-pages-so-far run has
        # `high_water_seen == None` mid-run, so `previous_mark` (this run's own
        # starting mark) is carried in the cursor to avoid regressing to None.
        resume = json.loads(state["cursor"])
        since: str | None = resume["since"]
        next_token: str | None = resume["next_token"]
        high_water_seen: str | None = resume["high_water_seen"]
        fallback_mark: str | None = resume["previous_mark"]
        # An in_progress row can be poisoned too (#186); clamp here too or a
        # resumed run re-persists the poison for another cycle.
        if since is not None and not _is_plausible_mark(since, now=now):
            since = _EPOCH_SINCE
        if high_water_seen is not None and not _is_plausible_mark(high_water_seen, now=now):
            high_water_seen = None
        if fallback_mark is not None:
            fallback_mark = _usable_resume_mark(fallback_mark, now=now)
    else:
        previous_mark = state["cursor"] if state is not None else None
        if previous_mark is not None:
            # Heal a poisoned cursor already on disk (#186) before use.
            previous_mark = _usable_resume_mark(previous_mark, now=now)
        since = (
            _apply_overlap(previous_mark, overlap_seconds)
            if previous_mark is not None
            else _EPOCH_SINCE
        )
        next_token = None
        high_water_seen = None
        # A no-op run must not regress the stored mark to None.
        fallback_mark = previous_mark

    fetch = getattr(client, spec.list_method)
    count = 0
    skipped_implausible = 0
    dropped_stale_cursor = False
    # True only for the first fetch of a resumed run (the STORED token); later
    # tokens are minted by WHOOP this run and keep #187's retry semantics.
    token_is_stored_resume = next_token is not None
    while True:
        try:
            page: Page = await fetch(
                start=since,
                limit=MAX_PAGE_SIZE,
                next_token=next_token,
                priority=RequestPriority.INTERACTIVE,
            )
        except WhoopAPIError as exc:
            # Cursor-recovery half of #201 (counterpart to #186's mark
            # recovery): a stored resume token WHOOP now 4xxs on would
            # otherwise wedge this entity forever with no way to clear it.
            # Drop it and re-walk from `since` (lossless: upserts are
            # idempotent). A 5xx is not a verdict on the token -- still raised.
            if token_is_stored_resume and 400 <= exc.status < 500:
                token_is_stored_resume = False
                next_token = None
                dropped_stale_cursor = True
                continue
            raise
        token_is_stored_resume = False
        for record in page.records:
            spec.upsert(conn, whoop_user_id, record)
            count += 1
            updated_at = record.get("updated_at")
            if updated_at is not None:
                updated_at = str(updated_at)
                # Checked after upsert: the record is kept regardless, only its
                # cursor claim is refused. String-max vs parsed-plausibility can
                # pick different records on format mismatch, but only ever a
                # chronologically earlier one -- the mark can lag, never overshoot.
                if not _is_plausible_mark(updated_at, now=now):
                    skipped_implausible += 1
                elif high_water_seen is None or updated_at > high_water_seen:
                    high_water_seen = updated_at
        next_token = page.next_token
        if next_token is not None:
            set_sync_state(
                conn,
                whoop_user_id,
                key,
                cursor=json.dumps(
                    {
                        "since": since,
                        "next_token": next_token,
                        "high_water_seen": high_water_seen,
                        "previous_mark": fallback_mark,
                    }
                ),
                last_run_at=_now(),
                outcome="in_progress",
            )
            continue
        final_mark = high_water_seen if high_water_seen is not None else fallback_mark
        set_sync_state(
            conn, whoop_user_id, key, cursor=final_mark, last_run_at=_now(), outcome="complete"
        )
        return EntitySyncResult(
            count=count,
            high_water_mark=final_mark,
            skipped_implausible=skipped_implausible,
            dropped_stale_cursor=dropped_stale_cursor,
        )
