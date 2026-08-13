"""Incremental sync from an ``updated_at`` high-water mark (#15).

Once #14's backfill has a user's full history, keeping it current should
cost almost nothing. ``run_sync`` walks the same four paginated collections
backfill does (recoveries, sleeps, cycles, workouts) -- reusing
``backfill.BACKFILL_ENTITIES`` rather than redefining an identical spec --
but forward from each collection's own high-water ``updated_at`` mark instead
of from the beginning of history. In steady state that costs exactly one
request per collection: the page WHOOP returns is empty, ``next_token`` is
``None``, and nothing is written.

``updated_at``, deliberately not ``created_at``: recoveries and sleeps are
rescored after the fact, and a ``created_at`` cursor would silently miss
every correction -- see the issue's own Notes.

**Coexistence with #14's backfill.** ``sync_state`` (``store.py``) is already
owned by backfill: its row, keyed on the bare entity name (e.g.
``"recoveries"``), holds WHOOP's own opaque ``nextToken`` as ``cursor`` while
``outcome == "in_progress"``, and ``None``/``outcome == "complete"`` once a
one-shot import finishes. This module's progress is a different shape
entirely -- a JSON blob (``since``/``next_token``/``high_water_seen``/
``previous_mark``) mid-run, a bare ISO-8601 high-water mark once complete --
and must never be written to, or read from, that same row: doing
so would have backfill resume a stalled import using sync's high-water mark
as if it were WHOOP's cursor, or have sync treat backfill's terminal
``cursor=None``/``outcome="complete"`` as "nothing synced yet". The fix is a
distinct entity-key namespace, ``_incremental_entity_key`` (``f"{name}:incremental"``,
e.g. ``"recoveries:incremental"``) -- zero schema change, since
``get_sync_state``/``set_sync_state`` already key purely on the free-form
``entity`` TEXT column. ``backfill.py`` is untouched by this module entirely.

Every page fetch runs at ``RequestPriority.INTERACTIVE`` (the default): unlike
backfill, a sync run is short (bounded by "what changed recently", not "all
of history") and is either triggered by a user waiting on ``whoop_sync`` or
would, once a scheduler exists (there is none yet -- #35), be a routine
foreground refresh rather than a background bulk import. There is no strong
reason found to prefer ``RequestPriority.BACKFILL`` here.

Gated on ``Config.cache_enabled`` exactly like ``backfill.BackfillDisabledError``:
PRIVACY.md promises the persistent store is off by default, and this module
is the second bulk writer (after backfill) that would otherwise break that
promise. Unlike backfill, ``whoop_sync`` (the MCP tool wrapper in
``server.py``) is sanctioned for the tool surface -- it is non-destructive,
upserts only -- so its wrapper catches ``SyncDisabledError`` and returns a
plain, non-error tool result rather than letting it propagate.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from whoopmcp.backfill import BACKFILL_ENTITIES, _EntitySpec
from whoopmcp.client import MAX_PAGE_SIZE, Page, RequestPriority, WhoopClient
from whoopmcp.config import Config
from whoopmcp.store import get_sync_state, set_sync_state

#: Overlap margin subtracted from the previous high-water mark before every
#: request -- exact-boundary comparisons eventually drop a record to clock
#: skew (the issue's own Notes), and upsert idempotency makes re-fetching a
#: minute's worth of already-seen records free to absorb.
_OVERLAP_SECONDS = 60.0

#: The concrete ``since`` bound a first-ever sync (no prior high-water mark,
#: no in-progress resume) records and requests with. "Walk full history" --
#: the resolved answer for a never-synced entity, since idempotent upsert
#: makes doing so safe even without backfill having run first -- still needs
#: a real value here, not a bare ``None``: an interrupted first run must
#: resume with the exact same ``since`` its first page used (see the module
#: docstring's cursor shape), and an epoch-old lower bound is functionally
#: unbounded against any real WHOOP record while staying a concrete,
#: round-trippable string.
_EPOCH_SINCE = "1970-01-01T00:00:00+00:00"


class SyncDisabledError(RuntimeError):
    """Incremental sync was invoked without the persistent store enabled."""


@dataclass(frozen=True, slots=True)
class EntitySyncResult:
    """One entity's outcome from a single ``run_sync`` call."""

    #: Records upserted during this call (0 in the steady-state case).
    count: int
    #: The high-water ``updated_at`` mark now on record for this entity, or
    #: ``None`` if nothing has ever been synced for it.
    high_water_mark: str | None
    #: Records stored but refused as mark candidates -- unparseable, or dated
    #: implausibly far ahead (#186). Reported because a run that refused
    #: something must not read as a clean one: both otherwise show the same
    #: ``count`` and the same unchanged cursor.
    skipped_implausible: int = 0


def _incremental_entity_key(name: str) -> str:
    """The ``sync_state`` entity key this module owns for collection ``name``.

    Deliberately distinct from the bare entity name (``name`` itself), which
    ``backfill.py`` owns -- see this module's own docstring for why the two
    must never collide.
    """
    return f"{name}:incremental"


def _now() -> str:
    """Current UTC time, the same ISO 8601 shape ``store._now``/``backfill._now`` write."""
    return datetime.now(UTC).isoformat()


#: How far ahead of local time a record's ``updated_at`` may sit and still be
#: trusted to advance the high-water mark.
#:
#: Some skew is normal -- WHOOP's clock and this host's are independent, and an
#: NTP-synced pair is within seconds -- so the bound cannot be "not after now"
#: without rejecting perfectly good records. Five minutes is far outside any
#: real skew while being far inside any value that could strand the cursor: a
#: mark five minutes ahead costs at most those few minutes of forward progress
#: on the next run, whereas a mark set to 2099 costs everything, forever (#186).
#:
#: The number is a judgement, not a derivation. Raising it widens the window in
#: which a bogus timestamp can still poison the mark; lowering it risks refusing
#: legitimate records on a host whose clock drifts.
_MAX_CLOCK_SKEW_SECONDS = 300


def _is_plausible_mark(value: str, *, now: datetime) -> bool:
    """Whether ``value`` may advance the high-water mark.

    Two ways to fail. It may not parse at all -- the mark is whatever string a
    record carried, and nothing validates that before it is stored -- and the
    parse is guarded rather than allowed to raise, because raising here would
    turn a malformed record into a crash mid-run, which is strictly worse than
    the stale mark this function exists to prevent. It may also sit implausibly
    far in the future, which is the poisoning case: once such a value becomes
    the mark, every later run asks WHOOP for a window starting in the future,
    gets nothing, and writes the same value back -- reporting success forever
    while syncing nothing.

    A refused record is still stored. Only its claim on the cursor is denied.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed <= now + timedelta(seconds=_MAX_CLOCK_SKEW_SECONDS)


def _usable_resume_mark(mark: str, *, now: datetime) -> str | None:
    """``mark`` if it is usable as a starting point, otherwise ``None``.

    This is the recovery half of #186. Refusing to *write* a poisoned mark
    protects installations that have not been bitten yet; it does nothing for a
    database that already holds one, and such a cursor never revises itself --
    every run starts in the future, finds nothing, and writes the same value
    back. Discarding it on read is what lets an already-poisoned installation
    heal on its next run.

    ``None``, not the present, because a poisoned mark tells us nothing about
    when it stopped being true, so clamping to now would silently skip every
    record that arrived while it was wrong. ``None`` means "no mark", which
    sends the next run through ``_EPOCH_SINCE`` and re-walks the history --
    lossless, and safe for exactly the reason the module docstring already gives
    for a never-synced entity: the upserts are idempotent, so a full walk costs
    requests rather than correctness.

    It is also what the *write* side already does with this class of failure --
    a run that cannot establish a mark leaves the cursor ``None`` and the next
    run re-walks. Returning the present here would have given one bug two
    contradictory recovery policies, the read side being the lossy one.
    """
    if _is_plausible_mark(mark, now=now):
        return mark
    return None


def _apply_overlap(high_water_mark: str, overlap_seconds: float) -> str:
    """``high_water_mark`` shifted back by ``overlap_seconds``, same ISO 8601 shape.

    ``datetime.fromisoformat`` accepts both the trailing ``Z`` WHOOP's own
    payloads use and the ``+00:00`` offset this store's own ``_now()``
    writes (supported directly since Python 3.11), so either shape a stored
    mark could be in round-trips correctly.
    """
    parsed = datetime.fromisoformat(high_water_mark)
    return (parsed - timedelta(seconds=overlap_seconds)).isoformat()


async def run_sync(
    conn: sqlite3.Connection,
    client: WhoopClient,
    config: Config,
    whoop_user_id: int,
) -> dict[str, EntitySyncResult]:
    """Sync ``whoop_user_id``'s recoveries, sleeps, cycles and workouts forward.

    Raises ``SyncDisabledError`` -- before touching the network or the store
    -- unless ``config.cache_enabled`` is set, exactly mirroring
    ``backfill.BackfillDisabledError``. Any fetch or upsert failure
    propagates without advancing the interrupted entity's high-water mark,
    so a re-run resumes from the last fully-committed page rather than
    skipping it.
    """
    if not config.cache_enabled:
        raise SyncDisabledError(
            "incremental sync requires the persistent store, which is off by default; "
            "set WHOOPMCP_CACHE=true to enable it (see PRIVACY.md)"
        )
    results: dict[str, EntitySyncResult] = {}
    for spec in BACKFILL_ENTITIES:
        results[spec.name] = await _sync_entity(conn, client, whoop_user_id, spec)
    return results


async def _sync_entity(
    conn: sqlite3.Connection,
    client: WhoopClient,
    whoop_user_id: int,
    spec: _EntitySpec,
    *,
    overlap_seconds: float = _OVERLAP_SECONDS,
) -> EntitySyncResult:
    """Walk one collection forward from its high-water ``updated_at`` mark.

    Per page: fetch (resuming from any in-progress cursor), upsert every
    record, track the run's own maximum observed ``updated_at``, and only
    then commit ``sync_state`` -- as a JSON blob (``since``/``next_token``/
    ``high_water_seen``) while more pages remain, or a bare ISO-8601 mark
    once the walk is exhausted. A failure mid-page leaves the previous
    checkpoint in place, so the interrupted page is re-fetched (never
    skipped) on the next run.
    """
    key = _incremental_entity_key(spec.name)
    state = get_sync_state(conn, whoop_user_id, key)
    # One reading of the clock for the whole run: every plausibility check below
    # is then made against the same instant, so two records in one page cannot
    # be judged against different `now`s.
    now = datetime.now(UTC)

    if state is not None and state["outcome"] == "in_progress":
        # Resume verbatim: the same `since` bound this run started with, and
        # the max `updated_at` already committed by an earlier page of this
        # same run -- never re-derived from a (possibly stale) prior mark.
        #
        # `fallback_mark` is NOT `high_water_seen`: a run that so far has
        # only committed empty-but-paginated pages has `high_water_seen ==
        # None` mid-run, and a crash right there must not let the eventual
        # resumed completion regress the ALREADY-ON-RECORD mark to `None`.
        # `previous_mark` -- this run's starting point, before any page of
        # it committed anything -- is carried through the JSON cursor
        # itself for exactly this reason, rather than re-read from the
        # (already overwritten) prior `sync_state` row.
        resume = json.loads(state["cursor"])
        since: str | None = resume["since"]
        next_token: str | None = resume["next_token"]
        high_water_seen: str | None = resume["high_water_seen"]
        fallback_mark: str | None = resume["previous_mark"]
        # An `in_progress` row can carry a poisoned value just as a `complete`
        # one can, and #186 asks for recovery on the *next* run. Clamping only
        # the fresh branch left a resumed run requesting a future window and
        # re-persisting the poison, so recovery took two runs instead of one.
        if since is not None and not _is_plausible_mark(since, now=now):
            since = _EPOCH_SINCE
        if high_water_seen is not None and not _is_plausible_mark(high_water_seen, now=now):
            high_water_seen = None
        if fallback_mark is not None:
            fallback_mark = _usable_resume_mark(fallback_mark, now=now)
    else:
        previous_mark = state["cursor"] if state is not None else None
        if previous_mark is not None:
            # Heal a cursor that is already poisoned on disk (#186), before it
            # is used to build this run's window.
            previous_mark = _usable_resume_mark(previous_mark, now=now)
        since = (
            _apply_overlap(previous_mark, overlap_seconds)
            if previous_mark is not None
            else _EPOCH_SINCE
        )
        next_token = None
        high_water_seen = None
        # A no-op run (nothing new since `previous_mark`) must not regress
        # the stored mark back to `None` -- fall back to what was already
        # on record.
        fallback_mark = previous_mark

    fetch = getattr(client, spec.list_method)
    count = 0
    skipped_implausible = 0
    while True:
        page: Page = await fetch(
            start=since,
            limit=MAX_PAGE_SIZE,
            next_token=next_token,
            priority=RequestPriority.INTERACTIVE,
        )
        for record in page.records:
            spec.upsert(conn, whoop_user_id, record)
            count += 1
            updated_at = record.get("updated_at")
            if updated_at is not None:
                updated_at = str(updated_at)
                # Checked after the upsert above, deliberately: the record is
                # the member's data and is kept regardless. What is refused is
                # only its claim on the cursor.
                # Plausibility parses; the max below compares strings. They
                # can pick different records when offsets or precision differ,
                # but only ever a *chronologically earlier* one -- so the mark
                # can lag and re-fetch, never overshoot. And since the check
                # runs per record before the string enters the max, an
                # implausible value cannot reach it either way.
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
            count=count, high_water_mark=final_mark, skipped_implausible=skipped_implausible
        )
