"""Periodic full reconciliation: the webhook backstop (#19).

Webhooks are an optimisation over polling, never a replacement for it.
#15's own incremental sync (``sync.run_sync``) already independently catches
a dropped webhook whose underlying record was updated or created, because it
re-polls WHOOP on an ``updated_at`` high-water mark with no dependency on
webhooks at all. What #15's mechanism can never catch, by construction, is a
*deletion*: a record removed upstream simply stops appearing in a forward
listing, with no signal in ``updated_at`` space -- exactly the gap #18's
``*.deleted`` webhook handling exists to close when the webhook actually
arrives, and exactly the gap a *lost* ``*.deleted`` webhook leaves open
forever, since the cursor has already moved past it by the time anyone
notices.

This module supplies exactly that missing mechanism, and nothing else: for a
bounded recent window, it fetches a fresh listing of each of the three
resources #18's webhook path understands (recoveries, sleeps, workouts --
cycles are out of scope, matching ``webhook_processor._TABLE_BY_RESOURCE``),
diffs it against what the store holds for that same window, and soft-deletes
(sets ``deleted_at``) any locally-live resource_id the fresh listing no
longer mentions. That soft-delete is ``webhook_processor.set_deleted_at`` --
the exact same column and convention the ``*.deleted`` webhook path already
uses -- reused verbatim, never a second mechanism.

Deliberately does NOT call ``sync.run_sync`` or attempt to also catch missed
``*.updated`` events: #15's own sync already covers that independently, on
its own schedule, and conflating the two jobs would force this module's
BACKFILL priority (see below) onto sync's own, separately-reasoned-about
fetches.

There is no in-process scheduler anywhere in this repository (#35) -- this
is a CLI subcommand (``whoopmcp reconcile-webhooks``, see ``__main__.py``),
never an MCP tool, exactly like #14's backfill and #15's own sync CLI story.

Every fetch here is issued at ``RequestPriority.BACKFILL``: this is a
background backstop an operator schedules externally, never a user-triggered
request, so it must never compete with an interactive tool call for the
shared, per-app WHOOP rate-limit budget (100/minute, 10,000/day, confirmed
shared across every member who has authorised this app -- see client.py's
own module docstring).

Window: ``DEFAULT_WINDOW_DAYS = 30``. The window bounds the local-side
comparison -- a locally-held record whose own date falls outside the window
is left alone even if the fresh listing omits it too, since that omission
carries no information about a record reconciliation was never asked to
look at. 30 days is a deliberate choice, not WHOOP's own default: it
comfortably exceeds the gap between any sane cron/systemd-timer schedule
(daily, or even weekly) so a genuine deletion is never missed between runs;
it keeps a full re-listing cheap against the shared daily/per-minute budget
(a handful of pages per resource at ``MAX_PAGE_SIZE`` even for a very
active member, not a real fraction of the daily 10,000); and a stale
deletion sitting undetected one extra day in the *rare* two-year-old-record
case is a non-event, whereas a hole in the last month is exactly what #31
would want to alert on.

**The fresh fetch's own lower bound is NOT the same as the window it
reconciles**, and this matters: WHOOP's own ``/v2/recovery`` documents its
``start``/``end`` as filtering on the *related sleep's* timeframe, not the
recovery's own ``created_at`` -- confirmed against WHOOP's published API
reference, not assumed -- while this store's local ``get_recoveries`` filters
on ``created_at`` (its own documented contract). A recovery whose
``created_at`` sits just inside the local comparison window but whose
associated sleep started a little earlier can be present in the local
window-bounded set yet absent from a fresh listing bounded to the exact
same ``start``, producing a false "missing" verdict -- and, because
``upsert_recovery``'s own ``ON CONFLICT`` update never clears ``deleted_at``,
a false soft-delete here is *permanent*, not something a later sync or
webhook self-heals. ``_FRESH_FETCH_MARGIN_DAYS`` widens only the fresh
fetch's lower bound (never the local comparison window, and never the upper
bound -- sorting/pagination already floor-anchored at ``start`` handles the
extra records for free) so every record eligible for the local-side
deletion check is guaranteed to fall inside the fresh listing's own bound
too, regardless of this skew. Applied uniformly to every walked resource for
simplicity, even though sleeps/workouts key ``start``/``end`` on their own
timeframe already and don't strictly need it.
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

#: Comfortably exceeds any sane reconciliation schedule while keeping a full
#: re-listing cheap -- see this module's own docstring for the full
#: reasoning.
DEFAULT_WINDOW_DAYS = 30

#: How many locally-held records one reconciliation run may close.
#:
#: Reconciliation exists to close holes left by dropped ``*.deleted`` events, and
#: a window whose last record was deleted upstream legitimately fetches zero --
#: ``test_reconciliation_closes_a_hole_left_by_a_dropped_deleted_event`` pins
#: exactly that. So refusing *every* empty listing, which is what #175's own
#: acceptance criterion asked for, would disable the feature rather than fix it.
#:
#: What is not legitimate is an incomplete response wiping a populated window,
#: and #175's original ``fetched == 0`` guard only recognised one way a
#: response can be incomplete. The other one -- named by this module's own
#: docstring since #175, but unguarded until #197 -- is a listing whose
#: pagination ends early because a ``next_token`` is wrongly absent: such a run
#: has ``fetched > 0``, sailed past the empty-listing check, and soft-deleted
#: every in-window record that didn't fit on the pages it did get. A failed
#: fetch, an empty body and a truncated walk are all indistinguishable from a
#: genuine deletion here, and a soft-delete is permanent (nothing ever clears
#: ``deleted_at``; the upserts' ON CONFLICT clauses do not touch it). So the
#: cases are separated by size rather than by a signal the response does not
#: carry: the limit applies to what a run would *close* (``missing``), which
#: for an empty listing is exactly the old "how many are held locally" count,
#: so #175's boundary behaviour is unchanged.
#:
#: The number is a judgement, not a derivation: a dropped-event hole is a handful
#: of records, a failed or truncated fetch strands most of the window. Set low
#: enough that a wholesale wipe always trips it, high enough that ordinary
#: hole-closing never does. Raising it weakens the guard; the operator can
#: always rerun once WHOOP is answering fully again, which is the recoverable
#: direction.
CLOSE_LIMIT_PER_RUN = 5

#: How much earlier than the reconciliation window the FRESH fetch's own
#: ``start`` bound reaches -- absorbing the recovery/related-sleep timeframe
#: skew this module's own docstring explains, so a real record already
#: created just inside the local comparison window is never fetched from a
#: fresh-listing bound that excludes it. A recovery is created shortly after
#: its sleep, in practice hours not days -- 3 days is a deliberately generous
#: multiple of that, still trivial against the shared rate budget.
_FRESH_FETCH_MARGIN_DAYS = 3


class ReconciliationDisabledError(RuntimeError):
    """Reconciliation was invoked without the persistent store enabled."""


@dataclass(frozen=True, slots=True)
class ReconciliationResult:
    """One reconciled collection's outcome: how many fresh records WHOOP
    reported for the window, and how many locally-held holes were closed."""

    resource: str
    fetched: int
    #: Records whose stored copy was replaced because the fresh listing carried
    #: a newer ``updated_at`` (#185).
    updated: int
    closed: int
    #: Why this collection closed nothing, when the reason was a refusal rather
    #: than "nothing to close" (#175, #197). ``None`` on a normal run. Reported
    #: by the CLI, because a run that declines to delete must not look identical
    #: to one that found nothing to delete -- that is what made the original bug
    #: silent.
    withheld: str | None = None


@dataclass(frozen=True, slots=True)
class _ReconcileSpec:
    """One collection reconciliation walks.

    ``entity`` doubles as the store's own table name and this module's
    result-dict key (matching ``_TABLE_BY_RESOURCE``'s plural table names);
    ``resource`` is the singular form ``webhook_processor.set_deleted_at``
    expects. ``list_method`` names the ``WhoopClient`` method rather than
    binding it, since the client instance only exists at run time --
    mirrors ``backfill.py``'s own ``_EntitySpec``.
    """

    entity: str
    resource: str
    list_method: str
    get_local: Callable[..., list[dict[str, Any]]]
    id_field: str
    #: Writes a fresh record back over the stored one, for update detection.
    upsert: Callable[..., Any]
    #: Whether a locally-live id missing from the fresh listing is soft-deleted.
    #:
    #: False for cycles, and that asymmetry is the point (#185). Update
    #: detection has to cover all four entities sync covers, or a corrected
    #: cycle -- which carries `strain`, one of the six analysed metrics -- has no
    #: path back. Soft-deletion is a different matter: it is irreversible (see
    #: `compact_database` and #175), and nothing here has validated how WHOOP
    #: bounds a *cycle* listing. This module already documents that
    #: `/v2/recovery` filters on the related sleep's timeframe rather than the
    #: recovery's own, so assuming cycles behave like sleeps would be exactly the
    #: kind of guess that deletes real records. Cycles therefore get corrections
    #: without being enrolled in deletion.
    soft_deletes: bool = True


#: The four entities sync covers, for update detection (#185). Deletion still
#: applies only to #18's webhook set -- see `_ReconcileSpec.soft_deletes`.
#:
#: Adding cycles costs one extra listing per run against the shared per-app
#: budget. That is the price of the correction path existing at all for them:
#: WHOOP offers no way to query by modification time (verified against its
#: published reference), so a re-listing of a bounded recent window is the only
#: mechanism that can see a rescored record.
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
    """The window's lower bound, formatted the same way WHOOP's own
    timestamps are stored (see ``store.py``'s schema comment) so a plain
    string comparison against a stored ``start``/``created_at`` column is
    meaningful."""
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
    """Diff a fresh listing of ``spec.entity`` against what the store holds
    for ``whoop_user_id`` in ``[window_start, now)``, soft-deleting any
    locally-live id the fresh listing no longer mentions.

    ``fresh_fetch_start`` is earlier than ``window_start`` by
    ``_FRESH_FETCH_MARGIN_DAYS`` -- see the module docstring's own "fresh
    fetch's own lower bound is NOT the same as the window it reconciles"
    section for why the two must differ. The local comparison itself still
    uses ``window_start`` unwidened.

    Mirrors ``backfill.py``'s own paging loop: one page per ``acquire()``
    call, all of them at ``RequestPriority.BACKFILL``.
    """
    fetch = getattr(client, spec.list_method)

    # Read the local set BEFORE the fresh fetch, not after (#175). Reading it
    # afterwards meant a row written *during* the fetch -- by the webhook
    # processor in the server process, or a concurrent `whoop_sync`, both of
    # which share this sqlite file while `reconcile-webhooks` runs as a cron job
    # -- appeared in `local_ids` but could not appear in `fresh_ids`, and was
    # soft-deleted at birth. The race window was the whole pagination, minutes
    # when the shared budget is contested.
    #
    # Reading first inverts the failure: a row that arrives mid-fetch is simply
    # not considered this run, and is reconciled on the next one. Missing a
    # deletion for one cycle is recoverable; a soft-delete is not (see below).
    local_records = spec.get_local(conn, whoop_user_id, start=window_start, include_deleted=False)
    local_ids = {str(record[spec.id_field]) for record in local_records}
    # The stored modification time per id, so a fresh record can be recognised
    # as a *correction* rather than merely as present (#185).
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
            # This re-listing is the only mechanism that can see a rescored
            # record, because `sync.py`'s forward walk cannot: it advances a mark
            # taken from `updated_at` but sends it as `start`, which WHOOP
            # applies to *occurrence* time -- "Return recoveries that occurred
            # after or during (inclusive) this time", and no parameter selects on
            # modification time at all. Once a record's own date falls behind the
            # mark it is unreachable forward, however often it is corrected.
            #
            # Strictly newer, and only for ids already held: an equal timestamp
            # means nothing changed, and a fresh id we do not hold is a *new*
            # record, which sync and backfill already find correctly by
            # occurrence time. Writing those here would duplicate their job and
            # make this walk's cost grow with history rather than with change.
            stored = local_updated_at.get(resource_id)
            incoming = record.get("updated_at")
            if stored is not None and incoming is not None and str(incoming) > str(stored):
                spec.upsert(conn, whoop_user_id, record)
                updated += 1
        cursor = page.next_token
        if cursor is None:
            break

    # An incomplete listing is indistinguishable from a genuinely emptier one,
    # and treating the two alike is the whole bug (#175, #197). Genuine errors
    # and exhausted retries do raise before reaching here, so what is left is a
    # response that *looks* successful: a 200 with an empty body, or a page
    # whose `next_token` is wrongly absent, ending pagination early -- the
    # second of which has `fetched > 0` and so sailed past #175's own
    # empty-listing guard while still omitting most of the window (#197).
    #
    # This matters more than a normal false positive because a soft-delete is
    # permanent by construction: nothing in store.py ever sets `deleted_at` back
    # to NULL, and the upserts' ON CONFLICT clauses do not touch it -- so a
    # later sync rewrites the row and leaves it invisible. There is no undelete
    # to fall back on, which is why this fails closed rather than trusting the
    # response.
    if not spec.soft_deletes:
        # Cycles reach here: corrected above, never closed. See
        # `_ReconcileSpec.soft_deletes` for why the two halves differ.
        return ReconciliationResult(
            resource=spec.entity, fetched=fetched, updated=updated, closed=0
        )

    # The limit is on what this run would CLOSE, not on whether the listing was
    # empty: for an empty listing `missing == local_ids`, so this is exactly
    # #175's original boundary, and for a truncated one it is the bound #175
    # never had. See `CLOSE_LIMIT_PER_RUN` for why size is the only available
    # separator and why closing nothing (rather than the first few) is the
    # deliberate choice -- a partial close would pick survivors arbitrarily.
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
    """Reconcile ``whoop_user_id``'s recoveries, sleeps and workouts against
    a fresh WHOOP listing of the last ``window_days`` days, closing any
    dropped-deletion hole -- the backstop #19 asks for.

    Raises ``ReconciliationDisabledError`` -- before touching the network or
    the store -- unless ``config.cache_enabled`` is set, mirroring
    ``backfill.run_backfill``'s own guard: this reads and writes the
    persistent store, which PRIVACY.md promises is off by default.
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
