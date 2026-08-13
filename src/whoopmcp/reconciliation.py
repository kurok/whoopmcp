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
too, regardless of this skew. Applied uniformly to all three resources for
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
from whoopmcp.store import get_recoveries, get_sleeps, get_workouts
from whoopmcp.webhook_processor import set_deleted_at

#: Comfortably exceeds any sane reconciliation schedule while keeping a full
#: re-listing cheap -- see this module's own docstring for the full
#: reasoning.
DEFAULT_WINDOW_DAYS = 30

#: How many locally-held records an *empty* WHOOP listing may close in one run.
#:
#: Reconciliation exists to close holes left by dropped ``*.deleted`` events, and
#: a window whose last record was deleted upstream legitimately fetches zero --
#: ``test_reconciliation_closes_a_hole_left_by_a_dropped_deleted_event`` pins
#: exactly that. So refusing *every* empty listing, which is what #175's own
#: acceptance criterion asked for, would disable the feature rather than fix it.
#:
#: What is not legitimate is an empty response wiping a populated window: an
#: empty listing and a failed one are indistinguishable here, and a soft-delete
#: is permanent (nothing ever clears ``deleted_at``; the upserts' ON CONFLICT
#: clauses do not touch it). So the two cases are separated by size rather than
#: by a signal the response does not carry.
#:
#: The number is a judgement, not a derivation: a dropped-event hole is a handful
#: of records, a failed fetch strands the whole window. Set low enough that a
#: wholesale wipe always trips it, high enough that ordinary hole-closing never
#: does. Raising it weakens the guard; the operator can always rerun once WHOOP
#: is answering again, which is the recoverable direction.
EMPTY_LISTING_CLOSE_LIMIT = 5

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
    closed: int
    #: Why this collection closed nothing, when the reason was a refusal rather
    #: than "nothing to close" (#175). ``None`` on a normal run. Reported by the
    #: CLI, because a run that declines to delete must not look identical to one
    #: that found nothing to delete -- that is what made the original bug silent.
    withheld: str | None = None


@dataclass(frozen=True, slots=True)
class _ReconcileSpec:
    """One of the three collections reconciliation walks.

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


#: Exactly #18's webhook path's own set -- never cycles.
_RECONCILE_SPECS: tuple[_ReconcileSpec, ...] = (
    _ReconcileSpec("recoveries", "recovery", "list_recoveries", get_recoveries, "cycle_id"),
    _ReconcileSpec("sleeps", "sleep", "list_sleeps", get_sleeps, "id"),
    _ReconcileSpec("workouts", "workout", "list_workouts", get_workouts, "id"),
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

    fresh_ids: set[str] = set()
    fetched = 0
    cursor: str | None = None
    while True:
        page: Page = await fetch(
            start=fresh_fetch_start,
            limit=MAX_PAGE_SIZE,
            next_token=cursor,
            priority=RequestPriority.BACKFILL,
        )
        for record in page.records:
            fresh_ids.add(str(record[spec.id_field]))
            fetched += 1
        cursor = page.next_token
        if cursor is None:
            break

    # An empty listing is indistinguishable from a failed one, and treating the
    # two alike is the whole bug (#175). Genuine errors and exhausted retries do
    # raise before reaching here, so what is left is a response that *looks*
    # successful: a 200 with an empty body, or a page whose `next_token` is
    # wrongly absent, ending pagination early.
    #
    # This matters more than a normal false positive because a soft-delete is
    # permanent by construction: nothing in store.py ever sets `deleted_at` back
    # to NULL, and the upserts' ON CONFLICT clauses do not touch it -- so a
    # later sync rewrites the row and leaves it invisible. There is no undelete
    # to fall back on, which is why this fails closed rather than trusting the
    # response.
    if fetched == 0 and len(local_ids) > EMPTY_LISTING_CLOSE_LIMIT:
        return ReconciliationResult(
            resource=spec.entity,
            fetched=0,
            closed=0,
            withheld=(
                f"WHOOP returned no {spec.entity} for the window while {len(local_ids)} "
                f"are held locally (more than {EMPTY_LISTING_CLOSE_LIMIT}); declining to "
                "close them, since an empty listing and a failed one look identical here "
                "and a soft-delete cannot be undone"
            ),
        )

    missing = local_ids - fresh_ids
    for resource_id in missing:
        set_deleted_at(conn, spec.resource, whoop_user_id, resource_id)

    return ReconciliationResult(resource=spec.entity, fetched=fetched, closed=len(missing))


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
