"""Webhook event consumer: idempotent processing keyed on trace_id (#18).

#17 verifies a webhook request's signature and puts its raw, still-unparsed
body on a queue. This module drains that queue: parse the body, resolve its
``user_id`` to a locally-known user, fetch the one changed resource (through
the same rate limiter every other outbound call goes through), and upsert it.

Idempotency's actual mechanism is ``store.webhook_events``'s ``PRIMARY KEY``
on ``trace_id``, written before processing starts -- a duplicate delivery of
the same trace_id is recognised before this module issues a second fetch.

The one WHOOP-specific trap this module exists to get right: ``recovery.updated``
and ``recovery.deleted`` carry the UUID of the associated *sleep* in their
``id`` field, not a recovery id (recoveries have none) and not a cycle id.
Every other event's ``id`` is exactly what it looks like. See ``_apply_event``
below and ``store.get_sleep_cycle_id``.

#67: every entity read/write this module needs goes through a store.py
accessor built on ``_execute_scoped`` -- this module itself issues no SQL of
its own and knows no entity table's name or column layout.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from whoopmcp.client import WhoopAPIError, WhoopClient
from whoopmcp.store import (
    get_resource_updated_at,
    get_sleep_cycle_id,
    get_webhook_event,
    insert_webhook_event,
    mark_webhook_event_dead_letter,
    mark_webhook_event_retry,
    mark_webhook_event_success,
    principal_is_linked_to_member,
    record_webhook_delivery,
    set_deleted_at,
    upsert_recovery,
    upsert_sleep,
    upsert_workout,
)

logger = logging.getLogger("whoopmcp")

#: The resource vocabulary a webhook event_type's first half
#: ("recovery"/"sleep"/"workout") must belong to -- just the keys of
#: store.py's own resource->table mapping (`store._TABLE_BY_RESOURCE`),
#: since this module has no more business knowing a table name than it does
#: issuing SQL against one (#67): every entity read/write it needs goes
#: through a store.py accessor instead.
_WEBHOOK_RESOURCES: frozenset[str] = frozenset({"recovery", "sleep", "workout"})

#: How many times `process_webhook_event` retries a transient failure before
#: giving up and dead-lettering the event. Matches client.py's own
#: `_MAX_429_RETRIES` in spirit (a bounded number, not a policy this issue
#: needs to make configurable) but is its own constant: that one governs a
#: single HTTP call's 429 handling inside `WhoopClient._get`, this one
#: governs a whole event's worth of attempts one layer up, and the two are
#: free to diverge without either becoming wrong.
DEFAULT_MAX_ATTEMPTS = 5

#: Capped exponential backoff with full jitter between attempts, same shape
#: as client.py's `_backoff_seconds` (independent constants, same reasoning:
#: don't hammer a struggling dependency, but don't wait forever either).
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_MAX_SECONDS = 30.0

#: How often a backoff wait rechecks its clock -- see client.py's own
#: `_POLL_INTERVAL_SECONDS` for why this is small and bounded: it is what
#: lets a test's fast-forwarding clock resolve a wait in one tick instead of
#: the full logical duration.
_POLL_INTERVAL_SECONDS = 0.02


class UnknownTraceIdError(ValueError):
    """`replay_webhook_event` was asked to replay a `trace_id` this store has
    never seen -- there is no stored `event_body` to re-run.

    Same family as `UnresolvableEventError`: both mean "there is nothing
    usable to process", just discovered at a different point (before ever
    parsing a body, versus before ever looking one up).
    """


class UnresolvableEventError(ValueError):
    """A webhook body couldn't be parsed into a usable event.

    Never retried and never persisted to `webhook_events` -- without a
    `trace_id` there is no key to record it under, and WHOOP already only
    calls the receiving endpoint (#17) with its own well-formed, signed
    bodies, so this is a defensive backstop, not a path expected to see any
    real traffic.
    """


class MemberNotLinkedError(Exception):
    """`_apply_event`'s signal that `event.whoop_user_id` has no live
    `principal_members` link yet (#66).

    Deliberately not the same thing as a transient failure (a WHOOP API
    error, a network blip) and not the same thing as "unparseable" --
    it means this event isn't actionable *by this server* yet, not that
    anything went wrong. `process_webhook_event` catches this one
    distinctly from the generic retry/dead-letter `except Exception` below
    it: no `mark_webhook_event_*` call is made at all, so the row is left
    exactly as `insert_webhook_event` (or the previous attempt) left it --
    `status='pending'`, `attempt_count` unchanged. That does two things at
    once: it never burns a retry attempt for something retrying wouldn't
    fix (the member has to log in; no amount of waiting changes that), and
    it keeps `status` out of the `('success', 'dead_letter')` set that
    `process_webhook_event`'s own idempotency check short-circuits on --
    so a later redelivery of the same `trace_id`, or a future #19
    reconciliation pass, still reaches `_apply_event` again. Actually
    reprocessing rows left in this state is #19's job, not this module's.
    """


@dataclass(frozen=True, slots=True)
class WebhookEvent:
    """One parsed webhook body.

    `resource_id` is copied verbatim from the payload's `id` field and named
    deliberately not `sleep_id`/`recovery_id`/etc: for `recovery.updated` and
    `recovery.deleted` it IS a sleep UUID (the v2 trap this module exists to
    handle), for the other four event types it is the resource's own UUID.
    Only `_apply_event` decides what that string actually identifies.
    """

    trace_id: str
    event_type: str
    resource: str
    action: str
    whoop_user_id: int
    resource_id: str
    raw_body: bytes


def _parse_event(raw_body: bytes) -> WebhookEvent:
    """Parse a verified webhook body into a `WebhookEvent`.

    Raises `UnresolvableEventError` (never anything else) for any body that
    doesn't carry the fields this module needs to act on -- malformed JSON,
    a missing/malformed `event_type`, or a missing `trace_id`/`user_id`/`id`.
    """
    try:
        payload = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UnresolvableEventError(f"webhook body is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise UnresolvableEventError(f"webhook body is not a JSON object: {type(payload)}")

    trace_id = payload.get("trace_id")
    event_type = payload.get("event_type") or payload.get("type")
    data = payload.get("data", payload)
    if not isinstance(trace_id, str) or not trace_id:
        raise UnresolvableEventError("webhook body has no usable trace_id")
    if not isinstance(event_type, str) or "." not in event_type:
        raise UnresolvableEventError(f"webhook body has no usable event_type: {event_type!r}")
    resource, _, action = event_type.partition(".")
    if resource not in _WEBHOOK_RESOURCES or action not in ("updated", "deleted"):
        raise UnresolvableEventError(f"unrecognised webhook event_type: {event_type!r}")

    try:
        whoop_user_id = int(data["user_id"])
        resource_id = str(data["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise UnresolvableEventError(
            f"webhook body missing/malformed user_id or id: {exc}"
        ) from exc

    return WebhookEvent(
        trace_id=trace_id,
        event_type=event_type,
        resource=resource,
        action=action,
        whoop_user_id=whoop_user_id,
        resource_id=resource_id,
        raw_body=raw_body,
    )


def _upsert_if_not_older(
    conn: sqlite3.Connection,
    resource: str,
    whoop_user_id: int,
    resource_id: str,
    record: dict[str, Any],
) -> None:
    """Upsert `record`, unless a newer record is already stored.

    Events arrive out of order and can describe data older than the store's
    cursor; comparing the fetched record's own `updated_at` against what is
    already stored (not the webhook's delivery order, and not this store's
    own write-time bookkeeping column) is what keeps a late, stale delivery
    from clobbering a newer one. Missing on either side (not every WHOOP
    resource necessarily carries `updated_at`) defaults to upserting, since
    there is nothing to compare and last-write-wins is this store's existing
    behaviour everywhere else.
    """
    stored = get_resource_updated_at(conn, resource, whoop_user_id, resource_id)
    incoming = record.get("updated_at")
    if stored is not None and incoming is not None and str(incoming) < stored:
        logger.info(
            "skipping out-of-order webhook upsert: %s %s/%s incoming=%s stored=%s",
            resource,
            whoop_user_id,
            resource_id,
            incoming,
            stored,
        )
        return
    if resource == "sleep":
        upsert_sleep(conn, whoop_user_id, record)
    elif resource == "workout":
        upsert_workout(conn, whoop_user_id, record)
    elif resource == "recovery":
        upsert_recovery(conn, whoop_user_id, record)


async def _apply_event(conn: sqlite3.Connection, client: WhoopClient, event: WebhookEvent) -> None:
    """Do the one thing `event` describes: fetch-and-upsert, or mark deleted.

    Every fetch here goes through `client`'s own rate limiter (`WhoopClient._get`
    acquires it internally on every call, same as every other client.py
    method) -- nothing in this module talks to `httpx` directly.
    """
    if not principal_is_linked_to_member(conn, event.whoop_user_id):
        # An event for a whoop_user_id with no live principal_members link
        # is dropped, not an error -- there's nothing to upsert against on
        # behalf of. Unlike a real failure, this is not retryable-into-
        # success (no amount of waiting links the member) and not
        # dead-letter-worthy (it isn't broken, it's just not actionable
        # *yet*): MemberNotLinkedError signals that distinction up to
        # `process_webhook_event`, which leaves the row `pending` without
        # spending a retry attempt on it (see that exception's docstring).
        logger.info("dropping webhook event for unknown user_id=%s", event.whoop_user_id)
        raise MemberNotLinkedError(event.whoop_user_id)

    if event.action == "deleted":
        if event.resource == "recovery":
            # THE V2 TRAP: event.resource_id is a sleep UUID, not a cycle id
            # and not a recovery id -- recoveries have no id of their own.
            # *.deleted must issue no fetch, so the cycle_id can only come
            # from a sleep record already sitting in this store; if there
            # isn't one, there is no fetch-free way to know which recovery
            # row to mark, and this event is skipped (not retried -- a
            # fetch wouldn't be new information the next attempt has that
            # this one doesn't).
            cycle_id = get_sleep_cycle_id(conn, event.whoop_user_id, event.resource_id)
            if cycle_id is None:
                logger.warning(
                    "recovery.deleted for user_id=%s sleep=%s: no locally-stored sleep to "
                    "resolve its cycle; skipping (a fetch here would violate *.deleted's "
                    "no-fetch rule)",
                    event.whoop_user_id,
                    event.resource_id,
                )
                return
            set_deleted_at(conn, "recovery", event.whoop_user_id, str(cycle_id))
        else:
            set_deleted_at(conn, event.resource, event.whoop_user_id, event.resource_id)
        return

    if event.resource == "recovery":
        # THE V2 TRAP, updated side: fetch the sleep the id actually names,
        # read *its* cycle_id, and only then fetch the recovery for that
        # cycle. Treating event.resource_id as a cycle id or a recovery id
        # directly is exactly the bug this two-fetch shape exists to avoid.
        sleep_record = await client.get_sleep(event.resource_id)
        cycle_id = sleep_record.get("cycle_id")
        if cycle_id is None:
            raise WhoopAPIError(0, f"sleep {event.resource_id} carries no cycle_id")
        recovery_record = await client.get_cycle_recovery(int(cycle_id))
        _upsert_if_not_older(
            conn, "recovery", event.whoop_user_id, str(recovery_record["cycle_id"]), recovery_record
        )
    elif event.resource == "sleep":
        sleep_record = await client.get_sleep(event.resource_id)
        _upsert_if_not_older(
            conn, "sleep", event.whoop_user_id, str(sleep_record["id"]), sleep_record
        )
    elif event.resource == "workout":
        workout_record = await client.get_workout(event.resource_id)
        _upsert_if_not_older(
            conn, "workout", event.whoop_user_id, str(workout_record["id"]), workout_record
        )


def _backoff_seconds(attempt: int) -> float:
    """Capped exponential backoff with full jitter -- see module docstring."""
    capped = min(_BACKOFF_MAX_SECONDS, _BACKOFF_BASE_SECONDS * (2**attempt))
    return random.uniform(0, capped)  # noqa: S311 -- jitter, not a security use


async def _wait_seconds(clock: Callable[[], float], seconds: float) -> None:
    """Wait `seconds` of `clock`'s time, polling rather than one long sleep --
    see client.py's own `_wait_seconds` for why: it lets a test's
    fast-forwarding clock resolve this in one real tick.
    """
    deadline = clock() + seconds
    while clock() < deadline:
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)


async def process_webhook_event(
    conn: sqlite3.Connection,
    client: WhoopClient,
    raw_body: bytes,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    clock: Callable[[], float] | None = None,
) -> None:
    """Process one webhook body to completion: idempotently, with retry.

    Idempotent on `trace_id`: a body whose `trace_id` already has a
    "success" or "dead_letter" row in `webhook_events` is recognised and
    returned from immediately, before any fetch. Otherwise this retries
    `_apply_event` up to `max_attempts` times, with capped exponential
    backoff between attempts, before giving up and dead-lettering the event
    so one permanently-failing event cannot wedge whatever is driving this
    (see `_consume_webhooks`) forever.

    Any exception `_apply_event` raises -- a WHOOP API error, a network
    failure, or anything else (a malformed response shape, say) -- counts as
    a transient failure for this purpose: retried, then dead-lettered, never
    left to propagate and take down a caller that is processing more than
    one event. The one exception to that: `MemberNotLinkedError` (#66) is
    handled separately, before the generic case, and leaves the row
    `pending` without spending a retry attempt -- see its own docstring for
    why "not yet actionable" has to be distinct from both "failed" and
    "succeeded".
    """
    clock = clock or time.time
    try:
        event = _parse_event(raw_body)
    except UnresolvableEventError:
        logger.warning("dropping unparseable webhook event", exc_info=True)
        return

    existing = get_webhook_event(conn, event.trace_id)
    if existing is not None:
        if existing["status"] in ("success", "dead_letter"):
            return
        attempt = int(existing["attempt_count"])
    else:
        insert_webhook_event(
            conn,
            event.trace_id,
            event.whoop_user_id,
            event.event_type,
            raw_body.decode("utf-8", errors="replace"),
        )
        attempt = 0

    while True:
        try:
            await _apply_event(conn, client, event)
        except MemberNotLinkedError:
            # Not yet actionable, not a failure -- see that exception's own
            # docstring. No mark_webhook_event_* call: the row stays exactly
            # as it was (status='pending', attempt_count untouched), so it
            # neither reaches success/dead_letter nor burns an attempt, and
            # a later redelivery of this trace_id still reaches _apply_event.
            return
        except Exception:  # see docstring: any failure here is transient-until-proven-otherwise
            attempt += 1
            if attempt >= max_attempts:
                mark_webhook_event_dead_letter(conn, event.trace_id, attempt)
                logger.warning(
                    "webhook event dead-lettered after %d attempts: trace_id=%s type=%s",
                    attempt,
                    event.trace_id,
                    event.event_type,
                    exc_info=True,
                )
                return
            mark_webhook_event_retry(conn, event.trace_id, attempt)
            await _wait_seconds(clock, _backoff_seconds(attempt))
            continue
        else:
            mark_webhook_event_success(conn, event.trace_id)
            # Every path that reaches here is a genuinely completed
            # delivery for event.whoop_user_id -- including the two vacuous
            # skips inside _apply_event (recovery.deleted with no locally-
            # resolvable cycle_id, and an out-of-order stale record in
            # _upsert_if_not_older) -- so it is real liveness signal for
            # #31, not just a "real" fetch-and-upsert. Never reached by the
            # MemberNotLinkedError branch above: no delivery has resolved to
            # an actionable identity yet.
            record_webhook_delivery(conn, event.whoop_user_id)
            return


async def replay_webhook_event(
    conn: sqlite3.Connection,
    client: WhoopClient,
    trace_id: str,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    clock: Callable[[], float] | None = None,
) -> bool:
    """Re-run `process_webhook_event` against a stored event's own
    `event_body`, never re-POSTing or re-signing anything (#19).

    `webhook_events.event_body` already holds the exact raw JSON bytes #17
    verified when the event first arrived; re-encoding it and calling
    `process_webhook_event` directly re-exercises this module's own
    processing logic without ever touching #17's signature verification or
    issuing an HTTP request back to this server's own `/webhooks/whoop` --
    so development can iterate on a code change without a deploy per
    change, and #66's not-yet-actionable rows can be recovered once their
    member has actually logged in.

    Raises `UnknownTraceIdError` for a `trace_id` this store has never seen,
    touching neither `client` nor the store otherwise. Because
    `process_webhook_event`'s own idempotency gate treats both "success" and
    "dead_letter" as terminal, replaying an event already in either state is
    a safe no-op -- exactly what makes "replay reproduces the same store
    state" assertable -- while a `pending` row (mid-retry, or #66's
    not-yet-actionable state) is genuinely reprocessed. Returns `True` when
    this call actually reprocessed the event, `False` when it found an
    already-terminal row and short-circuited -- the caller (the CLI) must
    not report a no-op as "replayed" (a real operational need: re-running an
    event that dead-lettered under a since-fixed bug does nothing here, and
    the operator needs to be told that plainly, not congratulated).
    """
    existing = get_webhook_event(conn, trace_id)
    if existing is None:
        raise UnknownTraceIdError(trace_id)
    was_terminal = existing["status"] in ("success", "dead_letter")
    raw_body = existing["event_body"].encode("utf-8")
    await process_webhook_event(conn, client, raw_body, max_attempts=max_attempts, clock=clock)
    return not was_terminal


async def _consume_webhooks(
    queue: asyncio.Queue[bytes],
    conn: sqlite3.Connection,
    client: WhoopClient,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    clock: Callable[[], float] | None = None,
) -> None:
    """Drain `queue` forever, one event at a time.

    Meant to run as a background task for the server's whole lifetime
    (started and cancelled by `server.lifespan`). Processing is serial, not
    concurrent: one event's retries (bounded by `max_attempts`, inside
    `process_webhook_event`) delay the next event behind it, but never block
    it indefinitely -- once an event dead-letters, the loop moves on. Any
    exception that escapes `process_webhook_event` regardless (it is not
    expected to raise, but this is the process's whole queue-draining loop)
    is logged and swallowed here rather than left to kill the task outright,
    which would stop every event queued after it from ever being processed.
    """
    while True:
        raw_body = await queue.get()
        try:
            await process_webhook_event(
                conn, client, raw_body, max_attempts=max_attempts, clock=clock
            )
        except Exception:
            logger.exception("webhook consumer: event processing raised unexpectedly")
        finally:
            queue.task_done()
