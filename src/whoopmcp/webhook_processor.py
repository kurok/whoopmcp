"""Webhook event consumer: idempotent (trace_id PK) processing of #17's queue
(#18): parse, resolve user_id, fetch, upsert. V2 trap: `recovery.*` events
carry the sleep's UUID as `id`, not a recovery/cycle id -- see `_apply_event`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
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

#: Resource vocabulary an event_type's first half must belong to -- keys of
#: store.py's own resource->table mapping (#67: this module knows no table
#: name, issues no SQL).
_WEBHOOK_RESOURCES: frozenset[str] = frozenset({"recovery", "sleep", "workout"})

#: Required shape of a webhook payload's `id`: a hyphenated UUID (recovery
#: events carry a sleep UUID -- see module docstring). Enforced because
#: `resource_id` is interpolated into a request path (e.g.
#: `f"/v2/activity/sleep/{sleep_id}"`); unchecked, a payload id of
#: `../../v2/user/profile/basic` would traverse to a different endpoint using
#: the member's own bearer token (#139). Second layer behind webhooks.py's HMAC gate.
_RESOURCE_ID = re.compile(r"\A[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\Z")

#: Retries for a transient failure before dead-lettering the event. Distinct
#: from client.py's `_MAX_429_RETRIES` (that governs one HTTP call's 429
#: handling; this governs a whole event's attempts) -- free to diverge.
DEFAULT_MAX_ATTEMPTS = 5

#: Capped exponential backoff with full jitter, same shape as client.py's
#: `_backoff_seconds` (independent constants, same reasoning).
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_MAX_SECONDS = 30.0

#: How often a backoff wait rechecks its clock -- small so a test's
#: fast-forwarding clock can resolve a wait in one tick.
_POLL_INTERVAL_SECONDS = 0.02


class UnknownTraceIdError(ValueError):
    """`replay_webhook_event` was asked to replay an unseen `trace_id` -- no
    stored `event_body` to re-run. Same family as `UnresolvableEventError`."""


class UnresolvableEventError(ValueError):
    """A webhook body couldn't be parsed into a usable event.

    Never retried or persisted -- no `trace_id` means no key to record it
    under. Defensive backstop; WHOOP only sends well-formed signed bodies.
    """


class MemberNotLinkedError(Exception):
    """Signal (#66) that `event.whoop_user_id` has no live `principal_members`
    link yet -- not actionable yet, not a failure.

    `process_webhook_event` catches this distinctly: no `mark_webhook_event_*`
    call, row stays `status='pending'`, `attempt_count` unchanged -- doesn't
    burn a retry on something waiting doesn't fix, and stays reachable by a
    later redelivery or #19 reconciliation.
    """


@dataclass(frozen=True, slots=True)
class WebhookEvent:
    """One parsed webhook body.

    `resource_id` is verbatim from payload `id`, named neutrally because for
    `recovery.*` it IS a sleep UUID (the V2 trap), elsewhere the resource's own.
    Only `_apply_event` decides what it identifies.
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

    Raises `UnresolvableEventError` (only) for malformed JSON or a missing/
    malformed `event_type`/`trace_id`/`user_id`/`id`.
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

    # Rejected before `insert_webhook_event` (#139): a hostile id is dropped
    # without a fetch or a stored row.
    if not _RESOURCE_ID.match(resource_id):
        raise UnresolvableEventError(
            f"webhook body's id is not a UUID, so it cannot be a {resource} id "
            f"and will not be interpolated into a request path: {resource_id!r}"
        )

    return WebhookEvent(
        trace_id=trace_id,
        event_type=event_type,
        resource=resource,
        action=action,
        whoop_user_id=whoop_user_id,
        resource_id=resource_id,
        raw_body=raw_body,
    )


def _parsed_updated_at(value: object) -> datetime | None:
    """`value` as an aware `datetime`, or None if unparseable.

    None means "not comparable" -- `_upsert_if_not_older` upserts in that case,
    same as an absent `updated_at`. A naive value is assumed UTC (not logged;
    it's still comparable). Precision limit: `fromisoformat` truncates beyond 6
    fractional digits, so two values differing only past that parse equal and
    the incoming record is applied (only strictly-older is skipped) -- a known,
    test-pinned cost since WHOOP only sends second/millisecond precision.
    """
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _upsert_if_not_older(
    conn: sqlite3.Connection,
    resource: str,
    whoop_user_id: int,
    resource_id: str,
    record: dict[str, Any],
) -> None:
    """Upsert `record` unless a newer one is already stored.

    Compares parsed `datetime`, not strings (#140: string compare broke on
    differing UTC spellings like `.500Z` vs `+00:00`). Unparseable/missing on
    either side upserts anyway (warns when unparseable) -- fails open since
    #19's reconciliation backstops it; failing closed would mean silent staleness.
    """
    stored_raw = get_resource_updated_at(conn, resource, whoop_user_id, resource_id)
    incoming_raw = record.get("updated_at")
    stored = _parsed_updated_at(stored_raw)
    incoming = _parsed_updated_at(incoming_raw)

    for label, raw, parsed in (
        ("stored", stored_raw, stored),
        ("incoming", incoming_raw, incoming),
    ):
        if raw is not None and parsed is None:
            logger.warning(
                "unparseable %s updated_at, upserting without the out-of-order check: "
                "%s %s/%s value=%r",
                label,
                resource,
                whoop_user_id,
                resource_id,
                raw,
            )

    if stored is not None and incoming is not None and incoming < stored:
        logger.info(
            "skipping out-of-order webhook upsert: %s %s/%s incoming=%s stored=%s",
            resource,
            whoop_user_id,
            resource_id,
            incoming_raw,
            stored_raw,
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

    Every fetch goes through `client`'s own rate limiter; nothing here talks
    to `httpx` directly.
    """
    if not principal_is_linked_to_member(conn, event.whoop_user_id):
        # No live principal_members link: dropped, not a failure -- not
        # retryable-into-success and not dead-letter-worthy, just not
        # actionable yet. See MemberNotLinkedError's own docstring.
        logger.info("dropping webhook event for unknown user_id=%s", event.whoop_user_id)
        raise MemberNotLinkedError(event.whoop_user_id)

    if event.action == "deleted":
        if event.resource == "recovery":
            # V2 TRAP: resource_id is a sleep UUID, not a cycle/recovery id.
            # *.deleted must issue no fetch, so cycle_id can only come from an
            # already-stored sleep; if none, skip (not retried -- no new info).
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
        # V2 TRAP, updated side: fetch the sleep the id names, read its
        # cycle_id, then fetch that cycle's recovery -- never treat
        # resource_id as a cycle/recovery id directly.
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
    return random.uniform(0, capped)  # noqa: S311 -- jitter, not a security use  # nosec B311


async def _wait_seconds(clock: Callable[[], float], seconds: float) -> None:
    """Wait `seconds` of `clock`'s time, polling (not one long sleep) so a
    test's fast-forwarding clock resolves this in one tick."""
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

    Idempotent on `trace_id`: a "success"/"dead_letter" row short-circuits
    before any fetch. Otherwise retries `_apply_event` up to `max_attempts`
    with capped backoff, then dead-letters. Any exception counts as
    transient (retried, never propagated) except `MemberNotLinkedError`
    (#66), handled separately: leaves the row `pending`, no attempt spent.
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
            # Not yet actionable, not a failure (see docstring): no mark
            # call, row stays pending, a later redelivery reaches _apply_event.
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
            # Includes _apply_event's vacuous skips (unresolvable cycle_id,
            # stale out-of-order record) -- still real liveness signal for #31.
            # Never reached by the MemberNotLinkedError branch.
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

    Reuses #17's already-verified raw bytes -- no signature re-check, no HTTP
    round-trip -- so #66's not-yet-actionable rows can be recovered once
    linked. Raises `UnknownTraceIdError` for an unseen `trace_id`. Returns
    `True` if actually reprocessed, `False` if the row was already terminal
    (success/dead_letter) and short-circuited -- the CLI must not report a
    no-op as "replayed".
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

    Background task for the server's lifetime (started/cancelled by
    `server.lifespan`). Serial, not concurrent: one event's retries delay the
    next but never block it forever. Any escaping exception is logged and
    swallowed here, not left to kill the task and stop every queued event after it.
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
