"""Webhook processing tests: idempotent event consumption and resource fetching (#18).

Tests the consumer that drains the webhook queue (populated by #17), resolves
events to local user IDs, fetches the changed resource, upserts it to the store,
and handles retry/dead-letter logic on transient failure.

No calls to the real WHOOP API are made; get_sleep, get_cycle_recovery, etc.
are mocked via respx. The store is an :memory: sqlite database. Test fixtures
demonstrate proper webhook event parsing and the critical recovery/sleep-UUID
resolution mapping.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sqlite3
import sys
import time
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from whoopmcp import webhook_processor
from whoopmcp.auth import Authenticator, FileTokenStore, Token
from whoopmcp.client import BASE_URL, WhoopClient
from whoopmcp.config import Config
from whoopmcp.store import open_store
from whoopmcp.webhook_processor import (
    UnknownTraceIdError,
    _consume_webhooks,
    process_webhook_event,
    replay_webhook_event,
)

# -- fixture setup ---------------------------------------------------------


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config.from_env(
        {
            "WHOOP_CLIENT_ID": "cid",
            "WHOOP_CLIENT_SECRET": "csecret",
            "WHOOP_REDIRECT_URI": "https://localhost:8443/callback",
            "WHOOPMCP_STATE_DIR": str(tmp_path),
        }
    )


@pytest.fixture
def auth(config: Config) -> Authenticator:
    FileTokenStore(config.token_path).save(
        Token(
            "valid-access-token",
            expires_at=time.time() + 3600,
            refresh_token="valid-refresh-token",
        )
    )
    return Authenticator(config)


@pytest.fixture
def db() -> sqlite3.Connection:
    """In-memory SQLite database for testing."""
    conn = open_store(":memory:")
    yield conn
    conn.close()


@pytest.fixture
async def client(config: Config, auth: Authenticator) -> AsyncIterator[WhoopClient]:
    """A real WhoopClient (entered, so `_get` can actually issue requests --
    respx intercepts them before they leave the process) wired to the same
    config/auth every other fixture here uses.
    """
    async with WhoopClient(config, auth) as c:
        yield c


def fast_forwarding_clock() -> Callable[[], float]:
    """A clock that jumps far ahead on every call.

    Mirrors tests/test_client.py's own helper of the same name: any
    `_wait_seconds` backoff loop driven by this clock sees its deadline
    already passed on the first check, so retry/dead-letter tests resolve in
    a handful of real milliseconds instead of the ~1-30s of actual backoff
    `webhook_processor`'s retry loop would otherwise sleep through.
    """
    state = {"now": 0.0}

    def _clock() -> float:
        state["now"] += 3600.0
        return state["now"]

    return _clock


def create_webhook_event_payload(
    event_type: str,
    id_val: str,
    user_id: int = 123,
    timestamp: str | None = None,
    trace_id: str | None = None,
) -> dict[str, Any]:
    """Build a minimal webhook event payload.

    Args:
        event_type: e.g. "recovery.updated", "sleep.updated", "workout.deleted"
        id_val: The resource ID in the payload (sleep UUID for recovery events,
                UUID for sleep/workout events, cycle ID for cycle.updated)
        user_id: The WHOOP user_id
        timestamp: ISO 8601 timestamp (defaults to now)
        trace_id: Idempotency key. Defaults to a fresh uuid4 per call, so two
            calls are two distinct events unless a test explicitly wants the
            *same* trace_id delivered twice -- build the payload/body once
            and reuse those same bytes for that case, rather than passing an
            explicit trace_id twice, so the two deliveries are actually
            byte-identical the way a real webhook retry would be.

    Returns:
        A dict ready to be JSON-encoded as the webhook body.
    """
    if timestamp is None:
        timestamp = datetime.now(UTC).isoformat()
    if trace_id is None:
        trace_id = str(uuid.uuid4())

    return {
        "event_type": event_type,
        "timestamp": timestamp,
        "trace_id": trace_id,
        "data": {
            "user_id": user_id,
            "id": id_val,
        },
    }


def encode_webhook_body(payload: dict[str, Any]) -> bytes:
    """Encode a webhook event payload to bytes."""
    return json.dumps(payload).encode("utf-8")


# -- Helper: link a principal (local user mapping) to a WHOOP member, the
# way `server.whoop_complete_login` really does via `link_principal_to_member`
# -- NOT via a `profiles` row. #66: the membership gate `_apply_event` checks
# is `principal_is_linked_to_member` against `principal_members`, and this
# helper has to create the same row that check reads, or every test using it
# would only be exercising a gate the fix already replaced.
def insert_principal(
    conn: sqlite3.Connection,
    whoop_user_id: int,
    client_id: str = "test-client",
) -> None:
    """Link a principal to `whoop_user_id` in `principal_members`, the table
    the membership gate actually reads (#66)."""
    from whoopmcp.store import link_principal_to_member

    link_principal_to_member(
        conn, client_id=client_id, issuer="", subject="", whoop_user_id=whoop_user_id
    )


# -- Tests: Idempotency, Recovery/Sleep Resolution, Resource Fetching


class TestWebhookProcessingIdempotency:
    """Tests for idempotent webhook processing keyed on trace_id."""

    @respx.mock
    async def test_same_trace_id_twice_processed_once(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Same trace_id delivered twice = one upsert and one fetch.

        This is the core idempotency guarantee: webhook_events has a UNIQUE
        constraint on trace_id, so a second delivery of the exact same body
        (same trace_id) is recognised as already-processed and skipped
        before any fetch, rather than re-fetching and re-upserting.
        """
        sleep_id = "sleep-uuid-001"
        user_id = 123

        insert_principal(db, user_id)

        sleep_record = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
        }
        sleep_route = respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=sleep_record)
        )

        # One event, delivered (processed) twice -- the exact same bytes
        # both times, the way a real WHOOP retry of its own webhook would be.
        event_payload = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        await process_webhook_event(db, client, raw_body)
        await process_webhook_event(db, client, raw_body)

        assert sleep_route.call_count == 1, "get_sleep should be called exactly once"

        from whoopmcp.store import get_sleeps, get_webhook_event

        sleeps = get_sleeps(db, user_id)
        assert len(sleeps) == 1
        assert sleeps[0]["id"] == sleep_id

        event_row = get_webhook_event(db, event_payload["trace_id"])
        assert event_row is not None
        assert event_row["status"] == "success"


class TestRecoverySleepUUIDResolution:
    """Tests for recovery.updated/recovery.deleted events and their sleep->cycle resolution.

    CRITICAL: recovery.updated and recovery.deleted carry the sleep UUID as the
    id field, NOT the recovery id or cycle id. The test must verify that the
    upserted recovery matches what get_cycle_recovery returned, and must be
    written so that treating the id as a recovery_id or cycle_id would fail.
    """

    @respx.mock
    async def test_recovery_updated_resolves_via_sleep_uuid(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Recovery.updated event uses payload id as sleep UUID.

        The critical test: the id field IS a sleep UUID, and we must fetch
        the sleep, extract its cycle_id, then fetch the recovery from that
        cycle. This test mocks get_sleep and get_cycle_recovery to return
        distinct data so using id directly as recovery_id or cycle_id fails.

        The test MUST fail if implementation treats id as recovery_id or
        cycle_id directly.
        """
        user_id = 123
        sleep_id = "sleep-uuid-abc"
        cycle_id = 999

        # Insert principal
        insert_principal(db, user_id)

        # Mock get_sleep: returns the sleep with its cycle_id. This is the
        # only place cycle_id=999 comes from -- a wrong implementation that
        # treats the payload's id (sleep_id) as a cycle_id or recovery_id
        # directly never reads this field, and would instead request
        # /v2/cycle/sleep-uuid-abc/recovery (no matching mock -> respx raises)
        # or otherwise never hit the /v2/cycle/999/recovery route below.
        sleep_record = {
            "id": sleep_id,
            "cycle_id": cycle_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
        }
        sleep_route = respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=sleep_record)
        )

        # Mock get_cycle_recovery: returns the recovery for that cycle
        # Key: the cycle_id here is 999, and we verify the upserted row
        # has cycle_id=999. If the code treated the payload id as a cycle_id
        # (treating sleep_id as if it were a cycle_id), the fetch would fail
        # or return wrong data.
        recovery_record = {
            "cycle_id": cycle_id,
            "created_at": "2026-08-10T10:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": 75.0},
        }
        recovery_route = respx.get(f"{BASE_URL}/v2/cycle/{cycle_id}/recovery").mock(
            return_value=httpx.Response(200, json=recovery_record)
        )

        # Event: recovery.updated, with id=sleep_uuid
        event_payload = create_webhook_event_payload("recovery.updated", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        await process_webhook_event(db, client, raw_body)

        # Assert: get_sleep was called exactly once with sleep_id
        assert sleep_route.called, "get_sleep should have been called"
        sleep_call = sleep_route.calls.last.request
        assert sleep_id in sleep_call.url.path

        # Assert: get_cycle_recovery was called with cycle_id=999
        assert recovery_route.called, "get_cycle_recovery should have been called"
        recovery_call = recovery_route.calls.last.request
        assert str(cycle_id) in recovery_call.url.path

        # Assert: recovery in store has cycle_id=999
        # (from get_cycle_recovery result). If code mistakenly used sleep_id
        # as cycle_id, this assertion fails.
        stored = db.execute(
            "SELECT raw_json FROM recoveries WHERE whoop_user_id = ? AND resource_id = ?",
            (user_id, str(cycle_id)),
        ).fetchone()
        assert stored, f"Recovery should be stored with resource_id={cycle_id}"
        stored_record = json.loads(stored[0])
        assert stored_record["cycle_id"] == cycle_id

    @respx.mock
    async def test_recovery_deleted_skips_fetch_and_sets_deleted_at(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Recovery.deleted event doesn't fetch resource, only sets deleted_at.

        First upsert a recovery, then process a recovery.deleted event for the
        same cycle. The deleted_at timestamp should be set, and no outbound
        fetch should occur.
        """
        user_id = 123
        sleep_id = "sleep-uuid-xyz"
        cycle_id = 999

        insert_principal(db, user_id)

        # Pre-populate the recovery
        from whoopmcp.store import upsert_recovery, upsert_sleep

        recovery_record = {
            "cycle_id": cycle_id,
            "created_at": "2026-08-10T10:00:00Z",
            "score_state": "SCORED",
            "score": {"recovery_score": 75.0},
        }
        upsert_recovery(db, user_id, recovery_record)

        # And the sleep<->cycle mapping recovery.deleted resolves through --
        # from an earlier `sleep.updated` event or backfill (#15). *.deleted
        # must not fetch, so this locally-stored sleep is the only way to
        # find which recovery row's cycle_id the deleted sleep belongs to.
        upsert_sleep(
            db,
            user_id,
            {
                "id": sleep_id,
                "cycle_id": cycle_id,
                "start": "2026-08-10T08:00:00Z",
                "end": "2026-08-10T16:00:00Z",
            },
        )

        # Event: recovery.deleted, id=sleep_uuid
        event_payload = create_webhook_event_payload("recovery.deleted", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        await process_webhook_event(db, client, raw_body)

        # No route was ever registered above (deliberately) -- respx's own
        # `@respx.mock` raises AllMockedAssertionError on any unmocked
        # request, so a fetch here would already have failed the test before
        # this assertion; it exists as an explicit, readable double-check.
        assert len(respx.calls) == 0, "recovery.deleted must not issue any outbound fetch"

        # Assert: deleted_at is set in the recovery row
        stored = db.execute(
            "SELECT raw_json, deleted_at FROM recoveries "
            "WHERE whoop_user_id = ? AND resource_id = ?",
            (user_id, str(cycle_id)),
        ).fetchone()
        assert stored, "Recovery should still exist"
        _, deleted_at = stored
        assert deleted_at is not None

    @respx.mock
    async def test_recovery_deleted_with_no_local_sleep_is_skipped_not_retried(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """recovery.deleted with no locally-stored sleep row: skipped, not dead-lettered.

        The cycle_id mapping can only come from a sleep record already in
        the store (see the test above); if there isn't one -- e.g. this
        server never saw the corresponding sleep.updated event -- there is
        no fetch-free way to resolve it, and *.deleted must not fetch. The
        event is logged and skipped rather than retried (retrying would not
        produce new information) or dead-lettered (this isn't a failure).
        Marked `status="success"` in `webhook_events`, same as a genuinely
        applied event -- "success" here means "handled, nothing further to
        do", not "data was written"; there is no separate status for a
        deliberately-unresolvable skip, and this issue's own scope does not
        ask for one.
        """
        user_id = 123
        sleep_id = "sleep-uuid-never-seen"

        insert_principal(db, user_id)
        # Deliberately no upsert_sleep call -- this is the "no locally-stored
        # sleep" case, unlike the test above.

        event_payload = create_webhook_event_payload("recovery.deleted", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        await process_webhook_event(db, client, raw_body)

        assert len(respx.calls) == 0, "an unresolvable recovery.deleted must not fetch"

        from whoopmcp.store import get_webhook_event

        event_row = get_webhook_event(db, event_payload["trace_id"])
        assert event_row is not None
        assert event_row["status"] == "success"

        # No recovery row exists at all -- nothing was resolved or written.
        recoveries = db.execute(
            "SELECT COUNT(*) FROM recoveries WHERE whoop_user_id = ?", (user_id,)
        ).fetchone()
        assert recoveries[0] == 0


class TestSleepAndWorkoutResolution:
    """Tests for sleep.updated and workout.updated events."""

    @respx.mock
    async def test_sleep_updated_resolves_by_uuid(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Sleep.updated event fetches sleep by its UUID (the id field)."""
        user_id = 123
        sleep_id = "sleep-uuid-001"

        insert_principal(db, user_id)

        sleep_record = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
            "score_state": "SCORED",
            "score": {
                "sleep_performance_percentage": 85.0,
                "sleep_efficiency_percentage": 90.0,
            },
        }
        sleep_route = respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=sleep_record)
        )

        event_payload = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        await process_webhook_event(db, client, raw_body)

        # Assert: get_sleep was called with the correct UUID
        assert sleep_route.called
        sleep_call = sleep_route.calls.last.request
        assert sleep_id in sleep_call.url.path

        # Assert: sleep is in the store with matching UUID
        from whoopmcp.store import get_sleeps

        sleeps = get_sleeps(db, user_id)
        assert len(sleeps) == 1
        assert sleeps[0]["id"] == sleep_id

    @respx.mock
    async def test_workout_updated_resolves_by_uuid(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Workout.updated event fetches workout by its UUID (the id field)."""
        user_id = 456
        workout_id = "workout-uuid-001"

        insert_principal(db, user_id)

        workout_record = {
            "id": workout_id,
            "start": "2026-08-10T18:00:00Z",
            "end": "2026-08-10T19:30:00Z",
            "score_state": "SCORED",
            "sport_name": "Running",
            "score": {"strain": 12.5},
        }
        workout_route = respx.get(f"{BASE_URL}/v2/activity/workout/{workout_id}").mock(
            return_value=httpx.Response(200, json=workout_record)
        )

        event_payload = create_webhook_event_payload("workout.updated", workout_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        await process_webhook_event(db, client, raw_body)

        # Assert: get_workout was called with the correct UUID
        assert workout_route.called
        workout_call = workout_route.calls.last.request
        assert workout_id in workout_call.url.path

        # Assert: workout is in the store with matching UUID
        from whoopmcp.store import get_workouts

        workouts = get_workouts(db, user_id)
        assert len(workouts) == 1
        assert workouts[0]["id"] == workout_id


class TestDeletedEvents:
    """Tests for *.deleted events."""

    @respx.mock
    async def test_sleep_deleted_sets_deleted_at(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Sleep.deleted event sets deleted_at and issues no fetch."""
        user_id = 123
        sleep_id = "sleep-uuid-deleted"

        insert_principal(db, user_id)

        # Pre-populate the sleep
        from whoopmcp.store import upsert_sleep

        sleep_record = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
        }
        upsert_sleep(db, user_id, sleep_record)

        # Event: sleep.deleted
        event_payload = create_webhook_event_payload("sleep.deleted", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        await process_webhook_event(db, client, raw_body)

        # No get_sleep mock registered above -- respx would raise on any
        # unmocked request, so this also confirms no fetch was attempted.
        assert len(respx.calls) == 0

        # Assert: deleted_at is set
        stored = db.execute(
            "SELECT deleted_at FROM sleeps WHERE whoop_user_id = ? AND resource_id = ?",
            (user_id, sleep_id),
        ).fetchone()
        assert stored and stored[0] is not None

    @respx.mock
    async def test_workout_deleted_sets_deleted_at(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Workout.deleted event sets deleted_at and issues no fetch."""
        user_id = 456
        workout_id = "workout-uuid-deleted"

        insert_principal(db, user_id)

        # Pre-populate the workout
        from whoopmcp.store import upsert_workout

        workout_record = {
            "id": workout_id,
            "start": "2026-08-10T18:00:00Z",
            "end": "2026-08-10T19:30:00Z",
        }
        upsert_workout(db, user_id, workout_record)

        # Event: workout.deleted
        event_payload = create_webhook_event_payload("workout.deleted", workout_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        await process_webhook_event(db, client, raw_body)

        # No get_workout mock registered above -- respx would raise on any
        # unmocked request, so this also confirms no fetch was attempted.
        assert len(respx.calls) == 0

        # Assert: deleted_at is set
        stored = db.execute(
            "SELECT deleted_at FROM workouts WHERE whoop_user_id = ? AND resource_id = ?",
            (user_id, workout_id),
        ).fetchone()
        assert stored and stored[0] is not None


class TestUnknownUserHandling:
    """Tests for events with unknown (unresolved) user IDs."""

    @respx.mock
    async def test_event_for_unknown_user_is_dropped_without_error(
        self,
        config: Config,
        auth: Authenticator,
        db: sqlite3.Connection,
        client: WhoopClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Event for a whoop_user_id with no `principal_members` link is
        dropped without a fetch, and left `pending` -- NOT `success` and NOT
        `dead_letter` (#66).

        This is genuinely "not yet actionable", not a success (nothing was
        upserted) and not a failure (nothing is broken; the member simply
        hasn't logged in). Marking it `success` -- the pre-#66 behaviour --
        would make a later redelivery of the same `trace_id` short-circuit
        before ever reaching `_apply_event` again, permanently losing the
        event even after the member does log in.

        `@respx.mock` with no routes registered, matching every other
        zero-fetch test in this file: if a regression ever reordered the
        unknown-user check after the fetch, this must fail loudly and
        offline (`respx.AllMockedAssertionError`), not attempt a real
        network call to the production WHOOP API -- which is exactly what
        would happen without this decorator, silently violating the "never
        call the real API from a test" rule instead of catching it.
        """
        unknown_user_id = 999999
        sleep_id = "sleep-uuid-unknown"

        # Deliberately don't link a principal for this user_id -- no
        # principal_members row, which is the gate _apply_event now checks.

        event_payload = create_webhook_event_payload("sleep.updated", sleep_id, unknown_user_id)
        raw_body = encode_webhook_body(event_payload)

        with caplog.at_level(logging.INFO):
            await process_webhook_event(db, client, raw_body)

        assert len(respx.calls) == 0, "an unlinked member's event must not fetch"

        # The positive half of the log contract: the drop IS logged for a
        # genuinely unlinked member. Its sibling test asserts the same
        # message is ABSENT for a linked member -- a negative-only assertion
        # that would pass vacuously if log capture ever broke, so this
        # companion assertion is what keeps that one honest.
        assert "dropping webhook event for unknown user_id" in caplog.text

        from whoopmcp.store import get_webhook_event

        event_row = get_webhook_event(db, event_payload["trace_id"])
        assert event_row is not None
        assert event_row["status"] not in ("success", "dead_letter")
        assert event_row["status"] == "pending"
        assert event_row["attempt_count"] == 0, "the drop must not consume a retry attempt"

        # Assert: no sleep row exists for this user
        sleeps = db.execute(
            "SELECT COUNT(*) FROM sleeps WHERE whoop_user_id = ?",
            (unknown_user_id,),
        ).fetchone()
        assert sleeps[0] == 0


class TestMembershipGate:
    """Tests for #66: `_apply_event`'s membership gate must key on
    `principal_members` (via `principal_is_linked_to_member`), not the
    never-populated `profiles` table, and a drop for lacking a link must
    never reach `mark_webhook_event_success`."""

    @respx.mock
    async def test_linked_member_with_no_profile_row_is_applied(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """A whoop_user_id with a live `principal_members` row is applied
        (fetch-and-upsert happens) even though no `profiles` row exists for
        that user -- `upsert_profile` has zero callers in `src/`, so a gate
        keyed on `profiles` would drop every event forever."""
        user_id = 123
        sleep_id = "sleep-uuid-linked-no-profile"

        insert_principal(db, user_id)  # principal_members only -- no profiles row

        sleep_record = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
        }
        sleep_route = respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=sleep_record)
        )

        event_payload = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        await process_webhook_event(db, client, raw_body)

        assert sleep_route.called, "a linked member's event must fetch, not drop"

        from whoopmcp.store import get_profile, get_sleeps, get_webhook_event

        assert get_profile(db, user_id) is None, "profiles stays empty -- that's the whole bug"

        sleeps = get_sleeps(db, user_id)
        assert len(sleeps) == 1
        assert sleeps[0]["id"] == sleep_id

        event_row = get_webhook_event(db, event_payload["trace_id"])
        assert event_row is not None
        assert event_row["status"] == "success"

    @respx.mock
    async def test_linked_member_is_not_logged_as_unknown_user(
        self,
        config: Config,
        auth: Authenticator,
        db: sqlite3.Connection,
        client: WhoopClient,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A linked member's event does not get logged as "dropping webhook
        event for unknown user_id" -- that log line is reserved for a
        genuinely unlinked whoop_user_id."""
        user_id = 456
        sleep_id = "sleep-uuid-no-drop-log"

        insert_principal(db, user_id)

        sleep_record = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
        }
        respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=sleep_record)
        )

        event_payload = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        with caplog.at_level(logging.INFO, logger="whoopmcp"):
            await process_webhook_event(db, client, raw_body)

        assert "dropping webhook event for unknown user_id" not in caplog.text

    @respx.mock
    async def test_redelivery_of_dropped_event_reaches_apply_event_again(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """A second delivery of the same trace_id, after a first delivery was
        dropped for lacking a principal link, is not short-circuited by the
        `existing["status"] in ("success", "dead_letter")` check -- it
        reaches `_apply_event` again, and (once the member has since linked)
        actually applies."""
        user_id = 789
        sleep_id = "sleep-uuid-redelivery"

        # Build the payload/body once, and redeliver the exact same bytes --
        # a real WHOOP retry of its own webhook is byte-identical, and this
        # is what keeps both deliveries keyed on the same trace_id.
        event_payload = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        # First delivery: user_id has no principal link yet -- dropped.
        await process_webhook_event(db, client, raw_body)

        assert len(respx.calls) == 0, "first delivery must not fetch: no link yet"

        from whoopmcp.store import get_webhook_event

        event_row = get_webhook_event(db, event_payload["trace_id"])
        assert event_row is not None
        assert event_row["status"] == "pending"

        # The member logs in between deliveries.
        insert_principal(db, user_id)

        sleep_record = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
        }
        sleep_route = respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=sleep_record)
        )

        # Second delivery of the exact same trace_id: must reach
        # _apply_event again now that a link exists, not short-circuit on
        # the still-pending row.
        await process_webhook_event(db, client, raw_body)

        assert sleep_route.called, "redelivery must reach _apply_event, not short-circuit"

        event_row = get_webhook_event(db, event_payload["trace_id"])
        assert event_row is not None
        assert event_row["status"] == "success"


class TestOutOfOrderEventHandling:
    """Tests for out-of-order events and updated_at timestamp checks."""

    @respx.mock
    async def test_out_of_order_event_older_than_stored_does_not_clobber(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Out-of-order event older than stored record doesn't overwrite.

        This is the upsert-on-updated_at pattern: we check the incoming
        record's updated_at against the stored one, and only update if
        incoming >= stored.
        """
        user_id = 123
        sleep_id = "sleep-uuid-ooo"

        insert_principal(db, user_id)

        # First, upsert a "newer" sleep record
        from whoopmcp.store import upsert_sleep

        newer_sleep = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
            "updated_at": "2026-08-10T16:00:00Z",
        }
        upsert_sleep(db, user_id, newer_sleep)

        # Mock get_sleep to return an older version. This is the record
        # actually fetched and compared -- the webhook body's own timestamp
        # (set below) is not itself a signal the processor trusts, since a
        # real WHOOP webhook body carries no such field; the fetched
        # record's own `updated_at` is the only trustworthy ordering signal.
        older_sleep = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T14:00:00Z",  # Different end time
            "updated_at": "2026-08-10T14:00:00Z",
        }

        sleep_route = respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=older_sleep)
        )

        # Event: sleep.updated, with older timestamp
        event_payload = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        # Manually set timestamp to old value
        event_payload["data"]["updated_at"] = "2026-08-10T14:00:00Z"
        raw_body = encode_webhook_body(event_payload)

        await process_webhook_event(db, client, raw_body)

        # The resource is still fetched -- #18's own scope is "one request
        # per event" regardless of ordering -- only the upsert is skipped.
        assert sleep_route.called

        # Assert: the stored record still has the newer end time
        from whoopmcp.store import get_sleeps

        sleeps = get_sleeps(db, user_id)
        assert len(sleeps) == 1
        assert sleeps[0]["end"] == "2026-08-10T16:00:00Z"

    @respx.mock
    async def test_finer_precision_newer_record_is_not_skipped_as_older(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """#140: a genuinely newer record at finer precision must be applied.

        The guard used to compare the two `updated_at` values as strings, which
        matches chronological order only while every value has identical
        precision. `.` (0x2E) sorts below `Z` (0x5A), so
        `...:00.500Z` < `...:00Z` lexicographically -- and a record half a
        second NEWER was discarded as older.

        This is the direction that loses data: the guard exists to stop a stale
        delivery clobbering a newer record, and here it dropped the newer one.
        """
        user_id = 456
        sleep_id = "sleep-uuid-precision"
        insert_principal(db, user_id)

        from whoopmcp.store import get_sleeps, upsert_sleep

        upsert_sleep(
            db,
            user_id,
            {
                "id": sleep_id,
                "start": "2026-08-10T08:00:00Z",
                "end": "2026-08-10T14:00:00Z",
                "updated_at": "2026-08-10T16:00:00Z",
            },
        )

        # Same second, finer precision, genuinely 0.5s newer.
        newer_sleep = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:30:00Z",
            "updated_at": "2026-08-10T16:00:00.500Z",
        }
        respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=newer_sleep)
        )

        payload = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        await process_webhook_event(db, client, encode_webhook_body(payload))

        sleeps = get_sleeps(db, user_id)
        assert len(sleeps) == 1
        assert sleeps[0]["end"] == "2026-08-10T16:30:00Z", (
            "a record 0.5s newer was skipped as older -- the comparison is still lexicographic"
        )


class TestUpdatedAtComparisonIsChronological:
    """#140: the out-of-order guard's comparison, exercised directly.

    Driving `_upsert_if_not_older` rather than a whole webhook round-trip, so
    each case pins one property of the comparison instead of also depending on
    signature verification, fetching and idempotency bookkeeping.
    """

    def _stored(self, db: sqlite3.Connection, user_id: int, sleep_id: str, updated_at: str) -> None:
        from whoopmcp.store import upsert_sleep

        upsert_sleep(
            db,
            user_id,
            {
                "id": sleep_id,
                "start": "2026-08-10T08:00:00Z",
                "end": "2026-08-10T14:00:00Z",
                "updated_at": updated_at,
            },
        )

    def _apply(
        self, db: sqlite3.Connection, user_id: int, sleep_id: str, updated_at: str | None
    ) -> str:
        """Offer a record with `end` moved, and report the stored `end`."""
        from whoopmcp.store import get_sleeps

        record: dict[str, object] = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:30:00Z",
        }
        if updated_at is not None:
            record["updated_at"] = updated_at
        webhook_processor._upsert_if_not_older(db, "sleep", user_id, sleep_id, record)
        return str(get_sleeps(db, user_id)[0]["end"])

    APPLIED = "2026-08-10T16:30:00Z"
    UNCHANGED = "2026-08-10T14:00:00Z"

    def test_same_instant_spelled_with_an_offset_is_not_older(self, db: sqlite3.Connection) -> None:
        """`+00:00` and `Z` are the same instant; `+` (0x2B) sorts below `Z`."""
        insert_principal(db, 1)
        self._stored(db, 1, "s1", "2026-08-10T16:00:00Z")
        assert self._apply(db, 1, "s1", "2026-08-10T16:00:00+00:00") == self.APPLIED

    def test_genuinely_older_at_finer_precision_is_still_skipped(
        self, db: sqlite3.Connection
    ) -> None:
        """The guard must still guard -- the regression that would make the fix
        worthless.

        The old comparison got this **wrong**, and this is the worse of the two
        directions: `Z` (0x5A) sorts above `.` (0x2E), so a plain `...:00Z`
        incoming value read as *newer* than a stored `...:00.500Z` and was
        applied -- a genuinely older record overwriting a newer one. That is the
        state regression this guard exists to prevent, so the guard was failing
        at its own job, not merely dropping updates.
        """
        insert_principal(db, 2)
        self._stored(db, 2, "s2", "2026-08-10T16:00:00.500Z")
        assert self._apply(db, 2, "s2", "2026-08-10T16:00:00Z") == self.UNCHANGED

    def test_equal_timestamps_are_applied(self, db: sqlite3.Connection) -> None:
        """Only *strictly* older is skipped, unchanged from before."""
        insert_principal(db, 3)
        self._stored(db, 3, "s3", "2026-08-10T16:00:00Z")
        assert self._apply(db, 3, "s3", "2026-08-10T16:00:00Z") == self.APPLIED

    def test_unparseable_incoming_upserts_and_warns(
        self, db: sqlite3.Connection, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Not comparable is treated as absent -- upsert -- but logged, since
        this is where the guard silently stops guarding."""
        insert_principal(db, 4)
        self._stored(db, 4, "s4", "2026-08-10T16:00:00Z")
        with caplog.at_level(logging.WARNING, logger="whoopmcp"):
            assert self._apply(db, 4, "s4", "tuesday-ish") == self.APPLIED
        assert any("unparseable incoming updated_at" in r.getMessage() for r in caplog.records)

    def test_absent_incoming_upserts_without_warning(
        self, db: sqlite3.Connection, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An absent `updated_at` is documented, expected, and not a warning --
        only an unparseable one is."""
        insert_principal(db, 5)
        self._stored(db, 5, "s5", "2026-08-10T16:00:00Z")
        with caplog.at_level(logging.WARNING, logger="whoopmcp"):
            assert self._apply(db, 5, "s5", None) == self.APPLIED
        assert not [r for r in caplog.records if "unparseable" in r.getMessage()]

    def test_naive_value_is_read_as_utc_rather_than_raising(self, db: sqlite3.Connection) -> None:
        """A value with no offset must not make the comparison raise on a
        naive/aware mix. It is read as UTC, which is what the string comparison
        this replaced already assumed."""
        insert_principal(db, 6)
        self._stored(db, 6, "s6", "2026-08-10T16:00:00Z")
        # Naive and genuinely older -> still skipped, so it really was compared.
        assert self._apply(db, 6, "s6", "2026-08-10T15:00:00") == self.UNCHANGED

    def test_parsed_updated_at_rejects_non_strings(self) -> None:
        """A non-string must return None rather than raise.

        This matters for the *incoming* side only: `record.get("updated_at")`
        comes straight out of a WHOOP API JSON response, where a number or an
        object is possible. The stored side cannot reach it --
        `get_resource_updated_at` already returns `str | None` -- so this is
        defence at the boundary that can actually see a non-string, not both.
        """
        for value in (None, 12345, {"not": "a timestamp"}, ["2026-08-10T16:00:00Z"]):
            assert webhook_processor._parsed_updated_at(value) is None

    def test_sub_microsecond_difference_compares_equal_and_is_applied(
        self, db: sqlite3.Connection
    ) -> None:
        """A known, accepted cost of parsing: `fromisoformat` truncates past six
        fractional digits, so values differing only in a 7th digit parse equal
        and the incoming one is applied, because only *strictly* older is
        skipped.

        The string comparison this replaced ordered these correctly, so this is
        a narrow regression against it -- pinned here rather than left to be
        rediscovered. WHOOP sends second and millisecond precision; reading the
        remaining digits exactly would mean hand-parsing them for an input that
        does not occur. If WHOOP ever does emit sub-microsecond timestamps, this
        test is the thing that should fail and force the decision again.
        """
        insert_principal(db, 8)
        self._stored(db, 8, "s8", "2026-08-10T16:00:00.1234565Z")
        # 7th digit 1 < 5, so genuinely older -- yet not distinguishable.
        assert self._apply(db, 8, "s8", "2026-08-10T16:00:00.1234561Z") == self.APPLIED

    def test_one_unparseable_value_costs_one_unprotected_write_not_the_guard(
        self, db: sqlite3.Connection
    ) -> None:
        """The fail-open choice's real cost, and its limit.

        `upsert_*` persists `raw_json` verbatim, so an unparseable `updated_at`
        is stored and read back as the stored side next time -- meaning one
        garbled value buys one unprotected write, in which a stale replay lands.
        What it does *not* do is disable the guard permanently: the write that
        lands supplies the new `updated_at`, so once a well-formed value is
        stored the guard works again immediately.

        Pinned because the difference between "one window" and "permanently
        broken" is the whole basis for preferring fail-open here.
        """
        insert_principal(db, 9)
        self._stored(db, 9, "s9", "2026-08-10T16:00:00Z")

        # A garbled value is upserted (fail-open) and now sits in raw_json.
        assert self._apply(db, 9, "s9", "not-a-timestamp") == self.APPLIED

        # One unprotected write: a stale replay overwrites, because the stored
        # side is no longer comparable.
        from whoopmcp.store import get_resource_updated_at, get_sleeps

        webhook_processor._upsert_if_not_older(
            db,
            "sleep",
            9,
            "s9",
            {
                "id": "s9",
                "start": "2026-08-10T08:00:00Z",
                "end": "STALE",
                "updated_at": "2026-08-10T10:00:00Z",
            },
        )
        assert get_sleeps(db, 9)[0]["end"] == "STALE"

        # ...but the guard is functional again: stored is well-formed once more,
        # so a second, older replay is now correctly skipped.
        assert get_resource_updated_at(db, "sleep", 9, "s9") == "2026-08-10T10:00:00Z"
        assert self._apply(db, 9, "s9", "2026-08-10T09:00:00Z") == "STALE", (
            "the guard did not recover after a well-formed value was stored"
        )


class TestRetryAndDeadLetterLogic:
    """Tests for transient failure, retry with backoff, and dead-letter after max attempts."""

    @respx.mock
    async def test_permanently_failing_event_goes_to_dead_letter_after_max(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Failing event is retried 5 times, then goes to dead_letter.

        The failing event does not block the next event in the queue.

        Regression guard for #66: `user_id` here IS linked
        (`insert_principal` below), so `_apply_event` never raises
        `MemberNotLinkedError` -- every failure is a genuine transient
        `WhoopAPIError` from the mocked 500. A real, exhausted-retries
        failure must still land on `dead_letter`, not get swept into the
        new "not yet actionable" `pending` state #66 adds for a different,
        unrelated case.
        """
        user_id = 123
        sleep_id = "sleep-uuid-fail"

        insert_principal(db, user_id)

        # Mock get_sleep to always fail (transient error, e.g., 500)
        respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(500, json={"error": "Internal Server Error"})
        )

        # Event 1: sleep.updated, will fail and eventually dead-letter
        event_payload_1 = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        event_bytes_1 = encode_webhook_body(event_payload_1)

        # Event 2: Another event that should succeed (proves queue isn't blocked)
        sleep_id_2 = "sleep-uuid-ok"
        sleep_record_2 = {
            "id": sleep_id_2,
            "start": "2026-08-10T20:00:00Z",
            "end": "2026-08-10T22:00:00Z",
        }
        respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id_2}").mock(
            return_value=httpx.Response(200, json=sleep_record_2)
        )

        event_payload_2 = create_webhook_event_payload("sleep.updated", sleep_id_2, user_id)
        event_bytes_2 = encode_webhook_body(event_payload_2)

        event_queue: asyncio.Queue[bytes] = asyncio.Queue()
        await event_queue.put(event_bytes_1)
        await event_queue.put(event_bytes_2)
        consumer = asyncio.create_task(
            _consume_webhooks(
                event_queue, db, client, max_attempts=5, clock=fast_forwarding_clock()
            )
        )
        try:
            await asyncio.wait_for(event_queue.join(), timeout=5.0)
        finally:
            consumer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                _ = await consumer

        # Assert: event_1 is in dead_letter status after 5 attempts
        from whoopmcp.store import get_sleeps, get_webhook_event

        event_row = get_webhook_event(db, event_payload_1["trace_id"])
        assert event_row is not None
        assert event_row["status"] == "dead_letter"
        assert event_row["attempt_count"] == 5

        # Assert: event_2 succeeded and is in the store
        sleeps = get_sleeps(db, user_id)
        assert any(s["id"] == sleep_id_2 for s in sleeps), "Event 2 should succeed"


class TestRateLimiterIntegration:
    """Tests that webhook processor respects the rate limiter."""

    @respx.mock
    async def test_webhook_processor_uses_rate_limiter(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Webhook processor acquires from rate limiter before each fetch.

        Same technique as test_client.py's own
        `test_no_http_call_can_bypass_the_rate_limiter`: swap in a limiter
        that always rejects, and confirm the route is never actually hit.
        If webhook_processor issued its fetch some other way than through
        `WhoopClient`'s own rate-limited `_get` (e.g. a raw httpx call),
        the route would still be hit despite the rejecting limiter.
        """
        user_id = 123
        sleep_id = "sleep-uuid-rl"

        insert_principal(db, user_id)

        sleep_record = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
        }
        route = respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=sleep_record)
        )

        class RejectingRateLimiter:
            async def acquire(self, priority: Any = None) -> None:
                raise RuntimeError("rate limiter rejected")

            def reconcile(self, headers: httpx.Headers) -> None:
                pass

        client._rate_limiter = RejectingRateLimiter()  # type: ignore[assignment]

        event_payload = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)

        # max_attempts=1: the rejection is permanent (every attempt hits the
        # same limiter), so this dead-letters immediately without waiting
        # through any backoff.
        await process_webhook_event(db, client, raw_body, max_attempts=1)

        assert route.call_count == 0, "no HTTP call should reach WHOOP without the limiter's grant"

        from whoopmcp.store import get_webhook_event

        event_row = get_webhook_event(db, event_payload["trace_id"])
        assert event_row is not None
        assert event_row["status"] == "dead_letter"


class TestWebhookEventTable:
    """Tests for the webhook_events table structure and idempotency enforcement."""

    def test_webhook_events_table_exists(self, db: sqlite3.Connection) -> None:
        """The webhook_events table exists in schema version 2."""
        # TODO: This test will fail until schema version 2 is implemented.
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='webhook_events'"
        ).fetchall()
        assert len(tables) > 0, "webhook_events table should exist"

    def test_webhook_events_has_trace_id_unique_constraint(self, db: sqlite3.Connection) -> None:
        """The webhook_events table has a UNIQUE constraint on trace_id."""
        from whoopmcp.store import insert_webhook_event

        insert_webhook_event(db, "trace-unique-1", 123, "sleep.updated", "{}")

        with pytest.raises(sqlite3.IntegrityError):
            insert_webhook_event(db, "trace-unique-1", 123, "sleep.updated", "{}")

    def test_webhook_events_tracks_status_and_attempts(self, db: sqlite3.Connection) -> None:
        """Webhook_events tracks status and attempt_count through its lifecycle:
        pending (with a rising attempt_count on each retry), then a terminal
        success or dead_letter.
        """
        from whoopmcp.store import (
            get_webhook_event,
            insert_webhook_event,
            mark_webhook_event_dead_letter,
            mark_webhook_event_retry,
            mark_webhook_event_success,
        )

        insert_webhook_event(db, "trace-status-1", 123, "sleep.updated", "{}")
        row = get_webhook_event(db, "trace-status-1")
        assert row is not None
        assert row["status"] == "pending"
        assert row["attempt_count"] == 0

        mark_webhook_event_retry(db, "trace-status-1", attempt_count=1)
        row = get_webhook_event(db, "trace-status-1")
        assert row is not None
        assert row["status"] == "pending"
        assert row["attempt_count"] == 1

        mark_webhook_event_success(db, "trace-status-1")
        row = get_webhook_event(db, "trace-status-1")
        assert row is not None
        assert row["status"] == "success"

        insert_webhook_event(db, "trace-status-2", 123, "sleep.updated", "{}")
        mark_webhook_event_dead_letter(db, "trace-status-2", attempt_count=5)
        row = get_webhook_event(db, "trace-status-2")
        assert row is not None
        assert row["status"] == "dead_letter"
        assert row["attempt_count"] == 5


# =============================================================================
# Issue #19: local replay -- re-run process_webhook_event against a stored
# event's own event_body, never re-POSTing or re-signing anything.
#
# webhook_events.event_body (store.py) already holds the raw JSON payload,
# and process_webhook_event is idempotent on trace_id (#18) -- reprocessing
# an already-'success' (or 'dead_letter') row is a safe no-op, and that
# idempotency is exactly what makes "replay reproduces the same store state"
# assertable. replay_webhook_event re-encodes the stored event_body and calls
# process_webhook_event directly: it must never issue an HTTP POST back to
# this server's own /webhooks/whoop, and must never touch #17's signature
# verification.
# =============================================================================


class TestWebhookReplay:
    """Tests for #19's `webhook_processor.replay_webhook_event`."""

    @respx.mock
    async def test_replay_reposts_a_stored_event_and_reproduces_the_same_store_state(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """Idempotency (#18) makes this assertable: replaying an
        already-'success' event must reach exactly the same store state as
        the original delivery produced -- no second fetch, no changed row.
        """
        sleep_id = "sleep-replay-1"
        user_id = 123
        insert_principal(db, user_id)

        sleep_record = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
        }
        sleep_route = respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=sleep_record)
        )

        event_payload = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)
        trace_id = event_payload["trace_id"]

        await process_webhook_event(db, client, raw_body)
        assert sleep_route.call_count == 1

        from whoopmcp.store import get_sleeps, get_webhook_event

        before_sleeps = get_sleeps(db, user_id)
        before_event = get_webhook_event(db, trace_id)
        assert before_event is not None
        assert before_event["status"] == "success"

        await replay_webhook_event(db, client, trace_id)

        # Idempotency's own no-op guarantee (#18): the row was already
        # 'success', so replay never re-fetches and never changes the store.
        assert sleep_route.call_count == 1, "replay of an already-success event must not re-fetch"
        assert get_sleeps(db, user_id) == before_sleeps
        assert get_webhook_event(db, trace_id) == before_event

    @respx.mock
    async def test_replay_of_a_pending_event_genuinely_reprocesses(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """A row left 'pending' (mid-retry, or #66's not-yet-actionable
        MemberNotLinkedError state) is not a terminal status -- replay must
        genuinely re-run `_apply_event`, not silently no-op the way an
        already-'success'/'dead_letter' row does. This is replay's real
        operational value: development iteration on a code change, and
        recovering an event that never got a chance to complete."""
        sleep_id = "sleep-replay-2"
        user_id = 123
        insert_principal(db, user_id)

        sleep_record = {
            "id": sleep_id,
            "start": "2026-08-10T08:00:00Z",
            "end": "2026-08-10T16:00:00Z",
        }
        sleep_route = respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id}").mock(
            return_value=httpx.Response(200, json=sleep_record)
        )

        event_payload = create_webhook_event_payload("sleep.updated", sleep_id, user_id)
        raw_body = encode_webhook_body(event_payload)
        trace_id = event_payload["trace_id"]

        await process_webhook_event(db, client, raw_body)
        assert sleep_route.call_count == 1

        from whoopmcp.store import get_webhook_event, mark_webhook_event_retry

        # Force the row back to a non-terminal state, the way a crash
        # mid-retry (or the #66 not-yet-actionable path) would leave it.
        mark_webhook_event_retry(db, trace_id, attempt_count=1)
        pending_event = get_webhook_event(db, trace_id)
        assert pending_event is not None
        assert pending_event["status"] == "pending"

        await replay_webhook_event(db, client, trace_id)

        assert sleep_route.call_count == 2, (
            "a pending row must be genuinely reprocessed, not no-op'd"
        )
        replayed_event = get_webhook_event(db, trace_id)
        assert replayed_event is not None
        assert replayed_event["status"] == "success"

    @respx.mock
    async def test_replay_of_an_unknown_trace_id_raises(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """A trace_id this store has never seen has no `event_body` to
        replay -- raises rather than silently doing nothing, and touches
        neither the client nor the store. No route is mocked at all, so any
        HTTP call would already fail this test via respx's own
        AllMockedAssertionError before the explicit assertion below runs."""
        with pytest.raises(UnknownTraceIdError):
            await replay_webhook_event(db, client, "never-seen-trace-id")

        assert len(respx.calls) == 0


# =============================================================================
# Issue #19: per-user last-delivery time, for #31 (not this issue) to later
# alert on silence. Recorded on every successfully-processed delivery
# (including the *.deleted-with-no-locally-resolvable-cycle and out-of-order
# "vacuous success" skips -- both are still genuine, completed deliveries),
# never on the #66 MemberNotLinkedError path (no delivery has reached an
# actionable identity yet) and never on a retry/dead-letter path.
# =============================================================================


class TestLastDeliveryTracking:
    """Tests for #19's `store.record_webhook_delivery`/`get_last_webhook_delivery`."""

    @respx.mock
    async def test_last_delivery_time_is_recorded_per_user_and_advances_on_delivery(
        self,
        config: Config,
        auth: Authenticator,
        db: sqlite3.Connection,
        client: WhoopClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from whoopmcp.store import get_last_webhook_delivery

        user_id = 123
        insert_principal(db, user_id)

        assert get_last_webhook_delivery(db, user_id) is None

        sleep_id_1 = "sleep-delivery-1"
        respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id_1}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": sleep_id_1,
                    "start": "2026-08-10T08:00:00Z",
                    "end": "2026-08-10T16:00:00Z",
                },
            )
        )
        first_payload = create_webhook_event_payload("sleep.updated", sleep_id_1, user_id)
        await process_webhook_event(db, client, encode_webhook_body(first_payload))

        first_delivery = get_last_webhook_delivery(db, user_id)
        assert first_delivery is not None

        # Advance the store's own clock deterministically, then deliver a
        # second, distinct event for the same user -- the recorded time must
        # strictly advance, not merely "be set" a second time. The module is
        # already imported (via `from whoopmcp.store import open_store`
        # above); fetched from sys.modules rather than a second `import
        # whoopmcp.store` statement so this file uses exactly one import
        # style per module.
        store_module = sys.modules["whoopmcp.store"]

        later = "2099-01-01T00:00:00+00:00"
        monkeypatch.setattr(store_module, "_now", lambda: later)

        sleep_id_2 = "sleep-delivery-2"
        respx.get(f"{BASE_URL}/v2/activity/sleep/{sleep_id_2}").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": sleep_id_2,
                    "start": "2026-08-11T08:00:00Z",
                    "end": "2026-08-11T16:00:00Z",
                },
            )
        )
        second_payload = create_webhook_event_payload("sleep.updated", sleep_id_2, user_id)
        await process_webhook_event(db, client, encode_webhook_body(second_payload))

        second_delivery = get_last_webhook_delivery(db, user_id)
        assert second_delivery is not None
        assert second_delivery > first_delivery
        assert second_delivery == later

    @respx.mock
    async def test_last_delivery_is_not_touched_by_the_member_not_linked_path(
        self, config: Config, auth: Authenticator, db: sqlite3.Connection, client: WhoopClient
    ) -> None:
        """#66's MemberNotLinkedError path is not a completed delivery -- no
        principal has resolved this event to an actionable identity yet, so
        it must not be recorded as a liveness signal for #31."""
        from whoopmcp.store import get_last_webhook_delivery

        unknown_user_id = 999999
        # Deliberately never insert_principal(db, unknown_user_id).

        event_payload = create_webhook_event_payload(
            "sleep.updated", "sleep-unknown-member", unknown_user_id
        )
        await process_webhook_event(db, client, encode_webhook_body(event_payload))

        assert get_last_webhook_delivery(db, unknown_user_id) is None
        assert len(respx.calls) == 0, "an unlinked member's event must never even reach a fetch"
