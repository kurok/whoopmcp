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
import time
import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from whoopmcp.auth import Authenticator, FileTokenStore, Token
from whoopmcp.client import BASE_URL, WhoopClient
from whoopmcp.config import Config
from whoopmcp.store import open_store
from whoopmcp.webhook_processor import _consume_webhooks, process_webhook_event

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
