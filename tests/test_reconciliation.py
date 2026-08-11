"""Tests for issue #19's reconciliation backstop: closing a dropped-webhook hole.

Written ahead of the implementation, per the issue's own instruction. The
issue's "Tests to write" section says explicitly: "A deliberately dropped
event leaves a hole, and the reconciliation sync closes it. This is the test
that justifies the whole issue -- write it first." That test is first in
this file too, ahead of every other case.

The contract under test (see the design notes carried in this branch):

- ``whoopmcp.reconciliation.run_reconciliation(conn, client, config,
  whoop_user_id, *, window_days=DEFAULT_WINDOW_DAYS, now=None)`` covers
  exactly the three resources #18's webhook path understands -- recoveries,
  sleeps, workouts (cycles are out of scope, matching webhook_processor.py).
- #15's own incremental sync (``sync.run_sync``) already independently
  catches a dropped webhook whose underlying record was updated or created,
  because it re-polls WHOOP on an ``updated_at`` high-water mark with no
  dependency on webhooks at all. What #15's mechanism can never catch, by
  construction, is a *deletion*: a record removed upstream simply stops
  appearing in a forward listing, with no signal in ``updated_at`` space.
  Reconciliation supplies exactly that missing mechanism: for a bounded
  recent window, it diffs a fresh listing against what the store holds, and
  soft-deletes (sets ``deleted_at``) any locally-live resource_id the fresh
  listing no longer mentions -- the same column and convention #18's own
  ``*.deleted`` webhook path already uses.
- Every fetch reconciliation issues goes through the real rate limiter at
  ``RequestPriority.BACKFILL``: it is a background backstop an operator
  schedules externally (there is no in-process scheduler -- #35), never a
  user-triggered request, so it must never compete with an interactive tool
  call for the shared per-app WHOOP budget.
- The window bounds the comparison itself, not just the fetch: a locally
  held record whose own date falls outside the window is left alone even if
  a fresh listing (correctly, since that listing is itself bounded to the
  window) omits it.
- Reconciliation is strictly single-member: it must never soft-delete
  another member's rows while reconciling one member's.

Every HTTP call is mocked with respx; the real WHOOP API is never called.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import respx

from whoopmcp.auth import Authenticator, FileTokenStore, Token
from whoopmcp.client import BASE_URL, RequestPriority, WhoopClient
from whoopmcp.config import Config
from whoopmcp.reconciliation import run_reconciliation
from whoopmcp.store import (
    get_recoveries,
    get_sleeps,
    get_workouts,
    link_principal_to_member,
    open_store,
    upsert_sleep,
)

USER_ID = 123
OTHER_USER_ID = 456

#: The three resources reconciliation covers -- exactly #18's webhook path's
#: own set (``_TABLE_BY_RESOURCE``), never cycles.
COLLECTION_PATHS: dict[str, str] = {
    "recoveries": "/v2/recovery",
    "sleeps": "/v2/activity/sleep",
    "workouts": "/v2/activity/workout",
}

EMPTY_PAGE: dict[str, Any] = {"records": [], "next_token": None}


# -- test helpers -------------------------------------------------------------


def make_config(state_dir: Path, **extra: str) -> Config:
    env = {
        "WHOOP_CLIENT_ID": "cid",
        "WHOOP_CLIENT_SECRET": "csecret",
        "WHOOP_REDIRECT_URI": "https://localhost:8443/callback",
        "WHOOPMCP_STATE_DIR": str(state_dir),
        "WHOOPMCP_CACHE": "true",
    } | extra
    return Config.from_env(env)


def make_auth(config: Config) -> Authenticator:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    FileTokenStore(config.token_path).save(
        Token(
            "valid-access-token",
            expires_at=time.time() + 3600,
            refresh_token="valid-refresh-token",
        )
    )
    return Authenticator(config)


def iso(dt: datetime) -> str:
    """WHOOP's own ISO 8601 shape ('Z' suffix), same as every other test
    fixture in this repo (see tests/test_backfill.py's make_record)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def mock_empty_collections(*, except_for: str | None = None) -> dict[str, respx.Route]:
    """Mock every reconciled collection endpoint (bar one) as a single,
    already-exhausted empty page -- the "fresh listing found nothing at all"
    case every non-hole-closing test in this file wants as its baseline.
    Returns the routes actually registered, for a caller that wants to
    inspect the requests they received."""
    routes: dict[str, respx.Route] = {}
    for entity, path in COLLECTION_PATHS.items():
        if entity == except_for:
            continue
        routes[entity] = respx.get(f"{BASE_URL}{path}").mock(
            return_value=httpx.Response(200, json=EMPTY_PAGE)
        )
    return routes


def link(conn: Any, whoop_user_id: int, client_id: str) -> None:
    link_principal_to_member(
        conn, client_id=client_id, issuer="", subject="", whoop_user_id=whoop_user_id
    )


# =============================================================================
# THE test that justifies the whole issue -- written first, per the issue's
# own literal instruction.
# =============================================================================


@respx.mock
async def test_reconciliation_closes_a_hole_left_by_a_dropped_deleted_event(
    tmp_path: Path,
) -> None:
    """A ``sleep.deleted`` webhook is lost before it is ever processed: the
    underlying sleep row stays live in the store forever, because #15's
    incremental sync only ever walks forward on ``updated_at`` and a
    deletion leaves no trace there at all -- the record simply stops
    appearing in a forward listing, which #15's own mechanism cannot notice
    by construction.

    Reconciliation's fresh-listing diff is the only thing that closes this
    hole: it re-lists the window from WHOOP directly, finds the record
    genuinely absent, and soft-deletes it -- provably, per the issue's own
    acceptance criterion.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    sleep_start = now - timedelta(days=2)

    # The hole: a sleep record this store still believes is live, because
    # the webhook that should have told it otherwise never arrived.
    sleep_record = {
        "id": "sleep-hole-1",
        "start": iso(sleep_start),
        "end": iso(sleep_start + timedelta(hours=8)),
        "score_state": "SCORED",
    }
    upsert_sleep(conn, USER_ID, sleep_record)
    assert get_sleeps(conn, USER_ID) == [sleep_record], (
        "the hole must exist before reconciliation runs"
    )

    # A fresh listing straight from WHOOP for this same window: the record
    # genuinely is not there any more (the real-world deletion the lost
    # webhook should have reported). Recoveries and workouts have nothing to
    # report either, which is the ordinary steady-state case for them.
    mock_empty_collections()

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    assert results["sleeps"].fetched == 0
    assert results["sleeps"].closed == 1

    # Provably closed: raw SQL against the row itself, not only the
    # already-filtering getter below.
    row = conn.execute(
        "SELECT deleted_at FROM sleeps WHERE whoop_user_id = ? AND resource_id = ?",
        (USER_ID, "sleep-hole-1"),
    ).fetchone()
    assert row is not None
    assert row[0] is not None, "the hole must be closed: deleted_at should now be set"

    # And the store-backed read every tool actually uses no longer surfaces
    # the deleted record by default -- the hole is closed end to end, not
    # just at the raw-column level.
    assert get_sleeps(conn, USER_ID) == []
    conn.close()


# =============================================================================
# Reconciliation respects the rate limiter.
# =============================================================================


@respx.mock
async def test_reconciliation_respects_the_rate_limiter(tmp_path: Path) -> None:
    """Every fetch reconciliation issues must go through the REAL
    RateLimiter at ``RequestPriority.BACKFILL`` -- mirrors
    tests/test_backfill.py::test_backfill_passes_backfill_priority_to_the_real_rate_limiter
    exactly. Reconciliation is a background backstop an operator schedules
    externally (there is no in-process scheduler -- #35), never a
    user-triggered request, so it must never compete with an interactive
    tool call for the shared per-app WHOOP budget.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")
    mock_empty_collections()

    async with WhoopClient(config, auth) as client:
        limiter = client._rate_limiter
        recorded: list[RequestPriority] = []
        original_acquire = limiter.acquire

        async def spying_acquire(
            priority: RequestPriority = RequestPriority.INTERACTIVE,
        ) -> None:
            recorded.append(priority)
            await original_acquire(priority)

        limiter.acquire = spying_acquire  # type: ignore[method-assign]
        await run_reconciliation(conn, client, config, USER_ID)

    # One page per reconciled collection (recoveries, sleeps, workouts),
    # every single acquire at BACKFILL priority -- never falling through to
    # the INTERACTIVE default.
    assert len(recorded) == len(COLLECTION_PATHS)
    assert all(priority is RequestPriority.BACKFILL for priority in recorded)
    conn.close()


# =============================================================================
# The window bounds the comparison itself, not only the fetch.
# =============================================================================


@respx.mock
async def test_reconciliation_never_touches_rows_outside_the_window(tmp_path: Path) -> None:
    """A locally-held record whose own date falls outside ``window_days`` is
    left alone even though a fresh listing (correctly, since that listing is
    itself bounded to the window) never mentions it either -- proving the
    window actually bounds the *comparison*, not merely how far back the
    fetch reaches."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    old_start = now - timedelta(days=100)  # well outside a 30-day window

    old_sleep = {
        "id": "sleep-old",
        "start": iso(old_start),
        "end": iso(old_start + timedelta(hours=8)),
        "score_state": "SCORED",
    }
    upsert_sleep(conn, USER_ID, old_sleep)

    mock_empty_collections()

    async with WhoopClient(config, auth) as client:
        await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    row = conn.execute(
        "SELECT deleted_at FROM sleeps WHERE whoop_user_id = ? AND resource_id = ?",
        (USER_ID, "sleep-old"),
    ).fetchone()
    assert row is not None
    assert row[0] is None, "a record outside the reconciliation window must never be touched"
    conn.close()


# =============================================================================
# A record the fresh listing DOES report must survive -- the direct
# counterpart to the hole-closing test above, and the one case a "soft-delete
# everything in the local window" regression would still pass without.
# =============================================================================


@respx.mock
async def test_reconciliation_never_soft_deletes_a_record_present_in_the_fresh_listing(
    tmp_path: Path,
) -> None:
    """A locally-held record that the fresh listing still reports must
    survive untouched -- this is the assertion a regression at
    ``missing = local_ids`` (dropping the ``- fresh_ids`` half of the diff
    entirely) would still pass every OTHER test in this file without,
    since every other test's fresh listing is empty."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    sleep_start = now - timedelta(days=2)
    sleep_record = {
        "id": "sleep-still-live",
        "start": iso(sleep_start),
        "end": iso(sleep_start + timedelta(hours=8)),
        "score_state": "SCORED",
    }
    upsert_sleep(conn, USER_ID, sleep_record)

    for entity, path in COLLECTION_PATHS.items():
        body = {"records": [sleep_record], "next_token": None} if entity == "sleeps" else EMPTY_PAGE
        respx.get(f"{BASE_URL}{path}").mock(return_value=httpx.Response(200, json=body))

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    assert results["sleeps"].fetched == 1
    assert results["sleeps"].closed == 0
    row = conn.execute(
        "SELECT deleted_at FROM sleeps WHERE whoop_user_id = ? AND resource_id = ?",
        (USER_ID, "sleep-still-live"),
    ).fetchone()
    assert row is not None
    assert row[0] is None, "a record the fresh listing still reports must never be soft-deleted"
    conn.close()


# =============================================================================
# The full fresh listing is paginated through before diffing -- a record on
# a later page must never be mistaken for missing just because it wasn't on
# the first one.
# =============================================================================


@respx.mock
async def test_reconciliation_paginates_the_fresh_listing_before_diffing(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    sleep_start = now - timedelta(days=2)
    page_two_record = {
        "id": "sleep-on-page-two",
        "start": iso(sleep_start),
        "end": iso(sleep_start + timedelta(hours=8)),
        "score_state": "SCORED",
    }
    upsert_sleep(conn, USER_ID, page_two_record)

    pages: dict[str | None, dict[str, Any]] = {
        None: {"records": [], "next_token": "tok2"},
        "tok2": {"records": [page_two_record], "next_token": None},
    }

    def sleep_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=pages[request.url.params.get("nextToken")])

    mock_empty_collections(except_for="sleeps")
    respx.get(f"{BASE_URL}{COLLECTION_PATHS['sleeps']}").mock(side_effect=sleep_handler)

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    # Both pages walked (two acquires for sleeps: the empty first page's
    # next_token led to a second request), and the second page's own record
    # counted as fetched, not as a hole.
    assert results["sleeps"].fetched == 1
    assert results["sleeps"].closed == 0
    row = conn.execute(
        "SELECT deleted_at FROM sleeps WHERE whoop_user_id = ? AND resource_id = ?",
        (USER_ID, "sleep-on-page-two"),
    ).fetchone()
    assert row is not None
    assert row[0] is None, "a record on a later fresh-listing page must never look missing"
    conn.close()


# =============================================================================
# The fresh fetch's own lower bound is wider than the local comparison
# window -- the fix for the recovery/related-sleep timeframe skew a real
# WHOOP API semantics mismatch can otherwise cause (verified against WHOOP's
# own published API reference, not assumed).
# =============================================================================


@respx.mock
async def test_reconciliation_fresh_fetch_start_is_earlier_than_the_comparison_window(
    tmp_path: Path,
) -> None:
    """The literal HTTP request reconciliation issues must use a ``start``
    earlier than the window it's reconciling, by exactly
    ``_FRESH_FETCH_MARGIN_DAYS`` -- mechanically verifying the fix, not just
    its behavioural consequence."""
    from whoopmcp.reconciliation import _FRESH_FETCH_MARGIN_DAYS

    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")
    now = datetime(2026, 8, 10, tzinfo=UTC)

    routes = mock_empty_collections()

    async with WhoopClient(config, auth) as client:
        await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    expected_window_start = iso(now - timedelta(days=30))
    expected_fresh_start = iso(now - timedelta(days=30 + _FRESH_FETCH_MARGIN_DAYS))
    assert expected_fresh_start != expected_window_start
    for entity, route in routes.items():
        assert route.calls[0].request.url.params.get("start") == expected_fresh_start, (
            f"{entity}'s fresh fetch must use the widened bound, not the bare window_start"
        )
    conn.close()


# =============================================================================
# Reconciliation is strictly single-member.
# =============================================================================


@respx.mock
async def test_reconciliation_never_soft_deletes_a_second_members_rows(tmp_path: Path) -> None:
    """Cross-tenant guard, analogous to tests/test_tenancy.py's own pattern:
    reconciling USER_ID must never soft-delete OTHER_USER_ID's rows, even
    though OTHER_USER_ID's row would look exactly like a dropped-deletion
    hole if reconciliation were (wrongly) run against every member's data at
    once instead of the one it was asked to reconcile."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")
    link(conn, OTHER_USER_ID, "client-b")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    recent_start = now - timedelta(days=1)

    other_sleep = {
        "id": "sleep-other-member",
        "start": iso(recent_start),
        "end": iso(recent_start + timedelta(hours=8)),
        "score_state": "SCORED",
    }
    upsert_sleep(conn, OTHER_USER_ID, other_sleep)

    # USER_ID has nothing live at all; the fresh listing (for USER_ID's own
    # client/grant) is empty too -- an entirely uneventful run for USER_ID.
    mock_empty_collections()

    async with WhoopClient(config, auth) as client:
        await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    row = conn.execute(
        "SELECT deleted_at FROM sleeps WHERE whoop_user_id = ? AND resource_id = ?",
        (OTHER_USER_ID, "sleep-other-member"),
    ).fetchone()
    assert row is not None
    assert row[0] is None, "reconciling one member must never touch another member's rows"
    assert get_workouts(conn, OTHER_USER_ID) == []
    assert get_recoveries(conn, OTHER_USER_ID) == []
    conn.close()
