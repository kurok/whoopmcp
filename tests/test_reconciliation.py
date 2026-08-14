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
from whoopmcp.reconciliation import CLOSE_LIMIT_PER_RUN, run_reconciliation
from whoopmcp.store import (
    get_cycles,
    get_recoveries,
    get_sleeps,
    get_workouts,
    link_principal_to_member,
    open_store,
    upsert_cycle,
    upsert_recovery,
    upsert_sleep,
)

USER_ID = 123
OTHER_USER_ID = 456

#: The collections reconciliation walks. Three of them are also #18's webhook
#: set and can be soft-deleted; cycles are walked for update detection only
#: (#185), so a corrected `strain` has a path back without cycles gaining a
#: deletion path nothing has validated.
COLLECTION_PATHS: dict[str, str] = {
    "recoveries": "/v2/recovery",
    "sleeps": "/v2/activity/sleep",
    "workouts": "/v2/activity/workout",
    # Cycles joined the walk with #185, for update detection only -- they are
    # never soft-deleted. See `_ReconcileSpec.soft_deletes`.
    "cycles": "/v2/cycle",
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


# =============================================================================
# #175: an empty listing must not be trusted to wipe a populated window, and a
# row written *during* the fetch must not be deleted by that same run.
#
# Both tests assert on the rows that are still live afterwards, never on the
# absence of an exception. Neither of these bugs raised anything -- they exited
# 0 and printed a "finished" summary -- so a test that only checked for a clean
# run would have passed against the broken code, which is exactly how the
# analogous gap in #155 stayed hidden.
# =============================================================================


@respx.mock
async def test_empty_listing_does_not_wipe_a_populated_window(tmp_path: Path) -> None:
    """WHOOP answers 200 with an empty page while the store holds a full
    window. An empty listing and a failed one are indistinguishable here, so
    reconciliation declines to close rather than deleting everything.

    This is not a recoverable mistake: nothing in the codebase ever sets
    ``deleted_at`` back to NULL, and the upserts' ``ON CONFLICT`` clauses do
    not touch it -- so re-syncing rewrites the row and leaves it invisible.
    A wrong deletion here destroys the member's history permanently.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    held = []
    for day in range(1, 8):  # 7 records -- above CLOSE_LIMIT_PER_RUN
        start = now - timedelta(days=day)
        record = {
            "id": f"sleep-live-{day}",
            "start": iso(start),
            "end": iso(start + timedelta(hours=8)),
            "score_state": "SCORED",
        }
        upsert_sleep(conn, USER_ID, record)
        held.append(record)
    assert len(get_sleeps(conn, USER_ID)) == 7

    mock_empty_collections()

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    # The point of the test: every record is still live. Asserting on the
    # survivors, not on a clean exit -- the broken version exited cleanly too.
    survivors = get_sleeps(conn, USER_ID)
    assert len(survivors) == 7
    assert {r["id"] for r in survivors} == {r["id"] for r in held}

    # And nothing was soft-deleted at the column level either.
    wiped = conn.execute(
        "SELECT COUNT(*) FROM sleeps WHERE whoop_user_id = ? AND deleted_at IS NOT NULL",
        (USER_ID,),
    ).fetchone()[0]
    assert wiped == 0

    # The refusal is reported, not silent: a run that declines to delete must
    # not look identical to one that found nothing to delete.
    assert results["sleeps"].closed == 0
    assert results["sleeps"].withheld is not None
    assert "declining to close" in results["sleeps"].withheld
    conn.close()


@respx.mock
async def test_record_written_during_the_fetch_is_not_deleted(tmp_path: Path) -> None:
    """The store is shared: the server process's webhook handler and a
    concurrent ``whoop_sync`` both write to the same sqlite file while
    ``reconcile-webhooks`` runs as a cron job. A record that arrives while
    reconciliation is paginating cannot appear in the fresh listing that was
    already in flight -- so reading the local set *after* the fetch soft-deleted
    it at birth.

    Here a webhook lands between page 1 and page 2. The new record must still
    be live when the run finishes.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    old_start = now - timedelta(days=3)
    old_record = {
        "id": "sleep-known",
        "start": iso(old_start),
        "end": iso(old_start + timedelta(hours=8)),
        "score_state": "SCORED",
    }
    upsert_sleep(conn, USER_ID, old_record)

    # The record the webhook handler writes mid-fetch. WHOOP's listing was
    # generated before it existed, so it is in no page of this response.
    arrival_start = now - timedelta(days=1)
    arrival = {
        "id": "sleep-arrived-mid-fetch",
        "start": iso(arrival_start),
        "end": iso(arrival_start + timedelta(hours=7)),
        "score_state": "SCORED",
    }

    pages = iter(
        [
            {"records": [old_record], "next_token": "page-2"},
            {"records": [], "next_token": None},
        ]
    )

    def paginate(request: httpx.Request) -> httpx.Response:
        page = next(pages)
        if page["next_token"] == "page-2":
            # Between the two pages, a concurrent writer commits a new row.
            upsert_sleep(conn, USER_ID, arrival)
        return httpx.Response(200, json=page)

    respx.get(f"{BASE_URL}{COLLECTION_PATHS['sleeps']}").mock(side_effect=paginate)
    mock_empty_collections(except_for="sleeps")

    async with WhoopClient(config, auth) as client:
        await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    live = {record["id"] for record in get_sleeps(conn, USER_ID)}
    assert "sleep-arrived-mid-fetch" in live, (
        "a record written during the fetch must survive the run that could not have seen it"
    )
    assert "sleep-known" in live, "the record the listing confirmed must stay live too"
    conn.close()


@respx.mock
async def test_empty_listing_still_closes_a_window_at_the_limit(tmp_path: Path) -> None:
    """The guard above separates "a hole to close" from "a wipe to refuse" by
    size, so the boundary is the whole contract: at
    ``CLOSE_LIMIT_PER_RUN`` records an empty listing still closes them,
    and one more refuses.

    Pinned explicitly because both halves fail silently. Turning ``>`` into
    ``>=`` would quietly narrow reconciliation by one record, and neither the
    hole-closing test above (1 record) nor the wipe test (7) would notice.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)

    async def closed_count(held: int) -> int:
        conn = open_store(":memory:")
        link(conn, USER_ID, "client-a")
        now = datetime(2026, 8, 10, tzinfo=UTC)
        for day in range(1, held + 1):
            start = now - timedelta(days=day)
            upsert_sleep(
                conn,
                USER_ID,
                {
                    "id": f"sleep-{day}",
                    "start": iso(start),
                    "end": iso(start + timedelta(hours=8)),
                    "score_state": "SCORED",
                },
            )
        async with WhoopClient(config, auth) as client:
            results = await run_reconciliation(
                conn, client, config, USER_ID, window_days=30, now=now
            )
        surviving = len(get_sleeps(conn, USER_ID))
        conn.close()
        assert surviving == held - results["sleeps"].closed
        return int(results["sleeps"].closed)

    mock_empty_collections()

    assert await closed_count(CLOSE_LIMIT_PER_RUN) == CLOSE_LIMIT_PER_RUN
    assert await closed_count(CLOSE_LIMIT_PER_RUN + 1) == 0


@respx.mock
async def test_truncated_listing_does_not_mass_soft_delete(tmp_path: Path) -> None:
    """WHOOP answers one page of records whose ``next_token`` is wrongly
    absent, ending pagination early -- the second looks-successful failure
    this module's own docstring has named since #175, and the one its
    ``fetched == 0`` guard could not see (#197): the run fetched *something*,
    so it sailed past the empty-listing check and soft-deleted every
    in-window record that didn't fit on the one page it got.

    Like the empty-listing case, this is unrecoverable when it goes wrong:
    nothing ever clears ``deleted_at``, so the close limit must bound what a
    run closes, not merely whether it fetched anything at all.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    held = []
    for day in range(1, 31):  # 30 records, a populated window
        start = now - timedelta(days=day)
        record = {
            "id": f"sleep-live-{day}",
            "start": iso(start),
            "end": iso(start + timedelta(hours=8)),
            "score_state": "SCORED",
        }
        upsert_sleep(conn, USER_ID, record)
        held.append(record)

    # The truncated listing: the first 5 held records come back, then the
    # walk ends -- no next_token -- even though 25 more are genuinely live
    # upstream. Indistinguishable from 25 real deletions, so it must be
    # refused, not trusted.
    respx.get(f"{BASE_URL}{COLLECTION_PATHS['sleeps']}").mock(
        return_value=httpx.Response(200, json={"records": held[:5], "next_token": None})
    )
    mock_empty_collections(except_for="sleeps")

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    # Every record is still live -- asserting on the survivors, since the
    # broken version exits cleanly too.
    survivors = get_sleeps(conn, USER_ID)
    assert len(survivors) == 30
    assert {r["id"] for r in survivors} == {r["id"] for r in held}

    # And the refusal is reported, not silent.
    assert results["sleeps"].fetched == 5
    assert results["sleeps"].closed == 0
    assert results["sleeps"].withheld is not None
    assert "declining to close" in results["sleeps"].withheld
    conn.close()


@respx.mock
async def test_partial_listing_still_closes_within_the_limit(tmp_path: Path) -> None:
    """The partial-listing half of the boundary contract: a non-empty,
    complete listing that omits no more than ``CLOSE_LIMIT_PER_RUN``
    locally-live records still closes them -- #197's guard bounds the wipe
    case without disabling ordinary hole-closing alongside live records.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    held = []
    for day in range(1, 11):  # 10 records held
        start = now - timedelta(days=day)
        record = {
            "id": f"sleep-live-{day}",
            "start": iso(start),
            "end": iso(start + timedelta(hours=8)),
            "score_state": "SCORED",
        }
        upsert_sleep(conn, USER_ID, record)
        held.append(record)

    # The fresh listing confirms all but CLOSE_LIMIT_PER_RUN of them -- a
    # plausible burst of dropped *.deleted events, exactly what this module
    # exists to backstop.
    fresh = held[CLOSE_LIMIT_PER_RUN:]
    respx.get(f"{BASE_URL}{COLLECTION_PATHS['sleeps']}").mock(
        return_value=httpx.Response(200, json={"records": fresh, "next_token": None})
    )
    mock_empty_collections(except_for="sleeps")

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    assert results["sleeps"].fetched == len(fresh)
    assert results["sleeps"].closed == CLOSE_LIMIT_PER_RUN
    assert results["sleeps"].withheld is None
    survivors = {r["id"] for r in get_sleeps(conn, USER_ID)}
    assert survivors == {r["id"] for r in fresh}
    conn.close()


# =============================================================================
# Issue #185: Update-detection for records rescored after the occurrence
# window has passed the sync high-water mark.
# =============================================================================


@respx.mock
async def test_reconciliation_detects_and_applies_recovery_updates(tmp_path: Path) -> None:
    """TEST 1: A recovery is stored with an old `updated_at`. WHOOP's fresh
    listing returns the SAME id with a NEWER `updated_at` and a changed score.
    After reconciliation, the STORED record must hold the new score. This is
    the test that justifies issue #185 -- the whole reason update-detection
    exists."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    sleep_start = now - timedelta(days=2)

    # Store a recovery with an old updated_at and a recovery_score.
    old_recovery = {
        "cycle_id": "cycle-1",
        "created_at": iso(sleep_start),
        "score_state": "SCORED",
        "score": {"recovery_score": 50.0},
        "updated_at": iso(now - timedelta(days=2)),
    }
    upsert_recovery(conn, USER_ID, old_recovery)
    stored = get_recoveries(conn, USER_ID)
    assert len(stored) == 1
    assert stored[0]["score"]["recovery_score"] == 50.0, "baseline: old recovery_score is stored"

    # WHOOP's fresh listing returns the SAME cycle_id with a NEWER updated_at
    # and a CHANGED score.
    fresh_recovery = {
        "cycle_id": "cycle-1",
        "created_at": iso(sleep_start),
        "score_state": "SCORED",
        "score": {"recovery_score": 75.0},
        "updated_at": iso(now),  # Much newer
    }

    # Mock only the recoveries endpoint to return the fresh record.
    respx.get(f"{BASE_URL}{COLLECTION_PATHS['recoveries']}").mock(
        return_value=httpx.Response(200, json={"records": [fresh_recovery], "next_token": None})
    )
    mock_empty_collections(except_for="recoveries")

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    # After reconciliation, the stored recovery must reflect the new score.
    updated = get_recoveries(conn, USER_ID)
    assert len(updated) == 1
    assert updated[0]["score"]["recovery_score"] == 75.0, (
        "the stored recovery_score must be updated to the fresh value"
    )

    # ReconciliationResult must report the update.
    assert results["recoveries"].updated == 1, (
        "ReconciliationResult.updated must count this correction"
    )
    conn.close()


@respx.mock
async def test_reconciliation_does_not_upsert_unchanged_records(tmp_path: Path) -> None:
    """TEST 2: A fresh record whose `updated_at` is UNCHANGED is not
    re-upserted. This test pins 'strictly newer' -- an unconditional
    upsert-everything would pass a naive test."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    sleep_start = now - timedelta(days=2)
    unchanged_at = iso(now - timedelta(days=1))

    # Store a recovery with a certain updated_at.
    sleep_record = {
        "cycle_id": "cycle-2",
        "created_at": iso(sleep_start),
        "score_state": "SCORED",
        "score": {"recovery_score": 60.0},
        "updated_at": unchanged_at,
    }
    upsert_recovery(conn, USER_ID, sleep_record)

    # Fresh listing returns the exact same record (same updated_at, no changes).
    fresh_record = {
        "cycle_id": "cycle-2",
        "created_at": iso(sleep_start),
        "score_state": "SCORED",
        "score": {"recovery_score": 60.0},
        "updated_at": unchanged_at,  # Identical, not newer
    }

    # Asserted on the reported count, not on a patched upsert. Patching
    # `store.upsert_recovery` does nothing here: `_RECONCILE_SPECS` captures the
    # function object when reconciliation.py is imported, so `spec.upsert` still
    # points at the original and the spy never fires -- the assertion passed
    # unconditionally, including against a build that wrote on every equal
    # timestamp. Verified by mutating `>` to `>=`, which the spy version did not
    # catch and this does.
    respx.get(f"{BASE_URL}{COLLECTION_PATHS['recoveries']}").mock(
        return_value=httpx.Response(200, json={"records": [fresh_record], "next_token": None})
    )
    mock_empty_collections(except_for="recoveries")

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    assert results["recoveries"].updated == 0, (
        "an unchanged `updated_at` is not a correction and must not be rewritten"
    )
    assert results["recoveries"].fetched == 1, "the record was still seen, just not rewritten"
    conn.close()


@respx.mock
async def test_reconciliation_does_not_overwrite_with_older_records(tmp_path: Path) -> None:
    """TEST 3: A fresh record with an OLDER `updated_at` than the stored one
    does not overwrite the newer local copy. The stored value must still be
    the newer one."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    sleep_start = now - timedelta(days=2)
    older_at = iso(now - timedelta(days=2))
    newer_at = iso(now - timedelta(days=1))

    # Store a recovery with a NEWER updated_at and score 75.
    stored_recovery = {
        "cycle_id": "cycle-3",
        "created_at": iso(sleep_start),
        "score_state": "SCORED",
        "score": {"recovery_score": 75.0},
        "updated_at": newer_at,
    }
    upsert_recovery(conn, USER_ID, stored_recovery)

    # Fresh listing returns the SAME cycle_id but with an OLDER updated_at
    # and different (older?) score.
    stale_recovery = {
        "cycle_id": "cycle-3",
        "created_at": iso(sleep_start),
        "score_state": "SCORED",
        "score": {"recovery_score": 50.0},  # Older score
        "updated_at": older_at,  # Older timestamp
    }

    respx.get(f"{BASE_URL}{COLLECTION_PATHS['recoveries']}").mock(
        return_value=httpx.Response(200, json={"records": [stale_recovery], "next_token": None})
    )
    mock_empty_collections(except_for="recoveries")

    async with WhoopClient(config, auth) as client:
        await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    # The stored recovery must still have the newer score.
    updated = get_recoveries(conn, USER_ID)
    assert len(updated) == 1
    assert updated[0]["score"]["recovery_score"] == 75.0, (
        "the stored recovery_score must NOT be overwritten by a stale update"
    )
    conn.close()


@respx.mock
async def test_reconciliation_detects_and_applies_cycle_updates(tmp_path: Path) -> None:
    """TEST 4: CYCLES get updates. A cycle is stored with an old `updated_at`.
    WHOOP's fresh listing returns the SAME id with a NEWER `updated_at` and a
    changed `strain`. After reconciliation, the STORED cycle must hold the new
    strain. This is the coverage gap the fix exists to close."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    cycle_start = now - timedelta(days=2)

    # Store a cycle with an old updated_at and a strain value.
    old_cycle = {
        "id": "cycle-old-1",
        "start": iso(cycle_start),
        "end": iso(cycle_start + timedelta(hours=24)),
        "score_state": "SCORED",
        "score": {"strain": 4.5},
        "updated_at": iso(now - timedelta(days=2)),
    }
    upsert_cycle(conn, USER_ID, old_cycle)
    stored = get_cycles(conn, USER_ID)
    assert len(stored) == 1
    assert stored[0]["score"]["strain"] == 4.5, "baseline: old cycle strain is stored"

    # WHOOP's fresh listing returns the SAME id with a NEWER updated_at
    # and a CHANGED strain.
    fresh_cycle = {
        "id": "cycle-old-1",
        "start": iso(cycle_start),
        "end": iso(cycle_start + timedelta(hours=24)),
        "score_state": "SCORED",
        "score": {"strain": 6.2},  # Different strain
        "updated_at": iso(now),  # Much newer
    }

    # `except_for="cycles"` matters: cycles joined COLLECTION_PATHS with #185, so
    # an unqualified mock_empty_collections() would re-register /v2/cycle as
    # empty and shadow the fresh listing this test is about.
    mock_empty_collections(except_for="cycles")
    respx.get(f"{BASE_URL}/v2/cycle").mock(
        return_value=httpx.Response(200, json={"records": [fresh_cycle], "next_token": None})
    )

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    # After reconciliation, the stored cycle must reflect the new strain.
    updated = get_cycles(conn, USER_ID)
    assert len(updated) == 1
    assert updated[0]["score"]["strain"] == 6.2, (
        "the stored cycle strain must be updated to the fresh value"
    )

    # ReconciliationResult must report the update for cycles.
    assert results["cycles"].updated == 1, (
        "ReconciliationResult.updated must count this cycle correction"
    )
    conn.close()


@respx.mock
async def test_reconciliation_never_soft_deletes_cycles(tmp_path: Path) -> None:
    """TEST 5: CYCLES ARE NEVER SOFT-DELETED. A locally-held cycle absent from
    the fresh listing must remain live (`deleted_at IS NULL`). This is the
    safety property of the decoupled design -- if it regresses, cycles gain a
    deletion path silently."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    cycle_start = now - timedelta(days=2)

    # Store a cycle that will NOT appear in the fresh listing.
    cycle_record = {
        "id": "cycle-missing",
        "start": iso(cycle_start),
        "end": iso(cycle_start + timedelta(hours=24)),
        "score_state": "SCORED",
        "score": {"strain": 5.0},
        "updated_at": iso(now - timedelta(days=1)),
    }
    upsert_cycle(conn, USER_ID, cycle_record)
    assert len(get_cycles(conn, USER_ID)) == 1, "baseline: cycle is stored"

    # Fresh listing returns nothing (empty page).
    respx.get(f"{BASE_URL}/v2/cycle").mock(
        return_value=httpx.Response(200, json={"records": [], "next_token": None})
    )
    # Also mock the other endpoints to be empty.
    mock_empty_collections(except_for=None)

    async with WhoopClient(config, auth) as client:
        await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    # The cycle must still be live: raw SQL check.
    row = conn.execute(
        "SELECT deleted_at FROM cycles WHERE whoop_user_id = ? AND resource_id = ?",
        (USER_ID, "cycle-missing"),
    ).fetchone()
    assert row is not None
    assert row[0] is None, "cycles must NEVER be soft-deleted, even if absent from fresh listing"

    # And get_cycles must still return it.
    survivors = get_cycles(conn, USER_ID)
    assert len(survivors) == 1, (
        "get_cycles must still return the cycle (with include_deleted=False default)"
    )
    conn.close()


@respx.mock
async def test_reconciliation_deletion_and_update_coexist_in_single_run(tmp_path: Path) -> None:
    """TEST 6: Deletion still works for the three that had it, and
    update-detection coexists in a single run. One record is corrected, a
    different one is closed."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    sleep_start = now - timedelta(days=2)

    # Store two sleeps: one to be updated, one to be deleted.
    updated_sleep = {
        "id": "sleep-to-update",
        "start": iso(sleep_start),
        "end": iso(sleep_start + timedelta(hours=8)),
        "score_state": "SCORED",
        "sleep_performance_percentage": 80.0,
        "updated_at": iso(now - timedelta(days=2)),
    }
    upsert_sleep(conn, USER_ID, updated_sleep)

    deleted_sleep = {
        "id": "sleep-to-delete",
        "start": iso(sleep_start + timedelta(days=1)),
        "end": iso(sleep_start + timedelta(days=1, hours=8)),
        "score_state": "SCORED",
        "sleep_performance_percentage": 85.0,
        "updated_at": iso(now - timedelta(days=1)),
    }
    upsert_sleep(conn, USER_ID, deleted_sleep)

    # Fresh listing returns only the updated sleep with a new score.
    fresh_sleep = {
        "id": "sleep-to-update",
        "start": iso(sleep_start),
        "end": iso(sleep_start + timedelta(hours=8)),
        "score_state": "SCORED",
        "sleep_performance_percentage": 92.0,  # Changed
        "updated_at": iso(now),  # Newer
    }

    respx.get(f"{BASE_URL}{COLLECTION_PATHS['sleeps']}").mock(
        return_value=httpx.Response(200, json={"records": [fresh_sleep], "next_token": None})
    )
    mock_empty_collections(except_for="sleeps")

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    # The updated sleep must have the new score.
    survivors = get_sleeps(conn, USER_ID)
    updated_survivors = [s for s in survivors if s["id"] == "sleep-to-update"]
    assert len(updated_survivors) == 1
    assert updated_survivors[0]["sleep_performance_percentage"] == 92.0, (
        "the sleep must be updated with the new score"
    )

    # The deleted sleep must be gone.
    deleted_survivors = [s for s in survivors if s["id"] == "sleep-to-delete"]
    assert len(deleted_survivors) == 0, "the sleep not in fresh listing must be soft-deleted"

    # Both operations reported.
    assert results["sleeps"].updated == 1, "one sleep was updated"
    assert results["sleeps"].closed == 1, "one sleep was deleted"
    conn.close()


@respx.mock
async def test_reconciliation_result_updated_counts_corrections(tmp_path: Path) -> None:
    """TEST 7: `ReconciliationResult.updated` counts corrections, and is 0 on a
    run with none."""
    config = make_config(tmp_path)
    auth = make_auth(config)

    # Case 1: no corrections
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")
    now = datetime(2026, 8, 10, tzinfo=UTC)

    mock_empty_collections()

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    assert results["recoveries"].updated == 0, "no updates: updated must be 0"
    assert results["sleeps"].updated == 0
    assert results["workouts"].updated == 0
    assert results["cycles"].updated == 0
    conn.close()

    # Case 2: multiple corrections
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")
    sleep_start = now - timedelta(days=2)

    # Store two recoveries to be updated.
    for i in range(2):
        rec = {
            "cycle_id": f"cycle-{i}",
            "created_at": iso(sleep_start),
            "score_state": "SCORED",
            "score": {"recovery_score": 50.0},
            "updated_at": iso(now - timedelta(days=2)),
        }
        upsert_recovery(conn, USER_ID, rec)

    # Fresh listing with newer versions.
    fresh_records = [
        {
            "cycle_id": f"cycle-{i}",
            "created_at": iso(sleep_start),
            "score_state": "SCORED",
            "score": {"recovery_score": 70.0},
            "updated_at": iso(now),
        }
        for i in range(2)
    ]

    respx.get(f"{BASE_URL}{COLLECTION_PATHS['recoveries']}").mock(
        return_value=httpx.Response(200, json={"records": fresh_records, "next_token": None})
    )
    mock_empty_collections(except_for="recoveries")

    async with WhoopClient(config, auth) as client:
        results = await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    assert results["recoveries"].updated == 2, (
        "ReconciliationResult.updated must count all corrections"
    )
    conn.close()


@respx.mock
async def test_reconciliation_does_not_insert_fresh_unknown_ids(tmp_path: Path) -> None:
    """TEST 8: A fresh id NOT held locally is not inserted (that is sync's job)
    -- the store still lacks it after reconciliation. Reconciliation is only
    for update-detection and deletion-detection, not insertion."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link(conn, USER_ID, "client-a")

    now = datetime(2026, 8, 10, tzinfo=UTC)
    sleep_start = now - timedelta(days=2)

    # Fresh listing contains a sleep the store has never seen.
    fresh_sleep = {
        "id": "sleep-new-unknown",
        "start": iso(sleep_start),
        "end": iso(sleep_start + timedelta(hours=8)),
        "score_state": "SCORED",
        "sleep_performance_percentage": 85.0,
        "updated_at": iso(now),
    }

    respx.get(f"{BASE_URL}{COLLECTION_PATHS['sleeps']}").mock(
        return_value=httpx.Response(200, json={"records": [fresh_sleep], "next_token": None})
    )
    mock_empty_collections(except_for="sleeps")

    async with WhoopClient(config, auth) as client:
        await run_reconciliation(conn, client, config, USER_ID, window_days=30, now=now)

    # The store must NOT contain this sleep: reconciliation never inserts.
    sleeps = get_sleeps(conn, USER_ID)
    assert len(sleeps) == 0, (
        "reconciliation must NOT insert fresh ids the store hasn't seen; that is sync's job"
    )
    conn.close()
