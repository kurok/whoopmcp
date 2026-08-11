"""Tests for the resumable, throttled history backfill (issue #14).

Written ahead of the implementation. The contract under test:

- ``whoopmcp.backfill.run_backfill(conn, client, config, whoop_user_id)``
  walks every collection (recoveries, sleeps, cycles, workouts) newest-first
  via the WHOOP API's own ``nextToken`` cursor, upserts every record through
  the store, and checkpoints into ``sync_state`` only after a page has been
  fully committed -- so an interrupted run resumes exactly where it stopped
  and never re-requests an already-committed page.
- Every page fetch goes through the REAL RateLimiter at
  ``RequestPriority.BACKFILL``, so an interactive request is never starved
  behind queued backfill pages and two concurrent backfills share one budget.
- The whole thing is gated on ``Config.cache_enabled`` (the resolved-blocker
  decision): ``BackfillDisabledError`` before any network or store touch.

Every HTTP call is mocked with respx; the real WHOOP API is never called.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from whoopmcp.auth import Authenticator, FileTokenStore, Token
from whoopmcp.backfill import BackfillDisabledError, run_backfill
from whoopmcp.client import (
    BASE_URL,
    MAX_PAGE_SIZE,
    RequestPriority,
    WhoopClient,
)
from whoopmcp.config import Config
from whoopmcp.store import (
    get_cycles,
    get_sync_state,
    open_store,
    set_sync_state,
)

USER_ID = 42

#: sync_state entity key -> the WHOOP v2 collection endpoint it walks.
COLLECTION_PATHS: dict[str, str] = {
    "recoveries": "/v2/recovery",
    "sleeps": "/v2/activity/sleep",
    "cycles": "/v2/cycle",
    "workouts": "/v2/activity/workout",
}

EMPTY_PAGE: dict[str, Any] = {"records": [], "next_token": None}


# -- test helpers -----------------------------------------------------------


class FakeClock:
    """A controllable clock for testing rate-limit logic without real sleeps.

    Same shape as test_client.py's helper: ``.now`` has the
    ``Callable[[], float]`` signature RateLimiter/WhoopClient expect and
    ``.advance()`` moves it forward instantly.
    """

    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


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


def make_record(entity: str, n: int) -> dict[str, Any]:
    """One WHOOP record acceptable to the entity's real store upsert.

    Recoveries carry no id of their own in the v2 API -- ``upsert_recovery``
    keys on ``record["cycle_id"]``; every other entity keys on ``record["id"]``.
    """
    if entity == "recoveries":
        return {"cycle_id": n, "created_at": "2026-01-01T00:00:00Z", "score_state": "SCORED"}
    return {"id": n, "start": "2026-01-01T00:00:00Z", "score_state": "SCORED"}


def three_pages(entity: str) -> dict[str | None, dict[str, Any]]:
    """Three full pages chained by nextToken: None -> tok2 -> tok3 -> done."""
    return {
        None: {
            "records": [make_record(entity, i) for i in range(25)],
            "next_token": "tok2",
        },
        "tok2": {
            "records": [make_record(entity, i) for i in range(25, 50)],
            "next_token": "tok3",
        },
        "tok3": {
            "records": [make_record(entity, i) for i in range(50, 75)],
            "next_token": None,
        },
    }


def paged_handler(
    pages: dict[str | None, dict[str, Any]],
) -> Callable[[httpx.Request], httpx.Response]:
    """A respx side_effect serving whichever page the request's nextToken names."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=pages[request.url.params.get("nextToken")])

    return handler


def endless_handler(entity: str) -> Callable[[httpx.Request], httpx.Response]:
    """A respx side_effect that never runs out of pages -- demand always
    exceeds whatever budget the rate limiter is configured with."""
    counter = itertools.count()

    def handler(request: httpx.Request) -> httpx.Response:
        del request
        n = next(counter)
        return httpx.Response(
            200,
            json={"records": [make_record(entity, 10_000 + n)], "next_token": f"t{n}"},
        )

    return handler


def mock_empty_collections(*, except_for: str | None = None) -> None:
    """Mock every collection endpoint (bar one) as a single empty page."""
    for entity, path in COLLECTION_PATHS.items():
        if entity == except_for:
            continue
        respx.get(f"{BASE_URL}{path}").mock(return_value=httpx.Response(200, json=EMPTY_PAGE))


def mock_endless_collections() -> None:
    for entity, path in COLLECTION_PATHS.items():
        respx.get(f"{BASE_URL}{path}").side_effect = endless_handler(entity)


# -- issue test 1: a three-page walk writes everything and checkpoints ------


@respx.mock
async def test_three_page_collection_writes_all_records_and_completes(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    cycle_route = respx.get(f"{BASE_URL}/v2/cycle")
    cycle_route.side_effect = paged_handler(three_pages("cycles"))
    mock_empty_collections(except_for="cycles")

    async with WhoopClient(config, auth) as client:
        result = await run_backfill(conn, client, config, USER_ID)

    # All 75 records landed, attributed to the right member.
    assert len(get_cycles(conn, USER_ID)) == 75
    assert result["cycles"] == 75
    assert set(result) == set(COLLECTION_PATHS)

    # The checkpoint says the walk is done: no cursor left, outcome complete.
    state = get_sync_state(conn, USER_ID, "cycles")
    assert state is not None
    assert state["cursor"] is None
    assert state["outcome"] == "complete"

    # Every entity -- including the empty ones -- got a sync_state row #16
    # can later read to know what range the store holds.
    for entity in ("recoveries", "sleeps", "workouts"):
        entity_state = get_sync_state(conn, USER_ID, entity)
        assert entity_state is not None
        assert entity_state["outcome"] == "complete"

    # Pages are requested at the API's own page cap, not the default.
    first_request = cycle_route.calls[0].request
    assert first_request.url.params.get("limit") == str(MAX_PAGE_SIZE)
    conn.close()


# -- issue test 2: interruption + resume never re-requests committed pages --


@respx.mock
async def test_interrupt_after_page_two_resumes_at_page_three(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    pages = three_pages("cycles")
    cycle_route = respx.get(f"{BASE_URL}/v2/cycle")
    mock_empty_collections(except_for="cycles")

    def dies_on_page_three(request: httpx.Request) -> httpx.Response:
        token = request.url.params.get("nextToken")
        if token == "tok3":
            raise httpx.ConnectError("interrupted after page two")
        return httpx.Response(200, json=pages[token])

    cycle_route.side_effect = dies_on_page_three

    async with WhoopClient(config, auth) as client:
        with pytest.raises(httpx.ConnectError):
            await run_backfill(conn, client, config, USER_ID)

    # Pages one and two committed and checkpointed before the interruption.
    assert len(get_cycles(conn, USER_ID)) == 50
    state = get_sync_state(conn, USER_ID, "cycles")
    assert state is not None
    assert state["cursor"] == "tok3"
    assert state["outcome"] == "in_progress"

    calls_in_first_run = len(cycle_route.calls)
    cycle_route.side_effect = paged_handler(pages)

    async with WhoopClient(config, auth) as client:
        await run_backfill(conn, client, config, USER_ID)

    # The resumed run's very first request to this collection carried the
    # stored checkpoint token, not a fresh unbounded query.
    resumed_first = cycle_route.calls[calls_in_first_run].request
    assert resumed_first.url.params.get("nextToken") == "tok3"

    # Pages one and two were requested exactly once ACROSS BOTH runs; only
    # the interrupted page three was fetched twice (its failed attempt never
    # committed, so re-fetching it is the safe, idempotent move).
    tokens = [call.request.url.params.get("nextToken") for call in cycle_route.calls]
    assert tokens.count(None) == 1
    assert tokens.count("tok2") == 1
    assert tokens.count("tok3") == 2

    assert len(get_cycles(conn, USER_ID)) == 75
    state = get_sync_state(conn, USER_ID, "cycles")
    assert state is not None
    assert state["cursor"] is None
    assert state["outcome"] == "complete"
    conn.close()


@respx.mock
async def test_entity_already_complete_is_skipped_on_rerun(tmp_path: Path) -> None:
    """Backfill is a one-shot import: a collection whose sync_state already
    says "complete" is never walked again (refreshing history is #15's job)."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    set_sync_state(
        conn,
        USER_ID,
        "cycles",
        cursor=None,
        last_run_at="2026-01-01T00:00:00+00:00",
        outcome="complete",
    )
    cycle_route = respx.get(f"{BASE_URL}/v2/cycle").mock(
        return_value=httpx.Response(200, json=EMPTY_PAGE)
    )
    mock_empty_collections(except_for="cycles")

    async with WhoopClient(config, auth) as client:
        await run_backfill(conn, client, config, USER_ID)

    assert not cycle_route.called
    conn.close()


# -- issue test 3: a page that fails to commit never advances the checkpoint --


@respx.mock
async def test_failed_page_commit_does_not_advance_checkpoint(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    mock_empty_collections(except_for="cycles")

    # Page two carries a poisoned record with no "id" -- the REAL
    # upsert_cycle raises on it, mid-page, after page one already committed.
    poisoned = {"start": "2026-01-02T00:00:00Z", "score_state": "SCORED"}
    pages: dict[str | None, dict[str, Any]] = {
        None: {
            "records": [make_record("cycles", i) for i in range(3)],
            "next_token": "tok2",
        },
        "tok2": {
            "records": [make_record("cycles", 3), poisoned],
            "next_token": "tok3",
        },
    }
    respx.get(f"{BASE_URL}/v2/cycle").side_effect = paged_handler(pages)

    async with WhoopClient(config, auth) as client:
        with pytest.raises(KeyError):
            await run_backfill(conn, client, config, USER_ID)

    # The checkpoint still names page two's own token (written after page
    # one committed) -- it never advanced to page three's.
    state = get_sync_state(conn, USER_ID, "cycles")
    assert state is not None
    assert state["cursor"] == "tok2"
    assert state["outcome"] == "in_progress"
    # Page one's records are all there; the walk is resumable from tok2.
    assert len(get_cycles(conn, USER_ID)) >= 3
    conn.close()


# -- issue test 4: two concurrent backfills share ONE real budget ------------


@respx.mock
async def test_two_concurrent_backfills_share_the_real_rate_limiter(tmp_path: Path) -> None:
    config = make_config(tmp_path, WHOOPMCP_RATE_LIMIT_PER_MINUTE="5")
    auth = make_auth(config)
    clock = FakeClock()
    mock_endless_collections()

    conn_a = open_store(":memory:")
    conn_b = open_store(":memory:")
    async with WhoopClient(config, auth, clock=clock.now) as client:
        task_a = asyncio.create_task(run_backfill(conn_a, client, config, USER_ID))
        task_b = asyncio.create_task(run_backfill(conn_b, client, config, USER_ID))

        # Give both walks plenty of real event-loop time. The fake clock
        # never advances, so the minute window never rolls over: the REAL
        # RateLimiter's budget of 5 is all they may spend between them,
        # against endless mocked pages that would happily serve thousands.
        for _ in range(25):
            await asyncio.sleep(0.02)

        assert 0 < respx.calls.call_count <= 5

        for task in (task_a, task_b):
            task.cancel()
        for task in (task_a, task_b):
            with contextlib.suppress(asyncio.CancelledError):
                await task
    conn_a.close()
    conn_b.close()


# -- issue test 5: interactive requests are never starved behind backfill ----


@respx.mock
async def test_interactive_request_is_not_delayed_behind_backfill(tmp_path: Path) -> None:
    config = make_config(tmp_path, WHOOPMCP_RATE_LIMIT_PER_MINUTE="1")
    auth = make_auth(config)
    clock = FakeClock()
    mock_endless_collections()
    profile_route = respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(200, json={"user_id": USER_ID})
    )

    conn = open_store(":memory:")
    async with WhoopClient(config, auth, clock=clock.now) as client:
        backfill_task = asyncio.create_task(run_backfill(conn, client, config, USER_ID))
        await asyncio.sleep(0.1)
        # Backfill spent the single per-minute slot on its first page and is
        # now blocked in the limiter waiting for its second.
        calls_before = respx.calls.call_count
        assert calls_before == 1

        profile_task = asyncio.create_task(client.get_profile())
        await asyncio.sleep(0.05)
        assert not profile_task.done()

        # Exactly one slot frees. The interactive caller must get it, even
        # though the backfill waiter has been queued for longer.
        clock.advance(61)
        result = await asyncio.wait_for(profile_task, timeout=2.0)
        assert result == {"user_id": USER_ID}
        assert profile_route.called

        # The freed slot went to the interactive call, not backfill's next
        # page -- total traffic grew only by the profile request.
        await asyncio.sleep(0.1)
        assert respx.calls.call_count == calls_before + 1

        backfill_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await backfill_task
    conn.close()


@respx.mock
async def test_backfill_passes_backfill_priority_to_the_real_rate_limiter(
    tmp_path: Path,
) -> None:
    """Backfill must actually issue RequestPriority.BACKFILL -- the low
    priority class #11 built and nothing consumed until now -- for every
    page fetch, not silently fall through to the INTERACTIVE default."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    mock_empty_collections()

    conn = open_store(":memory:")
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
        await run_backfill(conn, client, config, USER_ID)

    # One page per collection, every single acquire at BACKFILL priority.
    assert len(recorded) == len(COLLECTION_PATHS)
    assert all(priority is RequestPriority.BACKFILL for priority in recorded)
    conn.close()


# -- issue test 6: progress is queryable and monotonic ------------------------


@respx.mock
async def test_progress_is_queryable_and_monotonic(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    pages = three_pages("cycles")
    mock_empty_collections(except_for="cycles")

    # Snapshot the progress surface (sync_state + stored row count) at the
    # moment each page is requested -- i.e. between committed pages.
    snapshots: list[tuple[dict[str, Any] | None, int]] = []

    def observing_handler(request: httpx.Request) -> httpx.Response:
        snapshots.append((get_sync_state(conn, USER_ID, "cycles"), len(get_cycles(conn, USER_ID))))
        return httpx.Response(200, json=pages[request.url.params.get("nextToken")])

    respx.get(f"{BASE_URL}/v2/cycle").side_effect = observing_handler

    async with WhoopClient(config, auth) as client:
        await run_backfill(conn, client, config, USER_ID)

    assert len(snapshots) == 3
    # Before the first page: nothing yet. Every later snapshot is a live,
    # queryable in_progress row -- no separate progress mechanism needed.
    assert snapshots[0] == (None, 0)
    for state, _ in snapshots[1:]:
        assert state is not None
        assert state["outcome"] == "in_progress"
        assert state["cursor"] is not None

    # Stored record counts only ever grow.
    counts = [count for _, count in snapshots]
    assert counts == sorted(counts)

    # last_run_at is non-decreasing across checkpoints, including the final.
    final_state = get_sync_state(conn, USER_ID, "cycles")
    assert final_state is not None
    run_ats = [state["last_run_at"] for state, _ in snapshots[1:]]
    run_ats.append(final_state["last_run_at"])
    assert run_ats == sorted(run_ats)

    # The outcome transitions in_progress -> complete exactly once, at the end.
    assert final_state["outcome"] == "complete"
    assert final_state["cursor"] is None
    conn.close()


# -- issue test 7 (resolved blocker): the cache_enabled gate ------------------


@respx.mock
async def test_backfill_refuses_when_cache_disabled_and_proceeds_when_enabled(
    tmp_path: Path,
) -> None:
    mock_empty_collections()
    conn = open_store(":memory:")

    # Disabled: a specific, actionable error naming WHOOPMCP_CACHE, raised
    # before a single HTTP request is issued.
    disabled_config = make_config(tmp_path / "disabled", WHOOPMCP_CACHE="false")
    disabled_auth = make_auth(disabled_config)
    async with WhoopClient(disabled_config, disabled_auth) as client:
        with pytest.raises(BackfillDisabledError, match="WHOOPMCP_CACHE"):
            await run_backfill(conn, client, disabled_config, USER_ID)
    assert respx.calls.call_count == 0

    # Enabled: the exact same call proceeds normally.
    enabled_config = make_config(tmp_path / "enabled")
    enabled_auth = make_auth(enabled_config)
    async with WhoopClient(enabled_config, enabled_auth) as client:
        result = await run_backfill(conn, client, enabled_config, USER_ID)
    assert respx.calls.call_count == len(COLLECTION_PATHS)
    assert set(result) == set(COLLECTION_PATHS)
    conn.close()


# -- floor date: the configured lower bound is WHOOP's own `start` param ------


@respx.mock
async def test_floor_date_is_passed_as_start_param(tmp_path: Path) -> None:
    floor = "2024-01-01"
    config = make_config(tmp_path, WHOOPMCP_BACKFILL_FLOOR_DATE=floor)
    auth = make_auth(config)
    conn = open_store(":memory:")
    respx.get(f"{BASE_URL}/v2/cycle").side_effect = paged_handler(three_pages("cycles"))
    mock_empty_collections(except_for="cycles")

    async with WhoopClient(config, auth) as client:
        await run_backfill(conn, client, config, USER_ID)

    # Every collection request -- first pages and cursor-following pages
    # alike -- carries the floor as the API's own inclusive lower bound, so
    # WHOOP itself stops the walk at the floor.
    assert respx.calls.call_count > 0
    for call in respx.calls:
        assert call.request.url.params.get("start") == floor
    conn.close()
