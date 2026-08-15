"""Tests for incremental sync from an updated_at high-water mark (issue #15).

Written ahead of the implementation. The contract under test:

- ``whoopmcp.sync.run_sync(conn, client, config, whoop_user_id)`` walks each
  of the four paginated collections (recoveries, sleeps, cycles, workouts)
  forward from a per-(user, entity) high-water ``updated_at`` mark -- NOT
  ``created_at``, per the issue's own emphasized note (rescores are only
  visible on ``updated_at``) -- upserts every record, and advances the
  cursor only after a page commits, so a crash mid-page re-fetches and never
  skips.
- A small overlap margin (~60s) is subtracted from the stored mark before
  every request, absorbed by upsert idempotency, so a record exactly on the
  boundary is never silently dropped to clock skew.
- Steady state costs exactly one request per entity per run.
- Incremental sync's own progress lives in ``sync_state`` under a distinct
  entity namespace, ``f"{entity}:incremental"`` (e.g. ``"cycles:incremental"``)
  -- never the bare entity name backfill (#14) already owns. This is the
  coexistence fix: backfill's own row keys ``cursor`` as WHOOP's opaque
  ``nextToken`` and ``outcome`` as "stop, nothing to resume" on completion;
  sync's row keys ``cursor`` as a JSON blob (``{since, next_token,
  high_water_seen, previous_mark}``) while in progress and a bare ISO-8601
  high-water mark once complete. Neither consumer may ever read the other's
  row.
- Gated on ``Config.cache_enabled``, exactly mirroring backfill's own
  ``BackfillDisabledError`` check -- ``SyncDisabledError`` before any network
  or store touch, and the ``whoop_sync`` MCP tool wrapper turns that into a
  plain, non-error tool result rather than letting it propagate.

Every HTTP call is mocked with respx; the real WHOOP API is never called.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context, MCPServer

from whoopmcp.auth import Authenticator, FileTokenStore, Token
from whoopmcp.backfill import run_backfill
from whoopmcp.client import BASE_URL, WhoopClient
from whoopmcp.config import Config
from whoopmcp.server import AppContext, Principal, build_server
from whoopmcp.store import (
    get_cycles,
    get_recoveries,
    get_sleeps,
    get_sync_state,
    get_workouts,
    link_principal_to_member,
    open_store,
    set_sync_state,
    upsert_cycle,
)
from whoopmcp.sync import (
    SyncDisabledError,
    _apply_overlap,
    _incremental_entity_key,
    run_sync,
)

USER_ID = 42

#: sync_state entity key -> the WHOOP v2 collection endpoint it walks. Same
#: mapping tests/test_backfill.py uses, since #15 walks the same four
#: collections #14 does.
COLLECTION_PATHS: dict[str, str] = {
    "recoveries": "/v2/recovery",
    "sleeps": "/v2/activity/sleep",
    "cycles": "/v2/cycle",
    "workouts": "/v2/activity/workout",
}

GETTERS: dict[str, Callable[[Any, int], list[dict[str, Any]]]] = {
    "recoveries": get_recoveries,
    "sleeps": get_sleeps,
    "cycles": get_cycles,
    "workouts": get_workouts,
}

EMPTY_PAGE: dict[str, Any] = {"records": [], "next_token": None}
OVERLAP_SECONDS = 60.0


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


def make_record(
    entity: str, n: int, updated_at: str, *, start: str = "2026-01-01T00:00:00Z"
) -> dict[str, Any]:
    """One WHOOP record acceptable to the entity's real store upsert.

    Recoveries carry no id of their own in the v2 API -- keyed on
    ``cycle_id``; every other entity keys on ``id``. ``updated_at`` is
    WHOOP's own field (not the store's bookkeeping column of the same name)
    -- the thing #15's high-water mark actually tracks.
    """
    if entity == "recoveries":
        return {
            "cycle_id": n,
            "created_at": start,
            "score_state": "SCORED",
            "updated_at": updated_at,
        }
    return {
        "id": n,
        "start": start,
        "score_state": "SCORED",
        "updated_at": updated_at,
    }


def mock_collections(responses: dict[str, dict[str, Any]]) -> dict[str, respx.Route]:
    """Mock every collection endpoint with one JSON response body each.

    Any entity absent from ``responses`` gets a single empty page -- the
    steady-state default every test that only cares about one collection
    should build on.
    """
    routes: dict[str, respx.Route] = {}
    for entity, path in COLLECTION_PATHS.items():
        body = responses.get(entity, EMPTY_PAGE)
        routes[entity] = respx.get(f"{BASE_URL}{path}").mock(
            return_value=httpx.Response(200, json=body)
        )
    return routes


def paged_handler(
    pages: dict[str | None, dict[str, Any]],
) -> Callable[[httpx.Request], httpx.Response]:
    """A respx side_effect serving whichever page the request's nextToken names."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=pages[request.url.params.get("nextToken")])

    return handler


# -- MCP tool-call harness, mirroring tests/test_context_budget.py's own -----


async def call_tool(
    server: MCPServer[AppContext], name: str, arguments: dict[str, Any], app_context: AppContext
) -> Any:
    """Call a tool with proper context wiring, and unwrap its return value."""
    request_context = ServerRequestContext(
        session=None,  # type: ignore[arg-type]
        lifespan_context=app_context,
        protocol_version="2025-06-18",
        method="tools/call",
    )
    context = Context(request_context=request_context, mcp_server=server)
    result = await server.call_tool(name, arguments, context=context)
    if result.structured_content is not None:
        return result.structured_content
    return result


# -- issue test 1 / acceptance criterion: steady-state cost is one request --
# -- per entity, and a sync immediately following a sync writes nothing -----


@respx.mock
async def test_steady_state_sync_issues_one_request_per_entity_and_writes_nothing(
    tmp_path: Path,
) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    routes = mock_collections({})

    async with WhoopClient(config, auth) as client:
        first = await run_sync(conn, client, config, USER_ID)
        assert set(first) == set(COLLECTION_PATHS)
        for entity in COLLECTION_PATHS:
            assert routes[entity].call_count == 1

        calls_before = {entity: routes[entity].call_count for entity in COLLECTION_PATHS}
        second = await run_sync(conn, client, config, USER_ID)

    # Exactly one more request per entity on the immediately-following run --
    # never zero (a poll is still a request) and never more than one (no
    # extra page was needed since nothing new exists).
    for entity in COLLECTION_PATHS:
        assert routes[entity].call_count - calls_before[entity] == 1

    for getter in GETTERS.values():
        assert getter(conn, USER_ID) == []
    for result in second.values():
        assert result.count == 0
    conn.close()


@respx.mock
async def test_steady_state_cost_is_one_request_per_entity_asserted_on_respx_call_count(
    tmp_path: Path,
) -> None:
    """Acceptance criterion, verified directly against the global respx call
    count rather than any one route's own counter."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    mock_collections({})

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)
        calls_after_first_run = respx.calls.call_count
        await run_sync(conn, client, config, USER_ID)

    assert respx.calls.call_count - calls_after_first_run == len(COLLECTION_PATHS)
    conn.close()


# -- issue test 2: a record modified upstream is picked up on the next run --


@respx.mock
async def test_record_modified_upstream_is_picked_up_on_next_run(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    first_mark = "2026-01-01T00:00:00+00:00"
    routes = mock_collections(
        {"recoveries": {"records": [make_record("recoveries", 1, first_mark)], "next_token": None}}
    )

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

        state = get_sync_state(conn, USER_ID, _incremental_entity_key("recoveries"))
        assert state is not None
        assert state["outcome"] == "complete"
        assert state["cursor"] == first_mark

        # WHOOP reports a rescored (not newly-created) recovery: same
        # cycle_id, a later updated_at -- the case the issue's Notes call
        # out by name (created_at would silently miss this).
        second_mark = "2026-01-02T00:00:00+00:00"
        updated_record = make_record("recoveries", 1, second_mark)
        routes["recoveries"].mock(
            return_value=httpx.Response(200, json={"records": [updated_record], "next_token": None})
        )

        await run_sync(conn, client, config, USER_ID)

    recoveries = get_recoveries(conn, USER_ID)
    assert len(recoveries) == 1
    assert recoveries[0]["updated_at"] == second_mark

    new_state = get_sync_state(conn, USER_ID, _incremental_entity_key("recoveries"))
    assert new_state is not None
    assert new_state["outcome"] == "complete"
    assert new_state["cursor"] == second_mark
    conn.close()


# -- issue test 3 / acceptance criterion: an interrupted sync leaves the ----
# -- cursor at the last committed page, and never advances past uncommitted -
# -- data ---------------------------------------------------------------------


@respx.mock
async def test_interrupted_sync_resumes_from_last_committed_page(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    page_one_mark = "2026-03-01T00:00:00+00:00"
    page_two_mark = "2026-03-02T00:00:00+00:00"
    pages: dict[str | None, dict[str, Any]] = {
        None: {
            "records": [make_record("workouts", 1, page_one_mark)],
            "next_token": "tok2",
        },
        "tok2": {
            "records": [make_record("workouts", 2, page_two_mark)],
            "next_token": None,
        },
    }
    routes = mock_collections({})

    def dies_on_page_two(request: httpx.Request) -> httpx.Response:
        token = request.url.params.get("nextToken")
        if token == "tok2":
            raise httpx.ConnectError("interrupted mid-page-two")
        return httpx.Response(200, json=pages[token])

    routes["workouts"].side_effect = dies_on_page_two

    async with WhoopClient(config, auth) as client:
        # Reported rather than raised since #187; the resume behaviour this test
        # is about is asserted below and is unchanged.
        interrupted = await run_sync(conn, client, config, USER_ID)
    assert any(entity.error is not None for entity in interrupted.values())

    # Page one's record committed; page two's did not.
    assert len(get_workouts(conn, USER_ID)) == 1
    state = get_sync_state(conn, USER_ID, _incremental_entity_key("workouts"))
    assert state is not None
    assert state["outcome"] == "in_progress"
    cursor = json.loads(state["cursor"])
    assert cursor["next_token"] == "tok2"
    # The high-water mark committed so far reflects ONLY page one -- never
    # page two's uncommitted record. This is the "no path advances a cursor
    # past uncommitted data" acceptance criterion, made concrete.
    assert cursor["high_water_seen"] == page_one_mark
    assert cursor["since"] is not None

    calls_before = routes["workouts"].call_count
    routes["workouts"].side_effect = paged_handler(pages)

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    # The resumed run's first request to this collection carried the stored
    # next_token, not a fresh unbounded query -- page one is never re-walked.
    resumed_first = routes["workouts"].calls[calls_before].request
    assert resumed_first.url.params.get("nextToken") == "tok2"

    assert len(get_workouts(conn, USER_ID)) == 2
    final_state = get_sync_state(conn, USER_ID, _incremental_entity_key("workouts"))
    assert final_state is not None
    assert final_state["outcome"] == "complete"
    assert final_state["cursor"] == page_two_mark
    conn.close()


@respx.mock
async def test_interrupt_during_an_all_empty_run_never_regresses_the_prior_mark(
    tmp_path: Path,
) -> None:
    """A run that so far has only committed empty-but-paginated pages has
    ``high_water_seen is None`` mid-run -- an interrupt right there, resumed
    to an all-empty tail, must not let the eventual completion overwrite an
    already-on-record mark with ``None``. Reproduces the exact scenario the
    issue #15 review caught: crash after committing
    ``{high_water_seen: null}``, resume through nothing but empty pages,
    verify the ORIGINAL mark survives rather than regressing to a full
    re-walk."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    key = _incremental_entity_key("workouts")
    original_mark = "2026-05-01T00:00:00+00:00"
    set_sync_state(
        conn,
        USER_ID,
        key,
        cursor=original_mark,
        last_run_at="2026-05-01T00:00:00+00:00",
        outcome="complete",
    )

    # Page one: empty, but legally paginated (a next_token with zero
    # records is a real Page shape) -- this run commits high_water_seen=None.
    pages: dict[str | None, dict[str, Any]] = {
        None: {"records": [], "next_token": "tok2"},
        "tok2": {"records": [], "next_token": None},
    }
    routes = mock_collections({})

    def dies_on_page_two(request: httpx.Request) -> httpx.Response:
        token = request.url.params.get("nextToken")
        if token == "tok2":
            raise httpx.ConnectError("interrupted mid-page-two")
        return httpx.Response(200, json=pages[token])

    routes["workouts"].side_effect = dies_on_page_two

    async with WhoopClient(config, auth) as client:
        # Since #187 a per-entity failure is reported rather than raised, so the
        # other three entities are still attempted. The invariant this test
        # exists for is unchanged and asserted below: the interrupted entity's
        # mid-run cursor must still carry `previous_mark`, and the resume must
        # still restore the original mark rather than regressing to a re-walk.
        interrupted = await run_sync(conn, client, config, USER_ID)
    assert interrupted["workouts"].error is not None
    assert "ConnectError" in interrupted["workouts"].error

    mid_run_state = get_sync_state(conn, USER_ID, key)
    assert mid_run_state is not None
    mid_run_cursor = json.loads(mid_run_state["cursor"])
    assert mid_run_cursor["high_water_seen"] is None
    # The pre-run mark travels through the JSON cursor itself -- this is
    # the fix: without it, resuming would have no way back to it.
    assert mid_run_cursor["previous_mark"] == original_mark

    # Resume through an all-empty tail (no crash this time).
    routes["workouts"].side_effect = paged_handler(pages)
    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    final_state = get_sync_state(conn, USER_ID, key)
    assert final_state is not None
    assert final_state["outcome"] == "complete"
    assert final_state["cursor"] == original_mark, (
        "an all-empty resumed run must fall back to the mark already on "
        "record, not regress it to None and force a full history re-walk "
        "on the next sync"
    )
    conn.close()


# -- issue test 4: a record on the previous boundary is still fetched -------
# -- (the overlap margin) -----------------------------------------------------


@respx.mock
async def test_overlap_margin_is_applied_to_the_request_start_param(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    prior_mark = "2026-01-10T00:00:00+00:00"
    set_sync_state(
        conn,
        USER_ID,
        _incremental_entity_key("recoveries"),
        cursor=prior_mark,
        last_run_at=prior_mark,
        outcome="complete",
    )
    # A record whose updated_at sits exactly on the previous high-water
    # mark -- the issue's own boundary case.
    boundary_record = make_record("recoveries", 99, prior_mark)
    captured: dict[str, str | None] = {}
    routes = mock_collections({})

    def handler(request: httpx.Request) -> httpx.Response:
        captured["start"] = request.url.params.get("start")
        return httpx.Response(200, json={"records": [boundary_record], "next_token": None})

    routes["recoveries"].side_effect = handler

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    assert captured["start"] == _apply_overlap(prior_mark, OVERLAP_SECONDS)
    recoveries = get_recoveries(conn, USER_ID)
    assert len(recoveries) == 1
    assert recoveries[0]["updated_at"] == prior_mark
    conn.close()


# -- issue test 5: a record re-fetched by the overlap is upserted, not ------
# -- duplicated ----------------------------------------------------------------


@respx.mock
async def test_overlap_refetch_is_upserted_not_duplicated(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    mark = "2026-02-01T00:00:00+00:00"
    record = make_record("cycles", 5, mark)
    upsert_cycle(conn, USER_ID, record)
    assert len(get_cycles(conn, USER_ID)) == 1

    set_sync_state(
        conn,
        USER_ID,
        _incremental_entity_key("cycles"),
        cursor=mark,
        last_run_at=mark,
        outcome="complete",
    )
    mock_collections({"cycles": {"records": [record], "next_token": None}})

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    # Same primary key (whoop_user_id, resource_id): re-delivery upserts in
    # place, it never creates a second row.
    assert len(get_cycles(conn, USER_ID)) == 1
    conn.close()


# -- issue test 6: whoop_sync returns per-entity counts and the new cursor --


@respx.mock
async def test_whoop_sync_tool_returns_per_entity_counts_and_cursor(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=USER_ID
    )
    mark = "2026-03-05T00:00:00+00:00"
    mock_collections(
        {"recoveries": {"records": [make_record("recoveries", 1, mark)], "next_token": None}}
    )
    server = build_server()

    async with WhoopClient(config, auth) as client:
        app_context = AppContext(
            config=config,
            auth=auth,
            client=client,
            principal=Principal(user_id=USER_ID),
            store_conn=conn,
        )
        result = await call_tool(server, "whoop_sync", {}, app_context)

    assert result["synced"] is True
    assert set(result["entities"]) == set(COLLECTION_PATHS)
    for info in result["entities"].values():
        assert isinstance(info["count"], int)
        assert "cursor" in info
    assert result["entities"]["recoveries"]["count"] == 1
    assert result["entities"]["recoveries"]["cursor"] == mark
    conn.close()


@respx.mock
async def test_whoop_sync_tool_refuses_when_cache_disabled_and_proceeds_when_enabled(
    tmp_path: Path,
) -> None:
    server = build_server()

    # Disabled: a plain, non-error tool result naming WHOOPMCP_CACHE, and no
    # HTTP request is ever issued -- this is the resolved-blocker gate
    # applied at the tool surface, mirroring backfill's own but returning a
    # helpful message rather than raising.
    disabled_config = make_config(tmp_path / "disabled", WHOOPMCP_CACHE="false")
    disabled_auth = make_auth(disabled_config)
    disabled_conn = open_store(":memory:")
    link_principal_to_member(
        disabled_conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=USER_ID
    )
    async with WhoopClient(disabled_config, disabled_auth) as client:
        app_context = AppContext(
            config=disabled_config,
            auth=disabled_auth,
            client=client,
            principal=Principal(user_id=USER_ID),
            store_conn=disabled_conn,
        )
        result = await call_tool(server, "whoop_sync", {}, app_context)
    assert result["synced"] is False
    assert "WHOOPMCP_CACHE" in result["message"]
    assert respx.calls.call_count == 0
    # Not just "no HTTP call" -- the disabled gate must never write to the
    # store either, pinned directly against the raw tables rather than
    # trusted from the tool result alone (a future refactor that moved the
    # cache_enabled check after an initial write would still pass every
    # assertion above).
    for table in COLLECTION_PATHS:
        rows = disabled_conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchall()
        assert rows == [], f"{table} must stay empty when the store is disabled"
    disabled_conn.close()

    # Enabled: the exact same call proceeds normally.
    enabled_config = make_config(tmp_path / "enabled")
    enabled_auth = make_auth(enabled_config)
    enabled_conn = open_store(":memory:")
    link_principal_to_member(
        enabled_conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=USER_ID
    )
    mock_collections({})
    async with WhoopClient(enabled_config, enabled_auth) as client:
        app_context = AppContext(
            config=enabled_config,
            auth=enabled_auth,
            client=client,
            principal=Principal(user_id=USER_ID),
            store_conn=enabled_conn,
        )
        result = await call_tool(server, "whoop_sync", {}, app_context)
    assert result["synced"] is True
    assert respx.calls.call_count == len(COLLECTION_PATHS)
    enabled_conn.close()


# -- resolved constraint: run_sync's own cache_enabled gate ------------------


@respx.mock
async def test_run_sync_refuses_when_cache_disabled_and_proceeds_when_enabled(
    tmp_path: Path,
) -> None:
    conn = open_store(":memory:")

    disabled_config = make_config(tmp_path / "disabled", WHOOPMCP_CACHE="false")
    disabled_auth = make_auth(disabled_config)
    async with WhoopClient(disabled_config, disabled_auth) as client:
        with pytest.raises(SyncDisabledError, match="WHOOPMCP_CACHE"):
            await run_sync(conn, client, disabled_config, USER_ID)
    assert respx.calls.call_count == 0
    for table in COLLECTION_PATHS:
        rows = conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchall()
        assert rows == [], f"{table} must stay empty when the store is disabled"

    enabled_config = make_config(tmp_path / "enabled")
    enabled_auth = make_auth(enabled_config)
    mock_collections({})
    async with WhoopClient(enabled_config, enabled_auth) as client:
        result = await run_sync(conn, client, enabled_config, USER_ID)
    assert respx.calls.call_count == len(COLLECTION_PATHS)
    assert set(result) == set(COLLECTION_PATHS)
    conn.close()


# -- backfill/#15 coexistence: distinct sync_state namespaces never collide -


@respx.mock
async def test_sync_never_reads_or_writes_backfills_bare_entity_sync_state_row(
    tmp_path: Path,
) -> None:
    """An interrupted backfill's own (bare-entity) sync_state row must never
    be overwritten or reinterpreted by run_sync -- it lives at a distinct
    entity key, ``"cycles:incremental"``, not bare ``"cycles"``."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    # Simulate an interrupted backfill: bare "cycles" row mid-resume, exactly
    # tests/test_backfill.py's own interrupted-run shape.
    set_sync_state(
        conn,
        USER_ID,
        "cycles",
        cursor="tok3",
        last_run_at="2026-01-01T00:00:00+00:00",
        outcome="in_progress",
    )
    mock_collections({})

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    # Backfill's own resume state is untouched: same cursor, same outcome.
    backfill_state = get_sync_state(conn, USER_ID, "cycles")
    assert backfill_state == {
        "cursor": "tok3",
        "last_run_at": "2026-01-01T00:00:00+00:00",
        "outcome": "in_progress",
    }

    # Sync recorded its own progress under the distinct incremental key.
    sync_state_row = get_sync_state(conn, USER_ID, _incremental_entity_key("cycles"))
    assert sync_state_row is not None
    assert sync_state_row["outcome"] == "complete"
    conn.close()


@respx.mock
async def test_backfill_never_receives_syncs_high_water_mark_as_a_next_token(
    tmp_path: Path,
) -> None:
    """Sync's own committed high-water mark (a bare ISO-8601 string, stored
    under "recoveries:incremental") must never be fed to backfill as if it
    were WHOOP's opaque nextToken (stored, separately, under bare
    "recoveries") -- backfill's first request after a sync run still carries
    no nextToken at all, because its own bare-entity row was never touched."""
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    mark = "2026-04-01T00:00:00+00:00"
    routes = mock_collections(
        {"recoveries": {"records": [make_record("recoveries", 1, mark)], "next_token": None}}
    )

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    sync_row = get_sync_state(conn, USER_ID, _incremental_entity_key("recoveries"))
    assert sync_row is not None
    assert sync_row["cursor"] == mark
    # Backfill's own bare-entity row was never created by sync.
    assert get_sync_state(conn, USER_ID, "recoveries") is None

    calls_before = routes["recoveries"].call_count
    routes["recoveries"].side_effect = None
    routes["recoveries"].mock(return_value=httpx.Response(200, json=EMPTY_PAGE))

    async with WhoopClient(config, auth) as client:
        await run_backfill(conn, client, config, USER_ID)

    backfill_first_call = routes["recoveries"].calls[calls_before].request
    assert backfill_first_call.url.params.get("nextToken") is None
    conn.close()


# -- issue #186: high-water mark poisoning by implausible future timestamps ---


@respx.mock
async def test_far_future_updated_at_does_not_poison_cursor(tmp_path: Path) -> None:
    """Test 1: A record with a far-future updated_at (year 2099) does NOT
    advance the cursor past the present. The record IS persisted, but does not
    influence the high-water mark.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    # Record with year 2099 (far future, well beyond 5-minute skew allowance)
    future_mark = "2099-12-31T23:59:59+00:00"
    record = make_record("recoveries", 1, future_mark)
    mock_collections({"recoveries": {"records": [record], "next_token": None}})

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    # Record is upserted despite cursor skip
    recoveries = get_recoveries(conn, USER_ID)
    assert len(recoveries) == 1, "record must be persisted despite cursor skip"
    assert recoveries[0]["updated_at"] == future_mark

    # Cursor is NOT the future timestamp (this fails on main)
    state = get_sync_state(conn, USER_ID, _incremental_entity_key("recoveries"))
    assert state is not None
    assert state["outcome"] == "complete"
    stored_cursor = state["cursor"]

    # The stored cursor must not be the far-future value
    # On main: cursor = "2099-12-31T23:59:59+00:00" (poisoned) -- FAILS this assertion
    assert stored_cursor != future_mark, (
        "cursor should not be the far-future timestamp; it should be clamped or None"
    )
    # And should not contain 2099 at all
    assert "2099" not in str(stored_cursor), "cursor should not contain year 2099"

    conn.close()


@respx.mock
async def test_following_run_after_implausible_record_fetches_normally(tmp_path: Path) -> None:
    """Test 2: After a sync with an implausible record, the NEXT run still
    fetches with a sane start parameter (not a future date). Inspect the
    recorded request start parameter to verify.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    # First run: inject a far-future record
    future_mark = "2099-06-15T12:00:00+00:00"
    record = make_record("cycles", 1, future_mark)
    routes = mock_collections({"cycles": {"records": [record], "next_token": None}})

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    # Second run: capture the start parameter
    captured: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["start"] = request.url.params.get("start")
        return httpx.Response(200, json=EMPTY_PAGE)

    routes["cycles"].side_effect = handler

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    # The start parameter in the second run must NOT be a future date
    start_param = captured["start"]
    assert start_param is not None, "start parameter must be present"

    # Parse and verify it's not 2099 (or far in future)
    start_dt = datetime.fromisoformat(start_param)
    now = datetime.now(UTC)
    # On main: start_param will contain "2099-..." because cursor is poisoned
    # So this assertion will FAIL
    assert start_dt < now + timedelta(hours=1), (
        f"start parameter must be near-present, not future: {start_param}"
    )
    assert "2099" not in start_param, "start parameter should not reference year 2099"

    conn.close()


@respx.mock
async def test_recovery_from_database_poisoned_cursor(tmp_path: Path) -> None:
    """Test 3: When a sync_state cursor is ALREADY poisoned (future timestamp
    pre-written to the database), the next run clamps it to present before use,
    so the request's start parameter is sane and the cursor is corrected.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    key = _incremental_entity_key("sleeps")

    # Pre-poison the database: write a far-future cursor
    poisoned_mark = "2099-03-20T08:30:00+00:00"
    set_sync_state(
        conn,
        USER_ID,
        key,
        cursor=poisoned_mark,
        last_run_at=poisoned_mark,
        outcome="complete",
    )

    # Run sync with a normal record
    # Relative to now, not a hardcoded date: "an ordinary record" means one
    # dated in the past, and a fixed literal silently becomes a *future*
    # timestamp once the clock passes it -- which this guard then correctly
    # refuses, failing the test for the opposite of the reason it exists.
    normal_mark = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    record = make_record("sleeps", 1, normal_mark)
    routes = mock_collections({"sleeps": {"records": [record], "next_token": None}})

    captured: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["start"] = request.url.params.get("start")
        return httpx.Response(200, json={"records": [record], "next_token": None})

    routes["sleeps"].side_effect = handler

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    # The start parameter must be clamped to present, not based on the poisoned cursor
    start_param = captured["start"]
    assert start_param is not None

    # On main: the request start will still be based on poisoned cursor
    # (2099 - 60 seconds), so this assertion FAILS
    start_dt = datetime.fromisoformat(start_param)
    now = datetime.now(UTC)
    assert start_dt < now + timedelta(minutes=10), (
        f"start parameter must be clamped to near-present after recovery: {start_param}"
    )
    assert "2099" not in start_param, "start must not reference poisoned year 2099"

    # The cursor must no longer be the poisoned value
    new_state = get_sync_state(conn, USER_ID, key)
    assert new_state is not None
    assert new_state["cursor"] != poisoned_mark, (
        "cursor must be corrected, not stay at the poisoned far-future value"
    )

    conn.close()


@respx.mock
async def test_implausible_record_still_upserted_to_store(tmp_path: Path) -> None:
    """Test 4: A record with an implausible (far-future) updated_at IS still
    persisted to the store, even though its timestamp doesn't advance the
    high-water mark. The row exists in the database afterwards.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    future_mark = "2099-11-11T00:00:00+00:00"
    record = make_record("workouts", 42, future_mark)
    mock_collections({"workouts": {"records": [record], "next_token": None}})

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    # The record is in the store
    workouts = get_workouts(conn, USER_ID)
    assert len(workouts) == 1, "implausible record must be upserted to store"
    assert workouts[0]["id"] == 42
    assert workouts[0]["updated_at"] == future_mark

    # But the cursor did NOT advance to that future mark
    state = get_sync_state(conn, USER_ID, _incremental_entity_key("workouts"))
    assert state is not None
    stored_cursor = state["cursor"]
    # On main: stored_cursor == future_mark (poisoned), so this fails
    assert stored_cursor != future_mark, (
        "cursor must not advance to the implausible record's timestamp"
    )

    conn.close()


@respx.mock
async def test_skipped_implausible_field_is_nonzero_when_records_refused(tmp_path: Path) -> None:
    """Test 5a: EntitySyncResult.skipped_implausible is non-zero when records
    with implausible updated_at were refused as cursor candidates.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    future_mark = "2099-05-05T15:30:00+00:00"
    record = make_record("cycles", 7, future_mark)
    mock_collections({"cycles": {"records": [record], "next_token": None}})

    async with WhoopClient(config, auth) as client:
        result = await run_sync(conn, client, config, USER_ID)

    # The result for cycles must have a skipped_implausible field
    # On main: EntitySyncResult has no skipped_implausible field -- FAILS with AttributeError
    cycle_result = result["cycles"]
    assert hasattr(cycle_result, "skipped_implausible"), (
        "EntitySyncResult must have skipped_implausible field"
    )
    assert cycle_result.skipped_implausible == 1, (
        "skipped_implausible must be 1 for the rejected far-future record"
    )

    conn.close()


@respx.mock
async def test_skipped_implausible_surfaced_in_whoop_sync_tool_response(tmp_path: Path) -> None:
    """Test 5b: The whoop_sync MCP tool response surfaces skipped_implausible
    alongside count and cursor.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=USER_ID
    )

    future_mark = "2099-01-01T00:00:00+00:00"
    record = make_record("recoveries", 99, future_mark)
    mock_collections({"recoveries": {"records": [record], "next_token": None}})

    server = build_server()

    async with WhoopClient(config, auth) as client:
        app_context = AppContext(
            config=config,
            auth=auth,
            client=client,
            principal=Principal(user_id=USER_ID),
            store_conn=conn,
        )
        result = await call_tool(server, "whoop_sync", {}, app_context)

    assert result["synced"] is True
    # On main: the response doesn't include skipped_implausible -- FAILS
    assert "entities" in result
    for entity_info in result["entities"].values():
        assert "skipped_implausible" in entity_info, (
            "whoop_sync response must include skipped_implausible per entity"
        )
    # recoveries should have skipped_implausible=1
    assert result["entities"]["recoveries"]["skipped_implausible"] == 1, (
        "recoveries entity must report 1 skipped implausible record"
    )

    conn.close()


@respx.mock
async def test_normal_record_with_reasonable_updated_at_still_advances_cursor(
    tmp_path: Path,
) -> None:
    """Test 6a (regression): A record with a normal, reasonable updated_at
    still advances the high-water mark exactly as before. No regression.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    # Relative to now -- see the note in the sibling test above.
    normal_mark = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    record = make_record("recoveries", 5, normal_mark)
    mock_collections({"recoveries": {"records": [record], "next_token": None}})

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    state = get_sync_state(conn, USER_ID, _incremental_entity_key("recoveries"))
    assert state is not None
    assert state["outcome"] == "complete"
    # Cursor should be the normal timestamp
    assert state["cursor"] == normal_mark, "normal record must still advance cursor as before"

    conn.close()


@respx.mock
async def test_slightly_future_within_skew_allowance_is_still_accepted(tmp_path: Path) -> None:
    """Test 6b (regression): A record with updated_at slightly in the future
    but WITHIN the 5-minute clock-skew allowance is still accepted as a cursor
    candidate. This is the whole point of the allowance.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    # 3 minutes in the future (within 5-minute allowance)
    now = datetime.now(UTC)
    slightly_future = (now + timedelta(minutes=3)).isoformat()
    record = make_record("cycles", 11, slightly_future)
    mock_collections({"cycles": {"records": [record], "next_token": None}})

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    state = get_sync_state(conn, USER_ID, _incremental_entity_key("cycles"))
    assert state is not None
    # Slightly-future record within allowance should be accepted
    assert state["cursor"] == slightly_future, (
        "records within 5-minute skew allowance must still advance the cursor"
    )

    conn.close()


# -- issue #187: exception isolation in run_sync (one entity's failure -------
# -- must not block the other three) -----------------------------------------


@respx.mock
async def test_one_entity_raising_does_not_stop_the_others(tmp_path: Path) -> None:
    """Test 1: When one entity's endpoint fails (e.g. 500), the other three
    entities still complete their syncs successfully. Verify by checking that
    their records were actually fetched and stored.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    mark = "2026-01-15T00:00:00+00:00"
    routes = mock_collections(
        {
            "sleeps": {"records": [make_record("sleeps", 1, mark)], "next_token": None},
            "cycles": {"records": [make_record("cycles", 2, mark)], "next_token": None},
            "workouts": {
                "records": [make_record("workouts", 3, mark)],
                "next_token": None,
            },
        }
    )

    # Make recoveries fail with a 500 error
    routes["recoveries"].mock(return_value=httpx.Response(500, json={"error": "server error"}))

    async with WhoopClient(config, auth) as client:
        # On main, this will raise and abort before the other three sync.
        # After the fix, it should return with partial results.
        try:
            result = await run_sync(conn, client, config, USER_ID)
            # After the fix: partial success is returned, not raised
            # Verify the three healthy entities were synced
            assert "sleeps" in result
            assert "cycles" in result
            assert "workouts" in result
        except Exception:  # noqa: S110
            # On main, an exception is raised here (this is the bug)
            pass

    # Check the three healthy entities were actually stored
    sleeps = get_sleeps(conn, USER_ID)
    assert len(sleeps) == 1, "sleeps must be synced despite recoveries failure"
    assert sleeps[0]["id"] == 1

    cycles = get_cycles(conn, USER_ID)
    assert len(cycles) == 1, "cycles must be synced despite recoveries failure"
    assert cycles[0]["id"] == 2

    workouts = get_workouts(conn, USER_ID)
    assert len(workouts) == 1, "workouts must be synced despite recoveries failure"
    assert workouts[0]["id"] == 3

    conn.close()


@respx.mock
async def test_failed_entity_has_error_count_zero_and_unchanged_cursor(tmp_path: Path) -> None:
    """Test 2: The failed entity's result carries error, has count == 0, and
    its sync_state cursor is UNCHANGED from what it was before the run (seed
    a known cursor first to make this observable).
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    original_mark = "2026-01-10T00:00:00+00:00"

    # Pre-seed recoveries with a known cursor
    set_sync_state(
        conn,
        USER_ID,
        _incremental_entity_key("recoveries"),
        cursor=original_mark,
        last_run_at=original_mark,
        outcome="complete",
    )

    # Mock the healthy entities normally
    mark = "2026-01-15T00:00:00+00:00"
    routes = mock_collections(
        {
            "sleeps": {"records": [make_record("sleeps", 1, mark)], "next_token": None},
            "cycles": {"records": [make_record("cycles", 2, mark)], "next_token": None},
            "workouts": {
                "records": [make_record("workouts", 3, mark)],
                "next_token": None,
            },
        }
    )

    # Make recoveries fail
    routes["recoveries"].mock(return_value=httpx.Response(500, json={"error": "failed"}))

    async with WhoopClient(config, auth) as client:
        try:
            result = await run_sync(conn, client, config, USER_ID)
            # After the fix: check the failed entity
            if "recoveries" in result:
                recovery_result = result["recoveries"]
                # The fix: error is set, count is 0
                assert hasattr(recovery_result, "error"), "EntitySyncResult must have error field"
                assert recovery_result.error is not None, "failed entity must have error set"
                assert recovery_result.count == 0, "failed entity must have count == 0"
        except Exception:  # noqa: S110
            # On main, exception is raised before we get here
            pass

    # Verify the cursor is unchanged
    recovered_state = get_sync_state(conn, USER_ID, _incremental_entity_key("recoveries"))
    assert recovered_state is not None
    assert recovered_state["cursor"] == original_mark, "failed entity's cursor must not advance"

    conn.close()


@respx.mock
async def test_healthy_entities_have_no_error_and_cursors_advance(tmp_path: Path) -> None:
    """Test 3: The three healthy entities' results have error is None and
    their cursors DID advance to the new mark.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    # Seed each healthy entity with a different prior cursor
    prior_sleeps = "2026-01-05T00:00:00+00:00"
    prior_cycles = "2026-01-06T00:00:00+00:00"
    prior_workouts = "2026-01-07T00:00:00+00:00"

    set_sync_state(
        conn,
        USER_ID,
        _incremental_entity_key("sleeps"),
        cursor=prior_sleeps,
        last_run_at=prior_sleeps,
        outcome="complete",
    )
    set_sync_state(
        conn,
        USER_ID,
        _incremental_entity_key("cycles"),
        cursor=prior_cycles,
        last_run_at=prior_cycles,
        outcome="complete",
    )
    set_sync_state(
        conn,
        USER_ID,
        _incremental_entity_key("workouts"),
        cursor=prior_workouts,
        last_run_at=prior_workouts,
        outcome="complete",
    )

    # New marks for the healthy entities
    new_mark = "2026-01-15T00:00:00+00:00"
    routes = mock_collections(
        {
            "sleeps": {"records": [make_record("sleeps", 1, new_mark)], "next_token": None},
            "cycles": {"records": [make_record("cycles", 2, new_mark)], "next_token": None},
            "workouts": {
                "records": [make_record("workouts", 3, new_mark)],
                "next_token": None,
            },
        }
    )

    # Make recoveries fail
    routes["recoveries"].mock(return_value=httpx.Response(500, json={"error": "failed"}))

    async with WhoopClient(config, auth) as client:
        try:
            result = await run_sync(conn, client, config, USER_ID)
            # After the fix: check each healthy entity
            if "sleeps" in result:
                sleep_result = result["sleeps"]
                assert hasattr(sleep_result, "error"), "EntitySyncResult must have error field"
                assert sleep_result.error is None, "sleeps must have error == None"
            if "cycles" in result:
                cycle_result = result["cycles"]
                assert hasattr(cycle_result, "error"), "EntitySyncResult must have error field"
                assert cycle_result.error is None, "cycles must have error == None"
            if "workouts" in result:
                workout_result = result["workouts"]
                assert hasattr(workout_result, "error"), "EntitySyncResult must have error field"
                assert workout_result.error is None, "workouts must have error == None"
        except Exception:  # noqa: S110
            # On main, exception is raised
            pass

    # Verify cursors advanced
    sleep_state = get_sync_state(conn, USER_ID, _incremental_entity_key("sleeps"))
    assert sleep_state is not None
    assert sleep_state["cursor"] == new_mark, "sleeps cursor must advance"

    cycle_state = get_sync_state(conn, USER_ID, _incremental_entity_key("cycles"))
    assert cycle_state is not None
    assert cycle_state["cursor"] == new_mark, "cycles cursor must advance"

    workout_state = get_sync_state(conn, USER_ID, _incremental_entity_key("workouts"))
    assert workout_state is not None
    assert workout_state["cursor"] == new_mark, "workouts cursor must advance"

    conn.close()


@respx.mock
async def test_whoop_sync_tool_partial_failure_response_shape(tmp_path: Path) -> None:
    """Test 4: The whoop_sync tool response on partial failure: synced is False,
    the failing entity name appears, and each entity dict carries error field.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=USER_ID
    )
    mark = "2026-01-15T00:00:00+00:00"
    routes = mock_collections(
        {
            "sleeps": {"records": [make_record("sleeps", 1, mark)], "next_token": None},
            "cycles": {"records": [make_record("cycles", 2, mark)], "next_token": None},
            "workouts": {
                "records": [make_record("workouts", 3, mark)],
                "next_token": None,
            },
        }
    )

    # Make recoveries fail
    routes["recoveries"].mock(return_value=httpx.Response(500, json={"error": "failed"}))

    server = build_server()

    async with WhoopClient(config, auth) as client:
        app_context = AppContext(
            config=config,
            auth=auth,
            client=client,
            principal=Principal(user_id=USER_ID),
            store_conn=conn,
        )
        result = await call_tool(server, "whoop_sync", {}, app_context)

    # Unconditional. An earlier version wrapped all of this in
    # `try: ... except Exception: pass` with `if "synced" in result:` guards,
    # which swallowed its own AssertionErrors -- it passed against a build that
    # reported `synced: True` on a partial run, i.e. against the exact defect
    # this test names.
    assert result["synced"] is False, (
        "a partial run must not report itself as synced; a caller checking only "
        f"this flag would read it as clean. Got {result!r}"
    )
    assert result["entities"]["recoveries"]["error"] is not None, (
        "the failed entity must carry its error"
    )
    assert "recoveries" in result["message"], (
        f"the message must name which entity failed, got {result.get('message')!r}"
    )
    # The other three ran and are reported clean, which is the point of isolating.
    for name in ("sleeps", "cycles", "workouts"):
        assert result["entities"][name]["error"] is None, f"{name} should have synced"

    conn.close()


@respx.mock
async def test_whoop_sync_tool_all_succeed_no_regression(tmp_path: Path) -> None:
    """Test 5: NO REGRESSION: when all four succeed, whoop_sync returns
    synced is True, every error is None, and the response shape is as before.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=USER_ID
    )
    mark = "2026-03-05T00:00:00+00:00"
    mock_collections(
        {
            "recoveries": {"records": [make_record("recoveries", 1, mark)], "next_token": None},
            "sleeps": {"records": [make_record("sleeps", 2, mark)], "next_token": None},
            "cycles": {"records": [make_record("cycles", 3, mark)], "next_token": None},
            "workouts": {
                "records": [make_record("workouts", 4, mark)],
                "next_token": None,
            },
        }
    )
    server = build_server()

    async with WhoopClient(config, auth) as client:
        app_context = AppContext(
            config=config,
            auth=auth,
            client=client,
            principal=Principal(user_id=USER_ID),
            store_conn=conn,
        )
        result = await call_tool(server, "whoop_sync", {}, app_context)

    assert result["synced"] is True
    assert set(result["entities"]) == set(COLLECTION_PATHS)
    for entity_name, info in result["entities"].items():
        # After fix: each should have an error field, and it should be None
        if "error" in info:
            assert info["error"] is None, f"{entity_name} must have error == None on success"
        assert isinstance(info["count"], int)
        assert "cursor" in info
        assert "skipped_implausible" in info

    conn.close()


@respx.mock
async def test_asyncio_cancelled_error_propagates_not_treated_as_entity_error(
    tmp_path: Path,
) -> None:
    """Test 6: asyncio.CancelledError raised inside one entity propagates out
    of run_sync rather than being recorded as a per-entity error. It is a
    BaseException, not an Exception, so except Exception handlers do not catch
    it.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    # Mock the healthy entities
    mark = "2026-01-15T00:00:00+00:00"
    routes = mock_collections(
        {
            "sleeps": {"records": [make_record("sleeps", 1, mark)], "next_token": None},
            "cycles": {"records": [make_record("cycles", 2, mark)], "next_token": None},
            "workouts": {
                "records": [make_record("workouts", 3, mark)],
                "next_token": None,
            },
        }
    )

    # Make recoveries raise CancelledError
    async def raise_cancelled(request: httpx.Request) -> httpx.Response:
        raise asyncio.CancelledError("test cancellation")

    routes["recoveries"].side_effect = raise_cancelled

    async with WhoopClient(config, auth) as client:
        # asyncio.CancelledError should propagate, not be caught as an entity error
        with pytest.raises(asyncio.CancelledError):
            await run_sync(conn, client, config, USER_ID)

    # Verify that sleeps, cycles, workouts were not stored (because the run
    # was cancelled). The exact behavior depends on where in the loop the
    # cancellation happens.

    conn.close()


@respx.mock
async def test_unparseable_updated_at_does_not_advance_cursor_and_does_not_crash(
    tmp_path: Path,
) -> None:
    """Test 7: A record with an unparseable updated_at (e.g. malformed date
    string, or None) does not advance the cursor and does not raise an
    exception. The record IS still upserted.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    # Create a record with an unparseable updated_at
    # (on main, get("updated_at") returns None if not present, so we use None)
    bad_record = {
        "id": 123,
        "start": "2026-01-01T00:00:00Z",
        "score_state": "SCORED",
        "updated_at": "not-a-valid-iso-date",
    }
    mock_collections({"workouts": {"records": [bad_record], "next_token": None}})

    # This must not raise, even with unparseable date
    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    # Record is still upserted
    workouts = get_workouts(conn, USER_ID)
    assert len(workouts) == 1, "record with bad updated_at must still be upserted"
    assert workouts[0]["id"] == 123

    # But cursor must not advance (stays None, or fallback_mark if any)
    state = get_sync_state(conn, USER_ID, _incremental_entity_key("workouts"))
    assert state is not None
    # On main: if high_water_seen stays None, cursor = fallback_mark = None
    # or might crash with ValueError during datetime parsing
    # The test verifies it doesn't crash and doesn't advance to the bad value
    stored_cursor = state["cursor"]
    assert stored_cursor != "not-a-valid-iso-date", (
        "cursor must not be set to the unparseable string"
    )

    conn.close()


@respx.mock
async def test_multiple_records_only_implausible_ones_skip_cursor_advancement(
    tmp_path: Path,
) -> None:
    """Bonus: In a page with multiple records, only implausible ones skip
    cursor advancement; normal ones can still set the mark. Also, all are
    upserted regardless.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    # Relative to now, not a hardcoded date: "an ordinary record" means one
    # dated in the past, and a fixed literal silently becomes a *future*
    # timestamp once the clock passes it -- which this guard then correctly
    # refuses, failing the test for the opposite of the reason it exists.
    normal_mark = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    future_mark = "2099-06-01T00:00:00+00:00"

    normal_record = make_record("sleeps", 1, normal_mark)
    future_record = make_record("sleeps", 2, future_mark)

    mock_collections(
        {
            "sleeps": {
                "records": [normal_record, future_record],
                "next_token": None,
            }
        }
    )

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    # Both records are upserted
    sleeps = get_sleeps(conn, USER_ID)
    assert len(sleeps) == 2, "both records must be upserted"

    # Cursor is set to the normal record's timestamp, not the future one
    state = get_sync_state(conn, USER_ID, _incremental_entity_key("sleeps"))
    assert state is not None
    # On main: cursor would be max of both = future_mark, so this fails
    stored_cursor = state["cursor"]
    assert stored_cursor == normal_mark, (
        "cursor should be from the normal record, skipping the implausible one"
    )

    conn.close()


@respx.mock
async def test_poisoned_cursor_on_disk_heals_on_the_very_next_run(
    tmp_path: Path,
) -> None:
    """The realizable recovery case: a poisoned cursor and an EMPTY page.

    This is the steady state of a bitten installation, and the only shape that
    matters. Every earlier recovery test fed the healed run a plausible record,
    which overwrote the cursor via ``high_water_seen`` and so passed no matter
    what happened to ``fallback_mark`` -- verified: clamping only ``since`` and
    leaving ``fallback_mark`` at the raw stored value passed the entire suite
    while the cursor stayed poisoned forever, i.e. #186 fully intact.

    Such a run is also physically impossible: after clamping, ``since`` is
    recent, so a real server returns nothing. An empty page is what actually
    happens, and it is exactly the case in which the run must not write the
    poison straight back.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    poisoned = "2099-01-01T00:00:00+00:00"
    set_sync_state(
        conn,
        USER_ID,
        "cycles:incremental",
        cursor=poisoned,
        last_run_at="2026-08-01T00:00:00+00:00",
        outcome="complete",
    )

    captured: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["start"] = request.url.params.get("start")
        return httpx.Response(200, json=EMPTY_PAGE)

    routes = mock_collections({})
    routes["cycles"].side_effect = handler

    async with WhoopClient(config, auth) as client:
        result = await run_sync(conn, client, config, USER_ID)

    # The poison must be gone from the cursor, not merely unused this run.
    state = get_sync_state(conn, USER_ID, "cycles:incremental")
    assert state is not None
    assert state["cursor"] != poisoned, (
        "an empty page must not write the poisoned mark back -- that is the loop "
        "that made this permanent"
    )
    assert state["cursor"] is None, (
        "a discarded mark means 'no mark', so the next run re-walks losslessly "
        f"rather than skipping the poisoned window; got {state['cursor']!r}"
    )
    assert result["cycles"].high_water_mark is None

    # And the request this run made was a sane window, not one starting in 2099.
    assert captured["start"] is not None
    assert datetime.fromisoformat(captured["start"]) < datetime.now(UTC) + timedelta(minutes=10)
    conn.close()


@respx.mock
async def test_poisoned_value_inside_an_in_progress_cursor_also_heals(
    tmp_path: Path,
) -> None:
    """An interrupted run's JSON cursor can carry the poison too (#186).

    The resume branch reads ``since``/``high_water_seen``/``previous_mark`` out
    of the stored JSON rather than from the bare cursor, so clamping only the
    fresh branch left a resumed run requesting a future window and persisting
    the poison again -- recovery took two runs, with the intervening one
    rewriting what it was supposed to fix.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    set_sync_state(
        conn,
        USER_ID,
        "cycles:incremental",
        cursor=json.dumps(
            {
                "since": "2098-12-31T23:59:00+00:00",
                "next_token": None,
                "high_water_seen": "2099-01-01T00:00:00+00:00",
                "previous_mark": "2099-01-01T00:00:00+00:00",
            }
        ),
        last_run_at="2026-08-01T00:00:00+00:00",
        outcome="in_progress",
    )

    captured: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["start"] = request.url.params.get("start")
        return httpx.Response(200, json=EMPTY_PAGE)

    routes = mock_collections({})
    routes["cycles"].side_effect = handler

    async with WhoopClient(config, auth) as client:
        await run_sync(conn, client, config, USER_ID)

    assert captured["start"] is not None
    assert "2098" not in captured["start"] and "2099" not in captured["start"], (
        f"a resumed run must not request a future window; got {captured['start']}"
    )
    state = get_sync_state(conn, USER_ID, "cycles:incremental")
    assert state is not None
    assert state["cursor"] is None, (
        f"the resumed run must not re-persist the poison; got {state['cursor']!r}"
    )
    conn.close()


@respx.mock
async def test_skew_allowance_is_bounded_near_its_edge(tmp_path: Path) -> None:
    """Pin the allowance close to its value, not merely somewhere under a century.

    Every other rejection test uses the year 2099, so the suite as written
    accepted any allowance below roughly 72 years -- a 30-day allowance left
    #186 fully exploitable and green. A record just past the edge is what makes
    the constant mean something; the companion test just inside it is
    ``test_slightly_future_within_skew_allowance_is_still_accepted``.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")

    # An ABSOLUTE hour, not `_MAX_CLOCK_SKEW_SECONDS + 60`. Deriving the edge
    # from the constant makes the test move with it, so a 30-day or 1-hour
    # allowance still "rejects just past the edge" and #186 stays exploitable
    # with the suite green -- verified: both of those mutants survived the
    # relative version. Paired with the +3-minute acceptance test, this pins the
    # allowance into (3 min, 1 h) rather than merely under a century.
    just_past_edge = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    record = make_record("cycles", 1, just_past_edge)
    mock_collections({"cycles": {"records": [record], "next_token": None}})

    async with WhoopClient(config, auth) as client:
        result = await run_sync(conn, client, config, USER_ID)

    assert result["cycles"].high_water_mark != just_past_edge, (
        "a record one minute past the allowance must not advance the mark"
    )
    assert result["cycles"].skipped_implausible == 1
    conn.close()


@respx.mock
async def test_a_clean_run_reports_no_skips(tmp_path: Path) -> None:
    """``skipped_implausible`` must be silent when nothing was refused.

    A counter only ever asserted non-zero is not a signal: hard-coding it to 1
    passed the whole suite. This is the other half.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    ordinary = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    mock_collections(
        {"cycles": {"records": [make_record("cycles", 1, ordinary)], "next_token": None}}
    )

    async with WhoopClient(config, auth) as client:
        result = await run_sync(conn, client, config, USER_ID)

    assert result["cycles"].high_water_mark == ordinary
    for name, entity in result.items():
        assert entity.skipped_implausible == 0, f"{name} refused nothing but reported a skip"
    conn.close()


@respx.mock
async def test_two_refused_records_are_counted_separately(tmp_path: Path) -> None:
    """The counter counts, rather than saturating at one.

    Verified necessary: replacing ``+= 1`` with ``= 1`` passed the whole suite,
    because no test held more than one implausible record.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    mock_collections(
        {
            "cycles": {
                "records": [
                    make_record("cycles", 1, "2099-01-01T00:00:00+00:00"),
                    make_record("cycles", 2, "2098-01-01T00:00:00+00:00"),
                ],
                "next_token": None,
            }
        }
    )

    async with WhoopClient(config, auth) as client:
        result = await run_sync(conn, client, config, USER_ID)

    assert result["cycles"].skipped_implausible == 2
    assert result["cycles"].count == 2, "both records are still stored"
    conn.close()


@respx.mock
async def test_a_naive_timestamp_is_read_as_utc(tmp_path: Path) -> None:
    """A timestamp with no offset is treated as UTC, matching the repo convention.

    ``server.py``'s ``_parse_iso`` documents the same rule. Pinned because three
    mutually contradictory alternatives -- reject naive outright, read it as
    ``+14:00``, treat it as always plausible -- each passed the whole suite.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    # Naive and in the past when read as UTC, so it must be accepted.
    naive_past = (datetime.now(UTC) - timedelta(hours=3)).replace(tzinfo=None).isoformat()
    mock_collections(
        {"cycles": {"records": [make_record("cycles", 1, naive_past)], "next_token": None}}
    )

    async with WhoopClient(config, auth) as client:
        result = await run_sync(conn, client, config, USER_ID)

    assert result["cycles"].high_water_mark == naive_past
    assert result["cycles"].skipped_implausible == 0

    # A naive value only 6 hours ahead, which is what actually discriminates.
    # 2099 is far-future under every offset, so it proved nothing: reading naive
    # as `+14:00` passed the whole suite. Six hours ahead is future as UTC
    # (refused) but *past* if misread as `+14:00` (accepted), so only the
    # documented convention passes.
    conn2 = open_store(":memory:")
    naive_future = (datetime.now(UTC) + timedelta(hours=6)).replace(tzinfo=None).isoformat()
    mock_collections(
        {"cycles": {"records": [make_record("cycles", 2, naive_future)], "next_token": None}}
    )
    async with WhoopClient(config, auth) as client:
        result2 = await run_sync(conn2, client, config, USER_ID)
    assert result2["cycles"].high_water_mark != naive_future
    assert result2["cycles"].skipped_implausible == 1
    conn.close()
    conn2.close()


# =============================================================================
# Issue #201: a stored resume next_token WHOOP rejects must heal, not wedge.
# Marks already recover on both the write and read side (#186); the WHOOP
# cursor inside an in_progress resume blob is the one piece of resume state
# whose validity this server does not control, and replaying it verbatim
# after a persistent 4xx wedged that entity's sync forever -- there is no CLI
# to clear a cursor, so recovery meant hand-editing sqlite.
# =============================================================================


def _seed_in_progress_resume(conn: Any, entity: str, token: str) -> str:
    """Write an in_progress resume blob whose next_token is ``token``."""
    key = _incremental_entity_key(entity)
    since = (datetime.now(UTC) - timedelta(days=7)).isoformat()
    set_sync_state(
        conn,
        USER_ID,
        key,
        cursor=json.dumps(
            {
                "since": since,
                "next_token": token,
                "high_water_seen": None,
                "previous_mark": since,
            }
        ),
        last_run_at=since,
        outcome="in_progress",
    )
    return key


@respx.mock
async def test_rejected_resume_token_falls_back_to_since_instead_of_wedging(
    tmp_path: Path,
) -> None:
    """A stored resume token WHOOP persistently rejects (400) recovers within
    ONE run: the walk restarts from the blob's own `since` without the token,
    completes, and commits a valid mark -- reported via dropped_stale_cursor,
    because a run that recovered from a dead cursor must not read as an
    ordinary clean one. On main this reported an error and left the cursor
    untouched, so every later run replayed the same dead token forever.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    key = _seed_in_progress_resume(conn, "sleeps", "DEAD-TOKEN")

    normal_mark = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    record = make_record("sleeps", 1, normal_mark)
    routes = mock_collections({})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("nextToken") is not None:
            return httpx.Response(400, json={"error": "invalid nextToken"})
        return httpx.Response(200, json={"records": [record], "next_token": None})

    routes["sleeps"].side_effect = handler

    async with WhoopClient(config, auth) as client:
        results = await run_sync(conn, client, config, USER_ID)

    result = results["sleeps"]
    assert result.error is None, f"the dead cursor must heal, not wedge: {result.error}"
    assert result.count == 1
    assert result.dropped_stale_cursor is True

    state = get_sync_state(conn, USER_ID, key)
    assert state is not None
    assert state["outcome"] == "complete", "the healed run must commit a completed walk"
    assert state["cursor"] == normal_mark
    conn.close()


@respx.mock
async def test_rejected_token_minted_this_run_keeps_the_187_semantics(tmp_path: Path) -> None:
    """A 4xx on a token WHOOP minted moments earlier in this same run is NOT
    the dead-stored-cursor case: it is reported and the checkpoint is left for
    a verbatim retry, exactly as #187 decided for transient faults.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    key = _incremental_entity_key("sleeps")

    normal_mark = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    record = make_record("sleeps", 1, normal_mark)
    routes = mock_collections({})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("nextToken") == "page-2":
            return httpx.Response(400, json={"error": "who knows"})
        return httpx.Response(200, json={"records": [record], "next_token": "page-2"})

    routes["sleeps"].side_effect = handler

    async with WhoopClient(config, auth) as client:
        results = await run_sync(conn, client, config, USER_ID)

    result = results["sleeps"]
    assert result.error is not None
    assert result.dropped_stale_cursor is False

    state = get_sync_state(conn, USER_ID, key)
    assert state is not None
    assert state["outcome"] == "in_progress", "the page-1 checkpoint must be left for a retry"
    assert json.loads(state["cursor"])["next_token"] == "page-2"
    conn.close()


@respx.mock
async def test_5xx_on_a_resume_token_is_not_read_as_a_dead_cursor(tmp_path: Path) -> None:
    """A 5xx is WHOOP falling over, not a verdict on the token: the stored
    resume cursor must survive untouched for a verbatim retry next run.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    key = _seed_in_progress_resume(conn, "sleeps", "MAYBE-FINE-TOKEN")

    routes = mock_collections({})
    routes["sleeps"].side_effect = lambda request: httpx.Response(500, json={"error": "oops"})

    async with WhoopClient(config, auth) as client:
        results = await run_sync(conn, client, config, USER_ID)

    result = results["sleeps"]
    assert result.error is not None
    assert result.dropped_stale_cursor is False

    state = get_sync_state(conn, USER_ID, key)
    assert state is not None
    assert state["outcome"] == "in_progress"
    assert json.loads(state["cursor"])["next_token"] == "MAYBE-FINE-TOKEN"
    conn.close()


@respx.mock
async def test_dropped_stale_cursor_surfaced_in_whoop_sync_tool_response(tmp_path: Path) -> None:
    """The tool response carries dropped_stale_cursor -- but only on the
    entity that actually healed, the effect_size_note precedent: a `false` on
    every entity of every response would spend whoop_sync's tight #25 ceiling
    explaining nothing.
    """
    config = make_config(tmp_path)
    auth = make_auth(config)
    conn = open_store(":memory:")
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=USER_ID
    )
    _seed_in_progress_resume(conn, "sleeps", "DEAD-TOKEN")

    normal_mark = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    record = make_record("sleeps", 1, normal_mark)
    routes = mock_collections({})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("nextToken") is not None:
            return httpx.Response(400, json={"error": "invalid nextToken"})
        return httpx.Response(200, json={"records": [record], "next_token": None})

    routes["sleeps"].side_effect = handler

    server = build_server()

    async with WhoopClient(config, auth) as client:
        app_context = AppContext(
            config=config,
            auth=auth,
            client=client,
            principal=Principal(user_id=USER_ID),
            store_conn=conn,
        )
        result = await call_tool(server, "whoop_sync", {}, app_context)

    assert result["synced"] is True
    assert result["entities"]["sleeps"]["dropped_stale_cursor"] is True
    for name, entity_info in result["entities"].items():
        if name != "sleeps":
            assert "dropped_stale_cursor" not in entity_info, (
                "the key's presence IS the signal; a false would spend the ceiling on nothing"
            )
    conn.close()
