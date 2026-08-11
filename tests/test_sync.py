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

import json
import time
from collections.abc import Callable
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
        with pytest.raises(httpx.ConnectError):
            await run_sync(conn, client, config, USER_ID)

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
        with pytest.raises(httpx.ConnectError):
            await run_sync(conn, client, config, USER_ID)

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
        rows = disabled_conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchall()  # noqa: S608
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
        rows = conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchall()  # noqa: S608
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
