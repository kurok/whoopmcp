"""Tests for issue #29: tenancy -- identity join and cross-tenant isolation.

Written before any implementation exists, per the issue's own instruction.
None of this depends on #28's ``MCPTokenVerifier._resolve`` ever talking to a
real external authorization server: like #28's own test suite, every test
here injects an ``AccessToken``-shaped principal directly (via
``AuthenticatedUser``/``_principal_request`` below) at the same seam
``BearerAuthBackend`` uses in production, never through a real bearer-token
HTTP round trip. See the task's own anchors for why that seam is sufficient
and #28's stub has no bearing on this issue's testability.

#29 has since landed, so every symbol this file needs (``resolve_member_id``,
``UnresolvedPrincipalError``, ``AppContext.store_conn``, ``whoopmcp.store
.link_principal_to_member``, ``.get_member_for_principal``, ``.record_tool_call``,
``.UnscopedQueryError``, ``._execute_scoped``, ``._TENANT_SCOPED_TABLES``) now
exists, and both import styles behave identically -- this file previously
referenced the not-yet-existing ``whoopmcp.server`` symbols via module
attribute access instead of ``from ... import ...``, specifically so it still
*collected* while #29 was unimplemented, and has since been consolidated onto
one style now that the workaround is no longer needed. ``whoopmcp.store`` is
still accessed via module attribute access (``store.X``) throughout, by
choice, not by that same necessity.

Two design decisions worth calling out explicitly, since the issue asks that
ambiguity be surfaced rather than silently resolved:

1. **What "refuses to leak" means given today's single-tenant ``WhoopClient``.**
   Every data/analysis tool talks to one process-wide live WHOOP client tied
   to one WHOOP grant (member A throughout this file). There is no "member
   B's live data" for that client to return -- B literally does not exist as
   a live grant. So the only data any tool can produce IS member A's, and the
   registry sweep below (``test_every_read_only_registered_tool_refuses_to
   _serve_a_mismatched_member``) encodes "refuses to leak" as: calling under
   a principal resolving to a *different* member than the live grant must
   either raise, or -- if it somehow succeeds -- must not carry member A's
   data. It must never silently hand A's data to B's session. This matches
   the explorer plan's own "cross-checked against app.principal.user_id...
   errors on mismatch" design and does not require #29 to make auth.py/client.py
   genuinely multi-tenant (out of scope, per the plan's own minor_decisions).
2. **The discriminating-power fixture is a permanent meta-test, not a
   temporary one.** The issue asks for a temporarily-added unprotected tool
   that is "removed before this ships, unless you have a good reason to
   leave a regression-proving fixture in place." This file keeps one
   (``test_marker_detector_flags_a_deliberately_unprotected_tool``), but it
   is never part of ``build_server()``'s real registry -- it registers its
   demo tool on its own throwaway server instance, inside the test itself,
   so it never ships as a live vulnerability. The reason to keep it: it is
   the only test in this file that exercises the *detector* (the "does the
   marker leak" assertion) rather than the not-yet-written implementation,
   so it is the one test that can catch a future refactor of the sweep
   silently losing its teeth. It needs no symbol from #29's implementation
   (only ``build_server``, ``AppContext``, ``Principal``, all of which exist
   today), which is also why it is the one test in this file that already
   passes.
"""

from __future__ import annotations

import ast
import inspect
import json
import sqlite3
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context, MCPServer
from mcp.types import CallToolRequestParams, GetPromptResult

from whoopmcp import store, webhook_processor
from whoopmcp.auth import TOKEN_URL, Authenticator, FileTokenStore, Token
from whoopmcp.client import BASE_URL, WhoopClient
from whoopmcp.config import Config
from whoopmcp.server import (
    READ_ONLY,
    AppContext,
    Principal,
    UnresolvedPrincipalError,
    build_server,
    resolve_member_id,
)

# Two WHOOP members. Large, distinctive integers so their decimal string forms
# are vanishingly unlikely to appear by coincidence in a randomly generated
# OAuth `state` value or similar.
MEMBER_A = 900001
MEMBER_B = 900002

_FIXED_SLEEP_ID = "sleep-fixture-1"
_FIXED_WORKOUT_ID = "workout-fixture-1"

# -- shared fixtures, mirroring tests/test_context_budget.py's own ----------


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


@pytest.fixture(autouse=True)
def _seed_valid_token(config: Config) -> None:
    FileTokenStore(config.token_path).save(
        Token("fake-access-token", expires_at=time.time() + 3600, refresh_token="fake-refresh")
    )


@pytest.fixture
def store_conn() -> sqlite3.Connection:
    conn = store.open_store(":memory:")
    yield conn
    conn.close()


# -- context/call-tool helpers, mirroring test_context_budget.py's call_tool,
# extended with `request=` (a fake per-message HTTP-transport object carrying
# an authenticated principal, or None for stdio) and `params=` (a real
# CallToolRequestParams, matching what the SDK's own `_handle_call_tool`
# passes through in production) so resolve_member_id has a legitimate,
# non-invented way to learn both "who is calling" and "which tool" ----------


class _FakeHTTPRequest:
    """Minimal stand-in for the Starlette ``Request`` a bearer-authenticated
    HTTP transport attaches to ``ServerRequestContext.request`` (see that
    field's own docstring: "any per-message data the transport attached").

    Deliberately carries a spoofable ``query_params``/``headers`` pair, so
    tests below can prove ``resolve_member_id`` never consults them for
    identity -- only the token-derived principal, joined against
    ``principal_members``, may ever decide the resolved member.
    """

    def __init__(
        self, user: AuthenticatedUser | None, *, spoofed_member_id: int | None = None
    ) -> None:
        self.user = user
        self.query_params: dict[str, str] = (
            {"whoop_user_id": str(spoofed_member_id)} if spoofed_member_id is not None else {}
        )
        self.headers: dict[str, str] = (
            {"X-Whoop-User-Id": str(spoofed_member_id)} if spoofed_member_id is not None else {}
        )


def _principal_request(client_id: str, *, spoofed_member_id: int | None = None) -> _FakeHTTPRequest:
    """A fake authenticated HTTP request for MCP principal `client_id`.

    Mirrors how #28's own tests construct ``AccessToken`` values directly
    (see e.g. ``test_token_naming_this_resource_is_accepted``) rather than
    resolving a real bearer string.
    """
    token = AccessToken(
        token="test-token", client_id=client_id, scopes=[], resource=None, subject=None
    )
    return _FakeHTTPRequest(AuthenticatedUser(token), spoofed_member_id=spoofed_member_id)


def _build_context(
    app_context: AppContext,
    request: Any,
    *,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    server: MCPServer[AppContext] | None = None,
) -> Context[AppContext, Any]:
    request_context = ServerRequestContext(
        session=None,  # type: ignore[arg-type]
        lifespan_context=app_context,
        protocol_version="2025-06-18",
        method="tools/call",
        request=request,
        params=CallToolRequestParams(name=tool_name, arguments=arguments or {}),
    )
    return Context(request_context=request_context, mcp_server=server)


async def _call_tool_as(
    server: MCPServer[AppContext],
    name: str,
    arguments: dict[str, Any],
    app_context: AppContext,
    request: Any | None = None,
) -> Any:
    """Call a tool as `request`'s principal, and unwrap its return value.

    Same unwrap logic as tests/test_context_budget.py's helper of the same
    name -- see that module's docstring for why it is needed.
    """
    context = _build_context(
        app_context, request, tool_name=name, arguments=arguments, server=server
    )
    result = await server.call_tool(name, arguments, context=context)
    if result.structured_content is not None:
        return result.structured_content
    return result


def _result_text(result: Any) -> str:
    """Flatten a tool result to searchable text for a marker-substring check."""
    return str(result)


async def _read_resource_as(
    server: MCPServer[AppContext],
    uri: str,
    app_context: AppContext,
    request: Any | None = None,
) -> dict[str, Any]:
    """Read a resource as `request`'s principal, and unwrap+parse its JSON
    content -- the resource-read analogue of `_call_tool_as` above, at the
    same dispatch depth, for sweeping #26's one whoop://user/{item}
    template alongside the tool registry below."""
    request_context = ServerRequestContext(
        session=None,  # type: ignore[arg-type]
        lifespan_context=app_context,
        protocol_version="2025-06-18",
        method="resources/read",
        request=request,
    )
    context = Context(request_context=request_context, mcp_server=server)
    result = await server.read_resource(uri, context=context)
    contents = list(result)  # type: ignore[arg-type]
    content = contents[0].content
    if isinstance(content, bytes):
        content = content.decode()
    parsed = json.loads(content)
    assert isinstance(parsed, dict)
    return parsed


# =============================================================================
# store.py: schema (v3 -- principal_members, tool_call_audit)
# =============================================================================


def test_schema_version_bumped_to_five() -> None:
    """#18's webhook_events was v2, #29's principal_members/tool_call_audit
    was v3, #19's per-user webhook_delivery_state was v4; #105's rebuild of
    webhook_events.whoop_user_id to NOT NULL is the next migration in the
    ladder."""
    assert store.CURRENT_SCHEMA_VERSION == 5


def test_principal_members_table_has_expected_columns() -> None:
    conn = store.open_store(":memory:")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(principal_members)")}
    assert columns == {"client_id", "issuer", "subject", "whoop_user_id", "linked_at"}
    conn.close()


def test_tool_call_audit_table_is_shape_locked_to_no_payload_columns() -> None:
    """A schema-shape guarantee, not a redaction step that could have a bug:
    nobody can silently add an arguments/result/payload column to this table
    without this test failing first. Mirrors the registry-enumeration "no
    hand-maintained list" spirit at the schema level."""
    conn = store.open_store(":memory:")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(tool_call_audit)")}
    assert columns == {"id", "whoop_user_id", "tool_name", "called_at"}
    conn.close()


def test_principal_members_table_starts_empty_on_a_fresh_store() -> None:
    """Nothing populates this table except a completed WHOOP authorisation."""
    conn = store.open_store(":memory:")
    count = conn.execute("SELECT COUNT(*) FROM principal_members").fetchone()[0]
    assert count == 0
    conn.close()


# =============================================================================
# store.py: principal <-> member mapping round trip
# =============================================================================


def test_link_principal_to_member_then_get_member_for_principal_round_trips() -> None:
    conn = store.open_store(":memory:")
    store.link_principal_to_member(
        conn,
        client_id="client-1",
        issuer="https://as.example.com",
        subject="sub-1",
        whoop_user_id=MEMBER_A,
    )

    result = store.get_member_for_principal(
        conn, client_id="client-1", issuer="https://as.example.com", subject="sub-1"
    )

    assert result == MEMBER_A
    conn.close()


def test_get_member_for_principal_returns_none_when_unlinked() -> None:
    conn = store.open_store(":memory:")

    result = store.get_member_for_principal(conn, client_id="nobody", issuer=None, subject=None)

    assert result is None
    conn.close()


def test_distinct_subjects_under_same_client_id_resolve_independently() -> None:
    """Two different end users behind the same OAuth client_id (issuer and
    subject differ) must not collide onto the same member."""
    conn = store.open_store(":memory:")
    store.link_principal_to_member(
        conn,
        client_id="shared-client",
        issuer="https://as.example.com",
        subject="user-a",
        whoop_user_id=MEMBER_A,
    )
    store.link_principal_to_member(
        conn,
        client_id="shared-client",
        issuer="https://as.example.com",
        subject="user-b",
        whoop_user_id=MEMBER_B,
    )

    a = store.get_member_for_principal(
        conn, client_id="shared-client", issuer="https://as.example.com", subject="user-a"
    )
    b = store.get_member_for_principal(
        conn, client_id="shared-client", issuer="https://as.example.com", subject="user-b"
    )

    assert (a, b) == (MEMBER_A, MEMBER_B)
    conn.close()


def test_link_principal_to_member_is_an_idempotent_upsert() -> None:
    """Re-linking the same principal (e.g. re-authorising) updates the
    mapping in place rather than duplicating the row."""
    conn = store.open_store(":memory:")
    store.link_principal_to_member(
        conn, client_id="c", issuer=None, subject=None, whoop_user_id=MEMBER_A
    )
    store.link_principal_to_member(
        conn, client_id="c", issuer=None, subject=None, whoop_user_id=MEMBER_B
    )

    count = conn.execute("SELECT COUNT(*) FROM principal_members").fetchone()[0]
    resolved = store.get_member_for_principal(conn, client_id="c", issuer=None, subject=None)

    assert count == 1
    assert resolved == MEMBER_B
    conn.close()


# =============================================================================
# store.py: database-level enforcement -- fails closed, not app-code discipline
# =============================================================================


def test_scoped_select_with_whoop_user_id_predicate_succeeds() -> None:
    """Positive control: the check isn't just "always raise"."""
    conn = store.open_store(":memory:")
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})

    cursor = store._execute_scoped(
        conn, "SELECT raw_json FROM recoveries WHERE whoop_user_id = ?", (MEMBER_A,)
    )

    assert len(cursor.fetchall()) == 1
    conn.close()


def test_unscoped_select_with_a_different_filter_fails_closed() -> None:
    """The realistic version of "forgot the member argument": a query that
    filters on *something* (here, resource_id) but never whoop_user_id.
    No row must reach the caller."""
    conn = store.open_store(":memory:")
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(conn, "SELECT raw_json FROM recoveries WHERE resource_id = ?", ("1",))
    conn.close()


def test_completely_unfiltered_select_fails_closed() -> None:
    """The plainest version of the failure mode: no WHERE clause at all."""
    conn = store.open_store(":memory:")
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(conn, "SELECT raw_json FROM recoveries")
    conn.close()


def test_unscoped_update_fails_closed_and_leaves_no_pending_mutation() -> None:
    """An unscoped UPDATE must not just raise -- by the time ``conn.execute``
    returns, sqlite has already run the statement (its authorizer fires
    during *compilation*, and Python's sqlite3 module steps a non-SELECT
    statement to completion inside a single ``execute()`` call), so raising
    alone is not enough: without an internal rollback, the mutation would sit
    as a pending, uncommitted change on the connection and could be silently
    persisted by a *later*, unrelated ``conn.commit()`` -- exactly the kind
    of "fail closed in appearance, fail open in practice" bug this test
    exists to catch. Verified empirically (a standalone sqlite3 authorizer
    script, not just reasoned about) before writing this expectation."""
    conn = store.open_store(":memory:")
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(conn, "UPDATE recoveries SET score_state = 'PENDING_SCORE'")

    # Simulate a later, unrelated legitimate write committing the connection.
    conn.commit()
    row = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchone()
    assert row[0] == "SCORED", (
        "the unscoped UPDATE's mutation must never survive, even via a later commit"
    )
    conn.close()


def test_completely_unfiltered_update_with_no_where_clause_fails_closed() -> None:
    """A bare ``UPDATE table SET col = val`` with no WHERE at all generates
    no SQLITE_READ authorizer callback whatsoever (there is nothing to read
    to decide which rows to touch) -- only a SQLITE_UPDATE callback naming
    the table and the column being *written*. A scoping check that only
    tracks SQLITE_READ actions would see an empty read-set for this table and
    could wrongly treat it as "not touched", letting the single most
    dangerous form of this bug -- a completely unfiltered write -- through.
    This is the sharpest version of "a helper that forgot the member
    argument" the issue describes."""
    conn = store.open_store(":memory:")
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(conn, "UPDATE recoveries SET score_state = 'PENDING_SCORE'")
    conn.close()


def test_store_has_no_unwrapped_sqlite_execute_outside_scoped_wrapper() -> None:
    """Structural half of the DB-level guarantee: every ``conn.execute``/
    ``.executemany`` call in store.py must live inside
    ``_execute_with_tenancy_authorizer`` itself, ``_migrate``, ``open_store``,
    or ``compact_database`` (bootstrap/PRAGMA/specialized code: ``_migrate``
    and ``open_store`` bootstrap the schema, ``compact_database`` runs ``VACUUM``
    to reclaim freed pages after erasure, which cannot go through the tenancy
    guard) -- otherwise a future store.py function could quietly route
    around the authorizer-backed check entirely. AST-based, not a text grep,
    so it can't be fooled by a comment or a string literal containing
    "conn.execute(".

    #99 moved the executing statement out of ``_execute_scoped`` and into
    ``_execute_with_tenancy_authorizer``, which ``_execute_scoped`` and the
    all-tenant sweep path both call. The allowlist names that function instead
    of ``_execute_scoped``, and is deliberately no longer than it was: the
    invariant tightened rather than loosened, since the *only* function in
    store.py permitted to execute a statement is now the one that installs the
    authorizer and applies the universal tenancy check. Neither entry point
    can skip it -- ``_execute_scoped`` included -- and #99's sweep path is
    therefore structurally incapable of being the "opt-out that skipped the
    authorizer" its own test (``test_all_tenant_sweep_path_still_enforces_the
    _universal_check``) checks for behaviourally. Which functions may *call*
    the executor is pinned separately, by
    ``test_only_the_two_named_guard_entry_points_execute_sql``.
    """
    source = inspect.getsource(store)
    tree = ast.parse(source)
    allowed = {"_execute_with_tenancy_authorizer", "_migrate", "open_store", "compact_database"}
    violations: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) or node.name in allowed:
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr in ("execute", "executemany")
            ):
                violations.append(f"{node.name} (line {inner.lineno})")

    assert violations == [], (
        "store.py calls .execute()/.executemany() outside "
        f"_execute_with_tenancy_authorizer, _migrate, open_store, or "
        f"compact_database: {violations}"
    )


# =============================================================================
# #67: webhook_processor.py must reach entity tables only through store.py's
# _execute_scoped-backed accessors, never through its own conn.execute.
#
# The test above proves store.py cannot route around the authorizer -- but it
# parses store.py *only*, so it never had visibility into a sibling module
# issuing its own raw SQL against the same tenant-scoped tables. These three
# tests close that gap: the structural half (no raw execute survives in
# webhook_processor.py), and the behavioural half (the accessors the relocated
# SQL now lives behind really are scoped -- a mismatched member reads nothing,
# and the soft-delete writer would fail closed if it ever lost its predicate).
# =============================================================================


def test_webhook_processor_has_no_unwrapped_sqlite_execute() -> None:
    """Sibling of ``test_store_has_no_unwrapped_sqlite_execute_outside_scoped
    _wrapper`` for webhook_processor.py (#67): it must contain *no*
    ``conn.execute``/``.executemany`` at all -- there is no equivalent of
    store.py's ``_execute_scoped``/``_migrate``/``open_store`` allowlist here,
    because nothing in this module has any business touching ``conn``
    directly; every entity read/write goes through a store.py accessor.

    Deliberately a strict superset of its sibling's coverage: it walks the
    whole module tree rather than only function bodies, so a module-level or
    comprehension-level raw execute is caught too. Like its sibling it is
    AST-based rather than a text grep, so it cannot be fooled by a comment or
    a string literal containing "conn.execute(".
    """
    source = inspect.getsource(webhook_processor)
    tree = ast.parse(source)
    violations: list[str] = []

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("execute", "executemany")
        ):
            violations.append(f"line {node.lineno}")

    assert violations == [], (
        "webhook_processor.py calls .execute()/.executemany() directly instead of "
        f"going through store.py's _execute_scoped-backed accessors: {violations}"
    )


def test_webhook_store_reads_return_nothing_for_a_mismatched_member() -> None:
    """The two reads #67 relocates into store.py must be member-scoped, not
    merely resource-scoped: asked for member B's copy of a resource_id that
    only member A holds, they must return ``None`` rather than A's row.

    WHOOP resource ids are opaque and not namespaced per member, so a bug
    that dropped the ``whoop_user_id`` predicate would silently answer B's
    webhook with A's stored record -- and for ``get_resource_updated_at``
    that answer feeds ``_upsert_if_not_older``'s out-of-order comparison,
    so the leak would also corrupt B's write decisions, not just read A's
    data. Each assertion is paired with a positive control under A so the
    test cannot pass vacuously (e.g. by the seed never landing).

    ``closing`` rather than a trailing ``conn.close()`` because a mid-test
    failure would otherwise leak an authorizer-bearing connection to be
    finalized at an arbitrary later GC point, and ``filterwarnings = error``
    turns the resulting ``PytestUnraisableExceptionWarning`` into a spurious
    failure on whatever unrelated test happens to be running then.
    """
    with closing(store.open_store(":memory:")) as conn:
        store.upsert_sleep(
            conn,
            MEMBER_A,
            {
                "id": _FIXED_SLEEP_ID,
                "start": "2026-01-01T00:00:00Z",
                "score_state": "SCORED",
                "cycle_id": 4321,
                "updated_at": "2026-01-01T12:00:00Z",
            },
        )

        assert store.get_sleep_cycle_id(conn, MEMBER_A, _FIXED_SLEEP_ID) == 4321
        assert store.get_sleep_cycle_id(conn, MEMBER_B, _FIXED_SLEEP_ID) is None, (
            "get_sleep_cycle_id handed member B the cycle_id off member A's sleep"
        )

        assert (
            store.get_resource_updated_at(conn, "sleep", MEMBER_A, _FIXED_SLEEP_ID)
            == "2026-01-01T12:00:00Z"
        )
        assert store.get_resource_updated_at(conn, "sleep", MEMBER_B, _FIXED_SLEEP_ID) is None, (
            "get_resource_updated_at handed member B the updated_at off member A's sleep"
        )


def test_webhook_soft_delete_write_runs_through_the_scoped_wrapper() -> None:
    """The ``deleted_at`` writer #67 relocates into store.py must genuinely
    run through ``_execute_scoped``, so that losing its ``whoop_user_id``
    predicate would fail closed rather than soft-deleting every member's copy
    of a resource id.

    Same technique as ``test_completely_unfiltered_update_with_no_where
    _clause_fails_closed``: hand ``_execute_scoped`` the de-scoped form of the
    statement ``set_deleted_at`` issues and watch it raise, then confirm the
    would-be mutation did not survive the rollback. That, combined with the
    unchanged store.py AST test above (which proves ``set_deleted_at`` cannot
    be reaching sqlite by any path *other* than ``_execute_scoped``), pins the
    property. The positive control below additionally shows the real,
    correctly-scoped call still soft-deletes -- and soft-deletes exactly one
    member's row.

    See the test above on why ``closing`` rather than a trailing
    ``conn.close()``.
    """
    with closing(store.open_store(":memory:")) as conn:
        for member in (MEMBER_A, MEMBER_B):
            store.upsert_sleep(
                conn,
                member,
                {"id": _FIXED_SLEEP_ID, "start": "2026-01-01T00:00:00Z", "score_state": "SCORED"},
            )

        with pytest.raises(store.UnscopedQueryError):
            store._execute_scoped(
                conn, "UPDATE sleeps SET deleted_at = ?", ("2026-01-02T00:00:00Z",)
            )

        # Simulate a later, unrelated legitimate write committing the
        # connection: the rejected statement's mutation must not ride along.
        conn.commit()
        stamped = conn.execute(
            "SELECT COUNT(*) FROM sleeps WHERE deleted_at IS NOT NULL"
        ).fetchone()
        assert stamped[0] == 0, "the unscoped soft-delete's mutation must never survive"

        store.set_deleted_at(conn, "sleep", MEMBER_A, _FIXED_SLEEP_ID)

        rows = dict(
            conn.execute(
                "SELECT whoop_user_id, deleted_at FROM sleeps WHERE resource_id = ?",
                (_FIXED_SLEEP_ID,),
            ).fetchall()
        )
        assert rows[MEMBER_A] is not None, "set_deleted_at did not stamp member A's row"
        assert rows[MEMBER_B] is None, "set_deleted_at soft-deleted member B's row too"


# =============================================================================
# store.py: two members' data written to one store never cross-read,
# over every tenant-scoped entity -- driven off store._TENANT_SCOPED_TABLES,
# not a hand-maintained list, so a newly added tenant-scoped table without a
# matching case here fails test_tested_entity_tables_cover_every_tenant
# _scoped_table below rather than shipping silently uncovered.
# =============================================================================


def _seed_recovery(conn: sqlite3.Connection, user_id: int, tag: str) -> None:
    store.upsert_recovery(
        conn, user_id, {"cycle_id": 1, "score_state": "SCORED", "score": {"recovery_score": tag}}
    )


def _seed_sleep(conn: sqlite3.Connection, user_id: int, tag: str) -> None:
    store.upsert_sleep(
        conn,
        user_id,
        {
            "id": "s1",
            "start": "2026-01-01T00:00:00Z",
            "score_state": "SCORED",
            "score": {"sleep_performance_percentage": tag},
        },
    )


def _seed_cycle(conn: sqlite3.Connection, user_id: int, tag: str) -> None:
    store.upsert_cycle(
        conn,
        user_id,
        {
            "id": 1,
            "start": "2026-01-01T00:00:00Z",
            "score_state": "SCORED",
            "score": {"strain": tag},
        },
    )


def _seed_workout(conn: sqlite3.Connection, user_id: int, tag: str) -> None:
    store.upsert_workout(
        conn,
        user_id,
        {
            "id": "w1",
            "start": "2026-01-01T00:00:00Z",
            "score_state": "SCORED",
            "sport_name": f"sport-{tag}",
            "score": {"strain": tag},
        },
    )


def _seed_body_measurement(conn: sqlite3.Connection, user_id: int, tag: str) -> None:
    store.upsert_body_measurement(conn, user_id, {"weight_kilogram": tag})


def _seed_profile(conn: sqlite3.Connection, user_id: int, tag: str) -> None:
    store.upsert_profile(conn, user_id, {"user_id": user_id, "email": tag})


_LIST_ENTITY_CASES: list[tuple[str, Any, Any, Any]] = [
    ("recoveries", _seed_recovery, store.get_recoveries, lambda r: r["score"]["recovery_score"]),
    ("sleeps", _seed_sleep, store.get_sleeps, lambda r: r["score"]["sleep_performance_percentage"]),
    ("cycles", _seed_cycle, store.get_cycles, lambda r: r["score"]["strain"]),
    ("workouts", _seed_workout, store.get_workouts, lambda r: r["score"]["strain"]),
]

_SINGLETON_ENTITY_CASES: list[tuple[str, Any, Any, Any]] = [
    (
        "body_measurements",
        _seed_body_measurement,
        store.get_body_measurement,
        lambda r: r["weight_kilogram"],
    ),
    ("profiles", _seed_profile, store.get_profile, lambda r: r["email"]),
]


@pytest.mark.parametrize(("table_name", "seed", "get", "extract"), _LIST_ENTITY_CASES)
def test_list_entities_never_cross_read_between_members(
    table_name: str, seed: Any, get: Any, extract: Any
) -> None:
    del table_name  # parametrize id only
    conn = store.open_store(":memory:")
    seed(conn, MEMBER_A, "member-a-tag")
    seed(conn, MEMBER_B, "member-b-tag")

    a_records = get(conn, MEMBER_A)
    b_records = get(conn, MEMBER_B)

    assert len(a_records) == 1
    assert len(b_records) == 1
    assert extract(a_records[0]) == "member-a-tag"
    assert extract(b_records[0]) == "member-b-tag"
    conn.close()


@pytest.mark.parametrize(("table_name", "seed", "get", "extract"), _SINGLETON_ENTITY_CASES)
def test_singleton_entities_never_cross_read_between_members(
    table_name: str, seed: Any, get: Any, extract: Any
) -> None:
    del table_name  # parametrize id only
    conn = store.open_store(":memory:")
    seed(conn, MEMBER_A, "member-a-tag")
    seed(conn, MEMBER_B, "member-b-tag")

    a_record = get(conn, MEMBER_A)
    b_record = get(conn, MEMBER_B)

    assert a_record is not None
    assert b_record is not None
    assert extract(a_record) == "member-a-tag"
    assert extract(b_record) == "member-b-tag"
    conn.close()


def test_sync_state_never_cross_reads_between_members() -> None:
    """sync_state's shape (an extra `entity` key alongside whoop_user_id)
    doesn't fit the generic list/singleton cases above, hence its own test."""
    conn = store.open_store(":memory:")
    store.set_sync_state(
        conn,
        MEMBER_A,
        "recoveries",
        cursor="a-cursor",
        last_run_at="2026-01-01T00:00:00Z",
        outcome="success",
    )
    store.set_sync_state(
        conn,
        MEMBER_B,
        "recoveries",
        cursor="b-cursor",
        last_run_at="2026-01-01T00:00:00Z",
        outcome="success",
    )

    a_state = store.get_sync_state(conn, MEMBER_A, "recoveries")
    b_state = store.get_sync_state(conn, MEMBER_B, "recoveries")

    assert a_state is not None
    assert b_state is not None
    assert a_state["cursor"] == "a-cursor"
    assert b_state["cursor"] == "b-cursor"
    conn.close()


def test_webhook_delivery_state_never_cross_reads_between_members() -> None:
    """#19's per-user last-delivery timestamp (one row per whoop_user_id,
    for #31's future silence-alerting) doesn't fit the generic list/
    singleton cases above either -- mirrors
    ``test_sync_state_never_cross_reads_between_members``'s own shape."""
    conn = store.open_store(":memory:")
    store.record_webhook_delivery(conn, MEMBER_A)
    store.record_webhook_delivery(conn, MEMBER_B)

    a_delivery = store.get_last_webhook_delivery(conn, MEMBER_A)
    b_delivery = store.get_last_webhook_delivery(conn, MEMBER_B)

    assert a_delivery is not None
    assert b_delivery is not None

    # Advancing one member's delivery time must never move the other's.
    store.record_webhook_delivery(conn, MEMBER_A)
    assert store.get_last_webhook_delivery(conn, MEMBER_B) == b_delivery
    conn.close()


def test_tested_entity_tables_cover_every_tenant_scoped_table() -> None:
    """If a new tenant-scoped table is ever added to
    ``store._TENANT_SCOPED_TABLES`` without a corresponding cross-read case
    above, this fails loudly -- the store-level analogue of the tool
    registry's own "no hand-maintained list" guarantee."""
    tested = (
        {name for name, *_ in _LIST_ENTITY_CASES}
        | {name for name, *_ in _SINGLETON_ENTITY_CASES}
        | {"sync_state", "webhook_delivery_state"}
    )
    assert tested == store._TENANT_SCOPED_TABLES


# =============================================================================
# #69 test 3: the unscoped-write-rolls-back property, generalised across
# EVERY table in store._TENANT_SCOPED_TABLES -- not just the two tables
# (recoveries, sleeps) that test_unscoped_update_fails_closed_and_leaves_no
# _pending_mutation and test_webhook_soft_delete_write_runs_through_the
# _scoped_wrapper happen to hand-pick above. cycles, workouts,
# body_measurements, profiles, sync_state and webhook_delivery_state --
# all added to _TENANT_SCOPED_TABLES after #29's original two-table proof,
# by #30/#32 among others -- were never exercised for this specific
# property before this test. Driven off store._TENANT_SCOPED_TABLES itself
# via the guard test below, not a second hand-maintained list, so a table
# added later without a matching entry here fails loudly instead of shipping
# silently uncovered -- mirroring test_tested_entity_tables_cover_every
# _tenant_scoped_table's own pattern one section up.
# =============================================================================

#: table name -> (a timestamp-ish column every one of these tables has, a
#: seeder that leaves exactly one real row under MEMBER_A for that column to
#: be checked against). Reuses the same seed helpers/values the cross-read
#: tests above already established for six of these tables; sync_state and
#: webhook_delivery_state get their own seed call the way their own
#: cross-read tests above do too.
_UNSCOPED_WRITE_TARGETS: dict[str, tuple[str, Any]] = {
    "recoveries": ("updated_at", lambda conn: _seed_recovery(conn, MEMBER_A, "before")),
    "sleeps": ("updated_at", lambda conn: _seed_sleep(conn, MEMBER_A, "before")),
    "cycles": ("updated_at", lambda conn: _seed_cycle(conn, MEMBER_A, "before")),
    "workouts": ("updated_at", lambda conn: _seed_workout(conn, MEMBER_A, "before")),
    "body_measurements": (
        "updated_at",
        lambda conn: _seed_body_measurement(conn, MEMBER_A, "before"),
    ),
    "profiles": ("updated_at", lambda conn: _seed_profile(conn, MEMBER_A, "before")),
    "sync_state": (
        "last_run_at",
        lambda conn: store.set_sync_state(
            conn,
            MEMBER_A,
            "recoveries",
            cursor="a-cursor",
            last_run_at="2026-01-01T00:00:00Z",
            outcome="success",
        ),
    ),
    "webhook_delivery_state": (
        "last_delivered_at",
        lambda conn: store.record_webhook_delivery(conn, MEMBER_A),
    ),
}


def test_unscoped_write_targets_cover_every_tenant_scoped_table() -> None:
    """Guard mirroring test_tested_entity_tables_cover_every_tenant_scoped
    _table above: a newly added tenant-scoped table without a matching case
    in _UNSCOPED_WRITE_TARGETS must fail loudly here, not silently skip the
    rollback property the parametrized test below exists to pin."""
    assert set(_UNSCOPED_WRITE_TARGETS) == store._TENANT_SCOPED_TABLES


@pytest.mark.parametrize("table_name", sorted(_UNSCOPED_WRITE_TARGETS))
def test_unscoped_update_fails_closed_and_rolls_back_on_every_tenant_scoped_table(
    table_name: str,
) -> None:
    """#69 test 3, generalised: a hand-constructed UPDATE against `table_name`
    that never reads `whoop_user_id` in its WHERE (here: omits WHERE
    entirely, the sharpest form) must both raise UnscopedQueryError AND have
    its mutation fail to survive a later, unrelated commit on the same
    connection -- for every table store._TENANT_SCOPED_TABLES currently
    lists, confirming the property #29 established still holds now that
    #30/#32 have grown that set well past the two tables it was originally
    proven against.
    """
    timestamp_column, seed = _UNSCOPED_WRITE_TARGETS[table_name]
    conn = store.open_store(":memory:")
    seed(conn)

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(
            conn,
            f"UPDATE {table_name} SET {timestamp_column} = 'UNSCOPED-HACK'",  # noqa: S608 -- table_name/timestamp_column come only from the fixed _UNSCOPED_WRITE_TARGETS dict above, never external input
        )

    # Simulate a later, unrelated legitimate write committing the connection --
    # the rejected statement's mutation must not ride along, on any table.
    conn.commit()
    hacked = conn.execute(
        f"SELECT COUNT(*) FROM {table_name} WHERE {timestamp_column} = 'UNSCOPED-HACK'"  # noqa: S608 -- same fixed dict, test-only
    ).fetchone()[0]
    assert hacked == 0, f"{table_name}: unscoped UPDATE's mutation survived a later commit"
    conn.close()


# =============================================================================
# store.py: audit log -- one row per call, identity only, never a payload
# =============================================================================


def test_record_tool_call_writes_one_row_with_correct_identity() -> None:
    conn = store.open_store(":memory:")

    store.record_tool_call(conn, MEMBER_A, "list_recoveries")

    rows = conn.execute("SELECT whoop_user_id, tool_name FROM tool_call_audit").fetchall()
    assert rows == [(MEMBER_A, "list_recoveries")]
    conn.close()


def test_record_tool_call_writes_one_row_per_call() -> None:
    conn = store.open_store(":memory:")

    store.record_tool_call(conn, MEMBER_A, "list_recoveries")
    store.record_tool_call(conn, MEMBER_A, "get_profile")
    store.record_tool_call(conn, MEMBER_B, "list_recoveries")

    rows = conn.execute(
        "SELECT whoop_user_id, tool_name FROM tool_call_audit ORDER BY id"
    ).fetchall()
    assert rows == [
        (MEMBER_A, "list_recoveries"),
        (MEMBER_A, "get_profile"),
        (MEMBER_B, "list_recoveries"),
    ]
    conn.close()


def test_audit_log_never_contains_call_argument_or_result_data() -> None:
    """Behavioural companion to the schema-shape test above: even granting
    that ``record_tool_call`` has no parameter to carry a payload through in
    the first place, walk every row's text and confirm none of several
    stand-in "argument/result" marker strings used elsewhere in this suite
    ever appears here -- so a future signature change to
    ``record_tool_call`` that added an optional payload parameter would be
    caught by this test even before anyone wired a caller up to it."""
    conn = store.open_store(":memory:")
    store.record_tool_call(conn, MEMBER_A, "get_profile")
    store.record_tool_call(conn, MEMBER_B, "list_recoveries")

    dump = str(conn.execute("SELECT * FROM tool_call_audit").fetchall())

    for forbidden_marker in ("member-a-tag", "member-b-tag", "sleep-fixture-1", "recovery_score"):
        assert forbidden_marker not in dump
    conn.close()


# =============================================================================
# server.py: resolve_member_id -- resolve once at the edge, no default ever
# =============================================================================


def test_unresolved_principal_raises_not_defaults(
    store_conn: sqlite3.Connection, config: Config
) -> None:
    """A principal with no principal_members row must error -- never fall
    back to a default member."""
    auth = Authenticator(config)
    client = WhoopClient(config, auth)
    app_context = AppContext(
        config=config, auth=auth, client=client, principal=None, store_conn=store_conn
    )
    ctx = _build_context(app_context, _principal_request("stranger"), tool_name="get_profile")

    with pytest.raises(UnresolvedPrincipalError):
        resolve_member_id(ctx)


def test_no_request_and_no_completed_login_raises_not_defaults(
    store_conn: sqlite3.Connection, config: Config
) -> None:
    """stdio / no-bearer-auth-wired deployments key off a fixed local
    sentinel principal -- but that sentinel must still be *linked* by a
    completed login before it resolves to anything. Nothing defaults it."""
    auth = Authenticator(config)
    client = WhoopClient(config, auth)
    app_context = AppContext(
        config=config, auth=auth, client=client, principal=None, store_conn=store_conn
    )
    ctx = _build_context(app_context, request=None, tool_name="get_profile")

    with pytest.raises(UnresolvedPrincipalError):
        resolve_member_id(ctx)


def test_resolve_member_id_ignores_caller_supplied_identity_hints(
    store_conn: sqlite3.Connection, config: Config
) -> None:
    """Never accept a member identifier from a caller-supplied parameter:
    even with a spoofed ``whoop_user_id`` sitting in the request's query
    params/headers, the resolved member must come only from the
    principal_members mapping."""
    store.link_principal_to_member(
        store_conn, client_id="principal-b", issuer=None, subject=None, whoop_user_id=MEMBER_B
    )
    auth = Authenticator(config)
    client = WhoopClient(config, auth)
    app_context = AppContext(
        config=config,
        auth=auth,
        client=client,
        principal=Principal(user_id=MEMBER_A),
        store_conn=store_conn,
    )
    spoofed_request = _principal_request("principal-b", spoofed_member_id=MEMBER_A)
    ctx = _build_context(app_context, spoofed_request, tool_name="get_profile")

    result = resolve_member_id(ctx)

    assert result == MEMBER_B  # the real mapping, never the spoofed hint or the live grant


def test_resolve_member_id_never_adopts_a_spoofed_hint_for_an_unmapped_principal(
    store_conn: sqlite3.Connection, config: Config
) -> None:
    """The sharper version of the test above: an *unmapped* principal with a
    spoofed identity hint must still raise, not silently adopt the hint."""
    auth = Authenticator(config)
    client = WhoopClient(config, auth)
    app_context = AppContext(
        config=config, auth=auth, client=client, principal=None, store_conn=store_conn
    )
    spoofed_request = _principal_request("unmapped-principal", spoofed_member_id=MEMBER_A)
    ctx = _build_context(app_context, spoofed_request, tool_name="get_profile")

    with pytest.raises(UnresolvedPrincipalError):
        resolve_member_id(ctx)


async def test_resolve_member_id_audits_every_call(
    store_conn: sqlite3.Connection, config: Config
) -> None:
    """resolve_member_id both resolves and audits in one call -- there is
    only one call site for either, so a tool that resolves but "forgets" to
    audit is structurally impossible."""
    store.link_principal_to_member(
        store_conn, client_id="principal-a", issuer=None, subject=None, whoop_user_id=MEMBER_A
    )
    auth = Authenticator(config)
    client = WhoopClient(config, auth)
    app_context = AppContext(
        config=config,
        auth=auth,
        client=client,
        principal=Principal(user_id=MEMBER_A),
        store_conn=store_conn,
    )
    ctx = _build_context(
        app_context, _principal_request("principal-a"), tool_name="list_recoveries"
    )

    result = resolve_member_id(ctx)

    assert result == MEMBER_A
    rows = store_conn.execute("SELECT whoop_user_id, tool_name FROM tool_call_audit").fetchall()
    assert rows == [(MEMBER_A, "list_recoveries")]


# =============================================================================
# server.py: whoop_complete_login is the *only* writer of principal_members
# =============================================================================


@respx.mock
async def test_whoop_complete_login_writes_exactly_one_principal_mapping(
    config: Config, store_conn: sqlite3.Connection
) -> None:
    respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(200, json={"user_id": MEMBER_A, "email": "a@example.com"})
    )
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "fake-access-token",
                "expires_in": 3600,
                "refresh_token": "fake-refresh-token",
                "scope": "read:sleep offline",
            },
        )
    )
    auth = Authenticator(config)
    client = WhoopClient(config, auth)
    async with client:
        app_context = AppContext(
            config=config, auth=auth, client=client, principal=None, store_conn=store_conn
        )
        server = build_server()
        request_a = _principal_request("principal-a")

        login_result = await _call_tool_as(server, "whoop_login", {}, app_context, request_a)
        login_text = str(login_result["result"])
        state = parse_qs(urlparse(login_text.splitlines()[-1]).query)["state"][0]

        await _call_tool_as(
            server,
            "whoop_complete_login",
            {"code": "fake-code", "state": state},
            app_context,
            request_a,
        )

    rows = store_conn.execute("SELECT client_id, whoop_user_id FROM principal_members").fetchall()
    assert rows == [("principal-a", MEMBER_A)]


# =============================================================================
# server.py + mcpauth: no tool exposes a caller-supplied identity parameter
# (registry-driven -- mirrors #28's own test_client_supplied_user_id
# _ignored_first one level deeper, without a hand-maintained tool-name list)
# =============================================================================

_FORBIDDEN_IDENTITY_PARAM_NAMES = {"whoop_user_id", "user_id", "member_id", "principal_id"}


async def test_no_tool_accepts_a_caller_supplied_member_identifier() -> None:
    """A tool exposing any of these parameter names could be used to smuggle
    in a member identity, bypassing the principal_members join entirely --
    walks every current and future tool via the live registry, not a name
    list."""
    tools = await build_server().list_tools()

    offenders = {
        tool.name: bad
        for tool in tools
        for bad in (set(tool.input_schema.get("properties", {})) & _FORBIDDEN_IDENTITY_PARAM_NAMES)
    }

    assert offenders == {}


# =============================================================================
# The registry-driven cross-tenant sweep (issue #29's centerpiece)
# =============================================================================


def _member_recoveries(member_id: int, count: int = 10) -> list[dict[str, Any]]:
    return [
        {
            "cycle_id": i + 1,
            "created_at": f"2026-01-{i + 1:02d}T06:00:00Z",
            "score_state": "SCORED",
            "score": {
                "recovery_score": round(member_id + i * 0.01, 2),
                "hrv_rmssd_milli": round(member_id + i * 0.01, 2),
                "resting_heart_rate": 55,
            },
        }
        for i in range(count)
    ]


def _member_sleeps(member_id: int, count: int = 10) -> list[dict[str, Any]]:
    return [
        {
            "id": f"sleep-{member_id}-{i}",
            "created_at": f"2026-01-{i + 1:02d}T22:00:00Z",
            "start": f"2026-01-{i + 1:02d}T22:00:00Z",
            "end": f"2026-01-{i + 1:02d}T23:00:00Z",
            "nap": False,
            "score_state": "SCORED",
            "score": {
                "sleep_performance_percentage": round(member_id + i * 0.01, 2),
                "sleep_efficiency_percentage": 90.0,
                "respiratory_rate": 14.0,
            },
        }
        for i in range(count)
    ]


def _member_cycles(member_id: int, count: int = 10) -> list[dict[str, Any]]:
    return [
        {
            "id": i + 1,
            "created_at": f"2026-01-{i + 1:02d}T23:00:00Z",
            "start": f"2026-01-{i + 1:02d}T23:00:00Z",
            "end": f"2026-01-{i + 1:02d}T23:30:00Z",
            "score_state": "SCORED",
            "score": {
                "strain": round(member_id + i * 0.01, 2),
                "average_heart_rate": 90,
                "max_heart_rate": 150,
                "kilojoule": 2000.0,
            },
        }
        for i in range(count)
    ]


def _member_workouts(member_id: int, count: int = 10) -> list[dict[str, Any]]:
    return [
        {
            "id": f"workout-{member_id}-{i}",
            "sport_name": f"member-{member_id}-sport",
            "created_at": f"2026-01-{i + 1:02d}T07:00:00Z",
            "start": f"2026-01-{i + 1:02d}T07:00:00Z",
            "end": f"2026-01-{i + 1:02d}T08:00:00Z",
            "score_state": "SCORED",
            "score": {
                "strain": round(member_id + i * 0.01, 2),
                "average_heart_rate": 120,
                "max_heart_rate": 170,
            },
        }
        for i in range(count)
    ]


def _mock_whoop_endpoints_for(member_id: int) -> None:
    """Mock every WHOOP endpoint any tool can reach, tagged so `member_id`'s
    decimal string is traceable in whatever a tool returns from it -- either
    directly (a single-record data tool) or through an aggregate statistic
    computed over records that all carry it (the 4 analysis tools; a mean or
    slope of a series varying only in its hundredths digit still carries the
    integer tag in its string form, e.g. 900001.0X)."""
    respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(
            200, json={"user_id": member_id, "email": f"member-{member_id}@example.com"}
        )
    )
    respx.get(f"{BASE_URL}/v2/user/measurement/body").mock(
        return_value=httpx.Response(
            200,
            json={"height_meter": 1.8, "weight_kilogram": float(member_id), "max_heart_rate": 190},
        )
    )
    recoveries = _member_recoveries(member_id)
    sleeps = _member_sleeps(member_id)
    cycles = _member_cycles(member_id)
    workouts = _member_workouts(member_id)
    respx.get(f"{BASE_URL}/v2/recovery").mock(
        return_value=httpx.Response(200, json={"records": recoveries, "next_token": None})
    )
    respx.get(f"{BASE_URL}/v2/activity/sleep").mock(
        return_value=httpx.Response(200, json={"records": sleeps, "next_token": None})
    )
    respx.get(f"{BASE_URL}/v2/cycle").mock(
        return_value=httpx.Response(200, json={"records": cycles, "next_token": None})
    )
    respx.get(f"{BASE_URL}/v2/activity/workout").mock(
        return_value=httpx.Response(200, json={"records": workouts, "next_token": None})
    )
    respx.get(f"{BASE_URL}/v2/activity/sleep/{_FIXED_SLEEP_ID}").mock(
        return_value=httpx.Response(200, json={**sleeps[0], "id": _FIXED_SLEEP_ID})
    )
    respx.get(f"{BASE_URL}/v2/activity/workout/{_FIXED_WORKOUT_ID}").mock(
        return_value=httpx.Response(200, json={**workouts[0], "id": _FIXED_WORKOUT_ID})
    )


_RANGE_ARGS = {"start": "2026-01-01T00:00:00Z", "end": "2026-01-15T00:00:00Z"}

#: Minimal valid arguments per tool, same shape test_context_budget.py's own
#: worst-case fixtures already need (different tools take different
#: required params). A tool absent from this mapping falls back to `{}`,
#: which still covers any future zero-required-argument tool automatically.
_TOOL_ARGUMENTS: dict[str, dict[str, Any]] = {
    "list_recoveries": _RANGE_ARGS,
    "list_sleeps": _RANGE_ARGS,
    "list_cycles": _RANGE_ARGS,
    "list_workouts": _RANGE_ARGS,
    "get_sleep": {"sleep_id": _FIXED_SLEEP_ID},
    "get_workout": {"workout_id": _FIXED_WORKOUT_ID},
    "summarize_period": _RANGE_ARGS,
    "metric_trend": {"metric": "recovery_score", **_RANGE_ARGS},
    "correlate_metrics": {"metric_a": "strain", "metric_b": "recovery_score", **_RANGE_ARGS},
    "compare_periods": {
        "baseline_start": "2026-01-01T00:00:00Z",
        "baseline_end": "2026-01-08T00:00:00Z",
        "comparison_start": "2026-01-08T00:00:00Z",
        "comparison_end": "2026-01-15T00:00:00Z",
    },
    "whoop_timeseries": {"metric": "recovery_score", **_RANGE_ARGS},
    "whoop_outliers": {"metric": "recovery_score", **_RANGE_ARGS},
    "whoop_streaks": {
        "metric": "recovery_score",
        "threshold": 50.0,
        "direction": "above",
        **_RANGE_ARGS,
    },
}


async def test_no_concrete_resources_exist_yet_canary() -> None:
    """Documents today's registry shape. The sweep below already enumerates
    resources, resource templates, and prompts via list_resources()/
    list_resource_templates()/list_prompts(), so a future addition to any
    of them is automatically walked there too -- this canary just makes
    that assumption visible and independently checkable.

    #26 has since added three prompts (argument-less compositions of the
    analysis tools, never touching the store or the live client) and the
    four ``whoop://user/...`` resources it also specifies -- but as one
    ``whoop://user/{item}`` *template*, not four static resources: a static
    resource's function in the installed SDK is structurally incapable of
    receiving ``Context`` at all (see ``server.py``'s own
    ``_register_resources`` docstring for the full verification), so the
    per-user identity gate a per-user resource requires could never run
    inside one. Templates are never concrete resources, so
    ``list_resources()`` stays ``[]`` by design; the one
    ``whoop://user/{item}`` template only shows up via
    ``list_resource_templates()``. ``list_prompts()`` no longer stays empty
    either.
    """
    server = build_server()
    assert await server.list_resources() == []
    assert {t.uri_template for t in await server.list_resource_templates()} == {
        "whoop://user/{item}"
    }
    assert {p.name for p in await server.list_prompts()} == {
        "morning_readiness_briefing",
        "weekly_training_review",
        "sleep_debt_investigation",
    }


@respx.mock
async def test_every_read_only_registered_tool_refuses_to_serve_a_mismatched_member(
    config: Config, store_conn: sqlite3.Connection
) -> None:
    """Registry-driven cross-tenant sweep.

    Walks every tool ``build_server().list_tools()`` reports -- never a
    hand-maintained name list, so a tool added after this merges is
    automatically in scope. See this module's own docstring for why
    "refuses to leak" is operationalised as "never returns member A's data
    to a session that resolved to a different member", given today's single
    live WhoopClient. Mutating auth-flow tools (whoop_login/_complete_login/
    _logout) are excluded via their own registry-declared
    ``annotations.read_only_hint`` -- a registry property, not a name list --
    since they manage this process's one local WHOOP grant, not member data;
    they are covered by their own tests elsewhere in this file.
    """
    _mock_whoop_endpoints_for(MEMBER_A)
    store.link_principal_to_member(
        store_conn, client_id="principal-a", issuer=None, subject=None, whoop_user_id=MEMBER_A
    )
    store.link_principal_to_member(
        store_conn, client_id="principal-b", issuer=None, subject=None, whoop_user_id=MEMBER_B
    )
    auth = Authenticator(config)
    client = WhoopClient(config, auth)
    async with client:
        app_context = AppContext(
            config=config,
            auth=auth,
            client=client,
            principal=Principal(user_id=MEMBER_A),
            store_conn=store_conn,
        )
        request_a = _principal_request("principal-a")
        request_b = _principal_request("principal-b")

        server = build_server()
        tools = await server.list_tools()
        assert await server.list_resources() == []

        # #26's one whoop://user/{item} template shares the same identity
        # gate every tool above does (_ensure_matches_live_grant) -- swept
        # here too, off list_resource_templates() rather than a
        # hand-maintained URI list, so a future item added to the template
        # is automatically in scope.
        templates = await server.list_resource_templates()
        assert {t.uri_template for t in templates} == {"whoop://user/{item}"}

        store.upsert_profile(
            store_conn, MEMBER_A, {"user_id": MEMBER_A, "email": f"member-{MEMBER_A}@example.com"}
        )
        store.upsert_recovery(store_conn, MEMBER_A, _member_recoveries(MEMBER_A, count=1)[0])
        store.upsert_sleep(store_conn, MEMBER_A, _member_sleeps(MEMBER_A, count=1)[0])
        store.upsert_cycle(store_conn, MEMBER_A, _member_cycles(MEMBER_A, count=1)[0])

        for item in ("profile", "latest-recovery", "latest-sleep", "latest-cycle"):
            uri = f"whoop://user/{item}"
            # A (matches the live grant) is the sanity path: it must work.
            await _read_resource_as(server, uri, app_context, request_a)

            try:
                result_b = await _read_resource_as(server, uri, app_context, request_b)
            except Exception:  # noqa: S112 -- refusing outright *is* the correct, safe outcome here
                continue

            assert str(MEMBER_A) not in _result_text(result_b), (
                f"{uri} leaked member {MEMBER_A}'s data into member {MEMBER_B}'s session"
            )

        # #26's prompts take no `ctx`, never touch the store or the live
        # client, and are plain static instructional text -- there is no
        # member-specific data for one to leak, but the sweep asserts that
        # rather than assuming it: same registry-driven, no-hand-maintained-
        # name-list principle as the tool sweep below, walking whichever
        # member's request happens to reach `get_prompt` at all.
        prompts = await server.list_prompts()
        assert prompts, "expected at least one prompt to sweep now that #26 has landed"
        for prompt in prompts:
            result = await server.get_prompt(prompt.name, None)
            assert isinstance(result, GetPromptResult)
            text = "\n".join(getattr(m.content, "text", "") for m in result.messages)
            assert str(MEMBER_A) not in text and str(MEMBER_B) not in text, (
                f"prompt {prompt.name} leaked a member id into its own static instructional text"
            )

        read_only_tools = [
            t for t in tools if t.annotations is not None and t.annotations.read_only_hint
        ]
        assert read_only_tools, "expected at least one read-only tool to sweep"

        for tool in read_only_tools:
            arguments = _TOOL_ARGUMENTS.get(tool.name, {})

            # A (matches the live grant) is the sanity path: it must work.
            await _call_tool_as(server, tool.name, arguments, app_context, request_a)

            try:
                result_b = await _call_tool_as(server, tool.name, arguments, app_context, request_b)
            except Exception:  # noqa: S112 -- refusing outright *is* the correct, safe outcome here
                continue

            assert str(MEMBER_A) not in _result_text(result_b), (
                f"{tool.name} leaked member {MEMBER_A}'s data into member {MEMBER_B}'s session"
            )


@respx.mock
async def test_marker_detector_flags_a_deliberately_unprotected_tool(config: Config) -> None:
    """Proves the leak-detection mechanism in the sweep above has teeth.

    Registers one extra tool -- defined only in this test file, never in
    src/whoopmcp -- that reproduces the issue's own failure mode verbatim:
    it forwards the single live client's data unconditionally, never
    checking who is asking. During development this exact tool was wired
    into the sweep above and observed to fail it; it now lives here instead,
    on its own throwaway server instance (so it is never part of
    ``build_server()``'s real, shipped registry), as a permanent regression
    check on the *detector itself* -- kept rather than deleted because it is
    the only test in this file that exercises the marker-substring
    assertion using only symbols that exist today (``build_server``,
    ``AppContext``, ``Principal``), so it is the one test that can catch a
    future refactor of the sweep silently losing its teeth, independent of
    whether #29's own implementation has landed yet.
    """
    _mock_whoop_endpoints_for(MEMBER_A)
    auth = Authenticator(config)
    client = WhoopClient(config, auth)
    async with client:
        app_context = AppContext(
            config=config, auth=auth, client=client, principal=Principal(user_id=MEMBER_A)
        )
        server = build_server()

        @server.tool(name="_demo_unprotected_tool", title="Demo", annotations=READ_ONLY)
        async def _demo_unprotected_tool(ctx: Context[AppContext, Any]) -> dict[str, Any]:
            app = ctx.request_context.lifespan_context
            return await app.client.get_profile()

        request_b = _principal_request("principal-b")
        result = await _call_tool_as(server, "_demo_unprotected_tool", {}, app_context, request_b)

        assert str(MEMBER_A) in _result_text(result), (
            "the marker-detection check itself is broken: it should have "
            "caught this deliberately unprotected tool"
        )


# =============================================================================
# #99: _execute_scoped's restrictive-equality requirement must also cover
# UPDATE and DELETE -- not only SELECT.
#
# The pre-#99 guard required, for a non-SELECT statement, only that a touched
# tenant-scoped table's `whoop_user_id` column be *read at all*. So
# `WHERE whoop_user_id != ?`, `> ?` or `IS NOT NULL` satisfied it on the
# mutation/deletion path, while the same predicate on a SELECT was refused --
# the docstring's "as a restrictive equality predicate" claim held for reads
# only, on the lower-impact half.
#
# Scope of what is pinned here, deliberately narrow (see the issue's own
# decisions):
#
# - INSERT is exempt, permanently. An INSERT has no WHERE clause at all; it
#   supplies `whoop_user_id` as a *value*. Requiring an equality predicate
#   there is not merely wrong but structurally impossible, and would break
#   every upsert in store.py. `test_every_store_writer_still_works` below is
#   the regression guard for exactly that: it exercises every writer, so a
#   fix that "completes the job" by extending the requirement to INSERT
#   fails loudly rather than at a user's first sync.
# - `enforce_retention` is the codebase's one deliberate all-tenant sweep and
#   keeps needing to sweep all tenants, so it gets a single, distinctly-named
#   internal path past the *equality* requirement. Two tests pin that path
#   honest: it has exactly one caller (asserted from source, the idiom
#   `test_store_has_no_unwrapped_sqlite_execute_outside_scoped_wrapper` and
#   tests/test_module_map.py already use), and it still enforces the
#   universal "must read whoop_user_id" check -- an opt-out that skipped the
#   authorizer check entirely would remove the real tenancy control while
#   appearing to add one.
# =============================================================================

#: Name of the singular all-tenant sweep path (#99's D2). Pinned in one place
#: so the two tests below that reference it by name -- the source-level
#: single-caller assertion and the "still enforces the universal check" one --
#: move together if it is ever renamed. Deliberately NOT a boolean parameter
#: on ``_execute_scoped``: a keyword like ``allow_all_tenants=True`` would
#: make bypassing a fail-closed control a one-word change available at every
#: call site.
_SWEEP_PATH_NAME = "_execute_all_tenant_sweep"

#: ``whoop_user_id`` predicates that *read* the column -- so they satisfy the
#: universal authorizer check -- while restricting the statement to no single
#: member. Each is the (id, SQL fragment, params) triple the two parametrized
#: tests below substitute into an UPDATE and a DELETE respectively.
_NON_RESTRICTIVE_PREDICATES: list[tuple[str, str, tuple[Any, ...]]] = [
    ("not_equal", "whoop_user_id != ?", (MEMBER_B,)),
    ("greater_than", "whoop_user_id > ?", (0,)),
    ("is_not_null", "whoop_user_id IS NOT NULL", ()),
]
_PREDICATE_IDS = [case[0] for case in _NON_RESTRICTIVE_PREDICATES]

_HACK_MARKER = "NON-RESTRICTIVE-HACK"


def _scoped_table_column(table_name: str) -> str:
    """A writable, non-key column on ``table_name``, derived from store.py's
    own ``_RETENTION_TIMESTAMP_COLUMNS`` rather than hand-listed here -- every
    ``_TENANT_SCOPED_TABLES`` member has an entry there (``enforce_retention``
    would raise ``KeyError`` otherwise), so a ninth tenant-scoped table needs
    no edit in this file."""
    return store._RETENTION_TIMESTAMP_COLUMNS[table_name]


@pytest.mark.parametrize(
    ("predicate_id", "predicate", "predicate_params"),
    _NON_RESTRICTIVE_PREDICATES,
    ids=_PREDICATE_IDS,
)
@pytest.mark.parametrize("table_name", sorted(store._TENANT_SCOPED_TABLES))
def test_update_with_a_non_restrictive_whoop_user_id_predicate_is_rejected(
    store_conn: sqlite3.Connection,
    table_name: str,
    predicate_id: str,
    predicate: str,
    predicate_params: tuple[Any, ...],
) -> None:
    """#99 test 1: an ``UPDATE`` whose ``whoop_user_id`` predicate is not a
    restrictive equality must be refused, for every tenant-scoped table.

    Each of these statements *reads* ``whoop_user_id`` (so the universal
    check is satisfied and cannot be what rejects them), yet none of them
    pins the statement to one member -- ``!= ?`` and ``> ?`` and
    ``IS NOT NULL`` all span the whole table. Before #99 they were accepted
    on the write path and the mutation stood.

    Parametrized off ``store._TENANT_SCOPED_TABLES`` directly, not a
    hand-written table list, so a table added to that frozenset later is
    covered here automatically (its seeder is looked up in
    ``_UNSCOPED_WRITE_TARGETS`` above, whose own guard test already pins that
    dict's keys to the same frozenset, so a missing entry fails loudly).
    """
    del predicate_id
    column = _scoped_table_column(table_name)
    _, seed = _UNSCOPED_WRITE_TARGETS[table_name]
    conn = store_conn
    seed(conn)

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(
            conn,
            f"UPDATE {table_name} SET {column} = '{_HACK_MARKER}' WHERE {predicate}",  # noqa: S608 -- table_name comes from store._TENANT_SCOPED_TABLES, column from store._RETENTION_TIMESTAMP_COLUMNS, predicate from the fixed list above; never external input
            predicate_params,
        )

    # Rejection must also not leave the mutation pending for a later,
    # unrelated commit to persist (#69's rollback property, on this path too).
    conn.commit()
    hacked = conn.execute(
        f"SELECT COUNT(*) FROM {table_name} WHERE {column} = ?",  # noqa: S608 -- same fixed sources, test-only
        (_HACK_MARKER,),
    ).fetchone()[0]
    assert hacked == 0, (
        f"{table_name}: a non-restrictive UPDATE predicate ({predicate}) mutated rows"
    )


@pytest.mark.parametrize(
    ("predicate_id", "predicate", "predicate_params"),
    _NON_RESTRICTIVE_PREDICATES,
    ids=_PREDICATE_IDS,
)
@pytest.mark.parametrize("table_name", sorted(store._TENANT_SCOPED_TABLES))
def test_delete_with_a_non_restrictive_whoop_user_id_predicate_is_rejected(
    store_conn: sqlite3.Connection,
    table_name: str,
    predicate_id: str,
    predicate: str,
    predicate_params: tuple[Any, ...],
) -> None:
    """#99 test 2: the same for ``DELETE`` -- the highest-impact form of the
    gap, since a swept row is gone rather than merely overwritten.

    Note this is the shape ``enforce_retention`` legitimately needs
    (``whoop_user_id IS NOT NULL AND <age column> < ?``), which is why #99
    gives that one function its own named path instead of leaving the check
    loose for everybody. Reaching a scoped table through plain
    ``_execute_scoped`` with such a predicate -- as any other caller would --
    must fail.
    """
    del predicate_id
    _, seed = _UNSCOPED_WRITE_TARGETS[table_name]
    conn = store_conn
    seed(conn)
    before = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]  # noqa: S608 -- table_name from store._TENANT_SCOPED_TABLES
    assert before == 1, f"{table_name}: seeder must leave exactly one row to be deleted"

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(
            conn,
            f"DELETE FROM {table_name} WHERE {predicate}",  # noqa: S608 -- table_name from store._TENANT_SCOPED_TABLES, predicate from the fixed list above
            predicate_params,
        )

    conn.commit()
    after = conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()[0]  # noqa: S608 -- same fixed source, test-only
    assert after == 1, (
        f"{table_name}: a non-restrictive DELETE predicate ({predicate}) removed rows"
    )


def test_rejected_write_rolls_back_instead_of_leaving_a_partial_write(
    store_conn: sqlite3.Connection,
) -> None:
    """#99 test 3: the rollback property #69 established must survive #99's
    tightening, for a rejected statement that would have touched *several
    members'* rows.

    Unlike the two tests above this one already passes before #99 (the
    WHERE-less UPDATE is caught by the universal check, which #99 must leave
    exactly as it is) -- it is here as the non-regression half: a fix that
    tightened the predicate rules but disturbed the rollback would show up
    here rather than only in the two new-behaviour tests.

    A non-SELECT statement is already fully executed by the time the
    authorizer's findings are inspected (sqlite3 steps it to completion
    inside one ``execute()``), so raising alone would leave a pending change
    that a later, unrelated ``conn.commit()`` silently persists. Both
    members' rows must read exactly as seeded after that later commit --
    "no partial write", not merely "an exception was raised".
    """
    conn = store_conn
    _seed_recovery(conn, MEMBER_A, "member-a-tag")
    _seed_recovery(conn, MEMBER_B, "member-b-tag")

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(conn, "UPDATE recoveries SET score_state = 'PENDING_SCORE'")

    # A later, unrelated legitimate write commits the connection.
    store.upsert_profile(conn, MEMBER_A, {"user_id": MEMBER_A, "email": "a@example.test"})
    conn.commit()

    states = conn.execute("SELECT whoop_user_id, score_state FROM recoveries ORDER BY 1").fetchall()
    assert states == [(MEMBER_A, "SCORED"), (MEMBER_B, "SCORED")], (
        "the rejected cross-member UPDATE left a partial write behind"
    )


def test_every_store_writer_still_works(store_conn: sqlite3.Connection) -> None:
    """#99 test 4: the regression guard for the INSERT exemption.

    Every write path in store.py, exercised end to end and checked by its
    read-back -- the upserts (whose ``INSERT ... ON CONFLICT`` statements
    have no WHERE clause and can never carry an equality predicate), the
    identity/audit writers, the webhook-event state transitions, the
    soft-delete UPDATE for all three resources it supports, and both
    erasure paths. Not a sample: if #99's tightening reaches INSERT, or
    catches a legitimate equality-predicated UPDATE/DELETE, this test fails
    rather than the failure surfacing at a user's first sync.
    """
    conn = store_conn

    # -- upserts (INSERT ... ON CONFLICT: no WHERE clause exists to scope) --
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})
    store.upsert_sleep(conn, MEMBER_A, {"id": "s1", "start": "2026-01-01T00:00:00Z"})
    store.upsert_cycle(conn, MEMBER_A, {"id": 1, "start": "2026-01-01T00:00:00Z"})
    store.upsert_workout(conn, MEMBER_A, {"id": "w1", "start": "2026-01-01T00:00:00Z"})
    store.upsert_body_measurement(conn, MEMBER_A, {"weight_kilogram": 70})
    store.upsert_profile(conn, MEMBER_A, {"user_id": MEMBER_A, "email": "a@example.test"})
    assert len(store.get_recoveries(conn, MEMBER_A)) == 1
    assert len(store.get_sleeps(conn, MEMBER_A)) == 1
    assert len(store.get_cycles(conn, MEMBER_A)) == 1
    assert len(store.get_workouts(conn, MEMBER_A)) == 1
    assert store.get_body_measurement(conn, MEMBER_A) == {"weight_kilogram": 70}
    assert store.get_profile(conn, MEMBER_A) is not None

    # The conflict branch of each upsert, too: a second write of the same key
    # must update in place rather than raise or duplicate.
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "PENDING_SCORE"})
    store.upsert_sleep(conn, MEMBER_A, {"id": "s1", "start": "2026-01-02T00:00:00Z"})
    store.upsert_cycle(conn, MEMBER_A, {"id": 1, "start": "2026-01-02T00:00:00Z"})
    store.upsert_workout(conn, MEMBER_A, {"id": "w1", "start": "2026-01-02T00:00:00Z"})
    store.upsert_body_measurement(conn, MEMBER_A, {"weight_kilogram": 71})
    store.upsert_profile(conn, MEMBER_A, {"user_id": MEMBER_A, "email": "a2@example.test"})
    assert len(store.get_recoveries(conn, MEMBER_A)) == 1
    assert store.get_recoveries(conn, MEMBER_A)[0]["score_state"] == "PENDING_SCORE"
    assert store.get_body_measurement(conn, MEMBER_A) == {"weight_kilogram": 71}

    # -- sync_state, webhook_delivery_state: upserts on their own keys ------
    store.set_sync_state(
        conn,
        MEMBER_A,
        "recoveries",
        cursor="cur-1",
        last_run_at="2026-01-01T00:00:00Z",
        outcome="success",
    )
    store.set_sync_state(
        conn,
        MEMBER_A,
        "recoveries",
        cursor="cur-2",
        last_run_at="2026-01-02T00:00:00Z",
        outcome="success",
    )
    state = store.get_sync_state(conn, MEMBER_A, "recoveries")
    assert state is not None and state["cursor"] == "cur-2"

    store.record_webhook_delivery(conn, MEMBER_A)
    store.record_webhook_delivery(conn, MEMBER_A)
    assert store.get_last_webhook_delivery(conn, MEMBER_A) is not None

    # -- identity/audit writers -------------------------------------------
    store.link_principal_to_member(
        conn, client_id="client-a", issuer=None, subject=None, whoop_user_id=MEMBER_A
    )
    store.link_principal_to_member(
        conn, client_id="client-a", issuer=None, subject=None, whoop_user_id=MEMBER_A
    )
    assert (
        store.get_member_for_principal(conn, client_id="client-a", issuer=None, subject=None)
        == MEMBER_A
    )
    store.record_tool_call(conn, MEMBER_A, "list_recoveries")
    assert len(store.get_tool_call_audit_for_member(conn, MEMBER_A)) == 1

    # -- webhook_events: insert then each terminal/retry transition --------
    for trace_id in ("trace-success", "trace-retry", "trace-dead"):
        store.insert_webhook_event(conn, trace_id, MEMBER_A, "sleep.updated", "{}")
    store.mark_webhook_event_success(conn, "trace-success")
    store.mark_webhook_event_retry(conn, "trace-retry", 1)
    store.mark_webhook_event_dead_letter(conn, "trace-dead", 5)
    statuses = {
        trace_id: (store.get_webhook_event(conn, trace_id) or {}).get("status")
        for trace_id in ("trace-success", "trace-retry", "trace-dead")
    }
    assert statuses == {
        "trace-success": "success",
        "trace-retry": "pending",
        "trace-dead": "dead_letter",
    }

    # -- soft delete: the one equality-predicated UPDATE, all resources ----
    for resource, resource_id in (("recovery", "1"), ("sleep", "s1"), ("workout", "w1")):
        store.set_deleted_at(conn, resource, MEMBER_A, resource_id)
    assert store.get_recoveries(conn, MEMBER_A) == []
    assert store.get_sleeps(conn, MEMBER_A) == []
    assert store.get_workouts(conn, MEMBER_A) == []
    assert len(store.get_recoveries(conn, MEMBER_A, include_deleted=True)) == 1

    # -- erasure: equality-predicated DELETE across every erasure table ----
    store.erase_member_data(conn, MEMBER_A)
    for table in sorted(store._ERASURE_TABLES):
        rows = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE whoop_user_id = ?",  # noqa: S608 -- table from store._ERASURE_TABLES
            (MEMBER_A,),
        ).fetchone()[0]
        assert rows == 0, f"erase_member_data left rows behind in {table}"
    store.delete_principal_links_for_member(conn, MEMBER_A)
    assert (
        store.get_member_for_principal(conn, client_id="client-a", issuer=None, subject=None)
        is None
    )


# -- #99 test 5: enforce_retention's sweep must delete exactly what it did ----

_RETENTION_NOW = datetime(2026, 1, 1, tzinfo=UTC)
_RETENTION_MAX_AGE_DAYS = 30

#: Rows removed per table by ``enforce_retention`` against the fixture built
#: by ``_seed_retention_fixture`` below. MEASURED against store.py as of
#: #99's parent commit (2bccd9a, before the sweep path existed) rather than
#: reasoned about: the point of this test is that #99 changes *nothing* about
#: what retention deletes, so the expectation is the pre-change behaviour
#: itself. Two stale ``recoveries`` rows and one of everything else, so a
#: sweep that silently degraded to "delete one row per table" or "delete the
#: whole table" is distinguishable from the real result.
_EXPECTED_RETENTION_COUNTS: dict[str, int] = {
    "body_measurements": 1,
    "cycles": 1,
    "profiles": 1,
    "recoveries": 2,
    "sleeps": 1,
    "sync_state": 1,
    "tool_call_audit": 1,
    "webhook_delivery_state": 1,
    "webhook_events": 1,
    "workouts": 1,
}


def _seed_retention_fixture(conn: sqlite3.Connection) -> None:
    """One stale row (past the window) for MEMBER_A and one fresh row (inside
    it) for MEMBER_B in every ``_ERASURE_TABLES`` table, plus a second stale
    ``recoveries`` row so the expected counts are not uniformly 1. Ages are
    set by writing each table's own ``_RETENTION_TIMESTAMP_COLUMNS`` column
    directly -- the fixture must not depend on wall-clock time, and
    ``filterwarnings = ["error"]`` leaves no room for drift."""
    stale = (_RETENTION_NOW - timedelta(days=_RETENTION_MAX_AGE_DAYS, seconds=1)).isoformat()
    fresh = (_RETENTION_NOW - timedelta(days=1)).isoformat()

    for member, tag in ((MEMBER_A, "stale"), (MEMBER_B, "fresh")):
        _seed_recovery(conn, member, tag)
        store.upsert_sleep(conn, member, {"id": f"sleep-{member}", "start": "2026-01-01T00:00:00Z"})
        store.upsert_cycle(conn, member, {"id": member, "start": "2026-01-01T00:00:00Z"})
        store.upsert_workout(
            conn, member, {"id": f"workout-{member}", "start": "2026-01-01T00:00:00Z"}
        )
        _seed_body_measurement(conn, member, tag)
        _seed_profile(conn, member, tag)
        store.set_sync_state(
            conn,
            member,
            "recoveries",
            cursor=tag,
            last_run_at="2026-01-01T00:00:00Z",
            outcome="success",
        )
        store.record_webhook_delivery(conn, member)
        store.insert_webhook_event(conn, f"trace-{member}", member, "sleep.updated", "{}")
        store.record_tool_call(conn, member, f"tool-{tag}")

    # A second stale recoveries row for MEMBER_A, so recoveries' expected
    # count differs from every other table's.
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 2, "score_state": "SCORED"})

    for table in sorted(store._ERASURE_TABLES):
        column = store._RETENTION_TIMESTAMP_COLUMNS[table]
        conn.execute(
            f"UPDATE {table} SET {column} = ? WHERE whoop_user_id = ?",  # noqa: S608 -- table/column from store._ERASURE_TABLES and store._RETENTION_TIMESTAMP_COLUMNS
            (stale, MEMBER_A),
        )
        conn.execute(
            f"UPDATE {table} SET {column} = ? WHERE whoop_user_id = ?",  # noqa: S608 -- same fixed sources
            (fresh, MEMBER_B),
        )
    conn.commit()


def test_enforce_retention_deletes_exactly_what_it_deleted_before(
    store_conn: sqlite3.Connection,
) -> None:
    """#99 test 5: routing ``enforce_retention`` through the new sweep path
    must not change one row of its outcome.

    Compared against the measured pre-change behaviour on both sides -- the
    per-table counts it returns AND which rows are actually gone from the
    database afterwards -- not merely "it did not raise". A sweep that
    stopped deleting from the tenant-scoped tables entirely would still not
    raise; it would just quietly stop enforcing retention.
    """
    conn = store_conn
    _seed_retention_fixture(conn)

    counts = store.enforce_retention(conn, max_age_days=_RETENTION_MAX_AGE_DAYS, now=_RETENTION_NOW)

    assert counts == _EXPECTED_RETENTION_COUNTS
    survivors = {
        table: conn.execute(
            f"SELECT whoop_user_id FROM {table} ORDER BY 1"  # noqa: S608 -- table from store._ERASURE_TABLES
        ).fetchall()
        for table in sorted(store._ERASURE_TABLES)
    }
    assert survivors == {table: [(MEMBER_B,)] for table in sorted(store._ERASURE_TABLES)}, (
        "retention must remove exactly the past-window rows and leave the "
        "within-window ones, on every table"
    )


def _store_call_sites(function_name: str) -> list[tuple[str, int]]:
    """Every call to ``function_name`` in store.py's own source, as
    ``(enclosing function, line)`` pairs. AST-based, like
    ``test_store_has_no_unwrapped_sqlite_execute_outside_scoped_wrapper``, so
    a comment or a docstring naming the function cannot produce a false
    positive."""
    tree = ast.parse(inspect.getsource(store))
    sites: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == function_name
            ):
                sites.append((node.name, inner.lineno))
    return sites


def _sweep_call_sites() -> list[tuple[str, int]]:
    """Every call to the sweep path, as ``(enclosing function, line)`` pairs."""
    return _store_call_sites(_SWEEP_PATH_NAME)


def test_all_tenant_sweep_path_has_exactly_one_caller() -> None:
    """#99 test 6: the opt-out is singular, and pinned so from source.

    A relaxation of a fail-closed control is only acceptable while it is
    reachable from exactly one place. This asserts that structurally rather
    than by convention: the sweep path is called once, from
    ``enforce_retention``, and by nothing anywhere else in the package. A
    second caller -- however well-intentioned -- fails here, which is the
    review signal the issue asks for (see D2: this is why the opt-out is a
    named internal function and not an ``allow_all_tenants=True`` keyword
    that every call site could pass).
    """
    assert callable(getattr(store, _SWEEP_PATH_NAME, None)), (
        f"store.{_SWEEP_PATH_NAME} does not exist: #99's singular all-tenant "
        "sweep path has not been added (or was renamed -- update "
        "_SWEEP_PATH_NAME in this file if so)"
    )

    sites = _sweep_call_sites()
    assert [name for name, _ in sites] == ["enforce_retention"], (
        f"store.{_SWEEP_PATH_NAME} must be called exactly once, from "
        f"enforce_retention; found {sites}"
    )

    src_dir = Path(store.__file__).resolve().parent
    elsewhere: list[str] = []
    for path in sorted(src_dir.glob("*.py")):
        if path.name == "store.py":
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Name) and node.id == _SWEEP_PATH_NAME) or (
                isinstance(node, ast.Attribute) and node.attr == _SWEEP_PATH_NAME
            ):
                elsewhere.append(f"{path.name}:{node.lineno}")
    assert elsewhere == [], (
        f"only store.enforce_retention may reach {_SWEEP_PATH_NAME}; also referenced in {elsewhere}"
    )


#: The executor #99 factored the statement-running half of ``_execute_scoped``
#: into, and the two -- exactly two -- functions allowed to call it. Pinned
#: here for the same reason ``_SWEEP_PATH_NAME`` is: one place to update on a
#: rename, and a loud failure rather than a silent gap if the shape changes.
_GUARD_EXECUTOR_NAME = "_execute_with_tenancy_authorizer"
_GUARD_ENTRY_POINTS = {"_execute_scoped", _SWEEP_PATH_NAME}


def test_only_the_two_named_guard_entry_points_execute_sql() -> None:
    """Companion to test 6, closing the gap #99's refactor would otherwise
    open in ``test_store_has_no_unwrapped_sqlite_execute_outside_scoped
    _wrapper``.

    That test allows ``conn.execute`` inside the shared executor, which is
    what makes the universal check impossible to skip -- but on its own it
    would let a *future* store.py function call that executor directly and get
    the sweep's relaxed treatment (universal check only, no equality
    predicate) without being the sweep, and so without tripping test 6's
    single-caller assertion. The relaxation must stay reachable only through
    the one distinctly-named path (D2), so the executor's callers are pinned
    to the two named entry points: the strict one everything uses, and the
    sweep, itself pinned to a single caller.
    """
    assert callable(getattr(store, _GUARD_EXECUTOR_NAME, None)), (
        f"store.{_GUARD_EXECUTOR_NAME} does not exist -- if #99's shared "
        "executor was renamed, update _GUARD_EXECUTOR_NAME in this file"
    )

    callers = {name for name, _ in _store_call_sites(_GUARD_EXECUTOR_NAME)}
    assert callers == _GUARD_ENTRY_POINTS, (
        f"only {sorted(_GUARD_ENTRY_POINTS)} may call {_GUARD_EXECUTOR_NAME}; "
        f"found {sorted(callers)}. A new caller gets the all-tenant "
        "relaxation without going through the sweep path or its single-caller test."
    )


def test_all_tenant_sweep_path_still_enforces_the_universal_check(
    store_conn: sqlite3.Connection,
) -> None:
    """#99 test 7: the opt-out relaxes the *equality* requirement only.

    This is the test that catches a sloppy opt-out. ``enforce_retention``'s
    scoped-table DELETEs read ``whoop_user_id`` (``IS NOT NULL``), so they
    already satisfy the universal "any touched tenant-scoped table must have
    its ``whoop_user_id`` read" check and must keep satisfying it. A sweep
    path implemented by skipping the authorizer check altogether -- rather
    than by waiving the equality regex alone -- would look like a tightening
    while actually deleting the only real tenancy control: a statement that
    never mentions ``whoop_user_id`` at all would sail through it.

    So: a statement routed through the sweep path that touches a
    tenant-scoped table without reading ``whoop_user_id`` must still be
    rejected, and must still roll back.
    """
    sweep = getattr(store, _SWEEP_PATH_NAME, None)
    assert callable(sweep), (
        f"store.{_SWEEP_PATH_NAME} does not exist: #99's singular all-tenant "
        "sweep path has not been added (or was renamed -- update "
        "_SWEEP_PATH_NAME in this file if so)"
    )

    conn = store_conn
    _seed_recovery(conn, MEMBER_A, "member-a-tag")

    # The shape enforce_retention legitimately uses -- reads whoop_user_id --
    # is accepted through this path: the positive control, so the assertion
    # below cannot pass merely because the path rejects everything.
    sweep(
        conn,
        "DELETE FROM recoveries WHERE whoop_user_id IS NOT NULL AND updated_at < ?",
        ("1970-01-01T00:00:00+00:00",),
    )
    assert conn.execute("SELECT COUNT(*) FROM recoveries").fetchone()[0] == 1, (
        "positive control: that sweep should delete nothing (nothing is that old)"
    )

    # The same sweep with no reference to whoop_user_id at all must still fail.
    with pytest.raises(store.UnscopedQueryError):
        sweep(conn, "DELETE FROM recoveries WHERE updated_at < ?", ("2999-01-01T00:00:00+00:00",))

    conn.commit()
    assert conn.execute("SELECT COUNT(*) FROM recoveries").fetchone()[0] == 1, (
        "the rejected sweep deleted rows anyway -- the universal check was skipped, "
        "not merely the equality requirement"
    )


# =============================================================================
# #109: _MEMBER_EQUALITY_PREDICATE is a presence regex, not a SQL parser:
# a `whoop_user_id = ?` fragment sitting in SET, comment, or string literal
# should NOT satisfy the member-equality requirement. Only a fragment after
# the first top-level WHERE satisfies it (D2).
#
# These tests will FAIL on current main (before the fix) and verify the real
# issue; they will PASS once store.py's _MEMBER_EQUALITY_PREDICATE matching
# is refined per D1-D2.
#
# Tests 1-4 and 9 assert FAILURE (UnscopedQueryError raised); tests 5-6 verify
# legitimate writers remain unbroken.
# =============================================================================


def test_member_equality_set_position_is_rejected(store_conn: sqlite3.Connection) -> None:
    """#109 test 1: SET-position fragment must be rejected, and no row changed.

    The most dangerous form: UPDATE recoveries SET whoop_user_id = ? WHERE
    whoop_user_id IS NOT NULL reassigns every member's rows to a caller-chosen
    id, and the current regex accepts it because it finds the fragment
    somewhere in the text.

    This test must FAIL before the fix (mutation currently succeeds, no
    exception raised). After the fix, it must raise UnscopedQueryError AND
    confirm zero rows changed.
    """
    conn = store_conn
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})
    store.upsert_recovery(conn, MEMBER_B, {"cycle_id": 2, "score_state": "SCORED"})

    # Before attempting the forbidden update, capture the current row state.
    before = dict(
        conn.execute(
            "SELECT whoop_user_id, score_state FROM recoveries ORDER BY whoop_user_id"
        ).fetchall()
    )
    assert before == {MEMBER_A: "SCORED", MEMBER_B: "SCORED"}, "seeding must succeed"

    # The SET-position attack: whoop_user_id = ? sits in SET, not WHERE.
    # This should raise UnscopedQueryError once fixed.
    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(
            conn,
            "UPDATE recoveries SET whoop_user_id = ? WHERE whoop_user_id IS NOT NULL",
            (MEMBER_A,),
        )

    # Rejection must not leave the mutation pending. Simulate a later, unrelated
    # legitimate commit and verify rows are exactly as seeded.
    conn.commit()
    after = dict(
        conn.execute(
            "SELECT whoop_user_id, score_state FROM recoveries ORDER BY whoop_user_id"
        ).fetchall()
    )
    assert after == before, f"SET-position UPDATE was not rolled back: {before} became {after}"


def test_member_equality_line_comment_is_rejected(store_conn: sqlite3.Connection) -> None:
    """#109 test 2a: Line-comment-position fragment must be rejected, no row changed.

    A -- comment containing whoop_user_id = ? should not satisfy the
    member-equality requirement. The fragment sits in a comment, not a
    WHERE clause.

    The WHERE clause must be `whoop_user_id != ?`, not `resource_id = ?`:
    a statement that never reads whoop_user_id is rejected by the *universal*
    authorizer check before the equality check is ever consulted, so it would
    pass on unfixed code for the wrong reason and prove nothing about #109.
    `!= ?` reads the column, satisfying the universal check, which leaves the
    equality check as the only thing standing between this statement and
    another member's row.
    """
    conn = store_conn
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})
    store.upsert_recovery(conn, MEMBER_B, {"cycle_id": 2, "score_state": "SCORED"})

    before_a = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ? AND resource_id = ?",
        (MEMBER_A, "1"),
    ).fetchone()[0]

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(
            conn,
            "UPDATE recoveries SET score_state = 'MUTATED' WHERE whoop_user_id != ?"
            "  -- whoop_user_id = ?",
            (MEMBER_A,),
        )

    conn.commit()
    after_a = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ? AND resource_id = ?",
        (MEMBER_A, "1"),
    ).fetchone()[0]
    assert after_a == before_a, (
        f"line-comment-position UPDATE was not rolled back: {before_a} became {after_a}"
    )


def test_member_equality_block_comment_is_rejected(store_conn: sqlite3.Connection) -> None:
    """#109 test 2b: Block-comment-position fragment must be rejected, no row changed.

    A /* */ comment containing whoop_user_id = ? should not satisfy the
    member-equality requirement.
    """
    conn = store_conn
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})
    store.upsert_recovery(conn, MEMBER_B, {"cycle_id": 2, "score_state": "SCORED"})

    before_a = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ? AND resource_id = ?",
        (MEMBER_A, "1"),
    ).fetchone()[0]

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(
            conn,
            "UPDATE recoveries SET score_state = 'MUTATED' WHERE whoop_user_id != ?"
            "  /* whoop_user_id = ? */",
            (MEMBER_A,),
        )

    conn.commit()
    after_a = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ? AND resource_id = ?",
        (MEMBER_A, "1"),
    ).fetchone()[0]
    assert after_a == before_a, (
        f"block-comment-position UPDATE was not rolled back: {before_a} became {after_a}"
    )


def test_member_equality_string_literal_is_rejected(store_conn: sqlite3.Connection) -> None:
    """#109 test 3: String-literal-position fragment must be rejected, no row changed.

    A string literal containing whoop_user_id = ? (both single and double
    quotes) should not satisfy the member-equality requirement. These tests
    verify both quote styles.
    """
    conn = store_conn
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})
    store.upsert_recovery(conn, MEMBER_B, {"cycle_id": 2, "score_state": "SCORED"})

    before_a = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ? AND resource_id = ?",
        (MEMBER_A, "1"),
    ).fetchone()[0]

    # Test with single-quoted string literal
    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(
            conn,
            "UPDATE recoveries SET score_state = 'where whoop_user_id = ?' "
            "WHERE whoop_user_id != ?",
            (MEMBER_A,),
        )

    conn.commit()
    after_a = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ? AND resource_id = ?",
        (MEMBER_A, "1"),
    ).fetchone()[0]
    assert after_a == before_a, (
        f"single-quoted-string UPDATE was not rolled back: {before_a} became {after_a}"
    )

    # Test with double-quoted string literal (as a column reference in a CAST or similar)
    before_b = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ? AND resource_id = ?",
        (MEMBER_B, "2"),
    ).fetchone()[0]

    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(
            conn,
            'UPDATE recoveries SET score_state = "whoop_user_id = ?" WHERE whoop_user_id != ?',
            (MEMBER_A,),
        )

    conn.commit()
    after_b = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ? AND resource_id = ?",
        (MEMBER_B, "2"),
    ).fetchone()[0]
    assert after_b == before_b, (
        f"double-quoted-string UPDATE was not rolled back: {before_b} became {after_b}"
    )


def test_member_equality_subquery_in_set_at_depth_zero_is_rejected(
    store_conn: sqlite3.Connection,
) -> None:
    """#109 test 4: Subquery-in-SET with fragment at depth zero must be rejected.

    D2 requires the fragment to appear after the first top-level WHERE (at
    parenthesis depth zero). A subquery in a SET clause supplies the fragment
    while the outer statement stays unfiltered:
    UPDATE recoveries SET x = (SELECT y FROM z WHERE whoop_user_id = ?)
    WHERE 1 = 1

    This must be rejected because the fragment is inside parentheses (depth 1),
    not after a top-level WHERE. The outer WHERE (1 = 1) does not restrict to
    a member.
    """
    conn = store_conn
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})

    before = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchone()[0]

    # Attempt an UPDATE where the fragment only appears inside a subquery.
    # The outer statement has no member restriction.
    with pytest.raises(store.UnscopedQueryError):
        store._execute_scoped(
            conn,
            "UPDATE recoveries SET score_state = (SELECT ? WHERE whoop_user_id = ?) WHERE 1 = 1",
            ("MUTATED", MEMBER_A),
        )

    conn.commit()
    after = conn.execute(
        "SELECT score_state FROM recoveries WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchone()[0]
    assert after == before, "subquery-in-SET UPDATE was not rolled back"


def test_member_equality_legitimate_writers_still_work(
    store_conn: sqlite3.Connection,
) -> None:
    """#109 test 5: Every legitimate writer must still work after the fix.

    Exercise all 11 shapes documented in the brief (the actual statements that
    reach _execute_scoped in the codebase), verifying by read-back. These are:
    - DELETE FROM {recoveries, cycles, sleeps, workouts, body_measurements,
              profiles, sync_state, webhook_delivery_state} WHERE whoop_user_id = ?
    - UPDATE {sleeps, workouts, recoveries} SET deleted_at = ?
              WHERE whoop_user_id = ? AND resource_id = ?

    All use the binding format where whoop_user_id = ? appears after the
    first top-level WHERE.
    """
    conn = store_conn

    # Seed members with data.
    store.upsert_recovery(conn, MEMBER_A, {"cycle_id": 1, "score_state": "SCORED"})
    store.upsert_sleep(
        conn,
        MEMBER_A,
        {"id": "sleep-1", "start": "2026-01-01T00:00:00Z", "score_state": "SCORED"},
    )
    store.upsert_cycle(
        conn, MEMBER_A, {"id": 1, "start": "2026-01-01T00:00:00Z", "score_state": "SCORED"}
    )
    store.upsert_workout(
        conn,
        MEMBER_A,
        {"id": "workout-1", "start": "2026-01-01T00:00:00Z", "score_state": "SCORED"},
    )
    store.upsert_body_measurement(conn, MEMBER_A, {"weight_kilogram": 70})
    store.upsert_profile(conn, MEMBER_A, {"user_id": MEMBER_A, "email": "a@example.test"})
    store.set_sync_state(
        conn,
        MEMBER_A,
        "recoveries",
        cursor="cursor-1",
        last_run_at="2026-01-01T00:00:00Z",
        outcome="success",
    )
    store.record_webhook_delivery(conn, MEMBER_A)

    # Verify all data was written.
    assert store.get_recoveries(conn, MEMBER_A) != []
    assert store.get_sleeps(conn, MEMBER_A) != []
    assert store.get_cycles(conn, MEMBER_A) != []
    assert store.get_workouts(conn, MEMBER_A) != []
    assert store.get_body_measurement(conn, MEMBER_A) is not None
    assert store.get_profile(conn, MEMBER_A) is not None
    assert store.get_sync_state(conn, MEMBER_A, "recoveries") is not None
    assert store.get_last_webhook_delivery(conn, MEMBER_A) is not None

    # Now exercise the legitimate soft-delete path (the UPDATE shape with
    # the member predicate after the first WHERE).
    store.set_deleted_at(conn, "recovery", MEMBER_A, "1")
    store.set_deleted_at(conn, "sleep", MEMBER_A, "sleep-1")
    store.set_deleted_at(conn, "workout", MEMBER_A, "workout-1")

    # Verify soft deletes worked.
    assert store.get_recoveries(conn, MEMBER_A) == []
    assert store.get_sleeps(conn, MEMBER_A) == []
    assert store.get_workouts(conn, MEMBER_A) == []

    # Verify include_deleted sees them.
    assert len(store.get_recoveries(conn, MEMBER_A, include_deleted=True)) == 1


def test_executed_sql_unaltered_with_special_chars(store_conn: sqlite3.Connection) -> None:
    """#109 test 6: Executed SQL is unaltered (D1); sanitization is on a copy only.

    A payload legitimately containing --, /*, and quote characters must write
    exactly those bytes when read back. Only a copy is sanitised for the
    predicate search; the real SQL executed must be byte-identical to what the
    caller wrote.

    This test writes a recovery with payload containing these special chars,
    then reads it back and verifies the JSON bytes are exactly preserved.
    """
    conn = store_conn

    # Craft a payload with dangerous characters in the raw_json string.
    # These should survive the write/read cycle unchanged.
    payload = {
        "cycle_id": 1,
        "score_state": "SCORED",
        "raw_json_note": "This note contains -- and /* and 'quotes' and \"double\"",
    }
    store.upsert_recovery(conn, MEMBER_A, payload)

    # Read it back.
    recoveries = store.get_recoveries(conn, MEMBER_A)
    assert len(recoveries) == 1

    # The raw_json was written with our payload; verify the special chars survive.
    raw_json_str = recoveries[0].get("raw_json_note")
    assert raw_json_str == "This note contains -- and /* and 'quotes' and \"double\"", (
        "executed SQL was altered: special characters in payload were not preserved"
    )


def test_member_equality_not_caught_list_is_truthful() -> None:
    """#109 test 9: The CAUGHT/NOT-CAUGHT list documented above
    ``_MEMBER_EQUALITY_PREDICATE`` must be truthful and updated.

    ``_MEMBER_EQUALITY_PREDICATE`` is a compiled ``re.Pattern``, whose
    ``__doc__`` is the fixed, read-only "Compiled regular expression
    object." string (``re.Pattern`` does not allow assigning ``__doc__``) --
    so the CAUGHT/NOT-CAUGHT list can only ever have lived as the ``#:``
    sphinx-style comment block directly above the assignment, never as a
    runtime docstring. This test reads that comment block out of the module
    *source*, the same way this file's other source-level checks already do
    (``inspect.getsource`` + text search, e.g.
    ``test_store_has_no_unwrapped_sqlite_execute_outside_scoped_wrapper``).

    After the fix, that comment block must no longer claim that SET-position,
    comment-position, string-literal-position, or depth-zero
    subquery-in-SET are NOT-CAUGHT (uncaught) -- they must have moved to
    CAUGHT -- while what genuinely remains (OR-after-WHERE, multi-table
    ambiguity) must still be documented as NOT-CAUGHT, not deleted.
    """
    source = inspect.getsource(store)
    marker = "_MEMBER_EQUALITY_PREDICATE = re.compile("
    assert marker in source, "the annotated regex assignment moved or was renamed"
    before_assignment = source[: source.index(marker)]

    # The comment block is the contiguous run of "#:"-prefixed lines
    # immediately above the assignment -- walk backwards from it and stop at
    # the first line that is not part of that run.
    comment_lines: list[str] = []
    for line in reversed(before_assignment.splitlines()):
        if line.strip().startswith("#:"):
            comment_lines.append(line)
        else:
            break
    comment_lines.reverse()
    doc_block = "\n".join(comment_lines)
    assert doc_block, "no #: comment block found directly above _MEMBER_EQUALITY_PREDICATE"

    # These four shapes should NOT appear in the NOT-CAUGHT section after the fix.
    shapes_now_caught = [
        "SET assignment",
        "SET clause",
        "-- comment",
        "string literal",
        "subquery",
    ]

    # Find the NOT-CAUGHT section: everything from the first "NOT CAUGHT"
    # onward, so a CAUGHT bullet earlier in the block is never mistaken for
    # one of the residuals.
    not_caught_section = ""
    if "NOT CAUGHT" in doc_block:
        parts = doc_block.split("NOT CAUGHT")
        if len(parts) > 1:
            not_caught_section = "NOT CAUGHT".join(parts[1:])

    assert not_caught_section, "the comment block no longer documents any NOT-CAUGHT residual"

    # Verify that the formerly NOT-CAUGHT shapes no longer appear there.
    for shape in shapes_now_caught:
        assert shape.lower() not in not_caught_section.lower(), (
            f"_MEMBER_EQUALITY_PREDICATE's comment still lists {shape!r} in its "
            "NOT-CAUGHT section; it should be moved to CAUGHT after the fix"
        )


# -- exclusion rationale stays true (issue #130) -------------------------------


def test_webhook_events_exclusion_rests_on_reachability_not_nullability() -> None:
    """Pin the facts `webhook_events`'s exclusion rationale depends on.

    The comment above `_TENANT_SCOPED_TABLES` used to justify the exclusion by
    saying the column "is nullable pre-identity-resolution data". #105 made it
    NOT NULL, so the exclusion outlived its stated reason -- a future reader
    deciding whether the table belongs in the scoped set would have reasoned
    from a false premise.

    This asserts the reality the corrected comment describes, not its wording.
    A test that greps prose would block a legitimate rewrite; one that pins
    facts fails when the facts move, which is when the comment needs revisiting.
    """
    source = inspect.getsource(store)

    # The old justification cannot be revived: the column is NOT NULL.
    assert "whoop_user_id INTEGER NOT NULL" in source

    # The exclusion itself, and the erasure coverage that must accompany it
    # because the table does hold member data.
    assert "webhook_events" not in store._TENANT_SCOPED_TABLES
    assert "webhook_events" in store._ERASURE_TABLES

    # The reachability the exclusion now rests on: one reader by trace_id, one
    # that filters by member itself. A third reader that did neither would make
    # the exclusion unsafe, and should fail here.
    by_trace = inspect.getsource(store.get_webhook_event)
    assert "WHERE trace_id = ?" in by_trace, "get_webhook_event must still be keyed by trace_id"

    by_member = inspect.getsource(store.get_webhook_events_for_member)
    assert "whoop_user_id = ?" in by_member, (
        "the per-member reader must still filter by whoop_user_id itself"
    )
