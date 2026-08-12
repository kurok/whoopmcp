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


def test_schema_version_bumped_to_four() -> None:
    """#18's webhook_events was v2, #29's principal_members/tool_call_audit
    was v3; #19's per-user webhook_delivery_state (for #31's future
    silence-alerting) is the next migration in the ladder."""
    assert store.CURRENT_SCHEMA_VERSION == 4


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
    ``.executemany`` call in store.py must live inside ``_execute_scoped``
    itself, ``_migrate``, or ``open_store`` (migration/PRAGMA bootstrap code,
    which never touches an entity table) -- otherwise a future store.py
    function could quietly route around the authorizer-backed check entirely.
    AST-based, not a text grep, so it can't be fooled by a comment or a
    string literal containing "conn.execute(".
    """
    source = inspect.getsource(store)
    tree = ast.parse(source)
    allowed = {"_execute_scoped", "_migrate", "open_store"}
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
        "store.py calls .execute()/.executemany() outside _execute_scoped, "
        f"_migrate, or open_store: {violations}"
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
