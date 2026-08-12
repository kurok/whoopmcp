"""Tests for issue #32: data subject rights -- export, erasure, retention.

Written before any implementation exists, per the issue's own instruction.
None of the following symbols exist yet: ``store.export_member_data``,
``store.erase_member_data``, ``store.enforce_retention``,
``store._ERASURE_TABLES``, ``store._RETENTION_TIMESTAMP_COLUMNS``, the four
small ``get_*_for_member`` export helpers, or the ``export-member``/
``erase-member``/``enforce-retention`` CLI subcommands in ``__main__.py``.
``store`` and ``whoopmcp.__main__`` are referenced via module attribute access
below rather than ``from ... import ...`` for exactly the reason
``tests/test_tenancy.py``'s own docstring gives: this file must still
*collect* today, so an individual test missing an attribute fails with a
clear ``AttributeError``/``TypeError`` at call time rather than an
``ImportError`` hiding every other test in the file. Once #32 lands both
styles behave identically.

Anchors this file leans on, already merged:

- ``store._TENANT_SCOPED_TABLES`` / ``store._execute_scoped`` (#29) -- any new
  erasure/export function must go through the same enforcement, not around it.
- ``auth.Authenticator.revoke_and_forget`` / ``auth.revoke_upstream`` (#30) --
  reused, not rebuilt, for erasure's "tokens ... plus upstream revocation"
  scope. See ``tests/test_auth.py``'s own respx-mocked pattern, mirrored below.
- ``__main__._delete_member`` / the ``delete-member`` subcommand (#30) --
  ``erase-member`` is a new sibling subcommand, mirrored structurally
  (including ``tests/test_main.py``'s own two delete-member tests).

Erasure is a real ``DELETE``, never a ``deleted_at`` ``UPDATE`` -- that
machinery is #18's, reserved for ``*.deleted`` webhook events, and is a
deliberately distinct code path from a member exercising erasure (see the
"soft-delete vs erasure are distinct paths" section at the bottom of this
file). Every erasure assertion below reads the database directly with raw
SQL on a plain ``sqlite3.Connection`` -- never through a store.py ``get_*``
repository function that could itself filter member data and produce a false
negative.
"""

from __future__ import annotations

import inspect
import io
import os
import sqlite3
import stat
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from whoopmcp import store, webhook_processor
from whoopmcp.__main__ import main
from whoopmcp.auth import TOKEN_URL, USER_ACCESS_URL, FileTokenStore, Token
from whoopmcp.config import Config

# Two WHOOP members. Large, distinctive integers so their decimal string
# forms are vanishingly unlikely to collide with anything else in a fixture,
# mirroring tests/test_tenancy.py's own MEMBER_A/MEMBER_B convention (kept in
# a disjoint numeric range from that file's 900001/900002 purely so a
# copy-paste mistake between the two files would be obvious, not because
# anything here actually runs alongside test_tenancy.py's fixtures).
MEMBER_A = 910001
MEMBER_B = 910002


@pytest.fixture
def store_conn() -> sqlite3.Connection:
    conn = store.open_store(":memory:")
    yield conn
    conn.close()


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


def _set_required_env_and_state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://localhost:8443/callback")
    monkeypatch.setenv("WHOOPMCP_STATE_DIR", str(tmp_path))


# =============================================================================
# seed helpers -- one per table in the anchor's enumeration, mirroring
# tests/test_tenancy.py's own _seed_* helpers plus new ones for the three
# tables that file doesn't need (webhook_events, tool_call_audit,
# principal_members).
# =============================================================================


def _seed_recovery(conn: sqlite3.Connection, user_id: int, tag: str, cycle_id: int = 1) -> None:
    store.upsert_recovery(
        conn,
        user_id,
        {"cycle_id": cycle_id, "score_state": "SCORED", "score": {"recovery_score": tag}},
    )


def _seed_sleep(conn: sqlite3.Connection, user_id: int, tag: str, sleep_id: str = "s1") -> None:
    store.upsert_sleep(
        conn,
        user_id,
        {
            "id": sleep_id,
            "start": "2026-01-01T00:00:00Z",
            "score_state": "SCORED",
            "score": {"sleep_performance_percentage": tag},
        },
    )


def _seed_cycle(conn: sqlite3.Connection, user_id: int, tag: str, cycle_id: int = 1) -> None:
    store.upsert_cycle(
        conn,
        user_id,
        {
            "id": cycle_id,
            "start": "2026-01-01T00:00:00Z",
            "score_state": "SCORED",
            "score": {"strain": tag},
        },
    )


def _seed_workout(conn: sqlite3.Connection, user_id: int, tag: str, workout_id: str = "w1") -> None:
    store.upsert_workout(
        conn,
        user_id,
        {
            "id": workout_id,
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


def _seed_sync_state(conn: sqlite3.Connection, user_id: int, tag: str) -> None:
    store.set_sync_state(
        conn,
        user_id,
        "recoveries",
        cursor=tag,
        last_run_at="2026-01-01T00:00:00Z",
        outcome="success",
    )


def _seed_webhook_event(conn: sqlite3.Connection, user_id: int, trace_id: str, tag: str) -> None:
    store.insert_webhook_event(conn, trace_id, user_id, "sleep.updated", tag)


def _seed_tool_call_audit(conn: sqlite3.Connection, user_id: int, tool_name: str) -> None:
    store.record_tool_call(conn, user_id, tool_name)


def _seed_principal_link(conn: sqlite3.Connection, user_id: int, client_id: str) -> None:
    store.link_principal_to_member(
        conn, client_id=client_id, issuer=None, subject=None, whoop_user_id=user_id
    )


def _seed_webhook_delivery_state(conn: sqlite3.Connection, user_id: int) -> None:
    """#19's per-user last-delivery timestamp -- no tag to embed (the table
    carries only ``last_delivered_at``, nothing member-identifying beyond
    the row's own ``whoop_user_id`` key), so it is exercised by the generic
    ``_ERASURE_TABLES``/retention sweeps below by presence alone, not by a
    substring search the way the tagged tables are."""
    store.record_webhook_delivery(conn, user_id)


def _seed_every_entity_table(conn: sqlite3.Connection, user_id: int, tag: str) -> None:
    """Seed one row for ``user_id`` in every table the anchor names, tagged
    distinctly so a cross-member leak or a survivor after erasure is
    detectable by substring search."""
    _seed_recovery(conn, user_id, tag)
    _seed_sleep(conn, user_id, tag, sleep_id=f"sleep-{user_id}")
    _seed_cycle(conn, user_id, tag, cycle_id=user_id)
    _seed_workout(conn, user_id, tag, workout_id=f"workout-{user_id}")
    _seed_body_measurement(conn, user_id, tag)
    _seed_profile(conn, user_id, tag)
    _seed_sync_state(conn, user_id, tag)
    _seed_webhook_event(conn, user_id, f"trace-{user_id}", tag)
    _seed_tool_call_audit(conn, user_id, f"tool-{tag}")
    _seed_principal_link(conn, user_id, f"client-{user_id}")
    _seed_webhook_delivery_state(conn, user_id)


# =============================================================================
# export: every entity held for a member, and never another member's data
# =============================================================================


def _walk_strings(value: Any) -> list[str]:
    """Every string leaf reachable from ``value`` -- used to prove a marker
    tag never appears anywhere in an exported document, not just at the
    top level of whichever key happened to be checked."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for k, v in value.items():
            out.append(str(k))
            out.extend(_walk_strings(v))
        return out
    if isinstance(value, list | tuple):
        out = []
        for item in value:
            out.extend(_walk_strings(item))
        return out
    return [str(value)]


def test_export_returns_every_entity_held_for_the_member(store_conn: sqlite3.Connection) -> None:
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")

    export = store.export_member_data(store_conn, MEMBER_A)

    assert export["whoop_user_id"] == MEMBER_A
    assert "exported_at" in export
    assert export["profile"]["email"] == "member-a-tag"
    assert export["body_measurement"]["weight_kilogram"] == "member-a-tag"
    assert len(export["recoveries"]) == 1
    assert export["recoveries"][0]["score"]["recovery_score"] == "member-a-tag"
    assert len(export["sleeps"]) == 1
    assert len(export["cycles"]) == 1
    assert len(export["workouts"]) == 1
    assert len(export["sync_state"]) == 1
    assert len(export["webhook_events"]) == 1
    assert len(export["tool_call_audit"]) == 1
    assert len(export["principal_links"]) == 1
    assert export["webhook_delivery_state"]["last_delivered_at"] is not None


def test_export_never_leaks_a_second_members_data(store_conn: sqlite3.Connection) -> None:
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")
    _seed_every_entity_table(store_conn, MEMBER_B, "member-b-tag")

    export = store.export_member_data(store_conn, MEMBER_A)

    dump = _walk_strings(export)
    assert "member-b-tag" not in dump
    assert str(MEMBER_B) not in dump
    assert f"client-{MEMBER_B}" not in dump
    assert f"trace-{MEMBER_B}" not in dump
    # Positive control: member A's own tag really is present, so the
    # negative assertions above aren't vacuously true against an empty export.
    assert "member-a-tag" in dump


def test_export_of_a_member_with_nothing_synced_yet_has_empty_collections_not_errors(
    store_conn: sqlite3.Connection,
) -> None:
    export = store.export_member_data(store_conn, MEMBER_A)

    assert export["whoop_user_id"] == MEMBER_A
    assert export["profile"] is None
    assert export["body_measurement"] is None
    assert export["recoveries"] == []
    assert export["sleeps"] == []
    assert export["cycles"] == []
    assert export["workouts"] == []
    assert export["sync_state"] == []
    assert export["webhook_events"] == []
    assert export["tool_call_audit"] == []
    assert export["principal_links"] == []
    assert export["webhook_delivery_state"] == {}


# =============================================================================
# erasure: real DELETEs, verified at the database level -- never through a
# store.py get_* read, which could itself filter and produce a false negative
# =============================================================================


def test_erasure_registry_covers_every_schema_table() -> None:
    """Enumerates the *live schema* (not a second hand-written list) via
    ``PRAGMA table_list`` on a fresh store, so a future migration that adds a
    table without adding it to ``store._ERASURE_TABLES`` (or the one
    documented exception, ``principal_members``, erased separately by
    ``delete_principal_links_for_member``) fails this test immediately --
    one level stronger than #29's own hand-written-list-vs-test-cases parity
    check, since this compares against the schema itself."""
    conn = store.open_store(":memory:")
    tables = {
        row[1]
        for row in conn.execute("PRAGMA table_list")
        if row[0] == "main" and not row[1].startswith("sqlite_")
    }
    conn.close()

    assert tables == store._ERASURE_TABLES | {"principal_members"}


def test_erasure_covers_every_table_export_actually_reads_from(
    store_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#69 test 5: erase-member covers every table export-member reads from --
    the two must enumerate the same table set, so a table added to one but
    not the other is caught here rather than shipping silently uncovered.

    Genuinely new: no existing test compares these two sets dynamically.
    ``test_erasure_registry_covers_every_schema_table`` above compares
    ``_ERASURE_TABLES`` against the *live schema*'s table list, and
    ``test_export_returns_every_entity_held_for_the_member`` asserts
    export's *field* presence -- neither ever asks "which tables did
    ``export_member_data`` itself actually touch, at the sqlite level, and
    is that the same set ``erase_member_data`` deletes from?" A table that
    export starts reading from (or stops reading from) without a matching
    change to ``_ERASURE_TABLES`` would pass both existing tests untouched;
    this one exists to catch exactly that drift.

    Every entity read in ``export_member_data`` goes through
    ``store._execute_scoped`` (enforced structurally by
    ``test_store_has_no_unwrapped_sqlite_execute_outside_scoped_wrapper`` in
    test_tenancy.py). ``sqlite3.Connection`` is a C extension type and
    cannot be monkeypatched at the class level (tried first; raises
    ``TypeError: cannot set ... attribute of immutable type``), and
    ``_execute_scoped`` installs its own authorizer unconditionally on every
    call, so a callback set on the connection *before* calling it would just
    be clobbered. Instead this monkeypatches ``store._execute_scoped`` itself
    for the duration of the test: the replacement installs its own
    ``SQLITE_READ``-recording authorizer and runs the same ``sql``/``params``
    directly, so every table an export statement's compiled query actually
    names is captured straight from sqlite, not from a hand-maintained guess
    at which tables ``export_member_data`` "should" touch. (It does not
    replicate ``_execute_scoped``'s own scoping validation -- that property
    is test_tenancy.py's job, not this test's; every query the fixtures below
    issue is already known-correctly-scoped.)

    ``principal_members`` is read via the identity join but is not itself in
    ``_ERASURE_TABLES`` (erased separately, by
    ``delete_principal_links_for_member`` -- see that table's own comment in
    store.py), which is exactly why the assertion below adds it explicitly
    rather than asserting equality with ``_ERASURE_TABLES`` alone.
    """
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")

    tables_read: set[str] = set()

    def recording_execute_scoped(
        conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()
    ) -> sqlite3.Cursor:
        def authorizer(action: int, arg1: str | None, *_rest: object) -> int:
            if action == sqlite3.SQLITE_READ and arg1 is not None:
                tables_read.add(arg1)
            return sqlite3.SQLITE_OK

        conn.set_authorizer(authorizer)
        try:
            return conn.execute(sql, params)
        finally:
            conn.set_authorizer(None)

    monkeypatch.setattr(store, "_execute_scoped", recording_execute_scoped)

    store.export_member_data(store_conn, MEMBER_A)

    expected = store._ERASURE_TABLES | {"principal_members"}
    assert tables_read == expected, (
        "export_member_data's actual table reads and the erasure registry have "
        f"drifted apart: read-by-export-only={tables_read - expected}, "
        f"erasure-registry-only={expected - tables_read}"
    )


def test_erase_member_data_deletes_rows_from_every_erasure_table(
    store_conn: sqlite3.Connection,
) -> None:
    """Seeds one row per ``_ERASURE_TABLES`` table for MEMBER_A, erases, then
    asserts directly against the database (raw ``conn.execute``, never a
    store.py ``get_*`` read) that every one of those tables holds zero rows
    for MEMBER_A afterward."""
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")

    store.erase_member_data(store_conn, MEMBER_A)

    for table in sorted(store._ERASURE_TABLES):
        rows = store_conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608 -- table from a fixed internal frozenset, never user input
            (MEMBER_A,),
        ).fetchall()
        assert rows == [], f"erase_member_data left rows behind in {table}"


def test_erase_member_data_never_touches_another_members_rows(
    store_conn: sqlite3.Connection,
) -> None:
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")
    _seed_every_entity_table(store_conn, MEMBER_B, "member-b-tag")

    store.erase_member_data(store_conn, MEMBER_A)

    for table in sorted(store._ERASURE_TABLES):
        rows = store_conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (MEMBER_B,),
        ).fetchall()
        assert rows != [], (
            f"erase_member_data for MEMBER_A wrongly removed MEMBER_B's rows in {table}"
        )


def test_erase_member_data_covers_webhook_events_and_tool_call_audit_specifically(
    store_conn: sqlite3.Connection,
) -> None:
    """Focused companion to the full-registry sweep above, exercising exactly
    the two bookkeeping tables the issue calls out by name alongside health
    data: webhook_events and tool_call_audit."""
    _seed_webhook_event(store_conn, MEMBER_A, "trace-a", "member-a-tag")
    _seed_webhook_event(store_conn, MEMBER_B, "trace-b", "member-b-tag")
    _seed_tool_call_audit(store_conn, MEMBER_A, "tool-a")
    _seed_tool_call_audit(store_conn, MEMBER_B, "tool-b")

    store.erase_member_data(store_conn, MEMBER_A)

    remaining_webhooks = store_conn.execute(
        "SELECT trace_id FROM webhook_events WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchall()
    remaining_audit = store_conn.execute(
        "SELECT tool_name FROM tool_call_audit WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchall()
    assert remaining_webhooks == []
    assert remaining_audit == []

    b_webhooks = store_conn.execute(
        "SELECT trace_id FROM webhook_events WHERE whoop_user_id = ?", (MEMBER_B,)
    ).fetchall()
    b_audit = store_conn.execute(
        "SELECT tool_name FROM tool_call_audit WHERE whoop_user_id = ?", (MEMBER_B,)
    ).fetchall()
    assert b_webhooks == [("trace-b",)]
    assert b_audit == [("tool-b",)]


def test_erase_member_data_does_not_touch_principal_members(
    store_conn: sqlite3.Connection,
) -> None:
    """``principal_members`` is deliberately erased by
    ``delete_principal_links_for_member`` (#30), not duplicated inside
    ``erase_member_data`` -- the two are composed by the CLI orchestration,
    not by this one function alone."""
    _seed_principal_link(store_conn, MEMBER_A, "client-a")

    store.erase_member_data(store_conn, MEMBER_A)

    rows = store_conn.execute(
        "SELECT whoop_user_id FROM principal_members WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchall()
    assert rows == [(MEMBER_A,)], (
        "erase_member_data must leave principal_members alone -- that table's own "
        "erasure is delete_principal_links_for_member's job"
    )


# =============================================================================
# erasure covers the upstream revoke too (reusing #30's own primitive) --
# exercised at the CLI level (erase-member), mirroring
# tests/test_main.py's delete-member tests and tests/test_auth.py's
# revoke_and_forget respx pattern.
# =============================================================================


def test_erase_member_subcommand_revokes_upstream_and_deletes_everything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config as ConfigCls

    config = ConfigCls.from_env()
    FileTokenStore(config.token_path).save(
        Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    )

    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="local", issuer=None, subject=None, whoop_user_id=42
    )
    _seed_every_entity_table(conn, 42, "erase-me-tag")
    conn.close()

    with respx.mock:
        route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(204))
        exit_code = main(["erase-member", "--whoop-user-id", "42"])

    assert exit_code == 0
    assert route.called
    assert FileTokenStore(config.token_path).load() is None

    conn = store_module.open_store(config.cache_path)
    for table in sorted(store_module._ERASURE_TABLES):
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (42,),
        ).fetchall()
        assert rows == [], f"erase-member left rows behind in {table}"
    assert (
        store_module.get_member_for_principal(conn, client_id="local", issuer=None, subject=None)
        is None
    )
    conn.close()


def test_erase_member_subcommand_refuses_a_mismatched_whoop_user_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mirrors test_main.py's own delete-member refusal test: a mismatched
    id must refuse -- no upstream revoke, no local deletion -- not
    silently no-op-succeed."""
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config as ConfigCls

    config = ConfigCls.from_env()
    FileTokenStore(config.token_path).save(
        Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    )

    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="local", issuer=None, subject=None, whoop_user_id=42
    )
    _seed_every_entity_table(conn, 42, "erase-me-tag")
    conn.close()

    with respx.mock:
        route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(204))
        exit_code = main(["erase-member", "--whoop-user-id", "999"])

    assert exit_code != 0
    assert not route.called
    assert FileTokenStore(config.token_path).load() is not None

    conn = store_module.open_store(config.cache_path)
    rows = conn.execute("SELECT * FROM recoveries WHERE whoop_user_id = ?", (42,)).fetchall()
    assert rows != [], "a refused erase-member call must not delete anything"
    conn.close()


# =============================================================================
# erase-member: revoke-ordering / attribution fixes (issue #65) -- mirrors
# the three test_main.py delete-member additions above, for erase-member's
# fuller local-deletion story (health data, webhook events, audit rows, and
# the principal link, via erase_member_data + delete_principal_links_for_member).
# =============================================================================


def test_erase_member_subcommand_deletes_locally_when_refresh_hits_invalid_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stored token is expired and its refresh_token has been revoked in
    WHOOP's own app settings -- WHOOP's token endpoint answers invalid_grant.
    That must be treated as revoke-step success (the grant is already gone,
    not merely unreachable) and erasure must still complete."""
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config as ConfigCls

    config = ConfigCls.from_env()
    FileTokenStore(config.token_path).save(
        Token("stale-access", expires_at=time.time() - 3600, refresh_token="stale-refresh")
    )

    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="local", issuer=None, subject=None, whoop_user_id=42
    )
    _seed_every_entity_table(conn, 42, "erase-me-tag")
    conn.close()

    with respx.mock:
        token_route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={"error": "invalid_grant", "error_description": "revoked in-app"},
            )
        )
        revoke_route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(204))
        exit_code = main(["erase-member", "--whoop-user-id", "42"])

    assert exit_code == 0
    assert token_route.called
    # The refresh failed before a live access token ever existed, so the
    # revoke endpoint itself is never reached.
    assert not revoke_route.called
    # invalid_grant's own handling in Authenticator._do_refresh already
    # clears the token store -- nothing left to assert about the token file
    # beyond it being gone, which the local-deletion assertions below don't
    # depend on.

    conn = store_module.open_store(config.cache_path)
    for table in sorted(store_module._ERASURE_TABLES):
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (42,),
        ).fetchall()
        assert rows == [], f"erase-member left rows behind in {table} after invalid_grant"
    assert (
        store_module.get_member_for_principal(conn, client_id="local", issuer=None, subject=None)
        is None
    )
    conn.close()


def test_erase_member_subcommand_skips_revoke_for_an_unattributable_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mirrors test_main.py's delete-member equivalent: members A and B have
    both been linked, but there is only one stored token file, so it cannot
    be attributed to either. erase-member on A must not revoke that token --
    it may be B's live grant -- yet must still erase A's own rows and link."""
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config as ConfigCls

    config = ConfigCls.from_env()
    FileTokenStore(config.token_path).save(
        Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    )

    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="client-a", issuer=None, subject=None, whoop_user_id=MEMBER_A
    )
    store_module.link_principal_to_member(
        conn, client_id="client-b", issuer=None, subject=None, whoop_user_id=MEMBER_B
    )
    _seed_every_entity_table(conn, MEMBER_A, "member-a-tag")
    _seed_every_entity_table(conn, MEMBER_B, "member-b-tag")
    conn.close()

    with respx.mock:
        route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(204))
        exit_code = main(["erase-member", "--whoop-user-id", str(MEMBER_A)])

    assert exit_code == 0
    assert not route.called
    assert FileTokenStore(config.token_path).load() is not None

    conn = store_module.open_store(config.cache_path)
    for table in sorted(store_module._ERASURE_TABLES):
        a_rows = conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (MEMBER_A,),
        ).fetchall()
        assert a_rows == [], f"erase-member left MEMBER_A rows behind in {table}"
        b_rows = conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (MEMBER_B,),
        ).fetchall()
        assert b_rows != [], f"erase-member for A wrongly removed B's rows in {table}"
    assert (
        store_module.get_member_for_principal(conn, client_id="client-a", issuer=None, subject=None)
        is None
    )
    assert (
        store_module.get_member_for_principal(conn, client_id="client-b", issuer=None, subject=None)
        is not None
    )
    conn.close()


def test_erase_member_subcommand_still_aborts_on_a_genuine_transport_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression guard mirroring test_main.py's delete-member equivalent: a
    real failure talking to WHOOP's revoke endpoint (mocked as a 500, distinct
    from the invalid_grant/no-credentials "nothing to revoke" cases) must
    still abort with nothing erased -- the fix must not loosen this path."""
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config as ConfigCls

    config = ConfigCls.from_env()
    FileTokenStore(config.token_path).save(
        Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    )

    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="local", issuer=None, subject=None, whoop_user_id=42
    )
    _seed_every_entity_table(conn, 42, "erase-me-tag")
    conn.close()

    with respx.mock:
        route = respx.delete(USER_ACCESS_URL).mock(return_value=httpx.Response(500))
        exit_code = main(["erase-member", "--whoop-user-id", "42"])

    assert exit_code != 0
    assert route.called
    assert FileTokenStore(config.token_path).load() is not None

    conn = store_module.open_store(config.cache_path)
    for table in sorted(store_module._ERASURE_TABLES):
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (42,),
        ).fetchall()
        assert rows != [], f"a failed revoke must not erase {table}"
    assert (
        store_module.get_member_for_principal(conn, client_id="local", issuer=None, subject=None)
        is not None
    )
    conn.close()


# =============================================================================
# retention: a job that actually deletes rows past a configured age --
# a record just inside the window survives, one just past it does not.
# =============================================================================


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def test_enforce_retention_deletes_past_the_window_and_keeps_within_it(
    store_conn: sqlite3.Connection,
) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    max_age_days = 30

    _seed_recovery(store_conn, MEMBER_A, "just-inside", cycle_id=1)
    _seed_recovery(store_conn, MEMBER_A, "just-past", cycle_id=2)

    just_inside_at = _iso(now - timedelta(days=max_age_days) + timedelta(seconds=1))
    just_past_at = _iso(now - timedelta(days=max_age_days) - timedelta(seconds=1))
    store_conn.execute(
        "UPDATE recoveries SET updated_at = ? WHERE whoop_user_id = ? AND resource_id = ?",
        (just_inside_at, MEMBER_A, "1"),
    )
    store_conn.execute(
        "UPDATE recoveries SET updated_at = ? WHERE whoop_user_id = ? AND resource_id = ?",
        (just_past_at, MEMBER_A, "2"),
    )
    store_conn.commit()

    store.enforce_retention(store_conn, max_age_days=max_age_days, now=now)

    remaining = {
        row[0]
        for row in store_conn.execute(
            "SELECT resource_id FROM recoveries WHERE whoop_user_id = ?", (MEMBER_A,)
        ).fetchall()
    }
    assert remaining == {"1"}, (
        "the just-inside-window row must survive and the just-past one must not"
    )


def test_enforce_retention_honours_a_different_timestamp_column_per_table(
    store_conn: sqlite3.Connection,
) -> None:
    """webhook_events ages off ``created_at``, not ``updated_at`` -- proves
    ``_RETENTION_TIMESTAMP_COLUMNS`` is actually consulted per table, not a
    single hard-coded column name."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    max_age_days = 30

    _seed_webhook_event(store_conn, MEMBER_A, "trace-inside", "member-a-tag")
    _seed_webhook_event(store_conn, MEMBER_A, "trace-past", "member-a-tag")

    just_inside_at = _iso(now - timedelta(days=max_age_days) + timedelta(seconds=1))
    just_past_at = _iso(now - timedelta(days=max_age_days) - timedelta(seconds=1))
    store_conn.execute(
        "UPDATE webhook_events SET created_at = ? WHERE trace_id = ?",
        (just_inside_at, "trace-inside"),
    )
    store_conn.execute(
        "UPDATE webhook_events SET created_at = ? WHERE trace_id = ?",
        (just_past_at, "trace-past"),
    )
    store_conn.commit()

    store.enforce_retention(store_conn, max_age_days=max_age_days, now=now)

    remaining = {
        row[0]
        for row in store_conn.execute(
            "SELECT trace_id FROM webhook_events WHERE whoop_user_id = ?", (MEMBER_A,)
        ).fetchall()
    }
    assert remaining == {"trace-inside"}


def test_enforce_retention_only_touches_rows_past_the_window_for_their_own_member(
    store_conn: sqlite3.Connection,
) -> None:
    """A fresh row for one member must survive even while an old row for a
    *different* member, in the same table, is aged out -- proves the sweep
    doesn't over-delete across the whole table once it finds anything stale."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    max_age_days = 30

    _seed_recovery(store_conn, MEMBER_A, "fresh", cycle_id=1)
    _seed_recovery(store_conn, MEMBER_B, "old", cycle_id=1)

    fresh_at = _iso(now - timedelta(days=1))
    old_at = _iso(now - timedelta(days=max_age_days) - timedelta(seconds=1))
    store_conn.execute(
        "UPDATE recoveries SET updated_at = ? WHERE whoop_user_id = ?", (fresh_at, MEMBER_A)
    )
    store_conn.execute(
        "UPDATE recoveries SET updated_at = ? WHERE whoop_user_id = ?", (old_at, MEMBER_B)
    )
    store_conn.commit()

    store.enforce_retention(store_conn, max_age_days=max_age_days, now=now)

    a_remaining = store_conn.execute(
        "SELECT COUNT(*) FROM recoveries WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchone()[0]
    b_remaining = store_conn.execute(
        "SELECT COUNT(*) FROM recoveries WHERE whoop_user_id = ?", (MEMBER_B,)
    ).fetchone()[0]
    assert a_remaining == 1
    assert b_remaining == 0


def test_enforce_retention_covers_webhook_delivery_state(store_conn: sqlite3.Connection) -> None:
    """#19's ``webhook_delivery_state`` must have its own entry in
    ``_RETENTION_TIMESTAMP_COLUMNS`` (ages off its own ``last_delivered_at``)
    exactly like every other ``_ERASURE_TABLES`` entry -- a table added to
    that registry without a matching retention column raises ``KeyError``
    the first time ``enforce_retention`` actually runs, rather than at
    schema-load time, so nothing else catches this until this test does."""
    now = datetime(2026, 1, 1, tzinfo=UTC)
    max_age_days = 30

    _seed_webhook_delivery_state(store_conn, MEMBER_A)
    old_at = _iso(now - timedelta(days=max_age_days) - timedelta(seconds=1))
    store_conn.execute(
        "UPDATE webhook_delivery_state SET last_delivered_at = ? WHERE whoop_user_id = ?",
        (old_at, MEMBER_A),
    )
    store_conn.commit()

    store.enforce_retention(store_conn, max_age_days=max_age_days, now=now)

    remaining = store_conn.execute(
        "SELECT whoop_user_id FROM webhook_delivery_state WHERE whoop_user_id = ?",
        (MEMBER_A,),
    ).fetchall()
    assert remaining == [], "a past-window webhook_delivery_state row must be aged out too"


def test_enforce_retention_returns_per_table_counts(store_conn: sqlite3.Connection) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    max_age_days = 30
    _seed_recovery(store_conn, MEMBER_A, "old", cycle_id=1)
    old_at = _iso(now - timedelta(days=max_age_days) - timedelta(seconds=1))
    store_conn.execute(
        "UPDATE recoveries SET updated_at = ? WHERE whoop_user_id = ?", (old_at, MEMBER_A)
    )
    store_conn.commit()

    result = store.enforce_retention(store_conn, max_age_days=max_age_days, now=now)

    assert isinstance(result, dict)
    assert result.get("recoveries", 0) >= 1


# =============================================================================
# enforce-retention CLI wiring, mirroring delete-member's own subparser style
# =============================================================================


def test_enforce_retention_subcommand_runs_and_never_prints_a_token_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config as ConfigCls

    config = ConfigCls.from_env()
    sentinel_access = "SENTINEL-ACCESS-abc123"
    sentinel_refresh = "SENTINEL-REFRESH-xyz789"
    FileTokenStore(config.token_path).save(
        Token(sentinel_access, expires_at=time.time() + 3600, refresh_token=sentinel_refresh)
    )
    conn = store_module.open_store(config.cache_path)
    _seed_recovery(conn, 42, "old", cycle_id=1)
    conn.execute(
        "UPDATE recoveries SET updated_at = '2000-01-01T00:00:00+00:00' WHERE whoop_user_id = ?",
        (42,),
    )
    conn.commit()
    conn.close()

    exit_code = main(["enforce-retention", "--max-age-days", "30"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert sentinel_access not in captured.out
    assert sentinel_access not in captured.err
    assert sentinel_refresh not in captured.out
    assert sentinel_refresh not in captured.err

    conn = store_module.open_store(config.cache_path)
    remaining = conn.execute(
        "SELECT COUNT(*) FROM recoveries WHERE whoop_user_id = ?", (42,)
    ).fetchone()[0]
    conn.close()
    assert remaining == 0


# =============================================================================
# export-member CLI wiring
# =============================================================================


def test_export_member_subcommand_writes_json_scoped_to_the_target_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config as ConfigCls

    config = ConfigCls.from_env()
    FileTokenStore(config.token_path).save(
        Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    )
    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="local", issuer=None, subject=None, whoop_user_id=42
    )
    _seed_every_entity_table(conn, 42, "export-me-tag")
    _seed_every_entity_table(conn, 43, "other-member-tag")
    conn.close()

    out_path = tmp_path / "export.json"
    exit_code = main(["export-member", "--whoop-user-id", "42", "--out", str(out_path)])

    assert exit_code == 0
    import json as _json

    document = _json.loads(out_path.read_text(encoding="utf-8"))
    dump = _walk_strings(document)
    assert "export-me-tag" in dump
    assert "other-member-tag" not in dump
    assert "access-tok" not in dump
    assert "refresh-tok" not in dump


def test_export_member_subcommand_refuses_an_unlinked_whoop_user_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    exit_code = main(["export-member", "--whoop-user-id", "999999"])

    assert exit_code == 2


def test_export_member_subcommand_never_attributes_the_token_to_the_wrong_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """There is exactly one token file, but ``principal_members`` can still
    hold links to more than one distinct WHOOP member (e.g. an operator
    re-authorised against a different WHOOP account without ever running
    erase-member for the old one). Nothing local records which member the
    single stored token actually belongs to in that case -- the export must
    say so honestly instead of silently attaching another member's scopes."""
    _set_required_env_and_state_dir(monkeypatch, tmp_path)

    from whoopmcp import store as store_module
    from whoopmcp.config import Config as ConfigCls

    config = ConfigCls.from_env()
    FileTokenStore(config.token_path).save(
        Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    )
    conn = store_module.open_store(config.cache_path)
    store_module.link_principal_to_member(
        conn, client_id="local-old", issuer=None, subject=None, whoop_user_id=MEMBER_A
    )
    store_module.link_principal_to_member(
        conn, client_id="local-new", issuer=None, subject=None, whoop_user_id=MEMBER_B
    )
    conn.close()

    out_path = tmp_path / "export.json"
    exit_code = main(["export-member", "--whoop-user-id", str(MEMBER_A), "--out", str(out_path)])

    assert exit_code == 0
    import json as _json

    document = _json.loads(out_path.read_text(encoding="utf-8"))
    assert document["consent"]["scopes"] is None
    assert document["consent"]["token_present"] is None
    assert "access-tok" not in _walk_strings(document)
    assert "refresh-tok" not in _walk_strings(document)


# =============================================================================
# #68: export-member --out file permissions
#
# The export document is every scrap of health data this store holds for one
# member, in plain JSON. It gets the same treatment as the token file: 0600,
# with no window at the umask default. Mode assertions are skipped on Windows
# and assert "no group or other access" rather than an exact 0o600, following
# tests/test_auth.py:136-143.
# =============================================================================

_GROUP_OR_OTHER = stat.S_IRWXG | stat.S_IRWXO


def _link_and_seed_one_member(tmp_path: Path) -> None:
    """Minimal state for a successful ``export-member`` run: a stored token, a
    principal linked to member 42, and one row per entity table. Mirrors
    ``test_export_member_subcommand_writes_json_scoped_to_the_target_member``
    above; assumes ``_set_required_env_and_state_dir`` has already run."""
    config = Config.from_env()
    FileTokenStore(config.token_path).save(
        Token("access-tok", expires_at=time.time() + 3600, refresh_token="refresh-tok")
    )
    conn = store.open_store(config.cache_path)
    store.link_principal_to_member(
        conn, client_id="local", issuer=None, subject=None, whoop_user_id=42
    )
    _seed_every_entity_table(conn, 42, "export-me-tag")
    conn.close()


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_export_member_out_file_is_not_readable_by_other_users(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    _link_and_seed_one_member(tmp_path)
    out_path = tmp_path / "export.json"

    exit_code = main(["export-member", "--whoop-user-id", "42", "--out", str(out_path)])

    assert exit_code == 0
    mode = stat.S_IMODE(out_path.stat().st_mode)

    assert mode & _GROUP_OR_OTHER == 0, f"export file is mode {mode:o}"


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_export_member_tightens_a_pre_existing_world_readable_out_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-running an export over yesterday's world-readable file must not
    inherit its mode -- whether the implementation chmods it or replaces it
    with a fresh 0600 file, the end state is the same promise."""
    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    _link_and_seed_one_member(tmp_path)
    out_path = tmp_path / "export.json"
    out_path.write_text("stale", encoding="utf-8")
    out_path.chmod(0o644)

    exit_code = main(["export-member", "--whoop-user-id", "42", "--out", str(out_path)])

    assert exit_code == 0
    assert "export-me-tag" in out_path.read_text(encoding="utf-8"), (
        "the stale file must be replaced"
    )
    mode = stat.S_IMODE(out_path.stat().st_mode)

    assert mode & _GROUP_OR_OTHER == 0, f"export file is mode {mode:o}"


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_export_member_does_not_inherit_the_mode_of_a_stale_temp_neighbour(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Historically, ``Path.with_suffix(".tmp")`` *replaced* the suffix, so the
    temp file for ``export.json`` was the predictable ``export.tmp`` --
    reused as-is if a stale, world-readable one from an earlier interrupted
    run was left behind, carrying its old mode straight through to the
    destination. Since #98, the temp file is an unpredictable
    ``tempfile.mkstemp`` name instead, so a stale ``export.tmp`` neighbour is
    simply never reused: it is left exactly as it was, and the destination
    still ends up 0600 regardless of what that neighbour's mode was."""
    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    _link_and_seed_one_member(tmp_path)
    out_path = tmp_path / "export.json"
    stale_tmp = tmp_path / "export.tmp"
    stale_tmp.write_text("interrupted", encoding="utf-8")
    stale_tmp.chmod(0o644)

    exit_code = main(["export-member", "--whoop-user-id", "42", "--out", str(out_path)])

    assert exit_code == 0
    assert stale_tmp.read_text(encoding="utf-8") == "interrupted", (
        "the stale export.tmp neighbour was overwritten -- it should never be reused"
    )
    assert stat.S_IMODE(stale_tmp.stat().st_mode) == 0o644, (
        "the stale export.tmp neighbour's mode was changed -- it should never be touched"
    )
    mode = stat.S_IMODE(out_path.stat().st_mode)

    assert mode & _GROUP_OR_OTHER == 0, f"export file is mode {mode:o}"


@pytest.mark.skipif(os.name == "nt", reason="Windows uses ACLs, not POSIX modes")
def test_export_member_never_opens_a_world_readable_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Prove the *absence of a window* structurally, not by polling.

    A write-then-chmod implementation passes an end-state assertion while
    still having published the whole health record at 0644 for as long as the
    write took. The property that rules that out is checkable at the moment
    content first reaches the filesystem: the file being written into must
    already exist, and must already carry no group or other bits. Since #98,
    ``auth``'s atomic helper writes through the file object ``os.fdopen``
    hands back for the ``tempfile.mkstemp`` fd, never via ``Path.write_text``
    -- and ``io.TextIOWrapper`` is an immutable extension type pytest's
    monkeypatch can't patch directly, so this wraps ``os.fdopen`` itself in a
    spy that checks exactly that (via ``fstat`` on the fd) for whichever
    write carries the export payload, then delegates to the real write. A
    stronger guarantee than before, since ``mkstemp`` itself creates the file
    at 0600 with ``O_EXCL``, before any content lands.
    """
    _set_required_env_and_state_dir(monkeypatch, tmp_path)
    _link_and_seed_one_member(tmp_path)
    out_path = tmp_path / "export.json"

    writes: list[tuple[int, bool, int | None, str]] = []
    real_fdopen = os.fdopen

    class _SpyOnWrite:
        def __init__(self, real: io.TextIOWrapper) -> None:
            self._real = real

        def __enter__(self) -> _SpyOnWrite:
            return self

        def __exit__(self, *exc_info: object) -> None:
            self._real.close()

        def write(self, data: str) -> int:
            try:
                mode: int | None = stat.S_IMODE(os.fstat(self._real.fileno()).st_mode)
                existed = True
            except OSError:
                mode = None
                existed = False
            writes.append((self._real.fileno(), existed, mode, data))
            return self._real.write(data)

    def fake_fdopen(fd: int, *args: object, **kwargs: object) -> _SpyOnWrite:
        return _SpyOnWrite(real_fdopen(fd, *args, **kwargs))

    monkeypatch.setattr(os, "fdopen", fake_fdopen)

    exit_code = main(["export-member", "--whoop-user-id", "42", "--out", str(out_path)])

    assert exit_code == 0

    payload_writes = [w for w in writes if "export-me-tag" in w[3]]
    assert payload_writes, (
        f"no write carried the export payload; writes seen: {[w[0] for w in writes]}"
    )

    for fd, existed, mode, _data in payload_writes:
        assert existed, (
            f"fd {fd} did not already exist (via fstat) when the payload was written to it"
        )
        assert mode is not None
        assert mode & _GROUP_OR_OTHER == 0, (
            f"fd {fd} was mode {mode:o} at the instant the health record was "
            "written into it -- a world-readable window existed"
        )


# =============================================================================
# soft-delete (#18) and erasure (#32) are distinct code paths -- confirmed
# both statically (erasure never touches deleted_at; the *.deleted webhook
# path never calls into erasure) and never merged into one "delete" function.
# =============================================================================


def test_erase_member_data_never_references_deleted_at() -> None:
    """Reusing #18's soft-delete machinery is the obvious shortcut for
    erasure, and it is wrong: it would leave the row (and its raw_json) in
    the table. This asserts the real DELETE path never touches that column
    at all, not merely that it deletes rows despite also setting it."""
    source = inspect.getsource(store.erase_member_data)
    assert "deleted_at" not in source


def test_webhook_processor_never_calls_into_erasure_or_retention() -> None:
    """The *.deleted webhook path (`set_deleted_at`) and real member erasure
    must never call into each other -- an AST-free, source-level check (the
    module is small and stable enough that a substring check on function
    names is sufficient and avoids over-engineering an AST walk that store.py
    already needs for a much sharper property elsewhere)."""
    source = inspect.getsource(webhook_processor)
    assert "erase_member_data" not in source
    assert "enforce_retention" not in source


def test_set_deleted_at_and_erase_member_data_are_different_functions() -> None:
    """The plainest possible version of "these are two paths, not one":
    erasure's own function is not webhook_processor's soft-delete helper
    (renamed from the private `_set_deleted_at` by #19, so
    `reconciliation.py` can reuse the exact same mechanism instead of
    inventing a second one -- same body, still not erasure), and neither
    calls the other by name in its source."""
    assert store.erase_member_data is not webhook_processor.set_deleted_at
    erase_source = inspect.getsource(store.erase_member_data)
    assert "set_deleted_at" not in erase_source


# =============================================================================
# Issue #104: atomic erasure across the CLI composition of erase_member_data
# and delete_principal_links_for_member. Tests 1 and 7 will fail on current
# main; the rest should pass without code changes.
# =============================================================================


def test_erase_member_and_links_atomic_rolls_back_on_link_deletion_failure(
    store_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #104 headline: when deleting the principal link fails AFTER the
    health data has been deleted within the same transaction, a composed
    atomic erasure rolls back BOTH deletions, leaving the member fully intact.

    On current main, erase_member_data commits immediately after its deletes,
    so this test will FAIL: health data is already gone, not rolled back. After
    the fix, both operations batch in one transaction, and either both succeed
    or both roll back together."""
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")
    _seed_principal_link(store_conn, MEMBER_A, "client-a")

    original_execute_scoped = store._execute_scoped

    def failing_execute_scoped(
        conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()
    ) -> sqlite3.Cursor:
        """Fail when trying to delete from principal_members, after health
        data has already been deleted within the same transaction."""
        if "DELETE FROM principal_members" in sql:
            # Rollback before raising, like _execute_scoped does
            conn.rollback()
            raise RuntimeError("Simulated principal link deletion failure")
        return original_execute_scoped(conn, sql, params)

    monkeypatch.setattr(store, "_execute_scoped", failing_execute_scoped)

    # Try the composed erasure; the link delete will fail
    with pytest.raises(RuntimeError, match="Simulated principal link deletion failure"):
        store.erase_member_and_links_atomically(store_conn, MEMBER_A)

    # After a rolled-back transaction, both health data and link remain
    # (the whole transaction rolled back)
    for table in sorted(store._ERASURE_TABLES):
        rows = store_conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (MEMBER_A,),
        ).fetchall()
        assert rows != [], f"{table} should still have rows (transaction rolled back)"

    link_rows = store_conn.execute(
        "SELECT * FROM principal_members WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchall()
    assert link_rows != [], "Principal link should still be present (transaction rolled back)"


def test_erase_member_and_links_atomic_happy_path(
    store_conn: sqlite3.Connection,
) -> None:
    """Composed atomic erasure: both health data and principal link are
    deleted in one transaction, and conn.in_transaction is False afterward (D5)."""
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")
    _seed_principal_link(store_conn, MEMBER_A, "client-a")

    store.erase_member_and_links_atomically(store_conn, MEMBER_A)

    # All health data is gone
    for table in sorted(store._ERASURE_TABLES):
        rows = store_conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (MEMBER_A,),
        ).fetchall()
        assert rows == [], f"erase_member_and_links_atomically left rows in {table}"

    # Principal link is gone
    link_rows = store_conn.execute(
        "SELECT * FROM principal_members WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchall()
    assert link_rows == [], "erase_member_and_links_atomically left principal link"

    # Transaction is closed (D5)
    assert not store_conn.in_transaction


def test_erase_member_and_links_atomic_mid_health_data_failure(
    store_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure inside the health-data deletion phase (before the link is
    even touched) leaves nothing persisted -- the whole transaction rolls back."""
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")
    _seed_principal_link(store_conn, MEMBER_A, "client-a")

    original_execute_scoped = store._execute_scoped

    def failing_on_first_health_delete(
        conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()
    ) -> sqlite3.Cursor:
        """Fail on the first DELETE (which will be a health-data table per
        sorted(_ERASURE_TABLES))."""
        if "DELETE FROM" in sql and "WHERE whoop_user_id = ?" in sql:
            # This will be a health-data delete since they come first
            # in the execution order. Rollback before raising, like _execute_scoped does.
            conn.rollback()
            raise RuntimeError("Health data deletion failed mid-batch")
        return original_execute_scoped(conn, sql, params)

    monkeypatch.setattr(store, "_execute_scoped", failing_on_first_health_delete)

    with pytest.raises(RuntimeError, match="Health data deletion failed mid-batch"):
        store.erase_member_and_links_atomically(store_conn, MEMBER_A)

    # Nothing was persisted; everything is still there
    for table in sorted(store._ERASURE_TABLES):
        rows = store_conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (MEMBER_A,),
        ).fetchall()
        assert rows != [], f"{table} should still have rows (failed transaction rolled back)"

    link_rows = store_conn.execute(
        "SELECT * FROM principal_members WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchall()
    assert link_rows != [], "Principal link should still be present"


def test_erase_member_and_links_atomic_no_99_regression(
    store_conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Issue #99 regression check: an UnscopedQueryError raised mid-erasure
    still rolls back and still propagates, since the composed function batches
    both deletions in one transaction."""
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")
    _seed_principal_link(store_conn, MEMBER_A, "client-a")

    original_execute_scoped = store._execute_scoped

    def raise_unscoped_error(
        conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()
    ) -> sqlite3.Cursor:
        """Raise an UnscopedQueryError on the first DELETE to simulate a
        tenancy violation."""
        if "DELETE FROM" in sql:
            # Rollback before raising, like _execute_scoped does
            conn.rollback()
            raise store.UnscopedQueryError(f"Simulated tenancy violation: {sql}")
        return original_execute_scoped(conn, sql, params)

    monkeypatch.setattr(store, "_execute_scoped", raise_unscoped_error)

    with pytest.raises(store.UnscopedQueryError, match="Simulated tenancy violation"):
        store.erase_member_and_links_atomically(store_conn, MEMBER_A)

    # The transaction was rolled back, so nothing is persisted
    for table in sorted(store._ERASURE_TABLES):
        rows = store_conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (MEMBER_A,),
        ).fetchall()
        assert rows != [], f"{table} should still have rows (rolled back)"

    link_rows = store_conn.execute(
        "SELECT * FROM principal_members WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchall()
    assert link_rows != [], "Principal link should be present (rolled back)"


def test_erase_member_and_links_atomic_rolls_back_on_real_sqlite_failure(
    store_conn: sqlite3.Connection,
) -> None:
    """Pins the real rollback behaviour (not a mock's own courtesy rollback):
    a genuine sqlite error raised mid-batch, via a BEFORE DELETE trigger on
    `workouts` that RAISE(ABORT)s, must leave nothing persisted. Unlike the
    monkeypatch-based tests above, nothing here calls conn.rollback() itself --
    if `erase_member_and_links_atomically` ever loses its own rollback, this
    test fails."""
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")
    _seed_principal_link(store_conn, MEMBER_A, "client-a")

    store_conn.execute(
        """
        CREATE TEMP TRIGGER _t104_abort_workouts_delete
        BEFORE DELETE ON workouts
        BEGIN
            SELECT RAISE(ABORT, 'Simulated real sqlite failure');
        END
        """
    )

    with pytest.raises(sqlite3.IntegrityError, match="Simulated real sqlite failure"):
        store.erase_member_and_links_atomically(store_conn, MEMBER_A)

    assert not store_conn.in_transaction

    for table in sorted(store._ERASURE_TABLES):
        rows = store_conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (MEMBER_A,),
        ).fetchall()
        assert rows != [], f"{table} should still have rows (transaction rolled back)"

    link_rows = store_conn.execute(
        "SELECT * FROM principal_members WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchall()
    assert link_rows != [], "Principal link should still be present (transaction rolled back)"


def test_direct_callers_of_erase_member_data_still_commit_on_success(
    store_conn: sqlite3.Connection,
) -> None:
    """The public erase_member_data function, when called directly by a
    caller, commits immediately after its own _execute_scoped calls (unchanged
    behavior from before #104). Existing tests of erase_member_data must pass
    unmodified."""
    _seed_every_entity_table(store_conn, MEMBER_A, "member-a-tag")

    store.erase_member_data(store_conn, MEMBER_A)

    # Data is erased (committed)
    for table in sorted(store._ERASURE_TABLES):
        rows = store_conn.execute(
            f"SELECT * FROM {table} WHERE whoop_user_id = ?",  # noqa: S608
            (MEMBER_A,),
        ).fetchall()
        assert rows == [], f"erase_member_data should have deleted rows in {table}"


def test_direct_callers_of_delete_principal_links_still_commit_on_success(
    store_conn: sqlite3.Connection,
) -> None:
    """The public delete_principal_links_for_member function, when called
    directly by a caller, commits immediately after its own _execute_scoped
    call (unchanged behavior from before #104). Existing tests must pass
    unmodified."""
    _seed_principal_link(store_conn, MEMBER_A, "client-a")

    store.delete_principal_links_for_member(store_conn, MEMBER_A)

    # Link is deleted (committed)
    link_rows = store_conn.execute(
        "SELECT * FROM principal_members WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchall()
    assert link_rows == [], "delete_principal_links_for_member should have deleted the link"


def test_enforce_retention_untouched(
    store_conn: sqlite3.Connection,
) -> None:
    """Issue #104 is scoped to erasure atomicity; retention is untouched (D3).
    This test verifies enforce_retention still works exactly as before."""
    now = datetime(2026, 1, 15, tzinfo=UTC)

    _seed_recovery(store_conn, MEMBER_A, "old-tag", cycle_id=1)
    store_conn.execute(
        "UPDATE recoveries SET updated_at = ? WHERE whoop_user_id = ?",
        ("2026-01-01T00:00:00Z", MEMBER_A),  # 14 days old
    )
    store_conn.commit()

    # Enforce a 7-day retention window
    counts = store.enforce_retention(store_conn, max_age_days=7, now=now)

    # The old recovery is deleted
    assert counts["recoveries"] == 1
    rows = store_conn.execute(
        "SELECT * FROM recoveries WHERE whoop_user_id = ?", (MEMBER_A,)
    ).fetchall()
    assert rows == []


def test_execute_scoped_docstring_false_claim_corrected() -> None:
    """Issue #104 D4: the false claim in _execute_scoped's docstring
    ('Every store.py write function commits immediately after its own
    _execute_scoped call and never batches multiple writes in one
    transaction') is corrected. Assert it is no longer in the docstring."""
    docstring = store._execute_scoped.__doc__ or ""
    # The specific false sentence we're correcting
    false_claim = "never batches multiple writes in one transaction"
    assert false_claim not in docstring, (
        f"_execute_scoped's docstring still contains the false claim: {false_claim!r}"
    )
