"""Entry point. MCP clients launch this over stdio; ``--http`` is for testing."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from whoopmcp import __version__
from whoopmcp.config import Config, ConfigError

if TYPE_CHECKING:
    import sqlite3

    from whoopmcp.auth import Authenticator
    from whoopmcp.reconciliation import ReconciliationResult


def _route_uvicorn_access_log_to_stderr() -> None:
    """Send uvicorn's access log to stderr before the HTTP transport starts.

    PRIVACY.md states that this software's logs go to stderr and are never
    written to a file by it. That was false in hosted mode (#126). The SDK's
    ``run_streamable_http_async`` builds ``uvicorn.Config`` with only host, port
    and log level -- no ``log_config`` -- and uvicorn's default config points the
    ``uvicorn.access`` handler at ``ext://sys.stdout``. So every request line,
    client IP included, landed on stdout: for ``/webhooks/whoop`` and ``/metrics``
    that is the IP of someone whose health data this server holds. The trap is an
    operator redirecting stdout to a world-readable file *because the docs say
    nothing is logged there*.

    There is no parameter to pass. ``MCPServer.run`` forwards ``**kwargs`` to
    ``run_streamable_http_async``, whose signature is keyword-only and fixed, so
    a ``log_config`` cannot be threaded through. What is reachable is uvicorn's
    module-level ``LOGGING_CONFIG``: ``uvicorn.Config.__init__`` captures that
    dict *by reference* as its default argument, so mutating it in place here --
    before the server is constructed -- is seen by the ``dictConfig`` call uvicorn
    makes from inside that same ``__init__``. Verified against the installed
    uvicorn by identity check.

    **This depends on the SDK not supplying its own ``log_config``.** If it ever
    does, ``LOGGING_CONFIG`` stops being consulted and this redirect silently
    does nothing. ``test_sdk_still_leaves_uvicorns_log_config_to_its_default``
    pins exactly that, by reading the SDK's own source: it is the SDK's behaviour
    that has to be watched, and a test that builds its *own* ``uvicorn.Config``
    cannot see a change there -- which is what an earlier version of this
    docstring wrongly claimed was covered.

    The import is function-local for locality only, not to defer anything:
    ``mcp`` declares ``uvicorn>=0.31.1`` as a hard dependency, and importing
    ``whoopmcp.server`` -- which ``main`` does unconditionally, before the
    transport branch -- already pulls uvicorn into ``sys.modules`` on both
    transports via ``sse_starlette``. Measured; an earlier version of this
    docstring claimed the local import avoided an HTTP-only import, and that
    benefit does not exist here.
    """
    from uvicorn.config import LOGGING_CONFIG

    LOGGING_CONFIG["handlers"]["access"]["stream"] = "ext://sys.stderr"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="whoopmcp",
        description="Read-only MCP server for the WHOOP API v2.",
    )
    parser.add_argument("--version", action="version", version=f"whoopmcp {__version__}")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default=None,
        help=(
            "stdio is what MCP clients launch; streamable-http serves the MCP endpoint "
            "over HTTP (#27). Defaults to WHOOPMCP_TRANSPORT (itself 'stdio' if unset) "
            "when omitted, so CLI silence never overrides an operator's env var."
        ),
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Bind host for --transport streamable-http. Defaults to WHOOPMCP_HTTP_HOST.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port for --transport streamable-http. Defaults to WHOOPMCP_HTTP_PORT.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    )

    # Not `required=True`: the default (no subcommand) is "run the server",
    # the behaviour every test above this comment already exercises.
    subparsers = parser.add_subparsers(dest="command")
    delete_member_parser = subparsers.add_parser(
        "delete-member",
        help=(
            "Revoke a member's WHOOP grant upstream (DELETE /v2/user/access) and forget "
            "the local token and principal link (#30). Deliberately CLI-only: the "
            "underlying primitive, Authenticator.revoke_and_forget, is never registered "
            "as an MCP tool -- see its own docstring for why."
        ),
    )
    delete_member_parser.add_argument(
        "--whoop-user-id",
        type=int,
        required=True,
        help=(
            "Must match the WHOOP member id already linked in principal_members -- a "
            "confirmation guard against operator error, not a selector among several "
            "grants: there is exactly one live grant per process today."
        ),
    )

    export_member_parser = subparsers.add_parser(
        "export-member",
        help=(
            "Data-subject export (#32): every entity this store holds for one member, "
            "as one JSON document. Deliberately CLI-only, never an MCP tool -- see "
            "store.export_member_data's own docstring for why."
        ),
    )
    export_member_parser.add_argument(
        "--whoop-user-id",
        type=int,
        required=True,
        help="Must match a WHOOP member id already linked in principal_members.",
    )
    export_member_parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help=(
            "Write the export document to this path. Defaults to stdout. The file "
            "contains the member's full health record and is written mode 0600 "
            "(POSIX only; see PRIVACY.md for the Windows caveat)."
        ),
    )

    erase_member_parser = subparsers.add_parser(
        "erase-member",
        help=(
            "Data-subject erasure (#32): revokes the member's WHOOP grant upstream "
            "(via Authenticator.revoke_and_forget, #30's own primitive, reused here "
            "rather than rebuilt) and permanently deletes their token, health data, "
            "webhook events, audit rows, and principal link. A real DELETE, verified "
            "at the database level -- kept as a sibling of delete-member rather than "
            "extending it in place, since delete_principal_links_for_member's own "
            "docstring promises health data, webhook events, and audit rows are "
            "untouched by that narrower, already-shipped subcommand."
        ),
    )
    erase_member_parser.add_argument(
        "--whoop-user-id",
        type=int,
        required=True,
        help=(
            "Must match the WHOOP member id already linked in principal_members -- a "
            "confirmation guard against operator error, not a selector among several "
            "grants: there is exactly one live grant per process today."
        ),
    )

    enforce_retention_parser = subparsers.add_parser(
        "enforce-retention",
        help=(
            "Retention job (#32): deletes rows in every erasure-covered table whose "
            "own age column is past --max-age-days. There is no scheduler in this "
            "process -- an operator wires this subcommand into their own cron or "
            "systemd timer; this command IS the job that runs there."
        ),
    )
    enforce_retention_parser.add_argument(
        "--max-age-days",
        type=int,
        default=730,
        help="Delete rows older than this many days. Defaults to 730 (2 years).",
    )

    subparsers.add_parser(
        "doctor",
        help=(
            "Health check (#35): configuration, credentials, store reachability, and "
            "sync state, one sentence each. Exits non-zero if anything is wrong, zero "
            "if everything checked out clean. Takes no arguments."
        ),
    )

    backfill_parser = subparsers.add_parser(
        "backfill",
        help=(
            "Resumable, throttled history import (#14): walks every collection "
            "newest-first at BACKFILL priority into the persistent store, "
            "checkpointing into sync_state after every committed page so an "
            "interrupted run resumes exactly where it stopped. Honours "
            "WHOOPMCP_BACKFILL_FLOOR_DATE and requires WHOOPMCP_CACHE=true. "
            "Deliberately CLI-only, never an MCP tool -- a tool call that blocks "
            "for a minute is a broken tool call, per #30/#32's operator-only "
            "precedent."
        ),
    )
    backfill_parser.add_argument(
        "--whoop-user-id",
        type=int,
        required=True,
        help=(
            "Must match the WHOOP member id already linked in principal_members -- a "
            "confirmation guard against operator error, not a selector among several "
            "grants: there is exactly one live grant per process today."
        ),
    )

    replay_webhook_parser = subparsers.add_parser(
        "replay-webhook",
        help=(
            "Re-run a stored webhook event (#19) through the processing pipeline, "
            "from its own recorded event_body -- never re-POSTs or re-signs anything, "
            "so development does not require a deploy per change. Idempotent on an "
            "already-'success'/'dead_letter' row (a safe no-op, reported as such rather "
            "than as a replay); genuinely reprocesses a 'pending' one. Requires "
            "WHOOPMCP_CACHE=true. Deliberately CLI-only, never an MCP tool."
        ),
    )
    replay_webhook_parser.add_argument(
        "--trace-id",
        required=True,
        help="The webhook_events.trace_id to replay.",
    )

    reconcile_webhooks_parser = subparsers.add_parser(
        "reconcile-webhooks",
        help=(
            "Periodic full reconciliation (#19): the webhook backstop. Diffs a fresh "
            "WHOOP listing of the last --window-days against what the store holds and "
            "soft-deletes any locally-live record the listing no longer mentions -- the "
            "one thing #15's own incremental sync can never catch, a dropped deletion. "
            "There is no scheduler in this process -- an operator wires this subcommand "
            "into their own cron or systemd timer, alongside (never instead of) #15's "
            "own sync; webhooks and reconciliation are both an optimisation over "
            "polling, never a replacement for it."
        ),
    )
    reconcile_webhooks_parser.add_argument(
        "--whoop-user-id",
        type=int,
        required=True,
        help=(
            "Must match the WHOOP member id already linked in principal_members -- a "
            "confirmation guard against operator error, not a selector among several "
            "grants: there is exactly one live grant per process today."
        ),
    )
    reconcile_webhooks_parser.add_argument(
        "--window-days",
        type=int,
        default=30,
        help=(
            "Recent window to reconcile, in days. Defaults to 30 -- see "
            "reconciliation.py's own module docstring for why."
        ),
    )

    subparsers.add_parser(
        "login",
        help=(
            "Terminal-native OAuth login (#76): prints the authorize URL, prompts for "
            "the pasted redirect (or the code/state query parameters), and exchanges "
            "them via the same Authenticator the in-chat whoop_login/whoop_complete_login "
            "pair uses -- that pair stays exactly as it is; this is an additional path, "
            "not a replacement. Deliberately CLI-only: it exists so the authorization "
            "code never has to travel through the MCP client or its model provider on "
            "the way to the exchange. Takes no arguments."
        ),
    )

    args = parser.parse_args(argv)

    # stderr, never stdout: on stdio transport stdout carries the JSON-RPC
    # framing and a stray log line corrupts the protocol.
    logging.basicConfig(
        level=args.log_level,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    # doctor is dispatched ahead of the up-front Config.from_env() below,
    # deliberately: "missing configuration" is itself one of doctor's own
    # checks, so it must reach doctor's own reporting rather than being
    # preempted by the generic exit-2 path every other subcommand relies on.
    if args.command == "doctor":
        return _doctor()

    # Validate up front rather than leaving it to the lifespan. Once the
    # server is running the lifespan executes inside an anyio task group,
    # which wraps whatever it raises in an ExceptionGroup -- so a bare
    # `except ConfigError` there would miss it and the user would get a
    # traceback instead of the one line telling them which variable is unset.
    try:
        config = Config.from_env()
    except ConfigError as exc:
        print(f"whoopmcp: {exc}", file=sys.stderr)
        return 2

    if args.command == "delete-member":
        return _delete_member(config, args.whoop_user_id)
    if args.command == "export-member":
        return _export_member(config, args.whoop_user_id, args.out)
    if args.command == "erase-member":
        return _erase_member(config, args.whoop_user_id)
    if args.command == "enforce-retention":
        return _enforce_retention(config, args.max_age_days)
    if args.command == "backfill":
        return _backfill(config, args.whoop_user_id)
    if args.command == "replay-webhook":
        return _replay_webhook(config, args.trace_id)
    if args.command == "reconcile-webhooks":
        return _reconcile_webhooks(config, args.whoop_user_id, args.window_days)
    if args.command == "login":
        return _login(config)

    from whoopmcp.server import build_server

    transport = args.transport if args.transport is not None else config.transport
    host = args.host if args.host is not None else config.http_host
    port = args.port if args.port is not None else config.http_port

    try:
        if transport == "streamable-http":
            _route_uvicorn_access_log_to_stderr()
            build_server().run(transport="streamable-http", host=host, port=port)
        else:
            build_server().run(transport="stdio")
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    return 0


def _revoke_before_local_deletion(
    auth: Authenticator, conn: sqlite3.Connection, whoop_user_id: int
) -> int | None:
    """Shared revoke-step for ``_delete_member``/``_erase_member`` (issue #65).

    Returns ``None`` when the caller should proceed to local deletion, or a
    nonzero exit code when it must abort instead. Two independent things can
    make this a no-op-but-still-proceed rather than an abort:

    1. Attribution: reuses ``_export_member``'s own
       ``all_linked_whoop_user_ids(conn) == {whoop_user_id}`` predicate
       verbatim (see that function for why guessing is unsafe). When it does
       not hold, the single stored token cannot be attributed to
       ``whoop_user_id`` -- skip the upstream revoke entirely rather than
       revoking a different member's live grant, and point the operator at
       WHOOP's own app settings instead.
    2. "Nothing to revoke": ``revoke_and_forget`` raising
       ``GrantAlreadyGoneError`` (no stored credentials, or WHOOP's
       ``invalid_grant``) means the grant is already gone, not that
       revocation failed -- treat it as revoke-step success and continue.

    A plain ``AuthError`` (e.g. ``revoke_upstream``'s own non-2xx-response
    path -- a genuine transport/network failure) is caught here and turned
    into a nonzero exit code, which the caller returns BEFORE any local
    deletion runs -- the same abort-with-data-intact outcome as before this
    helper existed, just via a return code rather than an uncaught
    exception. The ``except GrantAlreadyGoneError`` clause must stay ordered
    before this one: the subclass is the only ignorable case.
    """
    from whoopmcp.auth import AuthError, GrantAlreadyGoneError
    from whoopmcp.store import all_linked_whoop_user_ids

    linked_ids = all_linked_whoop_user_ids(conn)
    if linked_ids != {whoop_user_id}:
        print(
            f"whoopmcp: the single stored token cannot be attributed to whoop-user-id "
            f"{whoop_user_id} (linked ids: {sorted(linked_ids)}); skipping the upstream "
            "revoke -- if a grant for this member still exists, revoke it from WHOOP's "
            "own app settings",
            file=sys.stderr,
        )
        return None

    try:
        asyncio.run(auth.revoke_and_forget())
    except GrantAlreadyGoneError as exc:
        print(
            f"whoopmcp: nothing to revoke upstream ({exc}); continuing with local deletion",
            file=sys.stderr,
        )
    except AuthError as exc:
        print(f"whoopmcp: {exc}", file=sys.stderr)
        return 1
    return None


def _refuse_if_store_is_ephemeral(config: Config, action: str) -> int | None:
    """Shared guard for the four data-rights/retention subcommands (#101).

    Returns exit code 2 when the store is guaranteed in-memory and no file
    has ever been created for it, or ``None`` when the caller should proceed
    to ``open_store``.

    Copies ``doctor.py``'s own ``_check_store`` condition verbatim --
    ``config.store_is_ephemeral and not config.cache_path.exists()`` -- and
    for the same two-part reason: a user who once ran with
    ``WHOOPMCP_CACHE=true`` has a real ``cache.sqlite3`` holding real health
    data, and refusing to touch it here would deny a data subject their
    erasure/export right, which is a worse bug than the one this guard
    exists to fix. The condition therefore only refuses when the file would
    have to be *created* to proceed; a leftover file is opened exactly as
    before. Unlike ``_backfill``/``_replay_webhook``/``_reconcile_webhooks``'s
    own ``not cache_enabled`` guards, the message here must never advise
    enabling the persistent store: telling someone who asked to delete,
    export, or erase their data (or enforce retention on it) to first turn
    on a cache is absurd advice for this class of subcommand.
    """
    if config.store_is_ephemeral and not config.cache_path.exists():
        print(
            f"whoopmcp: nothing is stored in default local mode; there is no data to {action}",
            file=sys.stderr,
        )
        return 2
    return None


def _delete_member(config: Config, whoop_user_id: int) -> int:
    """Handle ``whoopmcp delete-member --whoop-user-id N``.

    The only caller of ``Authenticator.revoke_and_forget`` anywhere in this
    codebase -- that primitive is not, and must never become, an MCP tool
    (see its own docstring for why); this CLI subcommand is the operator's
    one way to trigger it. Deletes the local token, calls WHOOP's
    ``DELETE /v2/user/access`` so the grant is revoked upstream rather than
    merely forgotten, and removes the local principal link. Health data,
    webhook events, and audit rows are untouched -- that is #32's job, not
    this one's.

    Local deletion is no longer conditioned on the upstream grant still
    being alive, nor does it revoke a token it cannot attribute to this
    member -- see ``_revoke_before_local_deletion`` (issue #65).

    Refuses -- before opening anything -- when the store is ephemeral and no
    file exists yet; see ``_refuse_if_store_is_ephemeral`` (#101).
    """
    from whoopmcp.auth import Authenticator
    from whoopmcp.store import (
        delete_principal_links_for_member,
        open_store,
        principal_is_linked_to_member,
    )

    abort_code = _refuse_if_store_is_ephemeral(config, "delete")
    if abort_code is not None:
        return abort_code

    conn = open_store(config.cache_path)
    try:
        if not principal_is_linked_to_member(conn, whoop_user_id):
            # Refuse rather than silently no-op-succeed: a mismatched id is
            # far more likely to be operator error than an intentional
            # deletion of a member with nothing linked to it.
            print(
                f"whoopmcp: no principal is linked to whoop-user-id {whoop_user_id}",
                file=sys.stderr,
            )
            return 2

        auth = Authenticator(config)
        abort_code = _revoke_before_local_deletion(auth, conn, whoop_user_id)
        if abort_code is not None:
            return abort_code

        delete_principal_links_for_member(conn, whoop_user_id)
    finally:
        conn.close()
    return 0


def _export_member(config: Config, whoop_user_id: int, out: Path | None) -> int:
    """Handle ``whoopmcp export-member --whoop-user-id N [--out PATH]`` (#32).

    Guards with the same ``principal_is_linked_to_member`` check
    ``_delete_member``/``_erase_member`` use, then builds the export document
    from ``store.export_member_data`` and adds one ``consent`` field: the
    scopes actually granted and whether a token is currently stored. The
    token store is read directly (``auth.build_store(config).load()``), never
    through ``Authenticator.access_token()`` -- mirroring ``whoop_auth_status``'s
    own "read the store, never trigger a refresh" precedent -- and only its
    ``scopes``/presence are used; the token value itself never enters the
    document.

    There is exactly one token file, but ``principal_members`` can still hold
    links to more than one distinct WHOOP member (see
    ``store.all_linked_whoop_user_ids``): if it ever does, nothing local
    records which member the stored token actually belongs to, so attaching
    its scopes to *this* member's export would risk silently misattributing
    another member's consent. In that case ``consent.scopes`` is reported as
    ``None`` with an explanatory note instead of guessing.

    Refuses -- before opening anything -- when the store is ephemeral and no
    file exists yet; see ``_refuse_if_store_is_ephemeral`` (#101).
    """
    from whoopmcp.auth import atomic_write_text, build_store
    from whoopmcp.store import (
        all_linked_whoop_user_ids,
        export_member_data,
        open_store,
        principal_is_linked_to_member,
    )

    abort_code = _refuse_if_store_is_ephemeral(config, "export")
    if abort_code is not None:
        return abort_code

    conn = open_store(config.cache_path)
    try:
        if not principal_is_linked_to_member(conn, whoop_user_id):
            print(
                f"whoopmcp: no principal is linked to whoop-user-id {whoop_user_id}",
                file=sys.stderr,
            )
            return 2
        document = export_member_data(conn, whoop_user_id)
        linked_ids = all_linked_whoop_user_ids(conn)
    finally:
        conn.close()

    if linked_ids == {whoop_user_id}:
        token = build_store(config).load()
        document["consent"] = {
            "scopes": list(token.scopes) if token is not None else [],
            "token_present": token is not None,
        }
    else:
        document["consent"] = {
            "scopes": None,
            "token_present": None,  # nosec B105 -- the literal None (unknown, not a credential value)
            "note": (
                "more than one WHOOP member has ever been linked in this store; "
                "which one the single locally-stored token belongs to cannot be "
                "determined, so scopes are not reported here"
            ),
        }

    payload = json.dumps(document, indent=2)
    if out is not None:
        # #68: the same 0600, no-world-readable-window write auth.py's token
        # stores use -- this document is the member's full health record.
        atomic_write_text(out, payload)
    else:
        print(payload)
    return 0


def _erase_member(config: Config, whoop_user_id: int) -> int:
    """Handle ``whoopmcp erase-member --whoop-user-id N`` (#32).

    The full data-subject erasure story: revokes the WHOOP grant upstream and
    forgets the local token (``Authenticator.revoke_and_forget``, #30's own
    primitive, reused verbatim rather than rebuilt), then permanently deletes
    every row ``store.erase_member_data`` covers (health data, webhook
    events, audit rows) plus the principal link
    (``delete_principal_links_for_member``, also reused from #30). Guards
    with the same mismatched-id refusal ``_delete_member`` uses, in the same
    order -- no local deletion on a refusal.

    Local deletion is no longer conditioned on the upstream grant still
    being alive, nor does it revoke a token it cannot attribute to this
    member -- see ``_revoke_before_local_deletion`` (issue #65).

    After the erasure commits, compacts the database file to overwrite freed
    pages (issue #100): deleted bytes are otherwise recoverable in the file
    in free space. A failed compaction does not abort or report as erasure
    failure (the deletes are already committed and irreversible); it prints
    a distinct stderr message (issue #100, decision D3) and returns exit
    code 3 -- distinct from the pre-deletion abort's 1, so callers can tell
    "nothing was deleted" from "deleted, compaction pending" without
    parsing stderr.

    Refuses -- before opening anything -- when the store is ephemeral and no
    file exists yet; see ``_refuse_if_store_is_ephemeral`` (#101).
    """
    import sqlite3

    from whoopmcp.auth import Authenticator
    from whoopmcp.store import (
        compact_database,
        erase_member_and_links_atomically,
        open_store,
        principal_is_linked_to_member,
    )

    abort_code = _refuse_if_store_is_ephemeral(config, "erase")
    if abort_code is not None:
        return abort_code

    conn = open_store(config.cache_path)
    try:
        if not principal_is_linked_to_member(conn, whoop_user_id):
            print(
                f"whoopmcp: no principal is linked to whoop-user-id {whoop_user_id}",
                file=sys.stderr,
            )
            return 2

        auth = Authenticator(config)
        abort_code = _revoke_before_local_deletion(auth, conn, whoop_user_id)
        if abort_code is not None:
            return abort_code

        erase_member_and_links_atomically(conn, whoop_user_id)
        try:
            compact_database(conn)
        except sqlite3.Error as exc:
            print(
                f"whoopmcp: member {whoop_user_id} is deleted but the database file "
                f"was not compacted ({exc})",
                file=sys.stderr,
            )
            return 3
    finally:
        conn.close()
    return 0


def _enforce_retention(config: Config, max_age_days: int) -> int:
    """Handle ``whoopmcp enforce-retention [--max-age-days N]`` (#32).

    There is no scheduler anywhere in this repository -- this subcommand IS
    the retention job; an operator wires it into their own cron or systemd
    timer. Prints a one-line per-table summary to stderr and never a token
    value, since nothing here ever reads one.

    Refuses -- before opening anything -- when the store is ephemeral and no
    file exists yet; see ``_refuse_if_store_is_ephemeral`` (#101). Printing
    the per-table summary in that case would be a false success: no
    retention work happened against a store that does not exist.
    """
    from whoopmcp.store import enforce_retention, open_store

    abort_code = _refuse_if_store_is_ephemeral(config, "expire")
    if abort_code is not None:
        return abort_code

    conn = open_store(config.cache_path)
    try:
        counts = enforce_retention(conn, max_age_days=max_age_days)
    finally:
        conn.close()

    summary = ", ".join(f"{table}={count}" for table, count in sorted(counts.items()))
    print(f"whoopmcp: retention enforced (max_age_days={max_age_days}): {summary}", file=sys.stderr)
    return 0


def _doctor() -> int:
    """Handle ``whoopmcp doctor`` (#35).

    Prints one line per check to stdout -- plain, human-readable text, not
    JSON: this is a terminal diagnostic an operator reads themselves, the
    same audience ``enforce-retention``'s own plain summary targets. Exits 0
    only if every check came back clean; 1 if any did not. Never 2 -- that
    code is reserved for the bad-argument class of error the other
    subcommands use, and doctor takes no arguments to get wrong.
    """
    from whoopmcp.doctor import run_checks

    checks = run_checks()
    all_ok = True
    for check in checks:
        status = "OK" if check.ok else "FAIL"
        print(f"{check.name}: {status} - {check.message}")
        if not check.ok:
            all_ok = False
    return 0 if all_ok else 1


def _backfill(config: Config, whoop_user_id: int) -> int:
    """Handle ``whoopmcp backfill --whoop-user-id N`` (#14).

    Refuses -- before opening anything -- unless ``config.cache_enabled`` is
    set: PRIVACY.md promises the persistent store is off by default, and
    backfill is the first bulk writer that would otherwise break that
    promise. Guards with the same ``principal_is_linked_to_member`` refusal
    ``_delete_member`` uses ("the user is an argument, never ambient" -- the
    id is explicit and verified against the login-written link, never
    inferred), then runs ``backfill.run_backfill`` and prints a one-line
    per-entity summary to stderr -- never stdout, never a token value.
    """
    from whoopmcp import backfill as backfill_module
    from whoopmcp.auth import Authenticator, AuthError
    from whoopmcp.client import WhoopAPIError, WhoopClient
    from whoopmcp.store import open_store, principal_is_linked_to_member

    if not config.cache_enabled:
        print(
            "whoopmcp: backfill requires the persistent store, which is off by "
            "default; set WHOOPMCP_CACHE=true to enable it (see PRIVACY.md)",
            file=sys.stderr,
        )
        return 2

    conn = open_store(config.cache_path)
    try:
        if not principal_is_linked_to_member(conn, whoop_user_id):
            print(
                f"whoopmcp: no principal is linked to whoop-user-id {whoop_user_id}",
                file=sys.stderr,
            )
            return 2

        auth = Authenticator(config)

        async def _run() -> dict[str, int]:
            async with WhoopClient(config, auth) as client:
                return await backfill_module.run_backfill(conn, client, config, whoop_user_id)

        try:
            imported = asyncio.run(_run())
        except (AuthError, WhoopAPIError) as exc:
            print(f"whoopmcp: {exc}", file=sys.stderr)
            return 1
    finally:
        conn.close()

    summary = ", ".join(f"{entity}={count}" for entity, count in sorted(imported.items()))
    print(
        f"whoopmcp: backfill finished for whoop-user-id {whoop_user_id}: {summary}",
        file=sys.stderr,
    )
    return 0


def _replay_webhook(config: Config, trace_id: str) -> int:
    """Handle ``whoopmcp replay-webhook --trace-id ID`` (#19).

    No ``--whoop-user-id`` guard, unlike ``backfill``/``erase-member``: the
    stored event already carries its own ``whoop_user_id`` in
    ``webhook_events``, and the #66 not-yet-actionable use case specifically
    requires replaying an event for a member who may only just now be
    linked. Prints only a one-line summary to stderr, never the event body
    (never a token, never health data) -- mirrors ``webhooks.py``'s own
    no-payload-in-logs rule.

    Refuses -- before opening anything -- unless ``config.cache_enabled`` is
    set, exactly like ``backfill``/``reconcile-webhooks``: a pending row's
    replay fetches from WHOOP and writes into the persistent store, which
    PRIVACY.md promises is off by default. An operator with an old store
    file left over from an earlier ``WHOOPMCP_CACHE=true`` period must not
    have this subcommand quietly keep writing to it after disabling caching.
    """
    from whoopmcp.auth import Authenticator, AuthError
    from whoopmcp.client import WhoopAPIError, WhoopClient
    from whoopmcp.store import open_store
    from whoopmcp.webhook_processor import UnknownTraceIdError, replay_webhook_event

    if not config.cache_enabled:
        print(
            "whoopmcp: replay requires the persistent store, which is off by "
            "default; set WHOOPMCP_CACHE=true to enable it (see PRIVACY.md)",
            file=sys.stderr,
        )
        return 2

    conn = open_store(config.cache_path)
    try:
        auth = Authenticator(config)

        async def _run() -> bool:
            async with WhoopClient(config, auth) as client:
                return await replay_webhook_event(conn, client, trace_id)

        try:
            reprocessed = asyncio.run(_run())
        except UnknownTraceIdError:
            print(f"whoopmcp: no webhook event recorded for trace_id {trace_id!r}", file=sys.stderr)
            return 2
        except (AuthError, WhoopAPIError) as exc:
            print(f"whoopmcp: {exc}", file=sys.stderr)
            return 1
    finally:
        conn.close()

    if reprocessed:
        print(f"whoopmcp: replayed webhook event trace_id={trace_id}", file=sys.stderr)
    else:
        print(
            f"whoopmcp: trace_id={trace_id} was already terminal (success or "
            "dead_letter); nothing was reprocessed",
            file=sys.stderr,
        )
    return 0


def _reconcile_webhooks(config: Config, whoop_user_id: int, window_days: int) -> int:
    """Handle ``whoopmcp reconcile-webhooks --whoop-user-id N [--window-days N]`` (#19).

    The periodic full-reconciliation backstop: refuses -- before opening
    anything -- unless ``config.cache_enabled`` is set (mirrors
    ``_backfill``'s own guard: this reads and writes the persistent store),
    and guards with the same ``principal_is_linked_to_member`` confirmation
    check every other operator-only subcommand uses. Prints a one-line
    per-resource ``fetched=M closed=N`` summary to stderr -- never stdout,
    never a token value.
    """
    from whoopmcp.auth import Authenticator, AuthError
    from whoopmcp.client import WhoopAPIError, WhoopClient
    from whoopmcp.reconciliation import run_reconciliation
    from whoopmcp.store import open_store, principal_is_linked_to_member

    if not config.cache_enabled:
        print(
            "whoopmcp: reconciliation requires the persistent store, which is off by "
            "default; set WHOOPMCP_CACHE=true to enable it (see PRIVACY.md)",
            file=sys.stderr,
        )
        return 2

    conn = open_store(config.cache_path)
    try:
        if not principal_is_linked_to_member(conn, whoop_user_id):
            print(
                f"whoopmcp: no principal is linked to whoop-user-id {whoop_user_id}",
                file=sys.stderr,
            )
            return 2

        auth = Authenticator(config)

        async def _run() -> dict[str, ReconciliationResult]:
            async with WhoopClient(config, auth) as client:
                return await run_reconciliation(
                    conn, client, config, whoop_user_id, window_days=window_days
                )

        try:
            results = asyncio.run(_run())
        except (AuthError, WhoopAPIError) as exc:
            print(f"whoopmcp: {exc}", file=sys.stderr)
            return 1
    finally:
        conn.close()

    summary = ", ".join(
        f"{resource}=(fetched={result.fetched}, closed={result.closed})"
        for resource, result in sorted(results.items())
    )
    print(
        f"whoopmcp: reconciliation finished for whoop-user-id {whoop_user_id} "
        f"(window_days={window_days}): {summary}",
        file=sys.stderr,
    )
    # A run that *declined* to close records must not read as a run that found
    # nothing to close (#175) -- both show `closed=0` in the summary above, and
    # an operator who cannot tell them apart never learns their reconciliation
    # has been refusing to do its job.
    for resource, result in sorted(results.items()):
        if result.withheld is not None:
            print(f"whoopmcp: {resource}: {result.withheld}", file=sys.stderr)
    return 0


def _extract_code_and_state(pasted: str) -> tuple[str | None, str | None]:
    """Parse ``code``/``state`` out of whatever the user pasted (D1, steps 1-2).

    Tries ``urlparse`` first: its ``query`` reads correctly whether the
    paste is a full redirect URL with a custom scheme or an ``https://``
    one, since either way ``code``/``state`` are ordinary query parameters.
    Falls back to ``parse_qs`` on the raw string for a bare
    ``code=...&state=...`` fragment -- verified empirically that ``urlparse``
    alone cannot read that shape: with no scheme, the whole string lands in
    ``path`` and ``query`` comes back empty. Returns ``(None, None)`` if
    neither yields both keys; the caller prompts separately in that case
    (D1 step 3) rather than guessing from a partial match.
    """
    for query in (urlparse(pasted).query, pasted):
        parsed = parse_qs(query)
        code = parsed.get("code", [None])[0]
        state = parsed.get("state", [None])[0]
        if code is not None and state is not None:
            return code, state
    return None, None


def _login(config: Config) -> int:
    """Handle ``whoopmcp login`` (#76).

    The terminal-native counterpart to the in-chat ``whoop_login``/
    ``whoop_complete_login`` pair, which stays exactly as it is -- some MCP
    clients have no terminal a user can reach. Today the authorization code
    travels through the MCP client and its model provider on its way back to
    ``whoop_complete_login``; running the same exchange here, with no model
    in the loop, is the entire point of this subcommand. Reuses
    ``Authenticator`` unchanged (the OAuth exchange itself is not
    reimplemented here) and constructs exactly one instance for the whole
    invocation: the pending ``state`` from ``start_login`` lives only on
    that instance, so a second ``Authenticator`` would break
    ``verify_state``.

    No localhost listener -- ``config.py`` rejects any non-``https://``
    redirect URI outright (WHOOP's dashboard rejects plain ``http://``,
    including ``http://localhost``), so manual paste is the only mechanism
    the redirect scheme leaves. No browser auto-launch either, a deliberate
    choice rather than an omission: it adds a failure mode for zero benefit
    to the likely user of a terminal subcommand (headless box, SSH session,
    container), and printing the URL is enough -- most terminals make it
    clickable. Every prompt goes to stderr and is read from stdin, matching
    this CLI's stderr-only output discipline; no TUI, no spinner, no colour.

    ``verify_state`` runs strictly before ``exchange_code`` (D4): a
    mismatched state must mean the code is never spent at all, not
    exchanged and then discarded. ``exchange_code`` already persists to
    whichever store ``WHOOPMCP_TOKEN_BACKEND`` selects, so there is no
    separate save step here. Never echoes the code or the state anywhere --
    not on success, not in an error message, not in a log line -- since an
    authorization code is a credential; only the granted scopes are
    reported on success, mirroring ``whoop_complete_login``'s own line.
    Error shape copied from ``_delete_member``/``_erase_member``: catch
    ``AuthError``, print one ``whoopmcp: ...`` line to stderr, return
    non-zero -- never let an ``AuthError`` reach the user as a traceback.
    """
    from whoopmcp.auth import Authenticator, AuthError

    auth = Authenticator(config)
    url = auth.start_login()
    print(
        "Open this URL in a browser to authorise whoopmcp with WHOOP:\n"
        f"  {url}\n"
        "After you approve access, WHOOP redirects you to this server's "
        "configured redirect URI. If that redirect URI uses a custom scheme "
        "(anything other than https://), or nothing is listening on it, the "
        "browser will show what looks like an error page once it gets "
        "there -- that is expected, not a bug. Paste that page's full URL "
        "below, or just its `code` and `state` query parameters.",
        file=sys.stderr,
    )
    code, state = _extract_code_and_state(input())
    if code is None or state is None:
        print(
            "whoopmcp: could not find both `code` and `state` in that paste; "
            "enter them separately.",
            file=sys.stderr,
        )
        print("code: ", end="", file=sys.stderr, flush=True)
        code = input()
        print("state: ", end="", file=sys.stderr, flush=True)
        state = input()

    try:
        auth.verify_state(state)
        token = asyncio.run(auth.exchange_code(code))
    except AuthError as exc:
        print(f"whoopmcp: {exc}", file=sys.stderr)
        return 1

    granted = ", ".join(token.scopes) if token.scopes else "(none)"
    print(f"whoopmcp: login complete. Granted scopes: {granted}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
