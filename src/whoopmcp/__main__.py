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
    """Redirect uvicorn's access log to stderr before the HTTP transport starts.

    Uvicorn's default sends access log lines -- client IPs included -- to
    stdout, contradicting PRIVACY.md's stderr-only promise (#126); an operator
    who redirects stdout trusting that promise leaks IPs of people whose
    health data this server holds.

    No kwarg reaches uvicorn's log_config through the SDK, so this mutates
    ``uvicorn.config.LOGGING_CONFIG`` in place before ``uvicorn.Config`` is
    built (its ``__init__`` captures that dict by reference). Breaks silently
    if the SDK ever supplies its own log_config -- see
    ``test_sdk_still_leaves_uvicorns_log_config_to_its_default``.
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

    # No `required=True`: default (no subcommand) means run the server.
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

    # stderr only: stdout carries JSON-RPC framing on stdio transport, and a
    # stray log line corrupts the protocol.
    logging.basicConfig(
        level=args.log_level,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    # doctor runs before Config.from_env(): missing config is itself one of
    # doctor's own checks, not the generic exit-2 path other subcommands use.
    if args.command == "doctor":
        return _doctor()

    # Validate here, not in the lifespan: anyio wraps lifespan exceptions in
    # an ExceptionGroup, so `except ConfigError` there would miss it.
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
    """Shared revoke-step for ``_delete_member``/``_erase_member`` (#65).

    Returns ``None`` to proceed with local deletion, else a nonzero exit code
    to abort. Skips (not aborts) the revoke if the token can't be attributed
    to ``whoop_user_id`` -- never revoke a different member's grant.
    ``GrantAlreadyGoneError`` (subclass of ``AuthError``) means already
    revoked, not failure; it must stay caught before the plain ``AuthError``
    case, which does abort with a nonzero code.
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

    Returns exit code 2 if the store is ephemeral and no cache file was ever
    created, else ``None`` to proceed to ``open_store``. A leftover file from
    past ``WHOOPMCP_CACHE=true`` use is still opened -- refusing would deny a
    data subject their erasure/export right. Unlike other guards' ``not
    cache_enabled`` message, never suggest enabling caching here -- absurd
    advice for delete/export/erase/retention.
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

    Only caller of ``Authenticator.revoke_and_forget`` (must never become an
    MCP tool -- see its docstring). Revokes the WHOOP grant upstream and
    deletes the local token + principal link; health data, webhook events,
    and audit rows are untouched (#32's job). Doesn't revoke a token it can't
    attribute to this member -- see ``_revoke_before_local_deletion`` (#65).
    Refuses up front if the store is ephemeral with no file yet
    (``_refuse_if_store_is_ephemeral``, #101).
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
            # Refuse rather than no-op: a mismatched id is more likely
            # operator error than an intentional deletion of nothing.
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

    Adds a ``consent`` field (granted scopes + token presence) to
    ``store.export_member_data``'s document, reading the token store
    directly -- never via ``access_token()``, which could trigger a refresh;
    the token value itself never enters the document. If more than one
    member is ever linked, which one owns the token is unknown, so
    ``consent.scopes`` is reported as ``None`` with a note rather than
    guessed. Refuses up front if the store is ephemeral with no file yet
    (``_refuse_if_store_is_ephemeral``, #101).
    """
    from whoopmcp.auth import AuthError, atomic_write_text, build_store
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
        try:
            token = build_store(config).load()
            document["consent"] = {
                "scopes": list(token.scopes) if token is not None else [],
                "token_present": token is not None,
            }
        except AuthError:
            # Degrade, don't fail: consent is a convenience, an unreadable
            # token store (#188) must not discard an already-built export.
            document["consent"] = {
                "scopes": None,
                "token_present": None,  # nosec B105 -- not a credential
                "note": (
                    "the token store could not be read, so granted scopes could not be determined"
                ),
            }
    else:
        document["consent"] = {
            "scopes": None,
            "token_present": None,  # nosec B105 -- not a credential
            "note": (
                "more than one WHOOP member has ever been linked in this store; "
                "which one the single locally-stored token belongs to cannot be "
                "determined, so scopes are not reported here"
            ),
        }

    payload = json.dumps(document, indent=2)
    if out is not None:
        # #68: same 0600 no-world-readable-window write as auth.py's token
        # stores -- this is the member's full health record.
        atomic_write_text(out, payload)
    else:
        print(payload)
    return 0


def _erase_member(config: Config, whoop_user_id: int) -> int:
    """Handle ``whoopmcp erase-member --whoop-user-id N`` (#32).

    The full data-subject erasure story: revokes the WHOOP grant upstream and
    forgets the local token, deletes every row ``store.erase_member_data``
    covers (health data, webhook events, audit rows) plus the principal
    link, then compacts the database (#100) so freed pages aren't left
    recoverable in the file. Doesn't revoke a token it can't attribute to
    this member -- see ``_revoke_before_local_deletion`` (#65). A failed
    compaction doesn't undo the erasure (already committed) -- prints to
    stderr and returns exit code 3 (vs. the pre-deletion abort's 1). Refuses
    up front if the store is ephemeral with no file yet (#101).
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

    No scheduler exists in this repo -- this subcommand IS the retention job;
    an operator wires it into cron/systemd. Prints a one-line per-table
    summary to stderr, never a token value. Refuses up front if the store is
    ephemeral with no file yet (#101); a summary there would be a false
    success.
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

    Prints one plain line per check to stdout (a terminal diagnostic, not
    JSON). Exits 0 only if every check passed, else 1 -- never 2, which is
    reserved for bad-argument errors this no-argument subcommand can't have.
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

    Refuses up front unless ``config.cache_enabled`` -- PRIVACY.md promises
    the persistent store is off by default, and this is the first bulk
    writer that would break that promise. Guards on
    ``principal_is_linked_to_member`` like ``_delete_member``, then runs
    ``backfill.run_backfill`` and prints a one-line summary to stderr only.
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

    No ``--whoop-user-id`` guard: the stored event already carries its own
    ``whoop_user_id`` (#66 needs replay for a member only just now linked).
    Prints only a one-line summary to stderr -- never the event body, a
    token, or health data. Refuses up front unless ``config.cache_enabled``,
    like ``backfill``/``reconcile-webhooks``: replay writes into the
    persistent store, which is off by default.
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

    Periodic full-reconciliation backstop for #15's incremental sync.
    Refuses up front unless ``config.cache_enabled`` (reads/writes the
    persistent store), and guards on ``principal_is_linked_to_member`` like
    other operator-only subcommands. Prints a one-line per-resource summary
    to stderr only, never a token value.
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
        f"{resource}=(fetched={result.fetched}, updated={result.updated}, closed={result.closed})"
        for resource, result in sorted(results.items())
    )
    print(
        f"whoopmcp: reconciliation finished for whoop-user-id {whoop_user_id} "
        f"(window_days={window_days}): {summary}",
        file=sys.stderr,
    )
    # #175: a declined close must not look like nothing-to-close (both show
    # closed=0) or an operator never learns reconciliation is refusing to act.
    for resource, result in sorted(results.items()):
        if result.withheld is not None:
            print(f"whoopmcp: {resource}: {result.withheld}", file=sys.stderr)
    return 0


def _extract_code_and_state(pasted: str) -> tuple[str | None, str | None]:
    """Parse ``code``/``state`` out of whatever the user pasted (D1, steps 1-2).

    Tries ``urlparse().query`` first (works for full redirect URLs, any
    scheme); falls back to ``parse_qs`` on the raw string for a bare
    ``code=...&state=...`` fragment, since a schemeless string leaves
    ``query`` empty. Returns ``(None, None)`` if neither yields both keys.
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

    Terminal counterpart to the in-chat ``whoop_login``/``whoop_complete_login``
    pair (unchanged) -- runs the OAuth exchange with no model in the loop, one
    ``Authenticator`` per invocation (``verify_state`` needs the same instance
    ``start_login`` used). Redirect URI must be ``https://`` (no localhost
    listener), so manual paste is the only path; no browser auto-launch.
    ``verify_state`` runs strictly before ``exchange_code`` (D4) so a
    mismatched state can't spend the code; the code/state are never echoed
    anywhere -- they're credentials. Catches ``AuthError``, prints one stderr
    line, returns nonzero.
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
