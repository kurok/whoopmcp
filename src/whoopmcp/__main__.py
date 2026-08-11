"""Entry point. MCP clients launch this over stdio; ``--http`` is for testing."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from whoopmcp import __version__
from whoopmcp.config import Config, ConfigError


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
        help="Write the export document to this path. Defaults to stdout.",
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

    args = parser.parse_args(argv)

    # stderr, never stdout: on stdio transport stdout carries the JSON-RPC
    # framing and a stray log line corrupts the protocol.
    logging.basicConfig(
        level=args.log_level,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

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

    from whoopmcp.server import build_server

    transport = args.transport if args.transport is not None else config.transport
    host = args.host if args.host is not None else config.http_host
    port = args.port if args.port is not None else config.http_port

    try:
        if transport == "streamable-http":
            build_server().run(transport="streamable-http", host=host, port=port)
        else:
            build_server().run(transport="stdio")
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    return 0


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
    """
    from whoopmcp.auth import Authenticator, AuthError
    from whoopmcp.store import (
        delete_principal_links_for_member,
        open_store,
        principal_is_linked_to_member,
    )

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
        try:
            asyncio.run(auth.revoke_and_forget())
        except AuthError as exc:
            print(f"whoopmcp: {exc}", file=sys.stderr)
            return 1

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
    """
    from whoopmcp.auth import build_store
    from whoopmcp.store import (
        all_linked_whoop_user_ids,
        export_member_data,
        open_store,
        principal_is_linked_to_member,
    )

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
            "token_present": None,
            "note": (
                "more than one WHOOP member has ever been linked in this store; "
                "which one the single locally-stored token belongs to cannot be "
                "determined, so scopes are not reported here"
            ),
        }

    payload = json.dumps(document, indent=2)
    if out is not None:
        out.write_text(payload, encoding="utf-8")
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
    order -- no upstream revoke and no local deletion on a refusal.
    """
    from whoopmcp.auth import Authenticator, AuthError
    from whoopmcp.store import (
        delete_principal_links_for_member,
        erase_member_data,
        open_store,
        principal_is_linked_to_member,
    )

    conn = open_store(config.cache_path)
    try:
        if not principal_is_linked_to_member(conn, whoop_user_id):
            print(
                f"whoopmcp: no principal is linked to whoop-user-id {whoop_user_id}",
                file=sys.stderr,
            )
            return 2

        auth = Authenticator(config)
        try:
            asyncio.run(auth.revoke_and_forget())
        except AuthError as exc:
            print(f"whoopmcp: {exc}", file=sys.stderr)
            return 1

        erase_member_data(conn, whoop_user_id)
        delete_principal_links_for_member(conn, whoop_user_id)
    finally:
        conn.close()
    return 0


def _enforce_retention(config: Config, max_age_days: int) -> int:
    """Handle ``whoopmcp enforce-retention [--max-age-days N]`` (#32).

    There is no scheduler anywhere in this repository -- this subcommand IS
    the retention job; an operator wires it into their own cron or systemd
    timer. Prints a one-line per-table summary to stderr and never a token
    value, since nothing here ever reads one.
    """
    from whoopmcp.store import enforce_retention, open_store

    conn = open_store(config.cache_path)
    try:
        counts = enforce_retention(conn, max_age_days=max_age_days)
    finally:
        conn.close()

    summary = ", ".join(f"{table}={count}" for table, count in sorted(counts.items()))
    print(f"whoopmcp: retention enforced (max_age_days={max_age_days}): {summary}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
