"""Entry point. MCP clients launch this over stdio; ``--http`` is for testing."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

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


if __name__ == "__main__":
    raise SystemExit(main())
