"""Entry point. MCP clients launch this over stdio; ``--http`` is for testing."""

from __future__ import annotations

import argparse
import logging
import sys

from whoopmcp import __version__
from whoopmcp.config import ConfigError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="whoopmcp",
        description="Read-only MCP server for the WHOOP API v2.",
    )
    parser.add_argument("--version", action="version", version=f"whoopmcp {__version__}")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
        help="stdio (default) is what MCP clients launch; streamable-http is for local testing.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    )
    args = parser.parse_args(argv)

    # stderr, never stdout: on stdio transport stdout carries the JSON-RPC
    # framing and a stray log line corrupts the protocol.
    logging.basicConfig(
        level=args.log_level,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    from whoopmcp.config import Config
    from whoopmcp.server import build_server

    # Validate up front rather than leaving it to the lifespan. Once the
    # server is running the lifespan executes inside an anyio task group,
    # which wraps whatever it raises in an ExceptionGroup -- so a bare
    # `except ConfigError` there would miss it and the user would get a
    # traceback instead of the one line telling them which variable is unset.
    try:
        Config.from_env()
    except ConfigError as exc:
        print(f"whoopmcp: {exc}", file=sys.stderr)
        return 2

    try:
        build_server().run(transport=args.transport)
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
