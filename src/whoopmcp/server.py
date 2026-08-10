"""The MCP server: tool definitions and their wiring.

Built on the official Python SDK's ``MCPServer`` (the class FastMCP became in
mcp 2.0). Every tool here is annotated read-only, because every tool here is
read-only -- there is no write path to a user's WHOOP account in this server,
and clients that surface ``readOnlyHint`` should be able to say so.

Tool docstrings are prompt surface, not just developer documentation: they are
what the model sees when deciding which tool to call. They state units and
they state what the data is not (a diagnosis).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import ToolAnnotations

from whoopmcp.auth import Authenticator, build_store
from whoopmcp.client import WhoopClient
from whoopmcp.config import Config

logger = logging.getLogger("whoopmcp")

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)

INSTRUCTIONS = """\
Read-only access to the signed-in user's own WHOOP data: recovery, sleep,
strain, cycles and workouts.

Guidance:
- Timestamps are ISO 8601 UTC. Ask for an explicit date range; do not fetch
  unbounded history, as WHOOP allows 100 requests/minute and long ranges
  will exhaust both the rate limit and the context window.
- A WHOOP "cycle" is a physiological day, which does not align with midnight.
  Join sleep and recovery to strain through cycle_id, not calendar date.
- Records carry a score_state; only "SCORED" records have usable scores.
- This is wellness data, not clinical data. Report what the numbers say and
  their sample size. Do not diagnose, and do not present a correlation over
  a few weeks as a causal finding.
"""


@dataclass(slots=True)
class AppContext:
    """What the server holds open for the life of the process."""

    config: Config
    auth: Authenticator
    client: WhoopClient


@asynccontextmanager
async def lifespan(_server: MCPServer[Any]) -> AsyncIterator[AppContext]:
    """Build the config, auth and HTTP client once, and tear them down cleanly."""
    config = Config.from_env()
    auth = Authenticator(config)
    async with WhoopClient(config, auth) as client:
        logger.info("whoopmcp ready (state dir: %s)", config.state_dir)
        yield AppContext(config=config, auth=auth, client=client)


def build_server() -> MCPServer[AppContext]:
    """Construct the server and register every tool on it."""
    server: MCPServer[AppContext] = MCPServer(
        name="whoopmcp",
        title="WHOOP",
        version="0.1.0",
        instructions=INSTRUCTIONS,
        website_url="https://github.com/kurok/whoopmcp",
        lifespan=lifespan,
    )
    _register_auth_tools(server)
    _register_data_tools(server)
    _register_analysis_tools(server)
    return server


# -- authentication --------------------------------------------------------


def _register_auth_tools(server: MCPServer[AppContext]) -> None:
    @server.tool(
        name="whoop_auth_status",
        title="Check WHOOP authentication",
        annotations=READ_ONLY,
    )
    async def whoop_auth_status(ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Report whether a valid WHOOP token is held, its scopes and its expiry.

        Call this first when a data tool fails; it distinguishes "never logged
        in" from "token expired" from "scope not granted".
        """
        app = ctx.request_context.lifespan_context
        token = build_store(app.config).load()
        if token is None:
            return {"logged_in": False}
        return {
            "logged_in": True,
            "expired": token.expired,
            "scopes": list(token.scopes),
            "expires_at": datetime.fromtimestamp(token.expires_at, tz=UTC).isoformat(),
        }

    @server.tool(
        name="whoop_login",
        title="Start WHOOP login",
        annotations=READ_ONLY,
    )
    async def whoop_login(ctx: Context[AppContext, Any]) -> str:
        """Return a URL the user must open in a browser to authorise this server.

        The user completes the WHOOP consent screen, is redirected to the
        configured redirect URI, and then passes the ``code`` and ``state``
        query parameters back via whoop_complete_login.
        """
        app = ctx.request_context.lifespan_context
        url = app.auth.start_login()
        return (
            "Open this URL in a browser to authorise whoopmcp with WHOOP. "
            "After you approve access, WHOOP redirects you to this server's "
            "configured redirect URI. If that redirect URI uses a custom scheme "
            "(anything other than https://), the browser will show what looks "
            "like an error page once it gets there -- that is expected, not a "
            "bug, because nothing on your machine is listening on that scheme. "
            "Copy the `code` and `state` query parameters from that page's "
            "address bar and pass them to whoop_complete_login.\n\n"
            f"{url}"
        )

    @server.tool(
        name="whoop_complete_login",
        title="Complete WHOOP login",
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=False, open_world_hint=True
        ),
    )
    async def whoop_complete_login(code: str, state: str, ctx: Context[AppContext, Any]) -> str:
        """Finish a login using the code and state from the redirect URL.

        Args:
            code: The ``code`` query parameter from the redirect.
            state: The ``state`` query parameter from the redirect. It is
                verified against the pending login before the code is used.
        """
        app = ctx.request_context.lifespan_context
        app.auth.verify_state(state)
        token = await app.auth.exchange_code(code)
        granted = ", ".join(token.scopes) if token.scopes else "(none)"
        return f"Login complete. Granted scopes: {granted}"

    @server.tool(
        name="whoop_logout",
        title="Forget WHOOP credentials",
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=True, open_world_hint=False
        ),
    )
    async def whoop_logout(ctx: Context[AppContext, Any]) -> str:
        """Delete the locally stored WHOOP token.

        This does not revoke the grant at WHOOP; do that from the WHOOP app
        under Settings if you want the authorisation itself withdrawn.
        """
        app = ctx.request_context.lifespan_context
        app.auth.logout()
        return (
            "Local WHOOP credentials removed. This does not revoke the "
            "authorization at WHOOP -- do that from the WHOOP app under "
            "Settings if you want the grant itself withdrawn."
        )


# -- raw data --------------------------------------------------------------


def _register_data_tools(server: MCPServer[AppContext]) -> None:
    @server.tool(name="get_profile", title="Get WHOOP profile", annotations=READ_ONLY)
    async def get_profile() -> dict[str, Any]:
        """Return the user's WHOOP profile: user id, email, first and last name.

        TODO(#5): delegate to WhoopClient.get_profile.
        """
        raise NotImplementedError("get_profile is not implemented yet -- see issue #5")

    @server.tool(name="get_body_measurement", title="Get body measurements", annotations=READ_ONLY)
    async def get_body_measurement() -> dict[str, Any]:
        """Return height in metres, weight in kilograms and max heart rate in bpm.

        TODO(#5): delegate to WhoopClient.get_body_measurement.
        """
        raise NotImplementedError("get_body_measurement is not implemented yet -- see issue #5")

    @server.tool(name="list_recoveries", title="List recoveries", annotations=READ_ONLY)
    async def list_recoveries(
        start: str | None = None, end: str | None = None, limit: int = 25
    ) -> dict[str, Any]:
        """List recovery records: recovery score (%), HRV (ms) and resting heart rate (bpm).

        Args:
            start: ISO 8601 start of the range, e.g. "2026-07-01T00:00:00Z".
            end: ISO 8601 end of the range.
            limit: Records to return, capped at 25 per page by WHOOP.

        TODO(#5): delegate to WhoopClient.list_recoveries.
        """
        raise NotImplementedError("list_recoveries is not implemented yet -- see issue #5")

    @server.tool(name="list_sleeps", title="List sleeps", annotations=READ_ONLY)
    async def list_sleeps(
        start: str | None = None, end: str | None = None, limit: int = 25
    ) -> dict[str, Any]:
        """List sleep records: performance (%), efficiency, and stage durations in milliseconds.

        Args:
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
            limit: Records to return, capped at 25 per page by WHOOP.

        TODO(#5): delegate to WhoopClient.list_sleeps.
        """
        raise NotImplementedError("list_sleeps is not implemented yet -- see issue #5")

    @server.tool(name="list_cycles", title="List cycles", annotations=READ_ONLY)
    async def list_cycles(
        start: str | None = None, end: str | None = None, limit: int = 25
    ) -> dict[str, Any]:
        """List physiological cycles: day strain (0-21), average and max heart rate, kilojoules.

        A cycle is WHOOP's notion of a day, bounded by sleep rather than by
        midnight, and is the key other records join on.

        Args:
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
            limit: Records to return, capped at 25 per page by WHOOP.

        TODO(#5): delegate to WhoopClient.list_cycles.
        """
        raise NotImplementedError("list_cycles is not implemented yet -- see issue #5")

    @server.tool(name="list_workouts", title="List workouts", annotations=READ_ONLY)
    async def list_workouts(
        start: str | None = None, end: str | None = None, limit: int = 25
    ) -> dict[str, Any]:
        """List workouts: sport, strain, average and max heart rate, and heart-rate zone durations.

        Args:
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
            limit: Records to return, capped at 25 per page by WHOOP.

        TODO(#5): delegate to WhoopClient.list_workouts.
        """
        raise NotImplementedError("list_workouts is not implemented yet -- see issue #5")

    @server.tool(name="get_sleep", title="Get one sleep", annotations=READ_ONLY)
    async def get_sleep(sleep_id: str) -> dict[str, Any]:
        """Return a single sleep by its v2 UUID.

        TODO(#5): delegate to WhoopClient.get_sleep.
        """
        raise NotImplementedError("get_sleep is not implemented yet -- see issue #5")

    @server.tool(name="get_workout", title="Get one workout", annotations=READ_ONLY)
    async def get_workout(workout_id: str) -> dict[str, Any]:
        """Return a single workout by its v2 UUID.

        TODO(#5): delegate to WhoopClient.get_workout.
        """
        raise NotImplementedError("get_workout is not implemented yet -- see issue #5")


# -- analysis --------------------------------------------------------------


def _register_analysis_tools(server: MCPServer[AppContext]) -> None:
    @server.tool(name="summarize_period", title="Summarise a period", annotations=READ_ONLY)
    async def summarize_period(start: str, end: str) -> dict[str, Any]:
        """Summarise recovery, sleep and strain over a date range.

        Returns mean, standard deviation, min and max for each metric, along
        with the number of scored records behind each figure.

        Args:
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.

        TODO(#6): fetch each collection once, then analysis.summarize per metric.
        """
        raise NotImplementedError("summarize_period is not implemented yet -- see issue #6")

    @server.tool(name="metric_trend", title="Trend of one metric", annotations=READ_ONLY)
    async def metric_trend(metric: str, start: str, end: str) -> dict[str, Any]:
        """Compute the direction and rate of change of one metric over a range.

        Args:
            metric: One of "recovery_score", "hrv", "resting_heart_rate",
                "sleep_performance", "sleep_efficiency", "strain".
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.

        Returns the least-squares slope in metric units per day. A slope is a
        description of the window requested, not a forecast.

        TODO(#6): resolve the metric to a collection, fetch, then analysis.trend.
        """
        raise NotImplementedError("metric_trend is not implemented yet -- see issue #6")

    @server.tool(name="correlate_metrics", title="Correlate two metrics", annotations=READ_ONLY)
    async def correlate_metrics(
        metric_a: str, metric_b: str, start: str, end: str
    ) -> dict[str, Any]:
        """Correlate two metrics over a range, joining records on cycle.

        Returns Pearson's r with the sample size it was computed from, and
        refuses to report below 8 paired observations. Correlation here is
        descriptive: it does not establish that one metric drives the other.

        Args:
            metric_a: First metric name, as in metric_trend.
            metric_b: Second metric name.
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.

        TODO(#6): fetch both collections, join, then analysis.correlate.
        """
        raise NotImplementedError("correlate_metrics is not implemented yet -- see issue #6")

    @server.tool(name="compare_periods", title="Compare two periods", annotations=READ_ONLY)
    async def compare_periods(
        baseline_start: str, baseline_end: str, comparison_start: str, comparison_end: str
    ) -> dict[str, Any]:
        """Compare every summary metric between a baseline period and a later one.

        Useful for "did the training block change anything" questions. Returns
        both periods' summaries and the delta, with sample sizes.

        Args:
            baseline_start: ISO 8601 start of the baseline period.
            baseline_end: ISO 8601 end of the baseline period.
            comparison_start: ISO 8601 start of the comparison period.
            comparison_end: ISO 8601 end of the comparison period.

        TODO(#6): summarize both windows and diff them.
        """
        raise NotImplementedError("compare_periods is not implemented yet -- see issue #6")
