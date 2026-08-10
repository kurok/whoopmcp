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
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import ToolAnnotations

from whoopmcp.auth import Authenticator
from whoopmcp.client import RateLimitedError, WhoopClient
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
    async def whoop_auth_status() -> dict[str, Any]:
        """Report whether a valid WHOOP token is held, its scopes and its expiry.

        Call this first when a data tool fails; it distinguishes "never logged
        in" from "token expired" from "scope not granted".

        TODO(#4): read the token store and return status, scopes, expires_at.
        """
        raise NotImplementedError("whoop_auth_status is not implemented yet -- see issue #4")

    @server.tool(
        name="whoop_login",
        title="Start WHOOP login",
        annotations=READ_ONLY,
    )
    async def whoop_login() -> str:
        """Return a URL the user must open in a browser to authorise this server.

        The user completes the WHOOP consent screen, is redirected to the
        configured redirect URI, and then passes the ``code`` and ``state``
        query parameters back via whoop_complete_login.

        TODO(#4): delegate to Authenticator.start_login and return the URL
        with a short instruction for the user.
        """
        raise NotImplementedError("whoop_login is not implemented yet -- see issue #4")

    @server.tool(
        name="whoop_complete_login",
        title="Complete WHOOP login",
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=False, open_world_hint=True
        ),
    )
    async def whoop_complete_login(code: str, state: str) -> str:
        """Finish a login using the code and state from the redirect URL.

        Args:
            code: The ``code`` query parameter from the redirect.
            state: The ``state`` query parameter from the redirect. It is
                verified against the pending login before the code is used.

        TODO(#4): verify_state, then exchange_code, then confirm granted scopes.
        """
        raise NotImplementedError("whoop_complete_login is not implemented yet -- see issue #4")

    @server.tool(
        name="whoop_logout",
        title="Forget WHOOP credentials",
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=True, open_world_hint=False
        ),
    )
    async def whoop_logout() -> str:
        """Delete the locally stored WHOOP token.

        This does not revoke the grant at WHOOP; do that from the WHOOP app
        under Settings if you want the authorisation itself withdrawn.

        TODO(#4): call Authenticator.logout and say what was removed.
        """
        raise NotImplementedError("whoop_logout is not implemented yet -- see issue #4")


# -- raw data --------------------------------------------------------------

#: Default lookback for the four list tools when the caller gives neither
#: end of the range.
_DEFAULT_LOOKBACK = timedelta(days=7)


async def _guard_rate_limit(
    build_response: Callable[[], Awaitable[dict[str, Any]]],
) -> dict[str, Any]:
    """Run a data-tool body, turning a RateLimitedError into something a model can act on.

    A raw RateLimitedError would otherwise propagate as an opaque ToolError;
    a model can't retry sensibly without knowing when to.
    """
    try:
        return await build_response()
    except RateLimitedError as exc:
        message = (
            f"WHOOP rate limit hit; retry after {exc.retry_after:.0f} seconds."
            if exc.retry_after is not None
            else "WHOOP rate limit hit; retry after a short delay."
        )
        return {"error": "rate_limited", "retry_after_seconds": exc.retry_after, "message": message}


def _default_range(
    start: datetime | str | None, end: datetime | str | None, next_token: str | None
) -> tuple[datetime | str | None, datetime | str | None]:
    """Default a wholly-unspecified range to the last 7 days; leave any partial range alone.

    Skipped entirely when ``next_token`` is set: that call is continuing a
    previous page, and layering a fresh "now minus 7 days" window on top of
    an opaque WHOOP cursor is exactly the kind of thing that could silently
    change what the cursor even means. Leaving start/end as None there means
    the request carries only the cursor (and limit), which is what "pass
    next_token to continue" promises.
    """
    if start is None and end is None and next_token is None:
        end = datetime.now(UTC)
        start = end - _DEFAULT_LOOKBACK
    return start, end


def _trim_recovery(record: dict[str, Any]) -> dict[str, Any]:
    trimmed: dict[str, Any] = {
        "cycle_id": record.get("cycle_id"),
        "created_at": record.get("created_at"),
        "score_state": record.get("score_state"),
    }
    if record.get("score_state") == "SCORED":
        score = record.get("score") or {}
        trimmed["recovery_score"] = score.get("recovery_score")
        trimmed["hrv_rmssd_milli"] = score.get("hrv_rmssd_milli")
        trimmed["resting_heart_rate"] = score.get("resting_heart_rate")
    return trimmed


def _trim_sleep(record: dict[str, Any]) -> dict[str, Any]:
    trimmed: dict[str, Any] = {
        "id": record.get("id"),
        "start": record.get("start"),
        "end": record.get("end"),
        "nap": record.get("nap"),
        "score_state": record.get("score_state"),
    }
    if record.get("score_state") == "SCORED":
        score = record.get("score") or {}
        trimmed["sleep_performance_percentage"] = score.get("sleep_performance_percentage")
        trimmed["sleep_efficiency_percentage"] = score.get("sleep_efficiency_percentage")
        trimmed["respiratory_rate"] = score.get("respiratory_rate")
        stages = score.get("stage_summary") or {}
        trimmed["stage_durations_milli"] = {
            "awake": stages.get("total_awake_time_milli"),
            "light": stages.get("total_light_sleep_time_milli"),
            "deep": stages.get("total_slow_wave_sleep_time_milli"),
            "rem": stages.get("total_rem_sleep_time_milli"),
        }
    return trimmed


def _trim_cycle(record: dict[str, Any]) -> dict[str, Any]:
    trimmed: dict[str, Any] = {
        "id": record.get("id"),
        "start": record.get("start"),
        "end": record.get("end"),
        "score_state": record.get("score_state"),
    }
    if record.get("score_state") == "SCORED":
        score = record.get("score") or {}
        trimmed["strain"] = score.get("strain")
        trimmed["average_heart_rate"] = score.get("average_heart_rate")
        trimmed["max_heart_rate"] = score.get("max_heart_rate")
        trimmed["kilojoule"] = score.get("kilojoule")
    return trimmed


def _trim_workout(record: dict[str, Any]) -> dict[str, Any]:
    trimmed: dict[str, Any] = {
        "id": record.get("id"),
        "sport_name": record.get("sport_name"),
        "start": record.get("start"),
        "end": record.get("end"),
        "score_state": record.get("score_state"),
    }
    if record.get("score_state") == "SCORED":
        score = record.get("score") or {}
        trimmed["strain"] = score.get("strain")
        trimmed["average_heart_rate"] = score.get("average_heart_rate")
        trimmed["max_heart_rate"] = score.get("max_heart_rate")
        zones = score.get("zone_duration") or {}
        trimmed["zone_durations_milli"] = {
            "zone_zero": zones.get("zone_zero_milli"),
            "zone_one": zones.get("zone_one_milli"),
            "zone_two": zones.get("zone_two_milli"),
            "zone_three": zones.get("zone_three_milli"),
            "zone_four": zones.get("zone_four_milli"),
            "zone_five": zones.get("zone_five_milli"),
        }
    return trimmed


def _register_data_tools(server: MCPServer[AppContext]) -> None:
    @server.tool(name="get_profile", title="Get WHOOP profile", annotations=READ_ONLY)
    async def get_profile(ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Return the user's WHOOP profile: user id, email, first and last name."""
        app = ctx.request_context.lifespan_context

        async def _fetch() -> dict[str, Any]:
            return await app.client.get_profile()

        return await _guard_rate_limit(_fetch)

    @server.tool(name="get_body_measurement", title="Get body measurements", annotations=READ_ONLY)
    async def get_body_measurement(ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Return height in metres, weight in kilograms and max heart rate in bpm."""
        app = ctx.request_context.lifespan_context

        async def _fetch() -> dict[str, Any]:
            return await app.client.get_body_measurement()

        return await _guard_rate_limit(_fetch)

    @server.tool(name="list_recoveries", title="List recoveries", annotations=READ_ONLY)
    async def list_recoveries(
        ctx: Context[AppContext, Any],
        start: str | None = None,
        end: str | None = None,
        limit: int = 25,
        next_token: str | None = None,
    ) -> dict[str, Any]:
        """List recovery records: recovery score (%), HRV (ms) and resting heart rate (bpm).

        Args:
            start: ISO 8601 start of the range, e.g. "2026-07-01T00:00:00Z".
                Defaults, with end, to the last 7 days when both are omitted.
            end: ISO 8601 end of the range.
            limit: Records to return, capped at 25 per page by WHOOP.
            next_token: Cursor from a previous truncated response, to continue
                that page.
        """
        app = ctx.request_context.lifespan_context
        range_start, range_end = _default_range(start, end, next_token)

        async def _fetch() -> dict[str, Any]:
            page = await app.client.list_recoveries(
                start=range_start, end=range_end, limit=limit, next_token=next_token
            )
            records = [_trim_recovery(r) for r in page.records]
            result: dict[str, Any] = {
                "records": records,
                "count": len(records),
                "next_token": page.next_token,
            }
            if page.next_token is not None:
                result["note"] = (
                    f"Only {len(records)} record(s) in this range were returned; WHOOP "
                    "paginates and has more records. Pass "
                    f"next_token={page.next_token!r} to this tool to continue, "
                    "or narrow the date range."
                )
            return result

        return await _guard_rate_limit(_fetch)

    @server.tool(name="list_sleeps", title="List sleeps", annotations=READ_ONLY)
    async def list_sleeps(
        ctx: Context[AppContext, Any],
        start: str | None = None,
        end: str | None = None,
        limit: int = 25,
        next_token: str | None = None,
    ) -> dict[str, Any]:
        """List sleep records: performance (%), efficiency, and stage durations in milliseconds.

        Args:
            start: ISO 8601 start of the range.
                Defaults, with end, to the last 7 days when both are omitted.
            end: ISO 8601 end of the range.
            limit: Records to return, capped at 25 per page by WHOOP.
            next_token: Cursor from a previous truncated response, to continue
                that page.
        """
        app = ctx.request_context.lifespan_context
        range_start, range_end = _default_range(start, end, next_token)

        async def _fetch() -> dict[str, Any]:
            page = await app.client.list_sleeps(
                start=range_start, end=range_end, limit=limit, next_token=next_token
            )
            records = [_trim_sleep(r) for r in page.records]
            result: dict[str, Any] = {
                "records": records,
                "count": len(records),
                "next_token": page.next_token,
            }
            if page.next_token is not None:
                result["note"] = (
                    f"Only {len(records)} record(s) in this range were returned; WHOOP "
                    "paginates and has more records. Pass "
                    f"next_token={page.next_token!r} to this tool to continue, "
                    "or narrow the date range."
                )
            return result

        return await _guard_rate_limit(_fetch)

    @server.tool(name="list_cycles", title="List cycles", annotations=READ_ONLY)
    async def list_cycles(
        ctx: Context[AppContext, Any],
        start: str | None = None,
        end: str | None = None,
        limit: int = 25,
        next_token: str | None = None,
    ) -> dict[str, Any]:
        """List physiological cycles: day strain (0-21), average and max heart rate, kilojoules.

        A cycle is WHOOP's notion of a day, bounded by sleep rather than by
        midnight, and is the key other records join on.

        Args:
            start: ISO 8601 start of the range.
                Defaults, with end, to the last 7 days when both are omitted.
            end: ISO 8601 end of the range.
            limit: Records to return, capped at 25 per page by WHOOP.
            next_token: Cursor from a previous truncated response, to continue
                that page.
        """
        app = ctx.request_context.lifespan_context
        range_start, range_end = _default_range(start, end, next_token)

        async def _fetch() -> dict[str, Any]:
            page = await app.client.list_cycles(
                start=range_start, end=range_end, limit=limit, next_token=next_token
            )
            records = [_trim_cycle(r) for r in page.records]
            result: dict[str, Any] = {
                "records": records,
                "count": len(records),
                "next_token": page.next_token,
            }
            if page.next_token is not None:
                result["note"] = (
                    f"Only {len(records)} record(s) in this range were returned; WHOOP "
                    "paginates and has more records. Pass "
                    f"next_token={page.next_token!r} to this tool to continue, "
                    "or narrow the date range."
                )
            return result

        return await _guard_rate_limit(_fetch)

    @server.tool(name="list_workouts", title="List workouts", annotations=READ_ONLY)
    async def list_workouts(
        ctx: Context[AppContext, Any],
        start: str | None = None,
        end: str | None = None,
        limit: int = 25,
        next_token: str | None = None,
    ) -> dict[str, Any]:
        """List workouts: sport, strain, average and max heart rate, and heart-rate zone durations.

        Args:
            start: ISO 8601 start of the range.
                Defaults, with end, to the last 7 days when both are omitted.
            end: ISO 8601 end of the range.
            limit: Records to return, capped at 25 per page by WHOOP.
            next_token: Cursor from a previous truncated response, to continue
                that page.
        """
        app = ctx.request_context.lifespan_context
        range_start, range_end = _default_range(start, end, next_token)

        async def _fetch() -> dict[str, Any]:
            page = await app.client.list_workouts(
                start=range_start, end=range_end, limit=limit, next_token=next_token
            )
            records = [_trim_workout(r) for r in page.records]
            result: dict[str, Any] = {
                "records": records,
                "count": len(records),
                "next_token": page.next_token,
            }
            if page.next_token is not None:
                result["note"] = (
                    f"Only {len(records)} record(s) in this range were returned; WHOOP "
                    "paginates and has more records. Pass "
                    f"next_token={page.next_token!r} to this tool to continue, "
                    "or narrow the date range."
                )
            return result

        return await _guard_rate_limit(_fetch)

    @server.tool(name="get_sleep", title="Get one sleep", annotations=READ_ONLY)
    async def get_sleep(sleep_id: str, ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Return a single sleep by its v2 UUID."""
        app = ctx.request_context.lifespan_context

        async def _fetch() -> dict[str, Any]:
            record = await app.client.get_sleep(sleep_id)
            return _trim_sleep(record)

        return await _guard_rate_limit(_fetch)

    @server.tool(name="get_workout", title="Get one workout", annotations=READ_ONLY)
    async def get_workout(workout_id: str, ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Return a single workout by its v2 UUID."""
        app = ctx.request_context.lifespan_context

        async def _fetch() -> dict[str, Any]:
            record = await app.client.get_workout(workout_id)
            return _trim_workout(record)

        return await _guard_rate_limit(_fetch)


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
