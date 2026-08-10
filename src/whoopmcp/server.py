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
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import ToolAnnotations

from whoopmcp.analysis import (
    InsufficientDataError,
    correlate,
    standardized_effect_size,
    summarize,
    trend,
)
from whoopmcp.auth import Authenticator, AuthError, build_store
from whoopmcp.client import RateLimitedError, WhoopClient, build_collection_params
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


@dataclass(frozen=True, slots=True)
class Principal:
    """The identity a tool call runs as.

    Every data/analysis tool receives this through ``AppContext`` rather than
    resolving a user id itself -- see CONTRIBUTING.md: "the user is an
    argument, never ambient." Single-user today; the shape is what lets a
    second user become a change to one resolver later (#29) instead of a
    rewrite of every tool.
    """

    user_id: int


@dataclass(slots=True)
class AppContext:
    """What the server holds open for the life of the process."""

    config: Config
    auth: Authenticator
    client: WhoopClient
    principal: Principal | None = None


async def _resolve_principal(client: WhoopClient) -> Principal | None:
    """Best-effort resolve the signed-in user's identity via a live profile call.

    Must never raise: called from ``lifespan()`` at startup, where "not
    logged in yet" is the ordinary case, not a failure -- an exception here
    would crash server startup over it. Any failure, or a successful
    response missing a usable ``user_id``, resolves to "no principal yet"
    rather than propagating.
    """
    try:
        profile = await client.get_profile()
        if not isinstance(profile, dict):
            return None
        user_id = profile.get("user_id")
        if user_id is None:
            return None
        return Principal(user_id=int(user_id))
    except Exception:
        # Deliberately broad: token-store read errors like UnicodeDecodeError
        # or PermissionError, malformed JSON responses (json.JSONDecodeError),
        # a client not entered as a context manager (RuntimeError), network
        # failures, auth failures (AuthError), and user_id coercion failures
        # (ValueError/TypeError from int()) must all degrade to None, never
        # propagate, since this runs inside lifespan() and an exception there
        # crashes the whole server at startup over what is usually just "not
        # logged in yet".
        return None


@asynccontextmanager
async def lifespan(_server: MCPServer[Any]) -> AsyncIterator[AppContext]:
    """Build the config, auth and HTTP client once, and tear them down cleanly."""
    config = Config.from_env()
    auth = Authenticator(config)
    async with WhoopClient(config, auth) as client:
        principal = await _resolve_principal(client)
        logger.info("whoopmcp ready (state dir: %s)", config.state_dir)
        yield AppContext(config=config, auth=auth, client=client, principal=principal)


def _ensure_principal(app: AppContext) -> Principal:
    """Gate a data/analysis tool on an already-resolved identity.

    Deliberately not a resolver: a lazy per-call resolve would cost an extra
    ``get_profile()`` request on every data/analysis tool invocation whenever
    the principal happens to be unset, which fights issue #11's whole point
    (conserving WHOOP's rate-limit budget). Resolution happens only in
    ``lifespan()`` and after ``whoop_complete_login`` -- this just checks the
    result.
    """
    if app.principal is None:
        raise AuthError("no WHOOP identity resolved; run whoop_login to authenticate")
    return app.principal


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
        app.principal = await _resolve_principal(app.client)
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
        app.principal = None
        return (
            "Local WHOOP credentials removed. This does not revoke the "
            "authorization at WHOOP -- do that from the WHOOP app under "
            "Settings if you want the grant itself withdrawn."
        )


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
        _ensure_principal(app)

        async def _fetch() -> dict[str, Any]:
            return await app.client.get_profile()

        return await _guard_rate_limit(_fetch)

    @server.tool(name="get_body_measurement", title="Get body measurements", annotations=READ_ONLY)
    async def get_body_measurement(ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Return height in metres, weight in kilograms and max heart rate in bpm."""
        app = ctx.request_context.lifespan_context
        _ensure_principal(app)

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
        _ensure_principal(app)
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
        _ensure_principal(app)
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
        _ensure_principal(app)
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
        _ensure_principal(app)
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
        _ensure_principal(app)

        async def _fetch() -> dict[str, Any]:
            record = await app.client.get_sleep(sleep_id)
            return _trim_sleep(record)

        return await _guard_rate_limit(_fetch)

    @server.tool(name="get_workout", title="Get one workout", annotations=READ_ONLY)
    async def get_workout(workout_id: str, ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Return a single workout by its v2 UUID."""
        app = ctx.request_context.lifespan_context
        _ensure_principal(app)

        async def _fetch() -> dict[str, Any]:
            record = await app.client.get_workout(workout_id)
            return _trim_workout(record)

        return await _guard_rate_limit(_fetch)


# -- analysis --------------------------------------------------------------

#: Friendly metric name -> the collection it is sourced from.
_METRIC_COLLECTION: dict[str, str] = {
    "recovery_score": "recovery",
    "hrv": "recovery",
    "resting_heart_rate": "recovery",
    "sleep_performance": "sleep",
    "sleep_efficiency": "sleep",
    "strain": "cycle",
}

#: Collection name -> its WHOOP v2 list endpoint.
_COLLECTION_PATH: dict[str, str] = {
    "recovery": "/v2/recovery",
    "sleep": "/v2/activity/sleep",
    "cycle": "/v2/cycle",
}


def _resolve_collection(metric: str) -> str:
    """Resolve a friendly metric name to the collection it is sourced from."""
    try:
        return _METRIC_COLLECTION[metric]
    except KeyError:
        raise ValueError(f"unknown metric: {metric!r}") from None


async def _fetch_collection(
    app: AppContext, collection: str, start: str, end: str
) -> list[dict[str, Any]]:
    """Walk every page of one collection over a range via WhoopClient.paginate.

    Analysis tools need raw WHOOP records (score_state, nested score dicts)
    -- the same shape analysis.py's extract_metric/summarize/trend/correlate
    already know how to read -- not the trimmed shapes the data tools return,
    so this goes straight to paginate() rather than through list_recoveries etc.
    """
    params = build_collection_params(start=start, end=end)
    return [record async for record in app.client.paginate(_COLLECTION_PATH[collection], params)]


def _actual_range(records: Sequence[dict[str, Any]]) -> tuple[str | None, str | None]:
    """The earliest/latest created_at actually present, not the range requested --
    a truncated page or a sparse collection covers less than what was asked for.
    """
    timestamps = sorted(r["created_at"] for r in records if r.get("created_at"))
    if not timestamps:
        return None, None
    return timestamps[0], timestamps[-1]


async def _summarize_window(
    app: AppContext, start: str, end: str
) -> tuple[dict[str, Any], tuple[str | None, str | None], int]:
    """Fetch each of the 3 collections once, then analysis.summarize per metric.

    6 metrics share only 3 collections -- fetching once per metric here would
    be 6 requests instead of 3, and summarize_period's whole point is not
    doing that. A metric whose collection can't produce enough SCORED records
    for analysis.summarize gets its own {"error": "insufficient_data", ...}
    entry rather than failing the other 5 metrics that DID have enough data.
    """
    expected_days = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).days
    records_by_collection = {
        collection: await _fetch_collection(app, collection, start, end)
        for collection in ("recovery", "sleep", "cycle")
    }
    summaries: dict[str, Any] = {}
    for metric, collection in _METRIC_COLLECTION.items():
        records = records_by_collection[collection]
        try:
            result = summarize(records, metric, expected_days=expected_days)
        except InsufficientDataError as exc:
            summaries[metric] = {"error": "insufficient_data", "message": str(exc)}
            continue
        summaries[metric] = {
            "mean": result.mean,
            "stdev": result.stdev,
            "minimum": result.minimum,
            "maximum": result.maximum,
            "median": result.median,
            "days_missing": result.days_missing,
            "count": result.count,
        }
    all_records = [r for records in records_by_collection.values() for r in records]
    return summaries, _actual_range(all_records), expected_days


def _period_length_note(baseline_days: int, comparison_days: int) -> str | None:
    """Explain when a period's length isn't a whole number of weeks.

    A period that doesn't span whole weeks can over- or under-represent
    weekdays vs. weekends relative to the other period, which confounds a
    delta between the two. Returns ``None`` when both periods are a multiple
    of 7 days.
    """
    baseline_ok = baseline_days % 7 == 0
    comparison_ok = comparison_days % 7 == 0
    if baseline_ok and comparison_ok:
        return None
    if not baseline_ok and not comparison_ok:
        detail = "neither is a multiple of 7"
    elif not baseline_ok:
        detail = "baseline is not a multiple of 7"
    else:
        detail = "comparison is not a multiple of 7"
    return (
        f"baseline is {baseline_days} days, comparison is {comparison_days} days -- "
        f"{detail}, so weekday/weekend proportions may not be comparable"
    )


def _register_analysis_tools(server: MCPServer[AppContext]) -> None:
    @server.tool(name="summarize_period", title="Summarise a period", annotations=READ_ONLY)
    async def summarize_period(
        start: str, end: str, ctx: Context[AppContext, Any]
    ) -> dict[str, Any]:
        """Summarise recovery, sleep and strain over a date range.

        Returns mean, standard deviation, median, min and max for each
        metric, along with the number of scored records behind each figure
        and ``days_missing`` -- how many calendar days in the range have no
        scored record for that metric, a coverage gap rather than a record
        count.

        Args:
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
        """
        app = ctx.request_context.lifespan_context
        _ensure_principal(app)

        async def _fetch() -> dict[str, Any]:
            summaries, (range_start, range_end), _expected_days = await _summarize_window(
                app, start, end
            )
            return {"summaries": summaries, "period": {"start": range_start, "end": range_end}}

        return await _guard_rate_limit(_fetch)

    @server.tool(name="metric_trend", title="Trend of one metric", annotations=READ_ONLY)
    async def metric_trend(
        metric: str, start: str, end: str, ctx: Context[AppContext, Any]
    ) -> dict[str, Any]:
        """Compute the direction and rate of change of one metric over a range.

        Args:
            metric: One of "recovery_score", "hrv", "resting_heart_rate",
                "sleep_performance", "sleep_efficiency", "strain".
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.

        Returns the least-squares slope in metric units per day. A slope is a
        description of the window requested, not a forecast.
        """
        app = ctx.request_context.lifespan_context
        _ensure_principal(app)

        async def _fetch() -> dict[str, Any]:
            collection = _resolve_collection(metric)
            records = await _fetch_collection(app, collection, start, end)
            try:
                result = trend(records, metric)
            except InsufficientDataError as exc:
                return {"error": "insufficient_data", "message": str(exc)}
            range_start, range_end = _actual_range(records)
            return {
                "metric": result.metric,
                "count": result.count,
                "slope_per_day": result.slope_per_day,
                "first": result.first,
                "last": result.last,
                "period": {"start": range_start, "end": range_end},
            }

        return await _guard_rate_limit(_fetch)

    @server.tool(name="correlate_metrics", title="Correlate two metrics", annotations=READ_ONLY)
    async def correlate_metrics(
        metric_a: str, metric_b: str, start: str, end: str, ctx: Context[AppContext, Any]
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
        """
        app = ctx.request_context.lifespan_context
        _ensure_principal(app)

        async def _fetch() -> dict[str, Any]:
            collection_a = _resolve_collection(metric_a)
            collection_b = _resolve_collection(metric_b)
            records_a = await _fetch_collection(app, collection_a, start, end)
            # Two metrics can share a collection (e.g. recovery_score and hrv are
            # both "recovery") -- fetch it once and reuse rather than twice.
            records_b = (
                records_a
                if collection_b == collection_a
                else await _fetch_collection(app, collection_b, start, end)
            )
            try:
                result = correlate(records_a, metric_a, records_b, metric_b)
            except InsufficientDataError as exc:
                return {"error": "insufficient_data", "message": str(exc)}
            return {
                "metric_a": result.metric_a,
                "metric_b": result.metric_b,
                "count": result.count,
                "r": result.r,
            }

        return await _guard_rate_limit(_fetch)

    @server.tool(name="compare_periods", title="Compare two periods", annotations=READ_ONLY)
    async def compare_periods(
        baseline_start: str,
        baseline_end: str,
        comparison_start: str,
        comparison_end: str,
        ctx: Context[AppContext, Any],
    ) -> dict[str, Any]:
        """Compare every summary metric between a baseline period and a later one.

        Useful for "did the training block change anything" questions. Returns
        both periods' summaries and the delta, with sample sizes.

        Args:
            baseline_start: ISO 8601 start of the baseline period.
            baseline_end: ISO 8601 end of the baseline period.
            comparison_start: ISO 8601 start of the comparison period.
            comparison_end: ISO 8601 end of the comparison period.
        """
        app = ctx.request_context.lifespan_context
        _ensure_principal(app)

        async def _fetch() -> dict[str, Any]:
            # Sequential, not concurrent (no asyncio.gather): each window's fetch
            # completes before the next window's starts.
            baseline_summaries, baseline_range, baseline_expected_days = await _summarize_window(
                app, baseline_start, baseline_end
            )
            (
                comparison_summaries,
                comparison_range,
                comparison_expected_days,
            ) = await _summarize_window(app, comparison_start, comparison_end)
            delta: dict[str, Any] = {}
            for metric in _METRIC_COLLECTION:
                b = baseline_summaries[metric]
                c = comparison_summaries[metric]
                if "error" in b or "error" in c:
                    delta[metric] = {"error": "insufficient_data"}
                    continue
                try:
                    effect_size: float | None = standardized_effect_size(
                        b["mean"], b["stdev"], b["count"], c["mean"], c["stdev"], c["count"]
                    )
                except InsufficientDataError:
                    effect_size = None
                coverage_b = (
                    1 - b["days_missing"] / baseline_expected_days
                    if baseline_expected_days
                    else 0.0
                )
                coverage_c = (
                    1 - c["days_missing"] / comparison_expected_days
                    if comparison_expected_days
                    else 0.0
                )
                delta[metric] = {
                    "delta_mean": c["mean"] - b["mean"],
                    "effect_size": effect_size,
                    "coverage_asymmetric": abs(coverage_b - coverage_c) > 0.5,
                }
            return {
                "baseline": {
                    "summary": baseline_summaries,
                    "period": {"start": baseline_range[0], "end": baseline_range[1]},
                },
                "comparison": {
                    "summary": comparison_summaries,
                    "period": {"start": comparison_range[0], "end": comparison_range[1]},
                },
                "delta": delta,
                "period_length_note": _period_length_note(
                    baseline_expected_days, comparison_expected_days
                ),
            }

        return await _guard_rate_limit(_fetch)
