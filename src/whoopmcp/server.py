"""The MCP server: tool definitions and their wiring.

Built on the SDK's ``MCPServer``; every tool is read-only. Docstrings here
are prompt surface -- the model reads them when deciding what to call.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hmac
import json
import logging
import sqlite3
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import principal_components
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ResourceNotFoundError
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

from whoopmcp import metrics, store
from whoopmcp.analysis import (
    _METRIC_PATHS,  # reused for whoop_timeseries (#20), not duplicated
    DEFAULT_LAG_SWEEP,
    MIN_EFFECT_SAMPLES,
    InsufficientDataError,
    RollingPoint,
    context_window,
    correlate_lag_sweep,
    find_streaks,
    mean,
    rolling_z_scores,
    standardized_effect_size,
    stdev,
    summarize,
    trend,
)
from whoopmcp.auth import Authenticator, AuthError, build_store
from whoopmcp.client import WhoopClient
from whoopmcp.config import Config
from whoopmcp.context_budget import (
    ROLLING_MAX_POINTS_PER_SERIES,
    shape_rolling_series,
    strip_nulls,
)
from whoopmcp.store import open_store
from whoopmcp.sync import SyncDisabledError, run_sync
from whoopmcp.webhook_processor import _consume_webhooks
from whoopmcp.webhooks import register_webhook_routes

logger = logging.getLogger("whoopmcp")

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=True)

#: whoop_sync (#15) writes to the local store, so read_only_hint=True would be
#: wrong; every write is an idempotent upsert.
SYNCS_LOCAL_STORE = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=True
)

INSTRUCTIONS = """\
Read-only access to the signed-in user's own WHOOP data: recovery, sleep,
strain, cycles and workouts.

Every data and analysis tool below answers from a local, persistent store
(``WHOOPMCP_CACHE=true``, off by default -- see PRIVACY.md), not from a live
WHOOP call: this makes ordinary reads cost zero WHOOP API requests, but it
also means the store has to actually hold the data first. ``whoop_sync``
(and, for a brand-new user, the operator-run ``whoopmcp backfill`` CLI
command) is what fills it; a miss is never silently retried against the live
API. Call ``whoop_data_coverage`` first when in doubt about what is held --
every other tool's own response also carries a "coverage" (and, for a
date-range tool, "range_coverage") field describing exactly what backs its
answer, so "no records" and "not imported yet" are never confused.

Guidance:
- Timestamps are ISO 8601 UTC. Ask for an explicit date range; unbounded
  history is still a large context-window cost even though it no longer
  costs a live rate-limit budget.
- A WHOOP "cycle" is a physiological day, which does not align with midnight.
  Join sleep and recovery to strain through cycle_id, not calendar date.
  Exception: correlate_metrics' lag sweep matches by calendar date instead,
  since a lag is fundamentally a date shift -- its lag values are
  day-to-day, not cycle-to-cycle, and can land one lag off from what
  cycle_id-based reasoning would predict.
- Records carry a score_state; only "SCORED" records have usable scores.
- This is wellness data, not clinical data. Report what the numbers say and
  their sample size. Do not diagnose, and do not present a correlation over
  a few weeks as a causal finding.
"""


@dataclass(frozen=True, slots=True)
class Principal:
    """The identity a tool call runs as.

    Passed through ``AppContext`` rather than resolved per-call; see
    CONTRIBUTING.md ("the user is an argument, never ambient").
    """

    user_id: int


@dataclass(slots=True)
class AppContext:
    """What the server holds open for the life of the process."""

    config: Config
    auth: Authenticator
    client: WhoopClient
    principal: Principal | None = None
    #: Persistent store opened by lifespan() (#13); None only if never opened.
    store_conn: sqlite3.Connection | None = None


async def _resolve_principal(client: WhoopClient) -> Principal | None:
    """Best-effort resolve the signed-in user's identity via a live profile call.

    Must never raise: called from lifespan() at startup, where "not logged
    in yet" is normal. Any failure degrades to None, never propagates.
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
        # Deliberately broad: must degrade to None, never propagate -- this
        # runs inside lifespan(), where an exception crashes server startup.
        return None


@asynccontextmanager
async def lifespan(_server: MCPServer[Any]) -> AsyncIterator[AppContext]:
    """Build the config, auth and HTTP client once, and tear them down cleanly.

    Under streamable-http with multiple workers, each process gets its own
    Authenticator, so refreshes aren't serialised across them; a cross-process
    lock was deliberately not added here (see create_streamable_http_app).

    Opens the store (#13): in-memory for default stdio (no WHOOPMCP_CACHE, no
    webhooks -- PRIVACY.md promises nothing but the token persists), on disk
    otherwise (#74). Starts the webhook consumer task (#18) when
    webhooks_enabled and a queue was stashed on the server by build_server().
    """
    config = Config.from_env()
    auth = Authenticator(config)
    async with WhoopClient(config, auth) as client:
        principal = await _resolve_principal(client)
        logger.info("whoopmcp ready (state dir: %s)", config.state_dir)

        ephemeral = config.store_is_ephemeral
        store_conn = open_store(":memory:" if ephemeral else config.cache_path)
        if ephemeral and principal is not None:
            # Seed the principal<->member link an ephemeral store can't
            # inherit across restarts; without it every tool raises (#29).
            client_id, issuer, subject = _principal_key(None)
            store.link_principal_to_member(
                store_conn,
                client_id=client_id,
                issuer=issuer,
                subject=subject,
                whoop_user_id=principal.user_id,
            )
        queue: asyncio.Queue[bytes] | None = getattr(_server, "_webhook_queue", None)
        consumer_task: asyncio.Task[None] | None = None
        if config.webhooks_enabled and queue is not None:
            consumer_task = asyncio.create_task(_consume_webhooks(queue, store_conn, client))

        try:
            yield AppContext(
                config=config, auth=auth, client=client, principal=principal, store_conn=store_conn
            )
        finally:
            if consumer_task is not None:
                consumer_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    # Awaited for the side effect (blocks until cancellation
                    # finishes); mypy misfires on this assignment.
                    _ = await consumer_task  # type: ignore[func-returns-value]
            store_conn.close()


def _ensure_principal(app: AppContext) -> Principal:
    """Gate a data/analysis tool on an already-resolved identity.

    Not a resolver: a lazy per-call resolve would cost an extra get_profile()
    request per invocation, fighting #11's rate-limit budget. Resolution
    happens only in lifespan() and after whoop_complete_login.
    """
    if app.principal is None:
        raise AuthError("no WHOOP identity resolved; run whoop_login to authenticate")
    return app.principal


class UnresolvedPrincipalError(RuntimeError):
    """A known principal has no WHOOP member linked to it.

    Distinct from ``AuthError`` ("nobody is logged in"). Raised by
    ``resolve_member_id`` and ``_ensure_matches_live_grant``; never
    resolved by defaulting to some other member.
    """


#: Fixed principal key for stdio/no-bearer-auth deployments: one login links
#: this sentinel to a member rather than inventing per-connection identity.
_LOCAL_PRINCIPAL_CLIENT_ID = "__local__"


def _principal_key(request: Any | None) -> tuple[str, str | None, str | None]:
    """The (client_id, issuer, subject) triple identifying `request`'s caller.

    Reads only request.user (a verified bearer token's identity), never
    query_params or headers -- those are caller-supplied smuggling vectors.
    `request` is None under stdio or before auth is wired; both fall back
    to the fixed local sentinel.
    """
    user = getattr(request, "user", None) if request is not None else None
    if isinstance(user, AuthenticatedUser):
        return principal_components(user.access_token)
    return _LOCAL_PRINCIPAL_CLIENT_ID, None, None


def _tool_name(ctx: Context[AppContext, Any]) -> str:
    """The name of the tool or resource this call is invoking, for the audit log.

    params is a plain Mapping in production but a typed request object in
    tests; both carry "name" (tools) or "uri" (resources) via a different
    access pattern. Falls back to uri since a resource read has no name.
    """
    params = ctx.request_context.params
    if isinstance(params, Mapping):
        name = params.get("name") or params.get("uri")
    else:
        name = getattr(params, "name", None) or getattr(params, "uri", None)
    return str(name) if name is not None else "<unknown>"


def resolve_member_id(ctx: Context[AppContext, Any]) -> int:
    """Resolve the calling MCP principal to a WHOOP member id, once, at the edge.

    The one join point between an MCP principal and a WHOOP member: every
    data/analysis tool calls this once via ``_ensure_matches_live_grant`` and
    threads the id through rather than re-resolving. Reads only
    principal_members (via ``_principal_key``, never caller-supplied data)
    and audits the call in the same step, so resolving without auditing is
    structurally impossible.

    Raises:
        RuntimeError: store_conn is None (only if AppContext is built
            outside lifespan()).
        UnresolvedPrincipalError: no principal_members row links this
            caller to a member.
    """
    app = ctx.request_context.lifespan_context
    if app.store_conn is None:
        raise RuntimeError(
            "resolve_member_id requires a persistent store (AppContext.store_conn must be set); "
            "this is always opened by lifespan(), so this error only occurs if AppContext is "
            "constructed outside lifespan(). Ensure lifespan() is called or open a store "
            "before calling this function."
        )

    client_id, issuer, subject = _principal_key(ctx.request_context.request)
    whoop_user_id = store.get_member_for_principal(
        app.store_conn, client_id=client_id, issuer=issuer, subject=subject
    )
    if whoop_user_id is None:
        raise UnresolvedPrincipalError(
            f"no WHOOP member is linked to principal {client_id!r}; "
            "run whoop_login and whoop_complete_login to authorise one"
        )
    store.record_tool_call(app.store_conn, whoop_user_id, _tool_name(ctx))
    return whoop_user_id


def _ensure_matches_live_grant(ctx: Context[AppContext, Any]) -> int:
    """Gate a live-WHOOP-client tool on the resolved identity matching this
    process's one live grant, and return the resolved member id.

    Every tool calls the single process-wide WhoopClient; there is no
    per-member routing yet, so a mismatched resolved member is refused here
    rather than silently served by the wrong grant.
    """
    app = ctx.request_context.lifespan_context
    whoop_user_id = resolve_member_id(ctx)
    principal = _ensure_principal(app)
    if whoop_user_id != principal.user_id:
        raise UnresolvedPrincipalError(
            f"resolved WHOOP member {whoop_user_id} does not match this "
            f"process's live WHOOP grant (member {principal.user_id}); "
            "concurrent live access for more than one member is not supported yet"
        )
    return whoop_user_id


async def _check_token_store_reachable() -> tuple[bool, str]:
    """Readiness check: the configured token store can be read without raising.

    Builds its own Config.from_env() since a custom_route handler has no
    access to the lifespan-resolved AppContext. A clean "not logged in yet"
    (None) counts as ready; only a genuine read failure does not. Runs in a
    thread so a slow store can't stall the event loop. Reports only the
    exception's type, never its message (may leak the token file's path).
    """
    try:
        await asyncio.to_thread(build_store(Config.from_env()).load)
    except Exception as exc:
        return False, type(exc).__name__
    return True, "ok"


#: Named, independent readiness checks: add a (name, check) pair here rather
#: than restructuring the /ready handler.
_READINESS_CHECKS: list[tuple[str, Callable[[], Awaitable[tuple[bool, str]]]]] = [
    ("token_store_reachable", _check_token_store_reachable),
]


def _register_health_routes(server: MCPServer[AppContext]) -> None:
    """Liveness and readiness for the streamable-http transport (#27).

    Plain HTTP via custom_route, not MCP tools, so a load balancer can poll
    without an MCP client. Only reachable under streamable-http. Just
    liveness/readiness -- the OAuth callback and webhook receiver (#17) are
    registered elsewhere.
    """

    @server.custom_route("/health", methods=["GET"])
    async def health(_request: Request) -> Response:
        # Liveness = "process can respond"; must not touch AppContext/lifespan.
        return JSONResponse({"status": "ok"})

    @server.custom_route("/ready", methods=["GET"])
    async def ready(_request: Request) -> Response:
        checks: list[dict[str, Any]] = []
        all_ok = True
        for name, check in _READINESS_CHECKS:
            ok, detail = await check()
            checks.append({"name": name, "ok": ok, "detail": detail})
            all_ok = all_ok and ok
        return JSONResponse(
            {"ready": all_ok, "checks": checks},
            status_code=200 if all_ok else 503,
        )


def _register_metrics_route(server: MCPServer[AppContext]) -> None:
    """``GET /metrics``: Prometheus exposition for issue #31.

    Reads Config fresh per request (no lifespan AppContext available in a
    custom_route handler), opening/closing its own store connection. Fails
    closed: no WHOOPMCP_METRICS_TOKEN -> 404 (byte-for-byte Starlette's own
    404, so the route isn't advertised); token set but Authorization
    missing/wrong -> 401, compared with hmac.compare_digest.
    """

    @server.custom_route("/metrics", methods=["GET"])
    async def metrics_endpoint(request: Request) -> Response:
        config = Config.from_env()
        if not config.metrics_token:
            # Matches Starlette's own 404 body byte-for-byte so this route's
            # existence isn't confirmed by a differing response.
            return PlainTextResponse("Not Found", status_code=404)

        provided = request.headers.get("Authorization", "")
        expected = f"Bearer {config.metrics_token}"
        # isascii() guard: hmac.compare_digest raises TypeError on non-ASCII,
        # which a caller could send since Starlette decodes headers as latin-1.
        if not (provided.isascii() and hmac.compare_digest(provided, expected)):
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        conn = open_store(config.cache_path)
        try:
            text = metrics.render(conn, config)
        finally:
            conn.close()
        return Response(text, media_type="text/plain; version=0.0.4; charset=utf-8")


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
    _register_prompts(server)
    _register_resources(server)
    _register_health_routes(server)
    _register_metrics_route(server)
    # Stashed on the server instance so lifespan() can read it back via
    # getattr to start the webhook consumer task (#18).
    server._webhook_queue = register_webhook_routes(server)  # type: ignore[attr-defined]
    return server


def create_streamable_http_app() -> Starlette:
    """ASGI app factory for running whoopmcp under multiple uvicorn workers (#27).

    Usage: ``uvicorn "whoopmcp.server:create_streamable_http_app" --factory
    --workers 4 --port 8000``. Only ``config.http_host`` feeds in here; port
    is a uvicorn concern, passed via ``--port``.

    **Known limitation**: each worker gets its own Authenticator, and no
    token refresh is serialised across them -- two workers can each refresh
    the same about-to-rotate token, forcing a re-login. Run one worker for
    token refresh until resolved (#12/#27).
    """
    config = Config.from_env()
    return build_server().streamable_http_app(host=config.http_host)


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
        if app.principal is not None and app.store_conn is not None:
            # The only writer of principal_members (#29): a completed
            # authorisation only, never a header or caller-supplied id.
            client_id, issuer, subject = _principal_key(ctx.request_context.request)
            store.link_principal_to_member(
                app.store_conn,
                client_id=client_id,
                issuer=issuer,
                subject=subject,
                whoop_user_id=app.principal.user_id,
            )
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
        under Settings, or with the CLI-only `whoopmcp delete-member`, which
        cannot be called as a tool.
        """
        # Docstring kept short: it is sent on every tools/list. Fuller detail
        # lives in the return value below, which costs nothing until called.
        app = ctx.request_context.lifespan_context
        app.auth.logout()
        app.principal = None
        return (
            "Local WHOOP credentials removed. This does not revoke the "
            "authorization at WHOOP -- do that from the WHOOP app under "
            "Settings, or run `whoopmcp delete-member --whoop-user-id N` "
            "from a terminal on this machine (a CLI-only operator command, "
            "not a tool call), if you want the grant itself withdrawn."
        )


# -- raw data --------------------------------------------------------------

#: Default lookback for the four list tools when the caller gives neither
#: end of the range.
_DEFAULT_LOOKBACK = timedelta(days=7)


#: Response-shape convention (#16): every response carries "coverage" keyed
#: by entity name(s); every range-taking tool also carries "range_coverage"
#: (same keys, each a flat {status, message} entry). Point/singleton lookups
#: (get_sleep, get_workout, get_profile, get_body_measurement) carry
#: "coverage" only, never "range_coverage".


def _require_store(app: AppContext) -> sqlite3.Connection:
    """The persistent store every data/analysis tool reads from.

    ``_ensure_matches_live_grant`` already raises before this is reached if
    store_conn is None; this exists only so mypy can narrow the type.
    """
    if app.store_conn is None:
        raise RuntimeError(
            "this tool requires a persistent store (AppContext.store_conn must be set); "
            "this is always opened by lifespan(), so this error only occurs if AppContext "
            "is constructed outside that context"
        )
    return app.store_conn


def _iso(value: datetime | str | None) -> str | None:
    """``value`` as one canonical ISO 8601 UTC string: ``...THH:MM:SS.mmmZ``.

    The store compares range bounds against stored timestamps as TEXT, so a
    caller's string and a datetime must come out in the exact shape WHOOP's
    own millisecond ``Z`` form uses -- an offset form (e.g. ``+00:00``) sorts
    wrong against it, off by as much as the offset itself (#174).
    """
    if value is None:
        return None
    moment = value if isinstance(value, datetime) else _parse_iso(value)
    moment = moment.astimezone(UTC)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{moment.microsecond // 1000:03d}Z"


#: Collection entity -> the store's (earliest, latest) coverage query. Keys
#: are the store's table names, matching every coverage envelope's keys.
_COLLECTION_COVERAGE_FN: dict[
    str, Callable[[sqlite3.Connection, int], tuple[str | None, str | None]]
] = {
    "recoveries": store.get_recovery_coverage,
    "sleeps": store.get_sleep_coverage,
    "cycles": store.get_cycle_coverage,
    "workouts": store.get_workout_coverage,
}

#: Friendly collection name (_METRIC_COLLECTION's values) -> store table
#: name; coverage envelopes key by table name, never the friendly name.
_COLLECTION_TO_ENTITY: dict[str, str] = {
    "recovery": "recoveries",
    "sleep": "sleeps",
    "cycle": "cycles",
}

_COLLECTION_GETTER: dict[str, Callable[..., list[dict[str, Any]]]] = {
    "recovery": store.get_recoveries,
    "sleep": store.get_sleeps,
    "cycle": store.get_cycles,
}


def _entity_coverage(conn: sqlite3.Connection, whoop_user_id: int, entity: str) -> dict[str, Any]:
    """The coverage envelope for one of the four collection entities.

    ``{"earliest": iso|None, "latest": iso|None, "backfill": {...},
    "incremental_sync": {...}}``. earliest/latest come from the entity's own
    activity-date columns, never ``updated_at``. ``last_successful_at`` is
    only set when the incremental row's own outcome is "complete".
    """
    earliest, latest = _COLLECTION_COVERAGE_FN[entity](conn, whoop_user_id)
    backfill_state = store.get_sync_state(conn, whoop_user_id, entity)
    incremental_state = store.get_sync_state(conn, whoop_user_id, f"{entity}:incremental")
    return {
        "earliest": earliest,
        "latest": latest,
        "backfill": {
            "status": backfill_state["outcome"] if backfill_state is not None else "never_run",
            "last_run_at": backfill_state["last_run_at"] if backfill_state is not None else None,
        },
        "incremental_sync": {
            "status": incremental_state["outcome"]
            if incremental_state is not None
            else "never_run",
            "last_successful_at": (
                incremental_state["last_run_at"]
                if incremental_state is not None and incremental_state["outcome"] == "complete"
                else None
            ),
        },
    }


def _singleton_coverage(updated_at: str | None) -> dict[str, Any]:
    """Coverage envelope for a singleton (profile/body measurement):
    ``{"synced": bool, "last_updated_at": iso|None}`` -- neither has an
    activity range to report, unlike ``_entity_coverage``."""
    return {"synced": updated_at is not None, "last_updated_at": updated_at}


def _parse_iso(value: str) -> datetime:
    """Parse a timestamp, accepting a trailing Z, a +00:00 offset, or a bare
    offset-less string.

    A naive string (no offset) is treated as UTC rather than raised, since a
    model dropping the offset is plausible input, not malicious.
    """
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _range_status(
    earliest: str | None, latest: str | None, start: str | None, end: str | None
) -> tuple[str, str | None]:
    """Compare a requested [start, end] against a held [earliest, latest]
    coverage window, returning one of four statuses plus a message for any
    status but "within_coverage".
    """
    if earliest is None or latest is None:
        return "no_data_synced_yet", (
            "Nothing has ever been synced for this entity; run whoop_sync "
            "(after an initial backfill) before requesting a range."
        )
    held_earliest, held_latest = _parse_iso(earliest), _parse_iso(latest)

    # Handle one-sided range: only end specified
    if start is None and end is not None:
        req_end = _parse_iso(end)
        if req_end < held_earliest:
            return "wholly_outside_coverage", (
                f"The requested range ends at {end}, which is before the earliest held record "
                f"({earliest}) for this entity."
            )
        if req_end > held_latest:
            return "partly_outside_coverage", (
                f"The requested range ends after the coverage window held for this entity "
                f"({earliest} to {latest}); results below reflect only what has been synced."
            )
        return "within_coverage", None

    # Handle one-sided range: only start specified
    if end is None and start is not None:
        req_start = _parse_iso(start)
        if req_start > held_latest:
            return "wholly_outside_coverage", (
                f"The requested range starts at {start}, which is after the latest held record "
                f"({latest}) for this entity."
            )
        if req_start < held_earliest:
            return "partly_outside_coverage", (
                f"The requested range starts before the coverage window held for this entity "
                f"({earliest} to {latest}); results below reflect only what has been synced."
            )
        return "within_coverage", None

    # Both are None or both are specified; both are None only if _default_range was
    # skipped (e.g., continuation pages that don't reset bounds).
    if start is None or end is None:
        # Both are None - no meaningful comparison
        return "within_coverage", None

    # Both start and end are specified
    req_start, req_end = _parse_iso(start), _parse_iso(end)
    if req_end < held_earliest or req_start > held_latest:
        return "wholly_outside_coverage", (
            f"The requested range ({start} to {end}) does not overlap the coverage window "
            f"held for this entity ({earliest} to {latest})."
        )
    if req_start < held_earliest or req_end > held_latest:
        return "partly_outside_coverage", (
            f"The requested range ({start} to {end}) extends beyond the coverage window held "
            f"for this entity ({earliest} to {latest}); results below reflect only what has "
            "been synced."
        )
    return "within_coverage", None


def _range_coverage_entry(
    earliest: str | None, latest: str | None, start: str | None, end: str | None
) -> dict[str, Any]:
    """One entity's ``range_coverage`` entry: ``{"status": ..., "message":
    ...}``, with ``"message"`` present only when ``status`` is not
    ``"within_coverage"`` -- see ``_range_status``."""
    status, message = _range_status(earliest, latest, start, end)
    entry: dict[str, Any] = {"status": status}
    if message is not None:
        entry["message"] = message
    return entry


#: Worst-to-best ordering _merge_range_coverage picks from; lower is worse.
_RANGE_STATUS_PRIORITY: dict[str, int] = {
    "no_data_synced_yet": 0,
    "wholly_outside_coverage": 1,
    "partly_outside_coverage": 2,
    "within_coverage": 3,
}


def _merge_range_coverage(entries: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Reconcile more than one ``_range_coverage_entry`` for the same entity
    (e.g. compare_periods' baseline and comparison windows) into the one
    flat entry every range tool's own ``range_coverage`` reports -- the
    worse status of the two, with every distinct message carried along."""
    worst_status = min(entries, key=lambda entry: _RANGE_STATUS_PRIORITY[entry["status"]])["status"]
    messages = [entry["message"] for entry in entries if "message" in entry]
    merged: dict[str, Any] = {"status": worst_status}
    if messages:
        merged["message"] = " ".join(dict.fromkeys(messages))
    return merged


def _with_created_at_fallback(record: dict[str, Any]) -> dict[str, Any]:
    """``record``, guaranteed to carry a ``created_at`` key.

    Real WHOOP payloads always have it; this only matters for a record
    written some other way, falling back to ``start``.
    """
    if record.get("created_at") is not None:
        return record
    return {**record, "created_at": record.get("start")}


#: SQLite's signed-64-bit parameter limit, not a product decision; above it
#: sqlite3 raises OverflowError from inside parameter binding.
_MAX_CURSOR_OFFSET = 2**63 - 1

#: The single message every rejected cursor gets. A constant so the "identical
#: for every case" property cannot drift as raise sites are added.
_CURSOR_REJECTED = "next_token is not a valid pagination cursor"


def _decode_store_cursor(next_token: str | None) -> tuple[int, str | None, str | None]:
    """This module's opaque store-pagination cursor: ``(offset, start, end)``.

    base64-encoded (not bare JSON) because the SDK's ``pre_parse_json``
    would otherwise try ``json.loads`` on a plain string field. No cursor
    (first page) is ``(0, None, None)``. Every malformed or out-of-range
    cursor raises one identical, caller-opaque ``ValueError`` (#179).
    """
    if next_token is None:
        return 0, None, None

    try:
        payload = json.loads(base64.urlsafe_b64decode(next_token.encode("ascii")).decode("utf-8"))
        offset, start, end = payload["offset"], payload["start"], payload["end"]
    except (
        # ValueError covers binascii/Unicode/JSON decode errors; KeyError is a
        # missing field; TypeError is indexing a non-dict decoded payload.
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError(_CURSOR_REJECTED) from exc

    # Types checked, not coerced: int(payload["offset"]) would accept
    # Infinity/"12"/2.9/true, and bool must be excluded (an int subclass).
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError(_CURSOR_REJECTED)
    if not 0 <= offset <= _MAX_CURSOR_OFFSET:
        raise ValueError(_CURSOR_REJECTED)
    if not all(bound is None or isinstance(bound, str) for bound in (start, end)):
        raise ValueError(_CURSOR_REJECTED)

    return offset, start, end


def _encode_store_cursor(offset: int, start: str | None, end: str | None) -> str:
    payload = json.dumps({"offset": offset, "start": start, "end": end})
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


#: Ceiling on a list tool's limit. Its own constant (not shared with
#: _ANALYSIS_MAX_RECORDS) since they bound different things.
_MAX_LIST_LIMIT = 1000


def _require_positive_limit(limit: int) -> None:
    """Bound a list tool's ``limit`` at both ends before it reaches a store query.

    ``limit=0`` would produce a next_token identical to the one that led to
    it -- an infinite-continuation loop. The upper bound (#173) keeps a list
    tool pageable and prevents overflow at the store: limit + 1 must still
    fit SQLite's bind range.
    """
    if limit <= 0:
        raise ValueError(f"limit must be a positive integer, got {limit}")
    if limit > _MAX_LIST_LIMIT:
        raise ValueError(f"limit must be at most {_MAX_LIST_LIMIT}, got {limit}")


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


def _trim_sleep(record: dict[str, Any], *, detail: str = "full") -> dict[str, Any]:
    """Trim a raw sleep record.

    detail="summary" (default) drops the stage-duration breakdown;
    detail="full" keeps it under "stage_durations" -- caller adds the
    sibling "units" key at the envelope level.
    """
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
        if detail == "full":
            stages = score.get("stage_summary") or {}
            trimmed["stage_durations"] = {
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


def _trim_workout(record: dict[str, Any], *, detail: str = "full") -> dict[str, Any]:
    """Trim a raw workout record.

    See _trim_sleep for the detail contract; the analogous nested field
    here is "zone_durations".
    """
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
        if detail == "full":
            zones = score.get("zone_duration") or {}
            trimmed["zone_durations"] = {
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
        """Return the user's WHOOP profile: user id, email, first and last name.

        Served from the local store, never a live call. A miss returns
        {"error": "not_synced", ...}. Every response carries a "coverage" key.
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        record = store.get_profile(conn, whoop_user_id)
        if record is None:
            return {"error": "not_synced", "coverage": {"profile": _singleton_coverage(None)}}
        updated_at = store.get_profile_updated_at(conn, whoop_user_id)
        result = strip_nulls(record)
        result["coverage"] = {"profile": _singleton_coverage(updated_at)}
        return result

    @server.tool(name="get_body_measurement", title="Get body measurements", annotations=READ_ONLY)
    async def get_body_measurement(ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Return height in metres, weight in kilograms and max heart rate in bpm.

        Served from the local store -- see ``get_profile`` for the miss
        shape and the "coverage" envelope, which this tool carries too.
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        record = store.get_body_measurement(conn, whoop_user_id)
        if record is None:
            return {
                "error": "not_synced",
                "coverage": {"body_measurement": _singleton_coverage(None)},
            }
        updated_at = store.get_body_measurement_updated_at(conn, whoop_user_id)
        result = strip_nulls(record)
        result["coverage"] = {"body_measurement": _singleton_coverage(updated_at)}
        return result

    @server.tool(name="list_recoveries", title="List recoveries", annotations=READ_ONLY)
    async def list_recoveries(
        ctx: Context[AppContext, Any],
        start: str | None = None,
        end: str | None = None,
        limit: int = 25,
        next_token: str | None = None,
        include_raw: bool = False,
    ) -> dict[str, Any]:
        """List recovery records: recovery score (%), HRV (ms) and resting heart rate (bpm).

        Served from the local store, never a live call. Every response
        carries "coverage" (the recoveries entity's own held earliest/
        latest and sync state) and "range_coverage" (how the requested
        range compares to that window: "within_coverage",
        "partly_outside_coverage", "wholly_outside_coverage", or
        "no_data_synced_yet") -- a range wholly or partly outside what has
        been synced says so explicitly rather than returning a silently
        short list.

        Args:
            start: ISO 8601 start of the range, e.g. "2026-07-01T00:00:00Z".
                Defaults, with end, to the last 7 days when both are omitted.
            end: ISO 8601 end of the range.
            limit: Records to return per page (default 25, capped at 1000).
            next_token: Cursor from a previous truncated response, to
                continue that page.
            include_raw: When true, each record additionally carries a
                "raw" key with the complete stored record, beyond the
                curated fields below.
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        _require_positive_limit(limit)
        offset, range_start, range_end = _decode_store_cursor(next_token)
        if next_token is None:
            resolved_start, resolved_end = _default_range(start, end, None)
            range_start, range_end = _iso(resolved_start), _iso(resolved_end)

        rows = store.get_recoveries(
            conn, whoop_user_id, start=range_start, end=range_end, limit=limit + 1, offset=offset
        )
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        records = []
        for raw in page_rows:
            trimmed = strip_nulls(_trim_recovery(raw))
            if include_raw:
                trimmed["raw"] = raw
            records.append(trimmed)
        result: dict[str, Any] = {"records": records, "count": len(records), "next_token": None}  # nosec B105 -- the literal None (no next page yet), not a credential value
        if has_more:
            result["next_token"] = _encode_store_cursor(offset + limit, range_start, range_end)
            result["note"] = (
                f"Only {len(records)} record(s) in this range were returned; more are held "
                f"locally. Pass next_token={result['next_token']!r} to this tool to continue, "
                "or narrow the date range."
            )
        coverage = _entity_coverage(conn, whoop_user_id, "recoveries")
        result["coverage"] = {"recoveries": coverage}
        result["range_coverage"] = {
            "recoveries": _range_coverage_entry(
                coverage["earliest"], coverage["latest"], range_start, range_end
            )
        }
        return result

    @server.tool(name="list_sleeps", title="List sleeps", annotations=READ_ONLY)
    async def list_sleeps(
        ctx: Context[AppContext, Any],
        start: str | None = None,
        end: str | None = None,
        limit: int = 25,
        next_token: str | None = None,
        detail: Literal["summary", "full"] = "summary",
        include_raw: bool = False,
    ) -> dict[str, Any]:
        """List sleep records: performance (%), efficiency, and stage durations in milliseconds.

        Served from the local store -- see ``list_recoveries`` for the
        "coverage"/"range_coverage" envelope every list_* tool carries.

        Args:
            start: ISO 8601 start of the range.
                Defaults, with end, to the last 7 days when both are omitted.
            end: ISO 8601 end of the range.
            limit: Records to return per page (default 25, capped at 1000).
            next_token: Cursor from a previous truncated response, to
                continue that page.
            detail: "summary" (default) omits the per-stage sleep-duration
                breakdown to keep the response small; "full" includes it
                under "stage_durations", with the units declared once in a
                top-level "units" key.
            include_raw: When true, each record additionally carries a
                "raw" key with the complete stored record.
        """
        if detail not in ("summary", "full"):
            raise ValueError(f"detail must be 'summary' or 'full', got {detail!r}")
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        _require_positive_limit(limit)
        offset, range_start, range_end = _decode_store_cursor(next_token)
        if next_token is None:
            resolved_start, resolved_end = _default_range(start, end, None)
            range_start, range_end = _iso(resolved_start), _iso(resolved_end)

        rows = store.get_sleeps(
            conn, whoop_user_id, start=range_start, end=range_end, limit=limit + 1, offset=offset
        )
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        records = []
        for raw in page_rows:
            trimmed = strip_nulls(_trim_sleep(raw, detail=detail))
            if include_raw:
                trimmed["raw"] = raw
            records.append(trimmed)
        result: dict[str, Any] = {"records": records, "count": len(records), "next_token": None}  # nosec B105 -- the literal None (no next page yet), not a credential value
        if detail == "full":
            result["units"] = {"stage_durations": "milliseconds"}
        if has_more:
            result["next_token"] = _encode_store_cursor(offset + limit, range_start, range_end)
            result["note"] = (
                f"Only {len(records)} record(s) in this range were returned; more are held "
                f"locally. Pass next_token={result['next_token']!r} to this tool to continue, "
                "or narrow the date range."
            )
        coverage = _entity_coverage(conn, whoop_user_id, "sleeps")
        result["coverage"] = {"sleeps": coverage}
        result["range_coverage"] = {
            "sleeps": _range_coverage_entry(
                coverage["earliest"], coverage["latest"], range_start, range_end
            )
        }
        return result

    @server.tool(name="list_cycles", title="List cycles", annotations=READ_ONLY)
    async def list_cycles(
        ctx: Context[AppContext, Any],
        start: str | None = None,
        end: str | None = None,
        limit: int = 25,
        next_token: str | None = None,
        include_raw: bool = False,
    ) -> dict[str, Any]:
        """List physiological cycles: day strain (0-21), average and max heart rate, kilojoules.

        A cycle is WHOOP's notion of a day, bounded by sleep rather than by
        midnight, and is the key other records join on. Served from the
        local store -- see ``list_recoveries`` for the "coverage"/
        "range_coverage" envelope every list_* tool carries.

        Args:
            start: ISO 8601 start of the range.
                Defaults, with end, to the last 7 days when both are omitted.
            end: ISO 8601 end of the range.
            limit: Records to return per page (default 25, capped at 1000).
            next_token: Cursor from a previous truncated response, to
                continue that page.
            include_raw: When true, each record additionally carries a
                "raw" key with the complete stored record.
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        _require_positive_limit(limit)
        offset, range_start, range_end = _decode_store_cursor(next_token)
        if next_token is None:
            resolved_start, resolved_end = _default_range(start, end, None)
            range_start, range_end = _iso(resolved_start), _iso(resolved_end)

        rows = store.get_cycles(
            conn, whoop_user_id, start=range_start, end=range_end, limit=limit + 1, offset=offset
        )
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        records = []
        for raw in page_rows:
            trimmed = strip_nulls(_trim_cycle(raw))
            if include_raw:
                trimmed["raw"] = raw
            records.append(trimmed)
        result: dict[str, Any] = {"records": records, "count": len(records), "next_token": None}  # nosec B105 -- the literal None (no next page yet), not a credential value
        if has_more:
            result["next_token"] = _encode_store_cursor(offset + limit, range_start, range_end)
            result["note"] = (
                f"Only {len(records)} record(s) in this range were returned; more are held "
                f"locally. Pass next_token={result['next_token']!r} to this tool to continue, "
                "or narrow the date range."
            )
        coverage = _entity_coverage(conn, whoop_user_id, "cycles")
        result["coverage"] = {"cycles": coverage}
        result["range_coverage"] = {
            "cycles": _range_coverage_entry(
                coverage["earliest"], coverage["latest"], range_start, range_end
            )
        }
        return result

    @server.tool(name="list_workouts", title="List workouts", annotations=READ_ONLY)
    async def list_workouts(
        ctx: Context[AppContext, Any],
        start: str | None = None,
        end: str | None = None,
        limit: int = 25,
        next_token: str | None = None,
        detail: Literal["summary", "full"] = "summary",
        include_raw: bool = False,
    ) -> dict[str, Any]:
        """List workouts: sport, strain, average and max heart rate, and heart-rate zone durations.

        Served from the local store -- see ``list_recoveries`` for the
        "coverage"/"range_coverage" envelope every list_* tool carries.

        Args:
            start: ISO 8601 start of the range.
                Defaults, with end, to the last 7 days when both are omitted.
            end: ISO 8601 end of the range.
            limit: Records to return per page (default 25, capped at 1000).
            next_token: Cursor from a previous truncated response, to
                continue that page.
            detail: "summary" (default) omits the per-zone heart-rate
                duration breakdown to keep the response small; "full"
                includes it under "zone_durations", with the units declared
                once in a top-level "units" key.
            include_raw: When true, each record additionally carries a
                "raw" key with the complete stored record.
        """
        if detail not in ("summary", "full"):
            raise ValueError(f"detail must be 'summary' or 'full', got {detail!r}")
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        _require_positive_limit(limit)
        offset, range_start, range_end = _decode_store_cursor(next_token)
        if next_token is None:
            resolved_start, resolved_end = _default_range(start, end, None)
            range_start, range_end = _iso(resolved_start), _iso(resolved_end)

        rows = store.get_workouts(
            conn, whoop_user_id, start=range_start, end=range_end, limit=limit + 1, offset=offset
        )
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        records = []
        for raw in page_rows:
            trimmed = strip_nulls(_trim_workout(raw, detail=detail))
            if include_raw:
                trimmed["raw"] = raw
            records.append(trimmed)
        result: dict[str, Any] = {"records": records, "count": len(records), "next_token": None}  # nosec B105 -- the literal None (no next page yet), not a credential value
        if detail == "full":
            result["units"] = {"zone_durations": "milliseconds"}
        if has_more:
            result["next_token"] = _encode_store_cursor(offset + limit, range_start, range_end)
            result["note"] = (
                f"Only {len(records)} record(s) in this range were returned; more are held "
                f"locally. Pass next_token={result['next_token']!r} to this tool to continue, "
                "or narrow the date range."
            )
        coverage = _entity_coverage(conn, whoop_user_id, "workouts")
        result["coverage"] = {"workouts": coverage}
        result["range_coverage"] = {
            "workouts": _range_coverage_entry(
                coverage["earliest"], coverage["latest"], range_start, range_end
            )
        }
        return result

    @server.tool(name="get_sleep", title="Get one sleep", annotations=READ_ONLY)
    async def get_sleep(
        sleep_id: str, ctx: Context[AppContext, Any], include_raw: bool = False
    ) -> dict[str, Any]:
        """Return a single sleep by its v2 UUID.

        Served from the local store. A miss is ``{"error": "not_synced",
        ...}`` when no sleep has ever been synced at all, or ``{"error":
        "not_found_in_store", ...}`` when sleeps have been synced but not
        this id -- never a live fetch either way.
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        coverage = {"sleeps": _entity_coverage(conn, whoop_user_id, "sleeps")}
        if coverage["sleeps"]["earliest"] is None:
            return {"error": "not_synced", "coverage": coverage}
        record = store.get_sleep_by_id(conn, whoop_user_id, sleep_id)
        if record is None:
            return {"error": "not_found_in_store", "coverage": coverage}
        trimmed = strip_nulls(_trim_sleep(record))
        trimmed["units"] = {"stage_durations": "milliseconds"}
        if include_raw:
            trimmed["raw"] = record
        trimmed["coverage"] = coverage
        return trimmed

    @server.tool(name="get_workout", title="Get one workout", annotations=READ_ONLY)
    async def get_workout(
        workout_id: str, ctx: Context[AppContext, Any], include_raw: bool = False
    ) -> dict[str, Any]:
        """Return a single workout by its v2 UUID.

        Served from the local store -- see ``get_sleep`` for the two
        distinct miss shapes ("not_synced" vs "not_found_in_store").
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        coverage = {"workouts": _entity_coverage(conn, whoop_user_id, "workouts")}
        if coverage["workouts"]["earliest"] is None:
            return {"error": "not_synced", "coverage": coverage}
        record = store.get_workout_by_id(conn, whoop_user_id, workout_id)
        if record is None:
            return {"error": "not_found_in_store", "coverage": coverage}
        trimmed = strip_nulls(_trim_workout(record))
        trimmed["units"] = {"zone_durations": "milliseconds"}
        if include_raw:
            trimmed["raw"] = record
        trimmed["coverage"] = coverage
        return trimmed

    @server.tool(
        name="whoop_data_coverage",
        title="Report locally-held data coverage",
        annotations=READ_ONLY,
    )
    async def whoop_data_coverage(ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Report, per entity, what the local store holds and how fresh it is.

        Distinguishes "no records" (nothing happened) from "not imported
        yet". For recoveries/sleeps/cycles/workouts: earliest/latest date
        held, backfill outcome, last incremental sync. For profile/body
        measurement: whether synced, and when.
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        result: dict[str, Any] = {
            entity: _entity_coverage(conn, whoop_user_id, entity)
            for entity in ("recoveries", "sleeps", "cycles", "workouts")
        }
        result["profile"] = _singleton_coverage(store.get_profile_updated_at(conn, whoop_user_id))
        result["body_measurement"] = _singleton_coverage(
            store.get_body_measurement_updated_at(conn, whoop_user_id)
        )
        return result

    @server.tool(name="whoop_sync", title="Sync recent WHOOP data", annotations=SYNCS_LOCAL_STORE)
    async def whoop_sync(ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Pull every recovery, sleep, cycle and workout changed since the last sync.

        Walks each collection from its own high-water updated_at mark (so a
        rescored record is picked up too) and upserts into the local store;
        once caught up, costs one request per collection. Deletions upstream
        are invisible to this walk. Requires the persistent store
        (WHOOPMCP_CACHE=true); returns {"synced": False, ...} rather than
        raising when disabled.
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        if app.store_conn is None:
            # Unreachable in practice; here only so mypy can narrow the type.
            raise RuntimeError("whoop_sync requires a persistent store")

        try:
            results = await run_sync(app.store_conn, app.client, app.config, whoop_user_id)
        except SyncDisabledError as exc:
            return {"synced": False, "message": str(exc)}

        failed = sorted(name for name, result in results.items() if result.error is not None)
        entities: dict[str, Any] = {}
        for name, result in results.items():
            entities[name] = {
                "count": result.count,
                "cursor": result.high_water_mark,
                "error": result.error,
                # Surfaced so a refused-cursor run doesn't read as clean (#186).
                "skipped_implausible": result.skipped_implausible,
            }
            # Key present only when true, to save context (#25); signals the
            # run abandoned a WHOOP-rejected resume cursor and re-walked (#201).
            if result.dropped_stale_cursor:
                entities[name]["dropped_stale_cursor"] = True
        response: dict[str, Any] = {
            # False when ANY entity failed, not just a wholly-refused run (#187).
            "synced": not failed,
            "entities": entities,
        }
        if failed:
            response["message"] = (
                f"{len(failed)} of {len(results)} entities failed to sync "
                f"({', '.join(failed)}); the rest completed and their cursors advanced"
            )
        return response


# -- analysis --------------------------------------------------------------

#: Largest sweep radius correlate_metrics accepts; unbounded would balloon
#: context cost per entry. 14 (29 entries) covers realistic lag questions.
_MAX_LAG_SWEEP_RADIUS = 14

#: Friendly metric name -> the collection it is sourced from.
_METRIC_COLLECTION: dict[str, str] = {
    "recovery_score": "recovery",
    "hrv": "recovery",
    "resting_heart_rate": "recovery",
    "sleep_performance": "sleep",
    "sleep_efficiency": "sleep",
    "strain": "cycle",
}


def _resolve_collection(metric: str) -> str:
    """Resolve a friendly metric name to the collection it is sourced from."""
    try:
        return _METRIC_COLLECTION[metric]
    except KeyError:
        raise ValueError(f"unknown metric: {metric!r}") from None


#: whoop_timeseries's unit per metric, echoed once in the response envelope.
#: Direction ("lower is better" etc.) lives in the tool docstring, not here.
_METRIC_UNIT: dict[str, str] = {
    "recovery_score": "%",
    "hrv": "ms",
    "resting_heart_rate": "bpm",
    "sleep_performance": "%",
    "sleep_efficiency": "%",
    "strain": "0-21 exertion scale",
}


def _resolve_metric_timeseries_source(metric: str) -> tuple[str, str, str]:
    """Resolve a friendly metric name to (entity, value_column, date_column)
    for whoop_timeseries.

    Separate from ``_resolve_collection`` (whose exact error message is
    likely pinned by tests); composes the existing mappings without
    duplicating them.
    """
    if metric not in _METRIC_COLLECTION:
        raise ValueError(
            f"unknown metric: {metric!r}; valid metrics are: "
            f"{', '.join(sorted(_METRIC_COLLECTION))}"
        )
    collection = _METRIC_COLLECTION[metric]
    entity = _COLLECTION_TO_ENTITY[collection]
    value_column = _METRIC_PATHS[metric]
    date_column = store._METRIC_TIMESERIES_DATE_COLUMNS[entity]
    return entity, value_column, date_column


#: Cap on the number of {date, value} points whoop_timeseries returns in one
#: call -- mirrors _ANALYSIS_MAX_RECORDS's own role/magnitude below, applied
#: to buckets rather than raw records.
_TIMESERIES_MAX_POINTS = 1000


#: Cap passed to every analysis-tool store read. Also the number quoted in
#: the truncation "note" below, so the two stay in sync without threading
#: the value through every call site.
_ANALYSIS_MAX_RECORDS = 1000


async def _fetch_collection(
    conn: sqlite3.Connection,
    whoop_user_id: int,
    collection: str,
    start: str,
    end: str,
    *,
    max_records: int = _ANALYSIS_MAX_RECORDS,
) -> tuple[list[dict[str, Any]], bool]:
    """Read one collection over a range from the local store.

    Repointed from ``WhoopClient.paginate()`` (#16): analysis tools need raw
    WHOOP records, not the trimmed data-tool shapes. Never falls through to
    the live API on a miss. Over-fetches by one row to detect truncation
    without a second query. Applies ``_with_created_at_fallback`` to every
    record.
    """
    getter = _COLLECTION_GETTER[collection]
    rows = getter(conn, whoop_user_id, start=start, end=end, limit=max_records + 1)
    truncated = len(rows) > max_records
    records = [_with_created_at_fallback(r) for r in rows[:max_records]]
    return records, truncated


def _actual_range(records: Sequence[dict[str, Any]]) -> tuple[str | None, str | None]:
    """The earliest/latest created_at actually present, not the range requested --
    a truncated page or a sparse collection covers less than what was asked for.
    """
    timestamps = sorted(r["created_at"] for r in records if r.get("created_at"))
    if not timestamps:
        return None, None
    return timestamps[0], timestamps[-1]


async def _summarize_window(
    conn: sqlite3.Connection, whoop_user_id: int, start: str, end: str
) -> tuple[dict[str, Any], tuple[str | None, str | None], bool, int, int]:
    """Read each of the 3 collections once from the store, then
    analysis.summarize per metric.

    6 metrics share only 3 collections, so this reads once per collection
    rather than per metric. A metric without enough SCORED records gets its
    own {"error": "insufficient_data", ...} entry rather than failing the
    whole window. truncated is true if any collection hit the fetch cap.
    """
    # Distinct UTC calendar dates in the window, matching how
    # analysis.summarize counts unique_dates (#181: subtracting timestamps
    # and taking .days undercounts the trailing partial day).
    start_dt = datetime.fromisoformat(start).astimezone(UTC)
    end_dt = datetime.fromisoformat(end).astimezone(UTC)
    # Clamped: expected_days also divides compare_periods' coverage ratios.
    expected_days = max(0, (end_dt.date() - start_dt.date()).days + 1)
    # Elapsed whole days -- distinct from expected_days, used by _period_length_note.
    span_days = max(0, (end_dt - start_dt).days)
    fetched = {
        collection: await _fetch_collection(conn, whoop_user_id, collection, start, end)
        for collection in ("recovery", "sleep", "cycle")
    }
    records_by_collection = {collection: records for collection, (records, _) in fetched.items()}
    truncated = any(collection_truncated for _, collection_truncated in fetched.values())
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
    return summaries, _actual_range(all_records), truncated, expected_days, span_days


def _period_length_note(baseline_days: int, comparison_days: int) -> str | None:
    """Explain when a period's length isn't a whole number of weeks.

    A non-week-multiple period can over/under-represent weekdays vs.
    weekends relative to the other, confounding the delta. None when both
    are multiples of 7.
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


#: Rolling window for whoop_outliers, in days. 14 balances fast re-adaptation
#: to genuine shifts against covering a full weekday+weekend cadence. Kept
#: in sync with tests/test_whoop_outliers.py's own WINDOW_DAYS literal.
_OUTLIERS_WINDOW_DAYS = 14

#: Nearest-measured-neighbour context radius reported alongside each
#: outlier. A fixed internal constant, not a tool parameter.
_OUTLIER_CONTEXT_DAYS = 3

#: Cap on the day-series fetched from the store per call -- mirrors
#: _TIMESERIES_MAX_POINTS's own role/magnitude.
_OUTLIERS_MAX_POINTS = 1000

#: Cap on outliers detailed in the response, independent of
#: _OUTLIERS_MAX_POINTS: an adversarial series can flag most points.
_OUTLIERS_MAX_FLAGGED = 50

#: Cap on compact warm-up entries listed in the response.
_OUTLIERS_MAX_WARMUP = 100

#: Calendar days swept/enumerated per whoop_streaks call -- same
#: magnitude as _TIMESERIES_MAX_POINTS/_OUTLIERS_MAX_POINTS.
_STREAKS_MAX_DAYS = 1000


def _local_neighborhood_z(
    daily: Sequence[RollingPoint], index: int, radius: int
) -> tuple[float, float | None, float | None]:
    """One point's ``(mean, stdev, z_score)`` against a local neighbourhood
    of up to ``radius`` measured points on each side, plus the point itself.

    Unlike a strictly-trailing window (``analysis.rolling_z_scores``), a
    two-sided neighbourhood doesn't starve on sparse coverage: two points 13
    days apart can't exceed ~0.71 z in a trailing-only window. Returns
    ``(mean, None, None)`` if fewer than 2 points; ``z_score`` is 0.0 when
    stdev is exactly 0.
    """
    before, after = context_window(daily, index, radius)
    neighborhood = [p.value for p in before] + [daily[index].value] + [p.value for p in after]
    nbhd_mean = mean(neighborhood)
    if len(neighborhood) < 2:
        return nbhd_mean, None, None
    nbhd_stdev = stdev(neighborhood)
    if nbhd_stdev == 0.0:
        return nbhd_mean, 0.0, 0.0
    return nbhd_mean, nbhd_stdev, (daily[index].value - nbhd_mean) / nbhd_stdev


def _register_analysis_tools(server: MCPServer[AppContext]) -> None:
    @server.tool(name="summarize_period", title="Summarise a period", annotations=READ_ONLY)
    async def summarize_period(
        start: str, end: str, ctx: Context[AppContext, Any]
    ) -> dict[str, Any]:
        """Summarise recovery, sleep and strain over a date range.

        Returns mean, stdev, median, min, max, record count and
        days_missing (calendar days with no scored record) per metric.
        Every response carries "coverage" and "range_coverage".

        Args:
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        (
            summaries,
            (range_start, range_end),
            truncated,
            _expected_days,
            _span_days,
        ) = await _summarize_window(conn, whoop_user_id, start, end)
        result: dict[str, Any] = {
            "summaries": summaries,
            "period": {"start": range_start, "end": range_end},
            "truncated": truncated,
        }
        if truncated:
            result["note"] = (
                f"Only records up to the {_ANALYSIS_MAX_RECORDS}-record cap were used; "
                "narrow the date range for a complete summary."
            )
        coverage: dict[str, Any] = {}
        range_coverage: dict[str, Any] = {}
        for entity in dict.fromkeys(_COLLECTION_TO_ENTITY.values()):
            ec = _entity_coverage(conn, whoop_user_id, entity)
            coverage[entity] = ec
            range_coverage[entity] = _range_coverage_entry(ec["earliest"], ec["latest"], start, end)
        result["coverage"] = coverage
        result["range_coverage"] = range_coverage
        return result

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

        Returns the least-squares slope in metric units per day (not a
        forecast), an r² fit-quality figure (as a number and as a word:
        "strong"/"moderate"/"weak"/"negligible"), and 7/30/90-day rolling
        means. Every response carries "coverage" and "range_coverage".
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        collection = _resolve_collection(metric)
        entity = _COLLECTION_TO_ENTITY[collection]
        records, truncated = await _fetch_collection(conn, whoop_user_id, collection, start, end)
        ec = _entity_coverage(conn, whoop_user_id, entity)
        coverage = {entity: ec}
        range_coverage = {entity: _range_coverage_entry(ec["earliest"], ec["latest"], start, end)}
        try:
            result = trend(records, metric)
        except InsufficientDataError as exc:
            # truncated/note would be noise here; too few records to matter.
            return {
                "error": "insufficient_data",
                "message": str(exc),
                "coverage": coverage,
                "range_coverage": range_coverage,
            }
        range_start, range_end = _actual_range(records)
        rolling_series = {
            "rolling_7d": [{"date": p.date, "value": p.value} for p in result.rolling_7d],
            "rolling_30d": [{"date": p.date, "value": p.value} for p in result.rolling_30d],
            "rolling_90d": [{"date": p.date, "value": p.value} for p in result.rolling_90d],
        }
        shaped_rolling, rolling_resolution, rolling_truncated = shape_rolling_series(rolling_series)
        response: dict[str, Any] = {
            "metric": result.metric,
            "count": result.count,
            "slope_per_day": result.slope_per_day,
            "first": result.first,
            "last": result.last,
            "r_squared": result.r_squared,
            "fit_quality": result.fit_quality,
            "rolling_7d": shaped_rolling["rolling_7d"],
            "rolling_30d": shaped_rolling["rolling_30d"],
            "rolling_90d": shaped_rolling["rolling_90d"],
            "rolling_resolution": rolling_resolution,
            "period": {"start": range_start, "end": range_end},
            "truncated": truncated,
        }
        if truncated:
            response["note"] = (
                f"Only records up to the {_ANALYSIS_MAX_RECORDS}-record cap were used; "
                "narrow the date range for a complete trend."
            )
        # Distinct from the record-count truncated/note pair above (#54): this
        # is a presentation cap on rolling points, not source records read.
        if rolling_resolution != "daily":
            response["rolling_note"] = (
                f"rolling_7d/rolling_30d/rolling_90d were downsampled to {rolling_resolution} "
                "resolution to keep the response a manageable size; every returned point is "
                "still a real computed rolling mean for its date, not an average of averages."
            )
        if rolling_truncated:
            response["rolling_truncated"] = True
            response["rolling_note"] = (
                response.get("rolling_note", "")
                + " Even at monthly resolution the series exceeded the "
                f"{ROLLING_MAX_POINTS_PER_SERIES}-point-per-series cap; only the most recent "
                f"{ROLLING_MAX_POINTS_PER_SERIES} monthly points are included."
            )
        response["coverage"] = coverage
        response["range_coverage"] = range_coverage
        return response

    @server.tool(name="correlate_metrics", title="Correlate two metrics", annotations=READ_ONLY)
    async def correlate_metrics(
        metric_a: str,
        metric_b: str,
        start: str,
        end: str,
        ctx: Context[AppContext, Any],
        lag_days: int = max(DEFAULT_LAG_SWEEP),
    ) -> dict[str, Any]:
        """Correlate two metrics over a range, sweeping a range of day-offsets.

        Joins by UTC calendar date, reporting Pearson's r and Spearman's rho
        at every lag from -lag_days to +lag_days, each with its sample size.
        A positive lag means metric_a leads. A lag with fewer than 8
        surviving pairs is reported as refused. Descriptive, not causal --
        WHOOP daily samples are autocorrelated.

        Args:
            metric_a: First metric name, as in metric_trend.
            metric_b: Second metric name.
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
            lag_days: Sweep radius in days (default 3, capped at 14).

        Every response carries "coverage" and "range_coverage".

        Raises:
            ValueError: if lag_days is negative.
        """
        if lag_days < 0:
            raise ValueError(f"lag_days must be >= 0, got {lag_days}")
        lag_days = min(lag_days, _MAX_LAG_SWEEP_RADIUS)

        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        collection_a = _resolve_collection(metric_a)
        collection_b = _resolve_collection(metric_b)
        entity_a = _COLLECTION_TO_ENTITY[collection_a]
        entity_b = _COLLECTION_TO_ENTITY[collection_b]
        records_a, truncated_a = await _fetch_collection(
            conn, whoop_user_id, collection_a, start, end
        )
        # Two metrics can share a collection (e.g. recovery_score and hrv are
        # both "recovery") -- fetch it once and reuse rather than twice.
        if collection_b == collection_a:
            records_b, truncated_b = records_a, truncated_a
        else:
            records_b, truncated_b = await _fetch_collection(
                conn, whoop_user_id, collection_b, start, end
            )
        truncated = truncated_a or truncated_b
        sweep_results = correlate_lag_sweep(
            records_a, metric_a, records_b, metric_b, lags=range(-lag_days, lag_days + 1)
        )
        response: dict[str, Any] = {
            "metric_a": metric_a,
            "metric_b": metric_b,
            "sweep": [
                {
                    "lag_days": entry.lag_days,
                    "refused": entry.correlation is None,
                    **(
                        {
                            "count": entry.correlation.count,
                            "r": entry.correlation.r,
                            "spearman_r": entry.correlation.spearman_r,
                        }
                        if entry.correlation is not None
                        else {"message": entry.refused_reason}
                    ),
                }
                for entry in sweep_results
            ],
            "truncated": truncated,
        }
        if truncated:
            response["note"] = (
                f"Only records up to the {_ANALYSIS_MAX_RECORDS}-record cap were used; "
                "narrow the date range for a complete correlation."
            )
        coverage: dict[str, Any] = {}
        range_coverage: dict[str, Any] = {}
        for entity in dict.fromkeys((entity_a, entity_b)):
            ec = _entity_coverage(conn, whoop_user_id, entity)
            coverage[entity] = ec
            range_coverage[entity] = _range_coverage_entry(ec["earliest"], ec["latest"], start, end)
        response["coverage"] = coverage
        response["range_coverage"] = range_coverage
        return response

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
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        # Sequential, not concurrent (no asyncio.gather): each window's read
        # completes before the next window's starts.
        (
            baseline_summaries,
            baseline_range,
            baseline_truncated,
            baseline_expected_days,
            baseline_span_days,
        ) = await _summarize_window(conn, whoop_user_id, baseline_start, baseline_end)
        (
            comparison_summaries,
            comparison_range,
            comparison_truncated,
            comparison_expected_days,
            comparison_span_days,
        ) = await _summarize_window(conn, whoop_user_id, comparison_start, comparison_end)
        truncated = baseline_truncated or comparison_truncated
        delta: dict[str, Any] = {}
        for metric in _METRIC_COLLECTION:
            b = baseline_summaries[metric]
            c = comparison_summaries[metric]
            if "error" in b or "error" in c:
                delta[metric] = {"error": "insufficient_data"}
                continue
            # Only the effect size is withheld on a thin window (#183);
            # delta_mean stays interpretable at small n, Cohen's d does not.
            effect_size_note: str | None = None
            effect_size: float | None
            if b["count"] < MIN_EFFECT_SAMPLES or c["count"] < MIN_EFFECT_SAMPLES:
                # Checked here, not via the exception, so the note attaches
                # only to this refusal (a zero-stdev refusal stays a bare null).
                effect_size = None
                # Explicit so a bare null isn't confused with "not computed".
                effect_size_note = (
                    f"withheld: effect size needs at least {MIN_EFFECT_SAMPLES} "
                    f"observations per period, got {b['count']} and {c['count']}"
                )
            else:
                try:
                    effect_size = standardized_effect_size(
                        b["mean"], b["stdev"], b["count"], c["mean"], c["stdev"], c["count"]
                    )
                except InsufficientDataError:
                    effect_size = None
            coverage_b = (
                1 - b["days_missing"] / baseline_expected_days if baseline_expected_days else 0.0
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
            # Key present only when non-None, to avoid costing context on
            # every well-sampled call for nothing (#25).
            if effect_size_note is not None:
                delta[metric]["effect_size_note"] = effect_size_note
        response: dict[str, Any] = {
            "baseline": {
                "summary": baseline_summaries,
                "period": {"start": baseline_range[0], "end": baseline_range[1]},
            },
            "comparison": {
                "summary": comparison_summaries,
                "period": {"start": comparison_range[0], "end": comparison_range[1]},
            },
            "delta": delta,
            "truncated": truncated,
            "period_length_note": _period_length_note(baseline_span_days, comparison_span_days),
        }
        if truncated:
            response["note"] = (
                f"Only records up to the {_ANALYSIS_MAX_RECORDS}-record cap were used; "
                "narrow the date range for a complete comparison."
            )
        # Two ranges merged into one flat range_coverage entry per entity,
        # like every other range tool (see response-shape note).
        coverage: dict[str, Any] = {}
        range_coverage: dict[str, Any] = {}
        for entity in dict.fromkeys(_COLLECTION_TO_ENTITY.values()):
            ec = _entity_coverage(conn, whoop_user_id, entity)
            coverage[entity] = ec
            range_coverage[entity] = _merge_range_coverage(
                [
                    _range_coverage_entry(
                        ec["earliest"], ec["latest"], baseline_start, baseline_end
                    ),
                    _range_coverage_entry(
                        ec["earliest"], ec["latest"], comparison_start, comparison_end
                    ),
                ]
            )
        response["coverage"] = coverage
        response["range_coverage"] = range_coverage
        return response

    @server.tool(name="whoop_timeseries", title="Metric time series", annotations=READ_ONLY)
    async def whoop_timeseries(
        metric: str,
        start: str,
        end: str,
        ctx: Context[AppContext, Any],
        granularity: Literal["day", "week", "month"] = "day",
    ) -> dict[str, Any]:
        """One metric's trend as a flat ``[{date, value}, ...]`` series --
        the cheap alternative to a list_* call for "how has X trended"
        questions.

        Aggregated in the database (SQL GROUP BY): multiple records in the
        same bucket are averaged, not summed. A bucket with no scored
        record is absent from "points", never a zero. A "week" bucket's
        "date" is the Monday that starts it; a "month" bucket's is the 1st.

        Args:
            metric: One of:
                - "recovery_score" (%, higher is generally better)
                - "hrv" (ms, higher is generally better)
                - "resting_heart_rate" (bpm, lower is generally better --
                  a rising trend is not an improvement)
                - "sleep_performance" (%, higher is generally better)
                - "sleep_efficiency" (%, higher is generally better)
                - "strain" (0-21 exertion scale, context-dependent -- not
                  inherently better or worse)
            start: ISO 8601 start of the range, e.g. "2026-07-01T00:00:00Z".
            end: ISO 8601 end of the range.
            granularity: "day" (default), "week", or "month".

        Served from the local store, never a live call. Carries a flat
        "range_coverage" rather than the full "coverage" envelope, to stay
        far cheaper than the equivalent list_* call. "truncated"/"note"
        report when the point cap is hit.
        """
        if granularity not in ("day", "week", "month"):
            raise ValueError(f"granularity must be 'day', 'week' or 'month', got {granularity!r}")
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        entity, value_column, date_column = _resolve_metric_timeseries_source(metric)

        rows = store.get_metric_series(
            conn,
            whoop_user_id,
            table=entity,
            value_column=value_column,
            date_column=date_column,
            granularity=granularity,
            start=start,
            end=end,
            limit=_TIMESERIES_MAX_POINTS + 1,
        )
        truncated = len(rows) > _TIMESERIES_MAX_POINTS
        page_rows = rows[:_TIMESERIES_MAX_POINTS]

        # One indexed MIN/MAX query -- never _entity_coverage's fuller
        # backfill/incremental-sync sub-lookups.
        earliest, latest = _COLLECTION_COVERAGE_FN[entity](conn, whoop_user_id)
        range_coverage = _range_coverage_entry(earliest, latest, start, end)

        response: dict[str, Any] = {
            "metric": metric,
            "unit": _METRIC_UNIT[metric],
            "granularity": granularity,
            "points": [{"date": bucket, "value": value} for bucket, value in page_rows],
            "truncated": truncated,
            "range_coverage": range_coverage,
        }
        if truncated:
            response["note"] = (
                f"Only the first {_TIMESERIES_MAX_POINTS} bucket(s) in this range were "
                "returned; narrow the date range or use a coarser granularity for the "
                "full series."
            )
        return response

    # -- issue #24: whoop_outliers / whoop_streaks --------------------------

    @server.tool(
        name="whoop_outliers", title="Find anomalous days for one metric", annotations=READ_ONLY
    )
    async def whoop_outliers(
        metric: str,
        start: str,
        end: str,
        ctx: Context[AppContext, Any],
        z: float = 2.0,
    ) -> dict[str, Any]:
        """Find days whose value is a local outlier, with nearby context.

        Outliers are scored against a local neighbourhood (up to 14 measured
        points either side), not a global baseline, so a sustained shift
        doesn't read as a month of anomalies. A day needs 14 calendar days
        of trailing history to be scored at all; unscored days are listed
        under "warmup_days" rather than dropped. Each outlier includes up
        to 3 nearest measured days either side and same-day values for the
        other 5 metrics.

        Args:
            metric: One of "recovery_score", "hrv", "resting_heart_rate",
                "sleep_performance", "sleep_efficiency", "strain".
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
            z: The absolute z-score a day must cross to be an outlier
                (default 2.0).

        Every response carries "coverage" and "range_coverage".
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        entity, value_column, date_column = _resolve_metric_timeseries_source(metric)

        rows = store.get_metric_series(
            conn,
            whoop_user_id,
            table=entity,
            value_column=value_column,
            date_column=date_column,
            granularity="day",
            start=start,
            end=end,
            limit=_OUTLIERS_MAX_POINTS + 1,
        )
        points_truncated = len(rows) > _OUTLIERS_MAX_POINTS
        daily = [RollingPoint(date=b, value=v) for b, v in rows[:_OUTLIERS_MAX_POINTS]]

        # 5 cheap SQL-aggregated queries total (never one per outlier),
        # applied only to the outlier day itself, not its context days.
        other_metric_series: dict[str, dict[str, float]] = {}
        for other_metric in _METRIC_COLLECTION:
            if other_metric == metric:
                continue
            o_entity, o_value_column, o_date_column = _resolve_metric_timeseries_source(
                other_metric
            )
            o_rows = store.get_metric_series(
                conn,
                whoop_user_id,
                table=o_entity,
                value_column=o_value_column,
                date_column=o_date_column,
                granularity="day",
                start=start,
                end=end,
                limit=_OUTLIERS_MAX_POINTS + 1,
            )
            other_metric_series[other_metric] = dict(o_rows[:_OUTLIERS_MAX_POINTS])

        warmup_stats = rolling_z_scores(daily, window_days=_OUTLIERS_WINDOW_DAYS)

        scores: dict[int, tuple[float, float | None, float | None]] = {}
        outlier_indices: list[int] = []
        scored_days_count = 0
        for i, stat in enumerate(warmup_stats):
            if stat.unscored_reason is not None:
                continue
            scored_days_count += 1
            nbhd_mean, nbhd_stdev, nbhd_z = _local_neighborhood_z(daily, i, _OUTLIERS_WINDOW_DAYS)
            scores[i] = (nbhd_mean, nbhd_stdev, nbhd_z)
            if nbhd_z is not None and abs(nbhd_z) >= z:
                outlier_indices.append(i)

        flagged_truncated = len(outlier_indices) > _OUTLIERS_MAX_FLAGGED
        outliers: list[dict[str, Any]] = []
        for i in outlier_indices[:_OUTLIERS_MAX_FLAGGED]:
            nbhd_mean, nbhd_stdev, nbhd_z = scores[i]
            before, after = context_window(daily, i, _OUTLIER_CONTEXT_DAYS)
            other_metrics: dict[str, Any] = {}
            for other_metric, series in other_metric_series.items():
                value = series.get(daily[i].date)
                if value is not None:
                    other_metrics[other_metric] = {
                        "value": value,
                        "unit": _METRIC_UNIT[other_metric],
                    }
            outliers.append(
                {
                    "date": daily[i].date,
                    "value": daily[i].value,
                    "z_score": nbhd_z,
                    "baseline_mean": nbhd_mean,
                    "baseline_stdev": nbhd_stdev,
                    "context_before": [{"date": p.date, "value": p.value} for p in before],
                    "context_after": [{"date": p.date, "value": p.value} for p in after],
                    "other_metrics": other_metrics,
                }
            )

        warmup_all = [stat for stat in warmup_stats if stat.unscored_reason is not None]
        warmup_truncated = len(warmup_all) > _OUTLIERS_MAX_WARMUP
        warmup_days = [
            {"date": stat.date, "value": stat.value, "reason": stat.unscored_reason}
            for stat in warmup_all[:_OUTLIERS_MAX_WARMUP]
        ]

        truncated = points_truncated or flagged_truncated or warmup_truncated
        response: dict[str, Any] = {
            "metric": metric,
            "window_days": _OUTLIERS_WINDOW_DAYS,
            "z_threshold": z,
            "scored_days_count": scored_days_count,
            "outliers": outliers,
            "warmup_days": warmup_days,
            "period": {"start": start, "end": end},
            "truncated": truncated,
        }
        notes: list[str] = []
        if points_truncated:
            notes.append(
                f"Only the first {_OUTLIERS_MAX_POINTS} day(s) in this range were used; "
                "narrow the date range for complete coverage."
            )
        if flagged_truncated:
            notes.append(
                f"Only the first {_OUTLIERS_MAX_FLAGGED} outlier(s) are detailed here; "
                "narrow the date range or raise z to see fewer."
            )
        if warmup_truncated:
            notes.append(f"Only the first {_OUTLIERS_MAX_WARMUP} warm-up day(s) are listed here.")
        if notes:
            response["note"] = " ".join(notes)

        ec = _entity_coverage(conn, whoop_user_id, entity)
        response["coverage"] = {entity: ec}
        response["range_coverage"] = {
            entity: _range_coverage_entry(ec["earliest"], ec["latest"], start, end)
        }
        return response

    @server.tool(
        name="whoop_streaks",
        title="Find consecutive-day streaks for one metric",
        annotations=READ_ONLY,
    )
    async def whoop_streaks(
        metric: str,
        start: str,
        end: str,
        threshold: float,
        direction: str,
        ctx: Context[AppContext, Any],
    ) -> dict[str, Any]:
        """Find maximal consecutive-day runs of one metric above or below a threshold.

        Every calendar day in range is enumerated in "days": "missing"
        (unmeasured), "failing" (measured but off-threshold), or "passing".
        Both "missing" and "failing" end a streak, with no bridging logic.

        Args:
            metric: One of "recovery_score", "hrv", "resting_heart_rate",
                "sleep_performance", "sleep_efficiency", "strain".
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
            threshold: The value a day must cross to "pass".
            direction: "above" (value >= threshold) or "below"
                (value <= threshold), both inclusive.

        Every response carries "coverage" and "range_coverage".
        """
        if direction not in ("above", "below"):
            raise ValueError(f"direction must be 'above' or 'below', got {direction!r}")
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        conn = _require_store(app)
        entity, value_column, date_column = _resolve_metric_timeseries_source(metric)

        range_start_date = _parse_iso(start).date()
        range_end_date = _parse_iso(end).date()
        truncated = False
        effective_end_date = range_end_date
        if range_start_date <= range_end_date:
            span_days = (range_end_date - range_start_date).days + 1
            if span_days > _STREAKS_MAX_DAYS:
                truncated = True
                effective_end_date = range_start_date + timedelta(days=_STREAKS_MAX_DAYS - 1)

        rows = store.get_metric_series(
            conn,
            whoop_user_id,
            table=entity,
            value_column=value_column,
            date_column=date_column,
            granularity="day",
            start=start,
            end=end,
            limit=_STREAKS_MAX_DAYS + 1,
        )
        daily = [RollingPoint(date=b, value=v) for b, v in rows]

        days, streaks = find_streaks(
            daily,
            threshold=threshold,
            direction=direction,
            range_start=range_start_date.isoformat(),
            range_end=effective_end_date.isoformat(),
        )

        response: dict[str, Any] = {
            "metric": metric,
            "direction": direction,
            "threshold": threshold,
            "days": [{"date": d.date, "status": d.status, "value": d.value} for d in days],
            "streaks": [
                {"start": s.start, "end": s.end, "length": s.length, "mean": s.mean}
                for s in streaks
            ],
            "period": {"start": start, "end": end},
            "truncated": truncated,
        }
        if truncated:
            response["note"] = (
                f"Only the first {_STREAKS_MAX_DAYS} calendar day(s) in this range were "
                "swept; narrow the date range for complete coverage."
            )
        ec = _entity_coverage(conn, whoop_user_id, entity)
        response["coverage"] = {entity: ec}
        response["range_coverage"] = {
            entity: _range_coverage_entry(ec["earliest"], ec["latest"], start, end)
        }
        return response


def _register_prompts(server: MCPServer[AppContext]) -> None:
    """Register the prompts (#26): compositions of analysis tools, not raw
    data tools, so the model imitates a habit rather than dumping records.

    Each prompt is an argument-less function returning list[str] -- it
    states which tools to call and why, never calling them itself.
    """

    @server.prompt(
        name="morning_readiness_briefing",
        title="Morning readiness briefing",
        description=(
            "Read today's recovery against the last fortnight, not in isolation, "
            "using metric_trend and whoop_outliers."
        ),
    )
    def morning_readiness_briefing() -> list[str]:
        return [
            "Compile a morning readiness briefing for the signed-in WHOOP user. "
            "Today's recovery number means little read in isolation -- read it "
            "against the recent trend, not on its own.\n\n"
            "1. Call whoop_data_coverage to see what is actually held in the "
            "local store before reasoning about it.\n"
            '2. Call metric_trend for the "recovery_score" metric over the '
            "last 14 days to place today's value in the context of the last "
            "fortnight.\n"
            '3. Call whoop_outliers for "recovery_score" over that same '
            "14-day window to say whether today is a local outlier or an "
            "ordinary day.\n\n"
            "State the actual coverage window you reasoned over -- the "
            "earliest and latest synced date and the record count, quoted "
            'from the tools\' own "coverage"/"range_coverage" fields -- so '
            "a briefing built on three days of data does not sound as "
            "confident as one built on three months.\n\n"
            "This is wellness data, not clinical data: report what the "
            "numbers say and their sample size, and do not diagnose."
        ]

    @server.prompt(
        name="weekly_training_review",
        title="Weekly training review",
        description=(
            "Review strain distribution, workouts, and recovery response "
            "using summarize_period and correlate_metrics."
        ),
    )
    def weekly_training_review() -> list[str]:
        return [
            "Compile a weekly training review for the signed-in WHOOP user.\n\n"
            "1. Call summarize_period for the last 7 days to get the strain "
            "distribution and workout summary.\n"
            '2. Call correlate_metrics for "strain" vs "recovery_score" '
            "over the last 4 weeks to see how recovery has responded to "
            "strain.\n\n"
            "State the coverage window each tool actually covered -- earliest "
            "and latest synced date, and sample count -- quoted from their "
            'own "coverage" fields, before drawing any conclusion.\n\n'
            "A several-week correlation between strain and recovery is not a "
            "causal finding. Report the correlation and its sample size; do "
            "not present it as strain causing a recovery outcome."
        ]

    @server.prompt(
        name="sleep_debt_investigation",
        title="Sleep debt investigation",
        description=(
            "Look at sleep consistency against recovery over a month using "
            "metric_trend and correlate_metrics."
        ),
    )
    def sleep_debt_investigation() -> list[str]:
        return [
            "Investigate sleep debt for the signed-in WHOOP user over the "
            "last 30 days.\n\n"
            "There is no direct sleep-duration metric registered for "
            'metric_trend/correlate_metrics; use "sleep_performance" as the '
            "nearest available proxy -- it measures actual sleep against "
            "sleep need, which is what sleep debt means, unlike "
            '"sleep_efficiency" (asleep-vs-in-bed, a quality measure, not a '
            "duration one). Say explicitly that this is a proxy, not a raw "
            "duration figure.\n\n"
            '1. Call metric_trend for "sleep_performance" over the last 30 '
            "days to see the trend and consistency of sleep.\n"
            '2. Call correlate_metrics for "sleep_performance" vs '
            '"recovery_score" over that same 30-day window to see how '
            "recovery responds to a shortfall against sleep need.\n\n"
            "State the coverage window you reasoned over -- earliest and "
            "latest synced date, and sample count -- quoted from the tools' "
            'own "coverage" fields.\n\n'
            "Describe findings descriptively, not diagnostically: this is "
            "wellness data, not a clinical assessment, and a month of data "
            "does not establish causality."
        ]


def _register_resources(server: MCPServer[AppContext]) -> None:
    """The four per-user resources (#26), as one ``whoop://user/{item}`` template.

    A template, not four static resources, because a static resource's read
    function can't receive Context, and the identity gate needs it. Matches
    any trailing segment, so the ResourceNotFoundError at dispatch's end is
    load-bearing -- an unrecognised item must fail, not fall through silently.
    """

    @server.resource(
        "whoop://user/{item}",
        name="whoop-user-item",
        title="WHOOP user record",
        description=(
            "One of the signed-in user's WHOOP records, selected by `item`: "
            '"profile", "latest-recovery", "latest-sleep", or "latest-cycle".'
        ),
        mime_type="application/json",
    )
    # Bare `Context`, not the parametrized form: pydantic's validate_call
    # would revalidate it and drop private attrs, breaking ctx.request_context.
    async def whoop_user_resource(item: str, ctx: Context) -> dict[str, Any]:
        # cast has no runtime effect, so it doesn't reintroduce the pydantic
        # revalidation the bare `Context` annotation above avoids.
        typed_ctx = cast("Context[AppContext, Any]", ctx)
        app = typed_ctx.request_context.lifespan_context
        # Gate runs before dispatch: an unauthenticated caller must not learn
        # which items exist, and the audit write should record the attempt.
        whoop_user_id = _ensure_matches_live_grant(typed_ctx)
        conn = _require_store(app)
        if item == "profile":
            record = store.get_profile(conn, whoop_user_id)
            if record is None:
                return {"error": "not_synced", "coverage": {"profile": _singleton_coverage(None)}}
            updated_at = store.get_profile_updated_at(conn, whoop_user_id)
            result = strip_nulls(record)
            result["coverage"] = {"profile": _singleton_coverage(updated_at)}
            return result
        if item == "latest-recovery":
            coverage = _entity_coverage(conn, whoop_user_id, "recoveries")
            if coverage["earliest"] is None:
                return {"error": "not_synced", "coverage": {"recoveries": coverage}}
            record = store.get_latest_recovery(conn, whoop_user_id)
            result = strip_nulls(_trim_recovery(record))  # type: ignore[arg-type]
            result["coverage"] = {"recoveries": coverage}
            return result
        if item == "latest-sleep":
            coverage = {"sleeps": _entity_coverage(conn, whoop_user_id, "sleeps")}
            if coverage["sleeps"]["earliest"] is None:
                return {"error": "not_synced", "coverage": coverage}
            record = store.get_latest_sleep(conn, whoop_user_id)
            # coverage["sleeps"]["earliest"] is non-None, so a row exists.
            trimmed = strip_nulls(_trim_sleep(record, detail="full"))  # type: ignore[arg-type]
            trimmed["units"] = {"stage_durations": "milliseconds"}
            trimmed["coverage"] = coverage
            return trimmed
        if item == "latest-cycle":
            coverage = _entity_coverage(conn, whoop_user_id, "cycles")
            if coverage["earliest"] is None:
                return {"error": "not_synced", "coverage": {"cycles": coverage}}
            record = store.get_latest_cycle(conn, whoop_user_id)
            result = strip_nulls(_trim_cycle(record))  # type: ignore[arg-type]
            result["coverage"] = {"cycles": coverage}
            return result
        raise ResourceNotFoundError(f"Unknown resource: whoop://user/{item}")
