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

import asyncio
import contextlib
import logging
import sqlite3
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import principal_components
from mcp.server.mcpserver import Context, MCPServer
from mcp.types import ToolAnnotations
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from whoopmcp import store
from whoopmcp.analysis import (
    DEFAULT_LAG_SWEEP,
    InsufficientDataError,
    correlate_lag_sweep,
    standardized_effect_size,
    summarize,
    trend,
)
from whoopmcp.auth import Authenticator, AuthError, build_store
from whoopmcp.client import RateLimitedError, WhoopClient, build_collection_params
from whoopmcp.config import Config
from whoopmcp.context_budget import strip_nulls
from whoopmcp.store import open_store
from whoopmcp.webhook_processor import _consume_webhooks
from whoopmcp.webhooks import register_webhook_routes

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
    #: The persistent store (#13), opened by ``lifespan`` for the life of the
    #: process. ``None`` only for a deployment/test that never opened one --
    #: see ``resolve_member_id`` for what that means for identity resolution.
    store_conn: sqlite3.Connection | None = None


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
    """Build the config, auth and HTTP client once, and tear them down cleanly.

    Under streamable-http (#27) with more than one worker, each process gets
    its own independent Authenticator, so the plain asyncio.Lock inside the
    default InProcessRefreshLock no longer serialises refreshes across them.
    A cross-process RefreshLock was deliberately NOT wired in here -- see the
    "Known limitation" note on create_streamable_http_app() below for why a
    lock alone (without changing Authenticator.refresh()'s internals, which
    this issue's own acceptance criteria forbid) cannot actually prevent two
    workers from both completing a refresh with the same soon-to-rotate
    token. stdio keeps InProcessRefreshLock, unchanged, since it is always
    exactly one process and this doesn't apply to it.

    Always opens the persistent store (#13) -- issue #29's principal<->member
    join and audit log need it on every request, not only when webhooks are
    enabled, so this is no longer gated on `config.webhooks_enabled` the way
    the webhook consumer task below still is. Also starts the webhook
    consumer (#18), when there is one to start: `build_server()` stashes the
    queue `register_webhook_routes` returns on `_server._webhook_queue` (see
    that function's own call site for why) -- an ad hoc attribute rather than
    a new constructor parameter, since `lifespan` is handed to `MCPServer(...)`
    and then called back by the SDK itself with exactly one argument, the
    server it belongs to; `_server` is the only channel available to get
    anything from `build_server()`'s scope into this function without
    changing that call shape. Absent (a server built by a test that never
    called `register_webhook_routes`) or `webhooks_enabled` false: no
    consumer task runs, matching `register_webhook_routes`'s own "off unless
    configured" default -- the store itself is unaffected either way.
    """
    config = Config.from_env()
    auth = Authenticator(config)
    async with WhoopClient(config, auth) as client:
        principal = await _resolve_principal(client)
        logger.info("whoopmcp ready (state dir: %s)", config.state_dir)

        store_conn = open_store(config.cache_path)
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
                    # Awaited for its side effect (blocking until the task
                    # has actually finished cancelling), not its result --
                    # assigned to make that discard explicit rather than a
                    # bare expression statement. mypy's func-returns-value
                    # check misfires on any assignment of an
                    # asyncio.Task[None]'s await result, regardless of the
                    # assignment target's own type -- verified in isolation,
                    # not assumed.
                    _ = await consumer_task  # type: ignore[func-returns-value]
            store_conn.close()


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


class UnresolvedPrincipalError(RuntimeError):
    """The calling MCP principal has no WHOOP member linked to it.

    Distinct from ``AuthError`` ("nobody is logged in to WHOOP at all"):
    this means a principal is known -- a bearer token's identity, or the
    local stdio sentinel -- but no completed WHOOP authorisation has ever
    linked it to a member via ``store.link_principal_to_member``. Raised by
    ``resolve_member_id`` (and by ``_ensure_matches_live_grant`` for the
    "resolves to a real member, but not this process's live grant" case).
    Never resolved by defaulting to some other member -- see both
    functions' own docstrings.
    """


#: Fixed principal key for stdio / no-bearer-auth-wired deployments (today's
#: only real deployment shape): one completed login links this one sentinel
#: to a member, rather than inventing per-connection identity that #28's
#: resource-server layer doesn't produce in that mode.
_LOCAL_PRINCIPAL_CLIENT_ID = "__local__"


def _principal_key(request: Any | None) -> tuple[str, str | None, str | None]:
    """The (client_id, issuer, subject) triple identifying `request`'s caller.

    Reads only `request.user` -- the `AuthenticatedUser` a verified bearer
    token resolves to under streamable-http with #28's auth wired -- via the
    SDK's own `principal_components()`, the single source `authorization
    _context`/session-ownership binding already use for "who is this token's
    principal". Never reads `request.query_params` or `request.headers`:
    those are caller-supplied and are exactly the smuggling vector #28's own
    `list_tools_protected` and this function both refuse to consult for
    identity. `request` is `None` under stdio, or before #28's resource
    server is wired into a deployment's transport -- both degrade to the
    fixed local sentinel below, never to inventing a per-request identity
    from anything the caller could control.
    """
    user = getattr(request, "user", None) if request is not None else None
    if isinstance(user, AuthenticatedUser):
        return principal_components(user.access_token)
    return _LOCAL_PRINCIPAL_CLIENT_ID, None, None


def _tool_name(ctx: Context[AppContext, Any]) -> str:
    """The name of the tool this call is invoking, for the audit log.

    ``ctx.request_context.params`` is a plain ``Mapping`` in production (the
    raw ``tools/call`` JSON-RPC params, read before typed validation) but a
    real ``CallToolRequestParams`` in tests that build one directly -- both
    carry a ``name``, just via a different access pattern.
    """
    params = ctx.request_context.params
    name = params.get("name") if isinstance(params, Mapping) else getattr(params, "name", None)
    return str(name) if name is not None else "<unknown>"


def resolve_member_id(ctx: Context[AppContext, Any]) -> int:
    """Resolve the calling MCP principal to a WHOOP member id, once, at the edge.

    The one join point between an MCP principal (#28's bearer token, or the
    local stdio sentinel) and a WHOOP member (#8's ``Principal``): every
    data/analysis tool calls this exactly once, as its first line via
    ``_ensure_matches_live_grant``, and threads the returned id through
    rather than re-resolving. Reads only the ``principal_members`` mapping
    table (via ``_principal_key``, never a caller-supplied parameter, header,
    or query string) and audits the call (``store.record_tool_call``) in the
    same step resolution succeeds, so a tool that resolves but "forgets" to
    audit is structurally impossible -- there is only one call site for
    either.

    Requires a persistent store (``AppContext.store_conn``). The store is
    always opened by ``lifespan()``, so only deployments or tests that
    construct ``AppContext`` outside ``lifespan()`` encounter an error here.

    Raises:
        RuntimeError: ``AppContext.store_conn`` is None. The persistent store
            is required for principal-to-member resolution. This is always
            opened by ``lifespan()``, so this error only occurs if ``AppContext``
            is constructed outside that context.
        UnresolvedPrincipalError: no ``principal_members`` row links the
            calling principal to a member. Never a default, never a
            fallback to some other member.
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

    Every data/analysis tool today calls the single process-wide live
    ``WhoopClient`` -- #13's store isn't read by any tool yet, so there is
    no per-member live client to route a resolved identity to.
    ``resolve_member_id`` must still answer truthfully even when the
    resolved member is not this grant (see its own tests, e.g. a spoofed
    hint must never be adopted) -- the refusal for that mismatch belongs
    one layer up, here, in the one place that actually knows "the live
    client can only ever speak for one member".
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

    Builds its own ``Config.from_env()`` rather than reaching into the live
    AppContext: a ``custom_route`` handler gets a plain Starlette ``Request``,
    not the ``ctx.request_context.lifespan_context`` every MCP tool gets, and
    under streamable-http the SDK keeps the resolved AppContext only on
    ``StreamableHTTPSessionManager``'s own private ``_lifespan_state``
    (`mcp/server/streamable_http_manager.py`, `StreamableHTTPSessionManager.run`)
    -- there is no public accessor for it (`MCPServer.session_manager` exposes
    the session manager itself, per its own docstring, "to enable advanced use
    cases like mounting multiple MCPServer instances", but not that private
    attribute). ``Config.from_env()`` is a pure, uncached read of the same
    environment ``lifespan()`` itself reads, so this reconstructs an equal
    ``Config`` rather than depending on SDK internals outside its public
    contract.

    A clean "not logged in yet" is not an infrastructure failure:
    ``FileTokenStore.load()`` already returns ``None`` for that case rather
    than raising, so it reports ready here exactly like a valid token would.
    Only a genuine read failure -- a corrupt token file, a permissions error,
    anything ``build_store(...).load()`` actually raises -- counts as not
    ready.

    Runs the (synchronous, possibly-blocking -- a local file read, or under
    the keyring backend a real OS keychain call) store read in a thread, so
    a contended or slow store can't stall the event loop this handler shares
    with every other in-flight request. The detail string reports only the
    exception's type, not its message: ``FileTokenStore``'s own error text
    includes the token file's absolute path, which this endpoint has no
    business handing to an unauthenticated caller polling /ready.
    """
    try:
        await asyncio.to_thread(build_store(Config.from_env()).load)
    except Exception as exc:
        return False, type(exc).__name__
    return True, "ok"


#: Named, independent readiness checks: add a ``(name, check)`` pair here
#: (e.g. a sync-freshness check once #13/#15 land) rather than restructuring
#: the /ready handler itself.
_READINESS_CHECKS: list[tuple[str, Callable[[], Awaitable[tuple[bool, str]]]]] = [
    ("token_store_reachable", _check_token_store_reachable),
]


def _register_health_routes(server: MCPServer[AppContext]) -> None:
    """Liveness and readiness for the streamable-http transport (#27).

    Plain HTTP via ``custom_route``, not MCP tools: an operator's load
    balancer or orchestrator polls these the same way it would for any other
    service, without needing an MCP client to do it. Not reachable under
    stdio -- there is no HTTP surface there -- so only streamable-http
    deployments see these at all. Deliberately just liveness/readiness: no
    OAuth-callback route belongs here, and the webhook receiver (#17) is
    registered separately by ``register_webhook_routes`` -- see that
    function's own docstring for why it reads ``Config`` fresh per request
    rather than once at server-build time, the same shape of problem
    ``_check_token_store_reachable`` below already solves the same way.
    """

    @server.custom_route("/health", methods=["GET"])
    async def health(_request: Request) -> Response:
        # Liveness means "the process can respond", not "everything
        # downstream works" -- must not touch AppContext/lifespan, so a
        # problem inside the lifespan can't take this down too.
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
    _register_health_routes(server)
    # Stashed on the server instance, not returned or discarded: `lifespan`
    # (already handed to MCPServer(...) above, and called back by the SDK
    # with only the server itself as an argument) reads it back via
    # `getattr(_server, "_webhook_queue", None)` to start #18's consumer
    # task. See `lifespan`'s own docstring for why this attribute, rather
    # than a constructor parameter, is the wiring point.
    server._webhook_queue = register_webhook_routes(server)  # type: ignore[attr-defined]
    return server


def create_streamable_http_app() -> Starlette:
    """ASGI app factory for running whoopmcp under multiple uvicorn workers (#27).

    __main__.py's own ``build_server().run(transport="streamable-http", ...)``
    is one uvicorn.Server in one process -- fine for a single worker. An
    operator wanting multiple workers points uvicorn directly at this
    factory instead of through __main__.py, e.g.::

        uvicorn "whoopmcp.server:create_streamable_http_app" --factory --workers 4 --port 8000

    Note: only ``config.http_host`` feeds into this call -- the installed SDK's
    ``MCPServer.streamable_http_app()`` takes a ``host`` (used for its
    DNS-rebinding-protection allowlist) but no ``port`` kwarg at all; a port is
    a uvicorn-server concern, not an ASGI-app one, so ``config.http_port`` has
    no equivalent here and the operator passes ``--port`` to uvicorn directly,
    same as ``--workers``.

    **Known limitation, deliberately not papered over**: each worker process
    gets its own independent ``AppContext``/``Authenticator``, and nothing in
    this codebase currently serialises a token refresh across them. A
    cross-process ``RefreshLock`` was prototyped for this (SQLite-file-lock
    backed) and then removed before merge: ``Authenticator.refresh()``
    releases its lock before the network call completes, coordinating
    within one process via a private ``asyncio.Future`` (issue #12's
    single-flight design) that has no cross-process equivalent. A lock that
    only covers the "am I already refreshing" check -- not the request
    itself -- cannot stop two separate workers from each independently
    reaching WHOOP with the same about-to-be-rotated refresh token, which
    reproduces exactly the credential-destroying race #12 exists to prevent,
    just across processes instead of within one. Actually closing this gap
    means either changing ``Authenticator.refresh()`` to hold a lock across
    the network call (a change to ``Authenticator`` itself) or a
    compare-and-swap against a shared store (needs #13, not yet merged) --
    a decision outside this issue's own scope, reported on #27 rather than
    guessed at. Until resolved, run exactly one worker for token refresh, or
    accept that a concurrent refresh under multiple workers can force a
    re-login.
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
            # The only writer of principal_members (#29): a completed WHOOP
            # authorisation, and nothing else -- never a header, a hostname,
            # or a caller-supplied member id.
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


def _trim_sleep(record: dict[str, Any], *, detail: str = "full") -> dict[str, Any]:
    """Trim a raw sleep record.

    ``detail="summary"`` (used by list_sleeps' default) drops the nested
    stage-duration breakdown; ``detail="full"`` (get_sleep's only mode, and
    list_sleeps' opt-in) keeps it under "stage_durations" -- the caller is
    responsible for adding the sibling "units" key documenting it, since
    that lives at the envelope level, not on the record itself.
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

    See ``_trim_sleep`` for the ``detail`` contract; the analogous nested
    field here is "zone_durations".
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
        """Return the user's WHOOP profile: user id, email, first and last name."""
        app = ctx.request_context.lifespan_context
        _ensure_matches_live_grant(ctx)

        async def _fetch() -> dict[str, Any]:
            return strip_nulls(await app.client.get_profile())

        return await _guard_rate_limit(_fetch)

    @server.tool(name="get_body_measurement", title="Get body measurements", annotations=READ_ONLY)
    async def get_body_measurement(ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Return height in metres, weight in kilograms and max heart rate in bpm."""
        app = ctx.request_context.lifespan_context
        _ensure_matches_live_grant(ctx)

        async def _fetch() -> dict[str, Any]:
            return strip_nulls(await app.client.get_body_measurement())

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
        _ensure_matches_live_grant(ctx)
        range_start, range_end = _default_range(start, end, next_token)

        async def _fetch() -> dict[str, Any]:
            page = await app.client.list_recoveries(
                start=range_start, end=range_end, limit=limit, next_token=next_token
            )
            records = [strip_nulls(_trim_recovery(r)) for r in page.records]
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
        detail: Literal["summary", "full"] = "summary",
    ) -> dict[str, Any]:
        """List sleep records: performance (%), efficiency, and stage durations in milliseconds.

        Args:
            start: ISO 8601 start of the range.
                Defaults, with end, to the last 7 days when both are omitted.
            end: ISO 8601 end of the range.
            limit: Records to return, capped at 25 per page by WHOOP.
            next_token: Cursor from a previous truncated response, to continue
                that page.
            detail: "summary" (default) omits the per-stage sleep-duration
                breakdown to keep the response small; "full" includes it
                under "stage_durations", with the units declared once in a
                top-level "units" key.
        """
        if detail not in ("summary", "full"):
            raise ValueError(f"detail must be 'summary' or 'full', got {detail!r}")
        app = ctx.request_context.lifespan_context
        _ensure_matches_live_grant(ctx)
        range_start, range_end = _default_range(start, end, next_token)

        async def _fetch() -> dict[str, Any]:
            page = await app.client.list_sleeps(
                start=range_start, end=range_end, limit=limit, next_token=next_token
            )
            records = [strip_nulls(_trim_sleep(r, detail=detail)) for r in page.records]
            result: dict[str, Any] = {
                "records": records,
                "count": len(records),
                "next_token": page.next_token,
            }
            if detail == "full":
                result["units"] = {"stage_durations": "milliseconds"}
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
        _ensure_matches_live_grant(ctx)
        range_start, range_end = _default_range(start, end, next_token)

        async def _fetch() -> dict[str, Any]:
            page = await app.client.list_cycles(
                start=range_start, end=range_end, limit=limit, next_token=next_token
            )
            records = [strip_nulls(_trim_cycle(r)) for r in page.records]
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
        detail: Literal["summary", "full"] = "summary",
    ) -> dict[str, Any]:
        """List workouts: sport, strain, average and max heart rate, and heart-rate zone durations.

        Args:
            start: ISO 8601 start of the range.
                Defaults, with end, to the last 7 days when both are omitted.
            end: ISO 8601 end of the range.
            limit: Records to return, capped at 25 per page by WHOOP.
            next_token: Cursor from a previous truncated response, to continue
                that page.
            detail: "summary" (default) omits the per-zone heart-rate
                duration breakdown to keep the response small; "full"
                includes it under "zone_durations", with the units declared
                once in a top-level "units" key.
        """
        if detail not in ("summary", "full"):
            raise ValueError(f"detail must be 'summary' or 'full', got {detail!r}")
        app = ctx.request_context.lifespan_context
        _ensure_matches_live_grant(ctx)
        range_start, range_end = _default_range(start, end, next_token)

        async def _fetch() -> dict[str, Any]:
            page = await app.client.list_workouts(
                start=range_start, end=range_end, limit=limit, next_token=next_token
            )
            records = [strip_nulls(_trim_workout(r, detail=detail)) for r in page.records]
            result: dict[str, Any] = {
                "records": records,
                "count": len(records),
                "next_token": page.next_token,
            }
            if detail == "full":
                result["units"] = {"zone_durations": "milliseconds"}
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
        _ensure_matches_live_grant(ctx)

        async def _fetch() -> dict[str, Any]:
            record = await app.client.get_sleep(sleep_id)
            trimmed = strip_nulls(_trim_sleep(record))
            trimmed["units"] = {"stage_durations": "milliseconds"}
            return trimmed

        return await _guard_rate_limit(_fetch)

    @server.tool(name="get_workout", title="Get one workout", annotations=READ_ONLY)
    async def get_workout(workout_id: str, ctx: Context[AppContext, Any]) -> dict[str, Any]:
        """Return a single workout by its v2 UUID."""
        app = ctx.request_context.lifespan_context
        _ensure_matches_live_grant(ctx)

        async def _fetch() -> dict[str, Any]:
            record = await app.client.get_workout(workout_id)
            trimmed = strip_nulls(_trim_workout(record))
            trimmed["units"] = {"zone_durations": "milliseconds"}
            return trimmed

        return await _guard_rate_limit(_fetch)


# -- analysis --------------------------------------------------------------

#: Largest sweep radius correlate_metrics accepts for lag_days. Unbounded
#: would let a caller request an arbitrarily large sweep (each entry costs
#: context, and #25's ceiling doesn't help here since this tool predates
#: it) from a handful of days of input -- 14 (29 entries) comfortably
#: covers the "does yesterday/last-week's X predict Y" questions this
#: feature exists for.
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


#: Cap passed to WhoopClient.paginate() for every analysis-tool fetch. Also
#: the number quoted in the truncation "note" below, so the two stay in
#: sync without threading the value through every call site.
_ANALYSIS_MAX_RECORDS = 1000


async def _fetch_collection(
    app: AppContext,
    collection: str,
    start: str,
    end: str,
    *,
    max_records: int = _ANALYSIS_MAX_RECORDS,
) -> tuple[list[dict[str, Any]], bool]:
    """Walk every page of one collection over a range via WhoopClient.paginate.

    Analysis tools need raw WHOOP records (score_state, nested score dicts)
    -- the same shape analysis.py's extract_metric/summarize/trend/correlate
    already know how to read -- not the trimmed shapes the data tools return,
    so this goes straight to paginate() rather than through list_recoveries etc.

    Returns the records and a ``truncated`` flag: true if the collection may
    hold more than ``max_records`` matched the range requested. Checking
    ``len(records) >= max_records`` is an approximation -- a collection with
    exactly that many real records and no more would be a false positive --
    but paginate() doesn't otherwise say whether it stopped because the
    cursor ran out or because the cap did, and that's an accepted tradeoff
    rather than a bug to fix.
    """
    params = build_collection_params(start=start, end=end)
    records = [
        record
        async for record in app.client.paginate(
            _COLLECTION_PATH[collection], params, max_records=max_records
        )
    ]
    return records, len(records) >= max_records


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
) -> tuple[dict[str, Any], tuple[str | None, str | None], bool, int]:
    """Fetch each of the 3 collections once, then analysis.summarize per metric.

    6 metrics share only 3 collections -- fetching once per metric here would
    be 6 requests instead of 3, and summarize_period's whole point is not
    doing that. A metric whose collection can't produce enough SCORED records
    for analysis.summarize gets its own {"error": "insufficient_data", ...}
    entry rather than failing the other 5 metrics that DID have enough data.

    The returned ``truncated`` flag is true if ANY of the 3 collections hit
    the per-fetch record cap -- one truncated collection is enough to make
    the whole window's summary incomplete. ``expected_days`` is threaded into
    every analysis.summarize call so each metric's ``days_missing`` reflects
    the requested window, not just what happened to come back.
    """
    expected_days = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).days
    fetched = {
        collection: await _fetch_collection(app, collection, start, end)
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
    return summaries, _actual_range(all_records), truncated, expected_days


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
        _ensure_matches_live_grant(ctx)

        async def _fetch() -> dict[str, Any]:
            (
                summaries,
                (range_start, range_end),
                truncated,
                _expected_days,
            ) = await _summarize_window(app, start, end)
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
            return result

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
        description of the window requested, not a forecast. Also returns an
        r² fit-quality figure for that slope -- both as the number and as a
        word ("strong"/"moderate"/"weak"/"negligible") -- and 7/30/90-day
        rolling means of the metric over calendar days.
        """
        app = ctx.request_context.lifespan_context
        _ensure_matches_live_grant(ctx)

        async def _fetch() -> dict[str, Any]:
            collection = _resolve_collection(metric)
            records, truncated = await _fetch_collection(app, collection, start, end)
            try:
                result = trend(records, metric)
            except InsufficientDataError as exc:
                # No records worth speaking of on this path -- truncated/note
                # would be noise, not signal.
                return {"error": "insufficient_data", "message": str(exc)}
            range_start, range_end = _actual_range(records)
            response: dict[str, Any] = {
                "metric": result.metric,
                "count": result.count,
                "slope_per_day": result.slope_per_day,
                "first": result.first,
                "last": result.last,
                "r_squared": result.r_squared,
                "fit_quality": result.fit_quality,
                "rolling_7d": [{"date": p.date, "value": p.value} for p in result.rolling_7d],
                "rolling_30d": [{"date": p.date, "value": p.value} for p in result.rolling_30d],
                "rolling_90d": [{"date": p.date, "value": p.value} for p in result.rolling_90d],
                "period": {"start": range_start, "end": range_end},
                "truncated": truncated,
            }
            if truncated:
                response["note"] = (
                    f"Only records up to the {_ANALYSIS_MAX_RECORDS}-record cap were used; "
                    "narrow the date range for a complete trend."
                )
            return response

        return await _guard_rate_limit(_fetch)

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

        Joins the two metrics by UTC calendar date rather than by cycle, and
        reports Pearson's r and Spearman's rho at every lag from -lag_days to
        +lag_days (inclusive), each with its own sample size. A positive lag
        means metric_a's date precedes metric_b's by that many days --
        metric_a "leads". A lag whose surviving pairs fall below 8 is
        reported as refused rather than omitted.

        Correlation here is descriptive, not causal: WHOOP daily samples are
        autocorrelated (today's recovery is not independent of yesterday's),
        so do not read a strong r at some lag as proof that one metric drives
        the other, and do not treat a handful of weeks as a stable finding.

        Args:
            metric_a: First metric name, as in metric_trend.
            metric_b: Second metric name.
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
            lag_days: Sweep radius in days (default 3, capped at 14); the
                sweep covers every integer lag from -lag_days to +lag_days.

        Raises:
            ValueError: if lag_days is negative.
        """
        if lag_days < 0:
            raise ValueError(f"lag_days must be >= 0, got {lag_days}")
        lag_days = min(lag_days, _MAX_LAG_SWEEP_RADIUS)

        app = ctx.request_context.lifespan_context
        _ensure_matches_live_grant(ctx)

        async def _fetch() -> dict[str, Any]:
            collection_a = _resolve_collection(metric_a)
            collection_b = _resolve_collection(metric_b)
            records_a, truncated_a = await _fetch_collection(app, collection_a, start, end)
            # Two metrics can share a collection (e.g. recovery_score and hrv are
            # both "recovery") -- fetch it once and reuse rather than twice.
            if collection_b == collection_a:
                records_b, truncated_b = records_a, truncated_a
            else:
                records_b, truncated_b = await _fetch_collection(app, collection_b, start, end)
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
            return response

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
        _ensure_matches_live_grant(ctx)

        async def _fetch() -> dict[str, Any]:
            # Sequential, not concurrent (no asyncio.gather): each window's fetch
            # completes before the next window's starts.
            (
                baseline_summaries,
                baseline_range,
                baseline_truncated,
                baseline_expected_days,
            ) = await _summarize_window(app, baseline_start, baseline_end)
            (
                comparison_summaries,
                comparison_range,
                comparison_truncated,
                comparison_expected_days,
            ) = await _summarize_window(app, comparison_start, comparison_end)
            truncated = baseline_truncated or comparison_truncated
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
                "period_length_note": _period_length_note(
                    baseline_expected_days, comparison_expected_days
                ),
            }
            if truncated:
                response["note"] = (
                    f"Only records up to the {_ANALYSIS_MAX_RECORDS}-record cap were used; "
                    "narrow the date range for a complete comparison."
                )
            return response

        return await _guard_rate_limit(_fetch)
