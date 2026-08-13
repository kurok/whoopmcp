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

#: For ``whoop_sync`` (#15) alone: WHOOP itself is only ever read (GET), but
#: the tool's entire purpose is writing upserted records to the local store,
#: so ``read_only_hint=True`` would be factually wrong per MCP's own
#: semantics ("does not modify its environment") -- a client that trusts the
#: hint could auto-approve it without the confirmation a writing tool
#: otherwise warrants. ``destructive_hint=False`` and ``idempotent_hint=True``
#: are both accurate: every write is an upsert, and running it twice with no
#: new upstream data is a no-op.
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

    Opens the store (#13) -- issue #29's principal<->member join and audit
    log need it on every request, not only when webhooks are enabled, so
    opening it is not gated on `config.webhooks_enabled` the way the webhook
    consumer task below still is. But *where* it opens follows
    `Config.store_is_ephemeral` (#74): in default local stdio mode -- no
    `WHOOPMCP_CACHE`, no webhooks -- the store lives in memory only, because
    PRIVACY.md promises that mode persists nothing but the token, and an
    unconditionally-created `cache.sqlite3` broke that promise. Every other
    mode (hosted, `WHOOPMCP_CACHE=true`, or webhooks enabled) still opens
    `config.cache_path` on disk, unchanged. Also starts the webhook
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

        ephemeral = config.store_is_ephemeral
        store_conn = open_store(":memory:" if ephemeral else config.cache_path)
        if ephemeral and principal is not None:
            # Seed the principal<->member link the ephemeral store cannot
            # have inherited from a previous process. `resolve_member_id`
            # requires a real `principal_members` row and has no fallback to
            # `app.principal` -- deliberately, since #29 depends on that
            # contract -- so without this every data tool would raise
            # UnresolvedPrincipalError after a restart even though the token
            # on disk is perfectly valid. `_principal_key(None)` is exactly
            # the key those tools will look under: there is no request at
            # lifespan time, and this branch is stdio-only, so the local
            # sentinel is the only principal that can ever call in here.
            # This is a real row from the live grant, not a fallback: the
            # profile call above already proved the token authorises this
            # member. `principal is None` (not logged in) seeds nothing, so
            # tools correctly say "run whoop_login".
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
    """The name of the tool or resource this call is invoking, for the audit log.

    ``ctx.request_context.params`` is a plain ``Mapping`` in production (the
    raw ``tools/call``/``resources/read`` JSON-RPC params, read before typed
    validation) but a real ``CallToolRequestParams``/``ReadResourceRequestParams``
    in tests that build one directly -- both carry a ``name`` (tools) or a
    ``uri`` (resources), just via a different access pattern. A resource read
    has no ``name`` at all, so falling back to ``name`` alone would silently
    audit every resource read as ``"<unknown>"``; fall back to ``uri`` before
    giving up.
    """
    params = ctx.request_context.params
    if isinstance(params, Mapping):
        name = params.get("name") or params.get("uri")
    else:
        name = getattr(params, "name", None) or getattr(params, "uri", None)
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


def _register_metrics_route(server: MCPServer[AppContext]) -> None:
    """``GET /metrics``: Prometheus exposition for issue #31.

    Same shape of problem ``_check_token_store_reachable`` and
    ``register_webhook_routes`` already solve: a ``custom_route`` handler
    gets a plain Starlette ``Request``, never the lifespan-resolved
    ``AppContext``, so ``Config`` is read fresh per request rather than
    captured once at server-build time, and the store connection is opened
    and closed here rather than reused from ``AppContext.store_conn``.

    Fails closed on both axes the issue's Notes and decision D2/D3 require:

    - No ``WHOOPMCP_METRICS_TOKEN`` configured -> ``404``, byte-for-byte the
      plain-text ``Not Found`` Starlette itself returns for an unregistered
      path, so this route's existence isn't advertised either. Per the SDK's
      own docstring, a ``@custom_route``
      "will not require authorization" on its own -- unlike every MCP tool,
      which goes through the SDK's auth middleware -- so this handler is
      the only thing standing between the internet and per-member health
      data once a token *is* configured.
    - Token configured but the request's ``Authorization`` header is
      missing or doesn't match -> ``401``. Compared with
      ``hmac.compare_digest``, never ``==``, the same discipline
      ``webhooks.py`` already applies to its own signature check.
    - The token itself, the ``member_ref`` salt, and the WHOOP client
      secret never appear in the response body -- ``metrics.render`` is
      what actually enforces that; this handler adds nothing to the body
      beyond what it returns.
    """

    @server.custom_route("/metrics", methods=["GET"])
    async def metrics_endpoint(request: Request) -> Response:
        config = Config.from_env()
        if not config.metrics_token:
            # Plain text, matching Starlette's own 404 body byte-for-byte: a
            # JSON {"error": ...} body here would differ from what an
            # unregistered path returns and so would confirm the route exists.
            return PlainTextResponse("Not Found", status_code=404)

        provided = request.headers.get("Authorization", "")
        expected = f"Bearer {config.metrics_token}"
        # The isascii() guard is not redundant: hmac.compare_digest raises
        # TypeError on a str containing any non-ASCII character, and Starlette
        # decodes raw header bytes as latin-1, so any caller can put one there
        # -- turning what should be a 401 into an unhandled 500. A non-ASCII
        # header cannot match a token this handler built itself, so failing it
        # here is the same answer, arrived at without the exception.
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
        under Settings, or with the CLI-only `whoopmcp delete-member`, which
        cannot be called as a tool.
        """
        # This docstring is the tool description sent on every `tools/list`,
        # so it pays context on every request and is kept to the two facts a
        # model needs: logout is local-only, and revocation has two routes
        # neither of which it can invoke. The fuller wording -- why the CLI
        # command is operator-only, and that it needs --whoop-user-id -- lives
        # in the return value below, which costs nothing until called.
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


#: Response-shape convention every repointed data/analysis tool below
#: follows (#16), stated once here rather than re-derived per tool:
#:
#: - Every response carries a top-level "coverage" dict, keyed by the
#:   entity name(s) the tool drew from -- "recoveries"/"sleeps"/"cycles"/
#:   "workouts" (the store's own table names, including for the
#:   metric-sourced analysis tools, which key by entity table name rather
#:   than the singular friendly collection name) or "profile"/
#:   "body_measurement" for the two singletons. Collection entities get
#:   ``_entity_coverage``'s shape; singletons get ``_singleton_coverage``'s.
#: - Every range-taking tool (the 4 list_* tools, plus summarize_period/
#:   metric_trend/correlate_metrics/compare_periods) additionally carries a
#:   "range_coverage" dict, entity-keyed the same way, each a flat
#:   ``_range_coverage_entry``: comparing the tool's own resolved request
#:   range against that entity's coverage window. compare_periods has two
#:   ranges (baseline/comparison) but still reports one flat entry per
#:   entity -- see ``_merge_range_coverage``.
#: - get_sleep/get_workout/get_profile/get_body_measurement are point/
#:   singleton lookups, not ranges: they carry "coverage" but no
#:   "range_coverage". A miss is never a live fetch -- ``{"error":
#:   "not_synced", ...}`` when the entity has no coverage at all, or (for
#:   get_sleep/get_workout only, since the singletons have no "which id"
#:   question) ``{"error": "not_found_in_store", ...}`` when the entity has
#:   *some* coverage but not this particular id.
#:
#: This is a deliberate, chosen convention -- the issue's own text calls the
#: exact field shape a normal implementation detail, not something it
#: resolves -- applied consistently across all 12 repointed tools plus
#: whoop_data_coverage.


def _require_store(app: AppContext) -> sqlite3.Connection:
    """The persistent store every repointed data/analysis tool reads from.

    ``_ensure_matches_live_grant`` (via ``resolve_member_id``) already raises
    before this is ever reached if ``app.store_conn`` is ``None`` -- this
    exists so mypy can narrow the type at each tool's own call site, not
    because this branch is actually reachable in practice.
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

    A ``datetime`` (from ``_default_range``) and a caller-supplied string both
    have to come out in *the same shape*, because the store compares range
    bounds against stored timestamps **as text** (``store.py`` -- ``created_at
    >= ?``, ``start <= ?`` and friends). Text comparison only agrees with
    chronological order when both sides share a format, and stored values are
    WHOOP's own verbatim, e.g. ``2026-07-03T06:30:00.000Z``.

    Before #174 this function returned a caller's string untouched, so an
    offset form was compared byte-wise against a ``Z`` form. ``+`` (0x2B) and
    ``.`` (0x2E) both sort below ``Z`` (0x5A), which is wrong in both
    directions and by as much as the offset:

        stored 2026-07-03T06:30:00.000Z
        end    2026-07-03T06:30:00+00:00   -- the same instant, EXCLUDED
        end    2026-07-03T09:00:00+03:00   -- 06:00Z, i.e. earlier, INCLUDED

    Converting to UTC and emitting WHOOP's own millisecond form makes the text
    comparison mean what the caller asked for. The docstring this replaces
    already claimed both inputs became "one consistent string shape"; it just
    was not true of the string branch.

    **The assumption this rests on**, stated because it is the same one #140
    was filed about: stored timestamps are uniformly WHOOP's millisecond ``Z``
    form. If WHOOP ever emits a different precision, a same-instant boundary
    can mis-sort again -- ``...00Z`` against ``...00.000Z`` differs at ``Z``
    versus ``.``. That residue is far smaller than the offset bug (sub-second,
    only exactly on a boundary) and is pinned by a test rather than left to be
    rediscovered.
    """
    if value is None:
        return None
    moment = value if isinstance(value, datetime) else _parse_iso(value)
    moment = moment.astimezone(UTC)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{moment.microsecond // 1000:03d}Z"


#: Every collection entity a repointed tool can consult, mapped to the
#: store's own (earliest, latest) coverage query for it. Keys are the
#: store's own table names -- what every coverage/range_coverage envelope in
#: this module is keyed by, per this file's own response-shape convention
#: (see ``_entity_coverage``'s docstring).
_COLLECTION_COVERAGE_FN: dict[
    str, Callable[[sqlite3.Connection, int], tuple[str | None, str | None]]
] = {
    "recoveries": store.get_recovery_coverage,
    "sleeps": store.get_sleep_coverage,
    "cycles": store.get_cycle_coverage,
    "workouts": store.get_workout_coverage,
}

#: Friendly analysis-tool collection name (``_METRIC_COLLECTION``'s own
#: values) -> the store's table name it corresponds to. Every coverage/
#: range_coverage envelope in this module keys by the table name, never the
#: singular friendly collection name -- see this module's response-shape note.
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
    "incremental_sync": {...}}`` -- earliest/latest come from the entity's
    own activity-date columns (``created_at``, or ``start``/``end`` -- see
    store.py's schema comment and its own coverage-query docstrings), never
    ``updated_at``. ``backfill`` reads ``sync_state``'s bare entity-name row
    (backfill.py's own key, ``_EntitySpec.name``); ``incremental_sync`` reads
    the ``f"{entity}:incremental"`` row (sync.py's own
    ``_incremental_entity_key`` format, inlined here rather than imported
    since that helper is private to sync.py -- see its own module docstring
    for why the two keys must never collide). ``last_successful_at`` is only
    populated when the incremental row's own outcome is "complete": an
    "in_progress" row's ``last_run_at`` is that run's own timestamp, not a
    prior completion's, and reporting it as if it were one would be exactly
    the kind of confidently-wrong answer this issue exists to prevent.
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
    """The coverage envelope for a singleton entity (profile, body
    measurement): ``{"synced": bool, "last_updated_at": iso|None}`` --
    deliberately not the earliest/latest shape ``_entity_coverage`` returns,
    since neither singleton has an activity range to report."""
    return {"synced": updated_at is not None, "last_updated_at": updated_at}


def _parse_iso(value: str) -> datetime:
    """Parse a stored or requested timestamp, accepting the trailing ``Z``
    WHOOP's own payloads use, the ``+00:00`` offset this store's ``_now()``
    writes, and a bare offset-less string.

    Every tool docstring in this module asks for "ISO 8601 UTC" and shows a
    ``Z``-suffixed example, but a model that drops the offset and sends a
    naive string is a plausible, not a malicious, input -- treated as UTC
    (the documented convention) rather than raised as a comparison error
    against this function's always-aware stored values. Without this, two
    naive/aware ``datetime`` objects compared in ``_range_status`` raise an
    unstructured ``TypeError`` that surfaces as an opaque tool error instead
    of a coverage-status response.
    """
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _range_status(
    earliest: str | None, latest: str | None, start: str | None, end: str | None
) -> tuple[str, str | None]:
    """Compare a requested ``[start, end]`` against a held ``[earliest,
    latest]`` coverage window, returning one of four statuses and, for
    every status but ``"within_coverage"``, an explicit human-readable
    message -- see this module's own response-shape note for the full
    convention every range tool follows.
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


#: Worst-to-best ordering ``_merge_range_coverage`` picks the worse status
#: from -- lower is worse. A tool with more than one range to reconcile into
#: one flat entry (compare_periods' baseline vs. comparison) surfaces the
#: worse of the two rather than picking one arbitrarily or inventing a
#: nested shape the generic "every range tool's range_coverage is
#: entity -> {status, message}" convention (see this module's own
#: response-shape note) doesn't otherwise have.
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

    Every real WHOOP payload -- recovery, sleep, cycle and workout alike --
    carries ``created_at`` (analysis.py has always assumed this uniformly;
    see e.g. its own ``_dated_means`` docstring), so a genuine sync's raw_json
    already has it. This only matters for a record that was written some
    other way without one; falling back to the entity's own ``start`` (the
    nearest thing sleep/cycle/workout rows have to an activity timestamp)
    keeps analysis.py itself unchanged rather than teaching it a second,
    per-collection date field.
    """
    if record.get("created_at") is not None:
        return record
    return {**record, "created_at": record.get("start")}


def _decode_store_cursor(next_token: str | None) -> tuple[int, str | None, str | None]:
    """This module's own opaque store-pagination cursor: ``(offset, start,
    end)``. Bounds are baked into the cursor at the page that created it,
    not re-derived from whatever the caller resends as ``start``/``end`` on
    a continuation call -- an offset is only valid against the exact same
    WHERE clause that produced it, so the bounds must travel with it, not be
    re-guessed. No cursor (a first page) is ``(0, None, None)``.

    base64-encoded, not a bare JSON string: every ``next_token`` parameter
    in this module is typed ``str | None``, and the MCP SDK's own
    ``FuncMetadata.pre_parse_json`` helpfully (and, here, wrongly) attempts
    ``json.loads`` on any string argument whose field annotation is not
    exactly ``str`` -- a bare ``{"offset": ...}`` token would silently arrive
    at this function as an already-parsed ``dict``, not the string this
    signature (and pydantic's own arg validation) expects. base64 text is
    never valid JSON syntax, so it always survives that pre-parse untouched.
    """
    if next_token is None:
        return 0, None, None
    payload = json.loads(base64.urlsafe_b64decode(next_token.encode("ascii")).decode("utf-8"))
    return int(payload["offset"]), payload["start"], payload["end"]


def _encode_store_cursor(offset: int, start: str | None, end: str | None) -> str:
    payload = json.dumps({"offset": offset, "start": start, "end": end})
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def _require_positive_limit(limit: int) -> None:
    """Reject ``limit <= 0`` before it reaches a store query.

    ``limit=0`` is not merely "return nothing": every list tool's
    ``next_token`` encodes ``offset + limit``, so a zero limit produces a
    cursor identical to the one that led to it -- an empty page whose own
    continuation token loops back to itself forever, never resolving to
    "no more data." Raising here surfaces one clear error instead of a
    silent infinite-continuation trap.
    """
    if limit <= 0:
        raise ValueError(f"limit must be a positive integer, got {limit}")


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
        """Return the user's WHOOP profile: user id, email, first and last name.

        Served from the local store, never a live call -- a miss is reported
        as ``{"error": "not_synced", ...}``, never a live fetch. Every
        response (success or miss) carries a "coverage" key: ``{"synced":
        bool, "last_updated_at": iso|None}``.
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
            limit: Records to return per page.
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
            limit: Records to return per page.
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
            limit: Records to return per page.
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
            limit: Records to return per page.
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

        This is the way to check whether "no records" means "nothing
        happened" or "nothing has been imported yet" -- every other data and
        analysis tool's own "coverage"/"range_coverage" fields are built from
        exactly the same underlying state this tool reports directly. Call
        this first when in doubt, and before assuming a range tool's result
        is complete.

        For recoveries, sleeps, cycles and workouts: the earliest and latest
        activity date held, the last backfill outcome, and the last
        successful incremental sync time. For the profile and body
        measurement (which have no date range of their own): whether each
        has ever been synced, and when.
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

        Walks each collection forward from its own high-water ``updated_at``
        mark (never ``created_at``, so a rescored recovery or sleep is
        picked up, not just a newly-created one) and upserts every record
        into the local store. Once caught up, this costs one request per
        collection.

        Deletions are invisible to this walk: a record removed upstream
        keeps whatever was last synced for it. Only a WHOOP webhook reports
        a delete, and reconciling one this tool missed is a separate,
        not-yet-built job -- do not rely on this tool to notice one.

        Requires the persistent store (``WHOOPMCP_CACHE=true``, off by
        default -- see PRIVACY.md). When it is disabled this returns
        ``{"synced": False, ...}`` explaining why, rather than raising.
        """
        app = ctx.request_context.lifespan_context
        whoop_user_id = _ensure_matches_live_grant(ctx)
        if app.store_conn is None:
            # _ensure_matches_live_grant (via resolve_member_id) already
            # requires a store to have resolved this far; this is here only
            # so mypy can narrow the type below, not a reachable branch.
            raise RuntimeError("whoop_sync requires a persistent store")

        try:
            results = await run_sync(app.store_conn, app.client, app.config, whoop_user_id)
        except SyncDisabledError as exc:
            return {"synced": False, "message": str(exc)}

        return {
            "synced": True,
            "entities": {
                name: {"count": result.count, "cursor": result.high_water_mark}
                for name, result in results.items()
            },
        }


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


def _resolve_collection(metric: str) -> str:
    """Resolve a friendly metric name to the collection it is sourced from."""
    try:
        return _METRIC_COLLECTION[metric]
    except KeyError:
        raise ValueError(f"unknown metric: {metric!r}") from None


#: whoop_timeseries's (#20) own unit per metric, keyed by the same 6 names
#: as _METRIC_COLLECTION. Declared once here and echoed in the response
#: envelope's "unit" field, per the issue's own Scope ("the unit declared
#: once in the envelope rather than repeated per point"). Direction (e.g.
#: "lower is generally better" for resting_heart_rate) is NOT repeated in
#: the envelope -- the issue's own Notes ask for it in "the tool
#: description", which is this tool's docstring (see its Args section
#: below), not a runtime payload field; keeping it out of every response
#: matters here specifically because this tool's whole point is costing
#: an order of magnitude fewer tokens than the equivalent list_* call
#: (measured in tests/test_whoop_timeseries.py's own
#: test_whoop_timeseries_is_cheaper_than_list_sleeps), and a repeated
#: direction sentence is pure per-call overhead the model already has from
#: the tool schema.
_METRIC_UNIT: dict[str, str] = {
    "recovery_score": "%",
    "hrv": "ms",
    "resting_heart_rate": "bpm",
    "sleep_performance": "%",
    "sleep_efficiency": "%",
    "strain": "0-21 exertion scale",
}


def _resolve_metric_timeseries_source(metric: str) -> tuple[str, str, str]:
    """Resolve a friendly metric name to whoop_timeseries's own
    ``(entity, value_column, date_column)`` -- the store table (keyed by
    the store's own table name, matching every other coverage/range_coverage
    envelope in this module), its SQL value column, and its SQL date column.

    Deliberately not a change to ``_resolve_collection`` above: that
    function is used today by metric_trend/correlate_metrics/compare_periods
    and its exact ``"unknown metric: {metric!r}"`` message is very likely
    pinned by their own tests, so it stays as-is. This resolver instead
    composes the already-existing mappings (#16's own
    ``_METRIC_COLLECTION``/``_COLLECTION_TO_ENTITY``, analysis.py's own
    ``_METRIC_PATHS``, store.py's own ``_METRIC_TIMESERIES_DATE_COLUMNS``)
    without duplicating any of them, and raises its own helpful, name-listing
    error rather than reusing (or widening) ``_resolve_collection``'s.
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
    WHOOP records (score_state, nested score dicts) -- the same shape
    analysis.py's extract_metric/summarize/trend/correlate already know how
    to read -- not the trimmed shapes the data tools return, so this reads
    the store's own collection getter directly rather than going through
    list_recoveries etc. Never falls through to the live API on a miss: an
    empty or partial result here is a coverage gap, reported by the caller's
    own "coverage"/"range_coverage" envelope, not retried against WHOOP.

    Over-fetches by one row (``max_records + 1`` at the call site) to detect
    ``truncated`` without a second query -- true if the store may hold more
    than ``max_records`` matching the range requested.

    Every record gets ``_with_created_at_fallback`` applied: analysis.py
    indexes ``record["created_at"]`` unconditionally regardless of which
    collection a record came from, and a genuine WHOOP payload always has
    it, but this store read makes no assumption about how a record arrived
    here.
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
) -> tuple[dict[str, Any], tuple[str | None, str | None], bool, int]:
    """Read each of the 3 collections once from the store, then
    analysis.summarize per metric.

    6 metrics share only 3 collections -- reading once per metric here would
    be 6 store reads instead of 3, and summarize_period's whole point is not
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


#: The rolling window for whoop_outliers, in calendar days. 14, not 7 or
#: 30: a rolling window's own mean absorbs a sustained level shift over
#: roughly half its length, so a SHORTER window re-adapts to a genuine
#: change (the "slow seasonal drift" acceptance test) faster than a
#: longer one; 7 gives a noisier baseline from fewer points and doesn't
#: span a full weekday+weekend cadence, so 14 is the smallest window
#: that reliably covers that cadence twice over while still adapting
#: quickly. Pinned by tests/test_whoop_outliers.py's own WINDOW_DAYS
#: literal -- keep the two in sync.
_OUTLIERS_WINDOW_DAYS = 14

#: Nearest-measured-neighbour context radius reported alongside each
#: outlier ("the few days either side" -- the issue's own Scope). A
#: fixed internal constant, not a tool parameter: the issue's own
#: signature has none.
_OUTLIER_CONTEXT_DAYS = 3

#: Cap on the day-series fetched from the store per call -- mirrors
#: _TIMESERIES_MAX_POINTS's own role/magnitude.
_OUTLIERS_MAX_POINTS = 1000

#: Cap on outliers actually detailed (with context + other-metrics) in
#: the response, independent of _OUTLIERS_MAX_POINTS: an adversarial
#: series can flag most of its points as outliers.
_OUTLIERS_MAX_FLAGGED = 50

#: Cap on compact warm-up entries listed in the response.
_OUTLIERS_MAX_WARMUP = 100

#: Calendar days swept/enumerated per whoop_streaks call -- same
#: magnitude as _TIMESERIES_MAX_POINTS/_OUTLIERS_MAX_POINTS.
_STREAKS_MAX_DAYS = 1000


def _local_neighborhood_z(
    daily: Sequence[RollingPoint], index: int, radius: int
) -> tuple[float, float | None, float | None]:
    """One point's ``(mean, stdev, z_score)`` against a LOCAL
    neighbourhood of up to ``radius`` measured points on EACH side
    (``context_window``'s own point-count radius mechanic, not a
    strictly causal calendar window) plus the point itself.

    Exists alongside ``analysis.rolling_z_scores`` (the strictly
    trailing, calendar-day-bounded definition ``whoop_outliers`` still
    uses for warm-up tagging) because a causal-only trailing window can
    starve on sparse coverage: two measured points 13 calendar days
    apart, just inside a 14-day trailing window, produce a 2-point
    trailing sample whose z-score can never exceed ~0.71 in magnitude,
    regardless of how extreme the more recent value is -- a
    mathematical property of a 2-point sample's own standard
    deviation, not a tuning problem (tests/test_whoop_outliers.py's own
    context-truncation fixture hits exactly this with sparse, 13-day
    spaced history). Looking to both sides for the comparison sample
    fixes this without widening the trailing window enough to make the
    seasonal-drift acceptance test's own transition period over-flag
    instead: a wider *trailing* window takes longer to forget an old
    baseline once one exists, but a wider *radius-bounded*
    neighbourhood only grows with however much data is actually
    available nearby, not with elapsed calendar time, so it does not
    carry that cost.

    Returns ``stdev``/``z_score`` as ``None`` when the neighbourhood
    (including the point itself) has fewer than 2 points -- a standard
    deviation needs at least two values; this is only reachable in
    practice for a pathologically small ``radius``, since a day that
    clears ``rolling_z_scores``' own warm-up already has at least one
    earlier point in its run. A neighbourhood whose stdev is exactly 0
    defines ``z_score`` as ``0.0``, matching ``rolling_z_scores``' own
    "no deviation to score against" convention.
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

        Returns mean, standard deviation, median, min and max for each
        metric, along with the number of scored records behind each figure
        and ``days_missing`` -- how many calendar days in the range have no
        scored record for that metric, a coverage gap rather than a record
        count.

        Served from the local store. Every response carries "coverage" and
        "range_coverage", each keyed by "recoveries"/"sleeps"/"cycles" (the
        3 entities behind the 6 metrics), reporting what the store holds for
        each and how the requested range compares to it.

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

        Returns the least-squares slope in metric units per day. A slope is a
        description of the window requested, not a forecast. Also returns an
        r² fit-quality figure for that slope -- both as the number and as a
        word ("strong"/"moderate"/"weak"/"negligible") -- and 7/30/90-day
        rolling means of the metric over calendar days.

        Served from the local store. Every response (including an
        "insufficient_data" one) carries "coverage" and "range_coverage",
        keyed by the metric's own entity ("recoveries"/"sleeps"/"cycles").
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
            # No records worth speaking of on this path -- truncated/note
            # would be noise, not signal.
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
        # #54: distinguishable from the record-count "truncated"/"note" pair
        # above (fact #5) -- this is a *presentation* cap on how many rolling
        # points come back, not a statement about how many source records
        # were read, so it gets its own flag and its own note, legible even
        # when both caps apply to the same response at once.
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

        Served from the local store. Every response carries "coverage" and
        "range_coverage", keyed by the entities metric_a/metric_b are sourced
        from (one entry, or two when the metrics come from different
        collections).

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
        ) = await _summarize_window(conn, whoop_user_id, baseline_start, baseline_end)
        (
            comparison_summaries,
            comparison_range,
            comparison_truncated,
            comparison_expected_days,
        ) = await _summarize_window(conn, whoop_user_id, comparison_start, comparison_end)
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
        # Two ranges, not one -- range_coverage still reports one flat entry
        # per entity, like every other range tool (see this module's own
        # response-shape note), by merging the baseline and comparison
        # windows' own statuses into the worse of the two.
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
        questions: the model never needs to fetch whole records and average
        them itself.

        Aggregated in the database (SQL ``GROUP BY``, never pandas/numpy):
        multiple records landing in the same bucket (e.g. two workouts'
        strain the same day) are averaged (mean), not summed. A bucket with
        no scored record for it is simply absent from "points" -- never a
        zero-valued entry; a day you didn't wear the strap did not have a
        resting heart rate of nought. Only records with ``score_state ==
        "SCORED"`` are counted, the same rule ``metric_trend`` and every
        other analysis tool in this module apply.

        A "week" bucket's "date" is the Monday that starts it (not a week
        number, and not the record's own date) -- unambiguous without a side
        table, since this response is read by a model, not a spreadsheet. A
        "month" bucket's "date" is the 1st of that month.

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

        Served from the local store, never a live call. Carries a single
        flat "range_coverage" ({"status": ..., "message": ...}, see
        whoop_data_coverage's own convention) rather than the full
        "coverage" envelope (earliest/latest, backfill status, incremental
        sync status) metric_trend and the list_* tools carry: that fuller
        envelope costs several hundred tokens of fixed bookkeeping
        regardless of range size, which would defeat this tool's whole
        reason to exist (an order of magnitude cheaper than the equivalent
        list_* call -- see this module's own token-ratio test). This
        lighter signal is the one that actually matters here: an absent
        bucket paired with a non-"within_coverage" status means the range
        may simply not be synced yet, never confidently reported as "no
        activity". Call whoop_data_coverage for the fuller backfill/sync
        status picture. The point count is capped; "truncated" and a
        "note" report it when the cap is hit, rather than silently dropping
        the tail of the range.
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

        # Cheap by construction: one indexed MIN/MAX query, never the
        # backfill/incremental-sync sub-lookups _entity_coverage's own
        # fuller envelope makes -- this tool intentionally reports only
        # the range-comparison RESULT, not the full status picture.
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

        Outliers are found against a LOCAL baseline, not a global one, so a
        genuine sustained shift in the metric does not read as a month of
        anomalies -- see this tool's own acceptance test for a fixture that
        would false-positive under a naive global z-score but correctly
        stays quiet here.

        Whether a day has enough trailing calendar history to be scored at
        all ("warm-up") is decided by a strict, causal 14-calendar-day
        window: a day is unscored until 14 calendar days have elapsed since
        the start of its current run of coverage (a gap of >= 14 days
        resets that clock), and is reported under "warmup_days" rather than
        silently dropped -- a dropped day would read as a normal one. A day
        that clears warm-up is scored against a LOCAL neighbourhood instead
        (up to 14 measured points on each side, plus the day itself, via
        nearest-measured-neighbour slicing) rather than that same trailing
        window: a strictly-trailing window can starve on sparse coverage in
        a way a neighbourhood-based one does not (see this module's own
        ``_local_neighborhood_z`` docstring). Each outlier's "baseline_mean"/
        "baseline_stdev" therefore reflect that two-sided neighbourhood, not
        a strictly-historical trailing average -- a day near the end of the
        requested range can be scored against measured points that come
        after it in calendar time, so re-running this tool later, once more
        recent days have been synced, can change a near-the-edge day's
        z_score and flagged status. This does not affect "rolling, not
        global": the baseline is still local to the day, never the whole
        range's own mean/stdev.

        Each outlier is reported with up to 3 nearest measured days either
        side (truncated at the range's own edges, never an error) and,
        for that day only, whichever of the other 5 friendly metrics have
        a value -- "your HRV cratered on the 14th" is only useful alongside
        what else happened that day.

        Args:
            metric: One of "recovery_score", "hrv", "resting_heart_rate",
                "sleep_performance", "sleep_efficiency", "strain".
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
            z: The absolute z-score a day must cross to be an outlier
                (default 2.0).

        Served from the local store, never a live call. Never refuses on
        an empty or single-day range -- both return a coherent, empty-but-
        honest response rather than raising. Every response carries
        "coverage" and "range_coverage" (metric_trend's own full envelope).
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

        # 5 extra, cheap SQL-aggregated queries total (never one per
        # outlier) -- "the other metrics for that day", per this tool's own
        # Scope. Applied only to the outlier day itself, never its context
        # days, matching the issue's literal wording.
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

        Every calendar day in the requested range is enumerated in "days"
        -- not just measured ones. A day absent from the store is
        "missing" (unmeasured -- e.g. the strap wasn't worn); a day that
        was measured but does not meet the threshold is "failing"; a day
        that does is "passing". Both "missing" and "failing" end a streak,
        with no bridging logic -- the simplest, most conservative
        interpretation. Whether an unmeasured day *should* break a streak
        is a judgement call this tool leaves to the caller (per the
        issue's own Notes): "days" is returned in full alongside "streaks"
        so a caller who disagrees can reconstruct the alternate
        interpretation, e.g. by noticing two streaks are separated only by
        "missing" days, never "failing" ones.

        Args:
            metric: One of "recovery_score", "hrv", "resting_heart_rate",
                "sleep_performance", "sleep_efficiency", "strain".
            start: ISO 8601 start of the range.
            end: ISO 8601 end of the range.
            threshold: The value a day must cross to "pass".
            direction: "above" (a day passes when value >= threshold) or
                "below" (value <= threshold) -- both inclusive of the
                threshold itself, so a value exactly at it is never
                silently excluded from both directions.

        Served from the local store, never a live call. Never refuses on
        an empty or single-day range. Every response carries "coverage"
        and "range_coverage" (metric_trend's own full envelope). Per-streak
        entries omit "direction": it is constant across the whole response
        and stated once at the top level.
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
    """Register the prompts (#26): compositions of the *analysis* tools, not
    the raw data tools, so the model sees a habit worth imitating rather than
    an invitation to dump records.

    Every prompt here is a plain, argument-less function with no ``ctx``
    parameter: a prompt states which tools to call and why, it does not call
    them itself (see the issue's own Notes -- fetching or computing data
    inside a prompt is exactly the "just dumps records" failure mode prompts
    exist to avoid). Each returns ``list[str]``; the SDK turns each string
    into its own user-role message.

    Every prompt below stays consistent with ``INSTRUCTIONS``: no diagnosis,
    and no correlation-over-a-few-weeks presented as causal.
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

    One template rather than four static resources because a *static*
    resource's read function in the installed SDK is structurally
    incapable of receiving ``Context`` -- ``MCPServer.resource()`` rejects a
    ``Context``-typed parameter on any URI with no ``{param}`` at
    registration time -- so the ``_ensure_matches_live_grant`` identity gate
    every one of these four requires would simply be unreachable behind a
    static registration. A template *does* receive ``Context``,
    and the four exact URIs the issue specifies --
    ``whoop://user/profile``, ``whoop://user/latest-recovery``,
    ``whoop://user/latest-sleep`` and ``whoop://user/latest-cycle`` -- still
    resolve through it unchanged. The one visible consequence: they now
    surface via ``resources/templates/list`` rather than ``resources/list``.

    The template itself matches ANY single trailing segment -- both
    ``whoop://user/`` (``item == ""``) and ``whoop://user/unknown-thing``
    match just as readily as the four real items -- so the
    ``ResourceNotFoundError`` at the end of the dispatch below is
    load-bearing, not defensive: without it, every unrecognised item would
    silently fall through instead of failing.
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
    # ctx is deliberately typed as the bare `Context`, not the parametrized
    # `Context[AppContext, Any]` every tool function above uses: a resource
    # *template*'s function is wrapped whole in pydantic's `validate_call`
    # (unlike a tool's, where the context parameter is stripped out before
    # argument validation and injected directly) -- verified empirically,
    # not assumed: a `Context[AppContext, Any]`-annotated parameter here
    # forces pydantic to revalidate the incoming `Context` instance against
    # that exact parametrized class, and since every caller in this
    # codebase (including every test harness that reads a resource)
    # constructs a plain, unparametrized `Context(...)`, that revalidation
    # silently rebuilds a blank instance missing the private
    # `_request_context`/`_mcp_server` attributes the object actually
    # carried -- `ctx.request_context` then raises "Context is not
    # available outside of a request" instead of ever reaching the
    # identity gate. The bare annotation matches what every call site here
    # actually constructs, so no such revalidation happens.
    async def whoop_user_resource(item: str, ctx: Context) -> dict[str, Any]:
        # A `cast`, not a real parametrized annotation on `ctx` itself (see
        # above) -- has no runtime effect, so it doesn't reintroduce the
        # pydantic revalidation this function's bare `Context` annotation
        # exists to avoid, while still giving `_ensure_matches_live_grant`/
        # `_require_store` below the `AppContext`-typed value they declare.
        typed_ctx = cast("Context[AppContext, Any]", ctx)
        app = typed_ctx.request_context.lifespan_context
        # The identity gate runs before the item dispatch below, deliberately:
        # an unauthenticated caller must not learn which items exist, and
        # resolve_member_id's own audit write (store.record_tool_call) should
        # record an attempted read of an unknown item rather than drop it.
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
