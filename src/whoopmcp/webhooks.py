"""Webhook receiver: HMAC verification and replay defence (#17).

WHOOP v2 offers six webhook events -- recovery, sleep and workout, each
updated and deleted -- so a server can learn what changed instead of polling
to discover nothing did. This module is the receiving endpoint and its
signature check only: verify, queue, return. Fetching the changed resource
and upserting it into the store is #18's job, not this one -- nothing here
parses an event body as anything but opaque bytes.

The endpoint is public and unauthenticated by construction (WHOOP calls it
from the internet, with no bearer token of ours to check), so the signature
is the *only* gate standing between the internet and this process. Get it
wrong and anyone can inject an event; log the wrong thing and health data
ends up in a log file. Both mistakes are treated as this module's whole job
to avoid:

- The raw bytes read off the wire are what gets HMAC'd -- never a
  re-serialised body, which would only coincidentally match WHOOP's own
  signature.
- ``hmac.compare_digest``, never ``==``, for the comparison.
- A body is rejected before it ever reaches a JSON decoder; if the
  signature doesn't check out, nothing downstream should be able to tell
  the difference between "malformed JSON" and "well-formed JSON we didn't
  bother parsing".
- No log record on any path -- success, bad signature, bad timestamp,
  missing header -- ever contains the raw body, the signature, or the
  signing secret.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import time
from typing import Any

from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from whoopmcp import metrics
from whoopmcp.config import Config

logger = logging.getLogger("whoopmcp")

#: WHOOP's own header names for the signature and the timestamp it covers.
SIGNATURE_HEADER = "X-WHOOP-Signature"
TIMESTAMP_HEADER = "X-WHOOP-Signature-Timestamp"

_WEBHOOK_PATH = "/webhooks/whoop"


def _timestamp_within_skew(timestamp_header: str, skew_seconds: float, *, now: float) -> bool:
    """Whether ``timestamp_header`` (unix milliseconds, as text) is within the skew window.

    ``now`` is unix seconds, matching ``time.time()``.

    WHOOP documents ``X-WHOOP-Signature-Timestamp`` as "the milliseconds
    since epoch timestamp", so the header is converted to seconds before
    comparison against ``now``, which is a ``time.time()``-shaped value.

    Checked in both directions -- WHOOP's clock and this process's clock are
    never perfectly synchronised -- but bounded, since an unbounded window
    would let a captured, correctly-signed request be replayed forever.
    """
    try:
        timestamp = float(timestamp_header) / 1000.0
    except ValueError:
        return False
    return abs(now - timestamp) <= skew_seconds


def _signature_matches(
    raw_body: bytes, timestamp_header: str, signature_header: str, client_secret: str
) -> bool:
    """Verify ``signature_header`` against HMAC-SHA256(timestamp + raw_body, client_secret).

    ``raw_body`` must be the exact bytes read off the wire, before any JSON
    parsing -- a re-serialised body changes whitespace and key order and
    would never match WHOOP's own signature even for a genuine event.
    Comparison is via ``hmac.compare_digest``, not ``==``, so a mismatch
    can't be timed character-by-character.
    """
    message = timestamp_header.encode("utf-8") + raw_body
    expected = hmac.new(client_secret.encode("utf-8"), message, hashlib.sha256).digest()
    try:
        provided = base64.b64decode(signature_header, validate=True)
    except ValueError:
        # Not valid base64 at all -- can't be a real signature.
        return False
    return hmac.compare_digest(expected, provided)


def verify_webhook_request(
    raw_body: bytes,
    signature_header: str | None,
    timestamp_header: str | None,
    client_secret: str,
    skew_seconds: float,
    *,
    now: float | None = None,
) -> bool:
    """Verify one inbound webhook request against WHOOP's documented signature formula.

    Returns ``False`` -- never raises -- for a missing header, a timestamp
    outside ``skew_seconds`` of ``now`` (even given an otherwise-valid
    signature: a captured request replays forever without this check), or a
    signature that doesn't match. Every caller must treat ``False`` as
    "reject before parsing the body as anything else."
    """
    if signature_header is None or timestamp_header is None:
        return False
    current = time.time() if now is None else now
    if not _timestamp_within_skew(timestamp_header, skew_seconds, now=current):
        return False
    return _signature_matches(raw_body, timestamp_header, signature_header, client_secret)


def _rejection_reason(
    signature_header: str | None, timestamp_header: str | None, skew_seconds: float, *, now: float
) -> str:
    """Re-derive, for #31's counter only, which of `verify_webhook_request`'s
    three checks failed -- that function itself collapses all three into one
    `False`, by design, so the caller learns nothing from the response.

    Neither branch here touches the signing secret or the raw body: the
    reason an operator sees is never an oracle a forger could use, only the
    generic `invalid_signature` response is (see the route handler).
    """
    if signature_header is None or timestamp_header is None:
        return "missing_header"
    if not _timestamp_within_skew(timestamp_header, skew_seconds, now=now):
        return "stale_timestamp"
    return "bad_signature"


def register_webhook_routes(server: MCPServer[Any]) -> asyncio.Queue[bytes]:
    """Register ``POST /webhooks/whoop`` on ``server``, returning the queue it feeds.

    Typed against ``MCPServer[Any]`` rather than server.py's own
    ``MCPServer[AppContext]``: this module has no need to know the shape of
    the lifespan context, and importing ``AppContext`` from server.py here
    would invert the natural direction (server.py wires modules together,
    not the reverse) and create a circular import, since server.py is what
    calls this function.

    The route is always registered; whether it actually accepts anything is
    decided per request, inside the handler, by a fresh ``Config.from_env()``
    read -- not by a ``Config`` captured once here at server-build time. Two
    reasons, both already established by ``_check_token_store_reachable`` in
    server.py for the same shape of problem: a ``custom_route`` handler gets
    a plain Starlette ``Request``, not the lifespan-resolved ``AppContext``
    every MCP tool gets, so there is no already-loaded ``Config`` to reach
    for here; and ``build_server()`` itself is called in places (see
    ``tests/test_server.py``'s ``server`` fixture) with no WHOOP_* variables
    in the environment at all, so requiring a valid ``Config`` at
    registration time would make constructing the server itself depend on
    configuration this feature doesn't otherwise need. A request that hits
    this route while ``webhooks_enabled`` is false gets the same `404` as a
    genuinely unregistered path would.

    Returns the queue verified events are placed on -- an in-process
    ``asyncio.Queue`` is sufficient for this issue, since #18, not this one,
    is what drains it. The queue therefore lives in this closure, not on
    ``AppContext``, so the handler below can reach it without needing the
    lifespan context either.
    """
    queue: asyncio.Queue[bytes] = asyncio.Queue()

    @server.custom_route(_WEBHOOK_PATH, methods=["POST"])
    async def whoop_webhook(request: Request) -> Response:
        config = Config.from_env()
        if not config.webhooks_enabled:
            return JSONResponse({"error": "not_found"}, status_code=404)

        # Raw bytes, read before anything else touches this request -- an
        # unverified body must never reach a JSON decoder, and this line is
        # the only place that body exists as anything other than opaque
        # bytes anywhere in this module.
        raw_body = await request.body()
        signature_header = request.headers.get(SIGNATURE_HEADER)
        timestamp_header = request.headers.get(TIMESTAMP_HEADER)
        now = time.time()

        if not verify_webhook_request(
            raw_body,
            signature_header,
            timestamp_header,
            config.client_secret,
            config.webhook_timestamp_skew_seconds,
            now=now,
        ):
            # #31: the reason is re-derived for the operator-facing counter
            # only -- the response below stays the same generic body for
            # every cause, so an unauthenticated caller gets nothing to help
            # it iterate toward a forgery.
            metrics.record_webhook_signature_failure(
                _rejection_reason(
                    signature_header,
                    timestamp_header,
                    config.webhook_timestamp_skew_seconds,
                    now=now,
                )
            )
            logger.warning("webhook rejected: signature verification failed")
            return JSONResponse({"error": "invalid_signature"}, status_code=400)

        # Verified, but still unparsed -- queued as opaque bytes for #18 to
        # decode and process. Returning 200 now, before any outbound WHOOP
        # call, matters: WHOOP retries a slow endpoint, and a retry of
        # in-flight work is how duplicate processing starts.
        metrics.record_webhook_accepted()
        await queue.put(raw_body)
        logger.info("webhook accepted and queued")
        return JSONResponse({"status": "accepted"}, status_code=200)

    return queue
