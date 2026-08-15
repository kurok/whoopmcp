"""Webhook receiver: HMAC verification and replay defence (#17).

Public, unauthenticated endpoint -- the signature is the only gate. Raw
bytes must be HMAC'd (never re-serialized), compared via
``hmac.compare_digest``, and never logged. #18 fetches/upserts; not here.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import math
import time
from collections.abc import Callable
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
    """True if ``timestamp_header`` (ms since epoch) is within ``skew_seconds`` of ``now`` (secs).

    Checked both directions to tolerate clock drift, but bounded -- unbounded
    would let a captured, validly-signed request replay forever.
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

    ``raw_body`` must be the exact wire bytes, pre-JSON-parse -- re-serializing
    would break the match. Uses ``hmac.compare_digest``, not ``==``, to avoid
    a timing side-channel.
    """
    message = timestamp_header.encode("utf-8") + raw_body
    expected = hmac.new(client_secret.encode("utf-8"), message, hashlib.sha256).digest()
    try:
        provided = base64.b64decode(signature_header, validate=True)
    except ValueError:
        # Not valid base64 -- can't be a real signature.
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
    """Verify one inbound webhook request per WHOOP's documented signature formula.

    Returns ``False`` -- never raises -- on a missing header, a stale
    timestamp, or a bad signature. Callers must reject the body unparsed
    on ``False``.
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
    """Re-derive which check failed, for #31's metrics only (`verify_webhook_request`
    collapses all three into one `False` by design).

    Never touches the secret or raw body -- must not become a forgery oracle;
    the route handler still returns the same generic response either way.
    """
    if signature_header is None or timestamp_header is None:
        return "missing_header"
    if not _timestamp_within_skew(timestamp_header, skew_seconds, now=now):
        return "stale_timestamp"
    return "bad_signature"


class _InboundRateLimiter:
    """Fixed-window per-minute counter gating `/webhooks/whoop`, kept separate
    from `client.RateLimiter`'s outbound budget (#17 rules out sharing one).

    Process-local, like other per-process counters here: under multiple
    uvicorn workers each process counts alone, so the limit is per-worker,
    not fleet-wide.
    """

    _WINDOW_SECONDS = 60.0

    def __init__(self, *, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.time
        self._window_start = self._clock()
        self._count = 0

    def check(self, per_minute_limit: int) -> int | None:
        """Return ``None`` if the caller may proceed, else whole seconds until reset.

        ``per_minute_limit <= 0`` means no limit -- an operator opt-out.
        """
        if per_minute_limit <= 0:
            return None
        now = self._clock()
        if now - self._window_start >= self._WINDOW_SECONDS:
            self._window_start = now
            self._count = 0
        if self._count >= per_minute_limit:
            return max(1, math.ceil(self._window_start + self._WINDOW_SECONDS - now))
        self._count += 1
        return None


def register_webhook_routes(server: MCPServer[Any]) -> asyncio.Queue[bytes]:
    """Register ``POST /webhooks/whoop`` on ``server``, returning the queue it feeds.

    Route is always registered; ``Config.from_env()`` is re-read per request
    rather than captured at build time, since a ``custom_route`` handler has
    no ``AppContext`` to read from and ``build_server()`` is sometimes called
    with no WHOOP_* env set (see ``tests/test_server.py``). Disabled config
    yields a plain 404. The returned queue lives in this closure; #18 drains
    it, not this module.
    """
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    inbound_rate_limiter = _InboundRateLimiter()

    @server.custom_route(_WEBHOOK_PATH, methods=["POST"])
    async def whoop_webhook(request: Request) -> Response:
        config = Config.from_env()
        if not config.webhooks_enabled:
            return JSONResponse({"error": "not_found"}, status_code=404)

        # Checked before body read/HMAC -- a 429 here leaks nothing about
        # whether a signature would have been valid.
        retry_after = inbound_rate_limiter.check(config.webhook_rate_limit_per_minute)
        if retry_after is not None:
            return JSONResponse(
                {"error": "rate_limited"},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        # Raw bytes, read before anything else -- an unverified body must
        # never reach a JSON decoder.
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
            # #31: reason is for the operator-facing counter only -- response
            # stays generic so a caller learns nothing to iterate a forgery.
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

        # Verified but unparsed -- queued for #18. Return 200 before any
        # outbound call: WHOOP retries slow endpoints, which is how
        # duplicate processing starts.
        metrics.record_webhook_accepted()
        await queue.put(raw_body)
        logger.info("webhook accepted and queued")
        return JSONResponse({"status": "accepted"}, status_code=200)

    return queue
