"""Thin async client over the WHOOP API v2.

Read-only by design: the only non-GET endpoint WHOOP exposes to an OAuth
client is ``DELETE /v2/user/access``, and this client deliberately does not
call it -- revoking a grant is something a user should do from WHOOP's own
settings, not something an LLM should be able to trigger.

Docs: https://developer.whoop.com/api/
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import random
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from whoopmcp.auth import Authenticator, AuthError, build_store
from whoopmcp.config import Config

BASE_URL = "https://api.prod.whoop.com/developer"

#: WHOOP caps a page at 25 records regardless of what you ask for.
MAX_PAGE_SIZE = 25

#: Documented default limits: 100 requests/minute and 10,000/day, signalled
#: by X-RateLimit-* headers and a 429 on breach.
RATE_LIMIT_PER_MINUTE = 100
RATE_LIMIT_PER_DAY = 10_000

#: How many times _get retries a 429 before giving up and raising.
_MAX_429_RETRIES = 5
_BACKOFF_BASE_SECONDS = 1.0
_BACKOFF_MAX_SECONDS = 30.0


class RequestPriority(enum.Enum):
    """Two priority classes. Nothing in this codebase issues BACKFILL yet
    (that's future work, #14) -- this just builds the mechanism ahead of it.
    """

    INTERACTIVE = "interactive"
    BACKFILL = "backfill"


#: How often a blocked acquire()/wait rechecks the clock. Bounded and small
#: so a test using an injected clock (advanced instantly, no real waiting)
#: still completes in well under a second -- production callers just see a
#: slightly-delayed, but still prompt, grant once a window rolls over, a
#: header reveals more room, or a 429's wait elapses.
_POLL_INTERVAL_SECONDS = 0.02


class RateLimiter:
    """An async token bucket in front of every request. Per-minute and
    per-day counters; the daily one resets on a UTC calendar boundary, not
    a rolling 24h window. Reconciled against WHOOP's own X-RateLimit-*
    headers on every response -- local accounting is an optimisation, the
    headers are the truth, and the budget may be shared with callers this
    process doesn't know about (#9).
    """

    def __init__(
        self,
        *,
        per_minute: int,
        per_day: int,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._per_minute_limit = per_minute
        self._per_day_limit = per_day
        self._clock = clock or time.time
        self._minute_remaining = per_minute
        self._minute_window_start = self._clock()
        self._day_remaining = per_day
        self._day_reset_at = self._next_utc_midnight(self._clock())
        self._lock = asyncio.Lock()
        self._interactive_waiting = 0

    @staticmethod
    def _next_utc_midnight(now: float) -> float:
        current = datetime.fromtimestamp(now, tz=UTC)
        next_day = (current + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        return next_day.timestamp()

    def _replenish_locked(self) -> None:
        """Reset any counter whose window has rolled over. Caller holds self._lock."""
        now = self._clock()
        if now - self._minute_window_start >= 60.0:
            self._minute_remaining = self._per_minute_limit
            self._minute_window_start = now
        if now >= self._day_reset_at:
            self._day_remaining = self._per_day_limit
            self._day_reset_at = self._next_utc_midnight(now)

    async def acquire(self, priority: RequestPriority = RequestPriority.INTERACTIVE) -> None:
        if priority is RequestPriority.INTERACTIVE:
            self._interactive_waiting += 1
        try:
            while True:
                async with self._lock:
                    self._replenish_locked()
                    capacity_available = self._minute_remaining > 0 and self._day_remaining > 0
                    # A BACKFILL caller must never consume a freed slot while
                    # any INTERACTIVE caller is still waiting for one.
                    may_take = capacity_available and (
                        priority is RequestPriority.INTERACTIVE or self._interactive_waiting == 0
                    )
                    if may_take:
                        self._minute_remaining -= 1
                        self._day_remaining -= 1
                        return
                await asyncio.sleep(_POLL_INTERVAL_SECONDS)
        finally:
            if priority is RequestPriority.INTERACTIVE:
                self._interactive_waiting -= 1

    def reconcile(self, headers: httpx.Headers) -> None:
        """WHOOP's own header values replace local accounting outright --
        not just a downward clamp -- since the header is the one source of
        truth for a budget that may be shared across other callers.
        """
        remaining = headers.get("X-RateLimit-Remaining")
        if remaining is not None:
            with contextlib.suppress(ValueError):
                self._minute_remaining = int(remaining)
        limit = headers.get("X-RateLimit-Limit")
        if limit is not None:
            with contextlib.suppress(ValueError):
                self._per_minute_limit = int(limit)
        reset_seconds = _reset_seconds(headers)
        if reset_seconds is not None:
            # X-RateLimit-Reset is seconds until the per-minute window rolls
            # over (the convention #2 already established for this header).
            # Back the window's start out from that so a local timer that has
            # drifted from WHOOP's own doesn't grant early, or make an
            # already-refilled bucket wait longer than it has to.
            self._minute_window_start = self._clock() + reset_seconds - 60.0


async def _wait_seconds(clock: Callable[[], float], seconds: float) -> None:
    """Wait `seconds` of the given clock's time, polling briefly rather than
    a single long asyncio.sleep -- so a test using a fake clock (advanced
    instantly) completes in a bounded, small amount of real time instead of
    the full logical duration.
    """
    deadline = clock() + seconds
    while clock() < deadline:
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)


class WhoopAPIError(RuntimeError):
    """A WHOOP API call failed."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"WHOOP API {status}: {message}")
        self.status = status


class RateLimitedError(WhoopAPIError):
    """WHOOP returned 429. ``retry_after`` is seconds, when it told us."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(429, message)
        self.retry_after = retry_after


@dataclass(frozen=True, slots=True)
class Page:
    """One page of a paginated collection."""

    records: list[dict[str, Any]]
    next_token: str | None


def build_collection_params(
    *,
    start: datetime | str | None = None,
    end: datetime | str | None = None,
    limit: int | None = None,
    next_token: str | None = None,
) -> dict[str, str]:
    """Normalise the query parameters every paginated WHOOP collection takes.

    Args:
        start: Inclusive lower bound, ISO 8601.
        end: Exclusive upper bound, ISO 8601.
        limit: Records per page. Clamped to ``MAX_PAGE_SIZE``; WHOOP 400s on
            anything larger rather than silently truncating.
        next_token: Cursor from a previous response.

    Raises:
        ValueError: if ``limit`` is not positive.
    """
    params: dict[str, str] = {}

    if start is not None:
        params["start"] = _iso(start)
    if end is not None:
        params["end"] = _iso(end)
    if limit is not None:
        if limit < 1:
            raise ValueError(f"limit must be >= 1, got {limit}")
        params["limit"] = str(min(limit, MAX_PAGE_SIZE))
    if next_token:
        params["nextToken"] = next_token

    return params


def _iso(value: datetime | str) -> str:
    return value.isoformat() if isinstance(value, datetime) else value


def _error_message(response: httpx.Response) -> str:
    """Build a human-readable error message from a failed response body.

    Only WHOOP's own ``error``/``message`` JSON fields are echoed back --
    never the request or response headers/body verbatim, since that is where
    a bearer token would end up in a bug report.
    """
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    if isinstance(payload, dict):
        detail = payload.get("error") or payload.get("message")
        if detail:
            return str(detail)
    return f"HTTP {response.status_code}"


def _reset_seconds(headers: httpx.Headers) -> float | None:
    """Extract ``retry_after`` from ``X-RateLimit-Reset``, if present and
    parseable. Existing, established (if ambiguous) convention from #2:
    kept exactly as-is, just factored out so the final-429 path, the
    ``RateLimitedError`` it raises, and ``RateLimiter.reconcile`` can all
    share it.
    """
    retry_after: float | None = None
    reset_header = headers.get("X-RateLimit-Reset")
    if reset_header is not None:
        try:
            retry_after = float(reset_header)
        except ValueError:
            retry_after = None
    return retry_after


def _parse_retry_after_seconds(response: httpx.Response) -> float | None:
    """Retry-After is a standard HTTP header, always seconds here (WHOOP
    doesn't use the HTTP-date form) -- unambiguous, unlike X-RateLimit-Reset.
    """
    header = response.headers.get("Retry-After")
    if header is None:
        return None
    try:
        return float(header)
    except ValueError:
        return None


def _backoff_seconds(attempt: int) -> float:
    """Capped exponential backoff with full jitter, used only when WHOOP
    doesn't tell us exactly how long to wait via Retry-After.
    """
    capped = min(_BACKOFF_MAX_SECONDS, _BACKOFF_BASE_SECONDS * (2**attempt))
    return random.uniform(0, capped)  # noqa: S311 -- jitter, not a security use


class WhoopClient:
    """Async WHOOP v2 client. One instance per server process.

    Every method maps to exactly one documented endpoint; the shaping of that
    data into something an LLM can reason about happens in ``analysis``, not
    here.
    """

    def __init__(
        self,
        config: Config,
        auth: Authenticator,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._config = config
        self._auth = auth
        self._http: httpx.AsyncClient | None = None
        self._clock = clock or time.time
        self._rate_limiter = RateLimiter(
            per_minute=config.rate_limit_per_minute,
            per_day=config.rate_limit_per_day,
            clock=self._clock,
        )

    async def __aenter__(self) -> WhoopClient:
        self._http = httpx.AsyncClient(
            base_url=BASE_URL,
            timeout=self._config.request_timeout,
            headers={"User-Agent": "whoopmcp (+https://github.com/kurok/whoopmcp)"},
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # -- transport ---------------------------------------------------------

    async def _request(
        self, path: str, params: dict[str, str] | None, token: str
    ) -> httpx.Response:
        """Issue one GET with the given bearer token attached."""
        if self._http is None:
            raise RuntimeError("WhoopClient must be used as an async context manager")
        return await self._http.get(
            path, params=params, headers={"Authorization": f"Bearer {token}"}
        )

    async def _force_refresh(self) -> str:
        """Refresh regardless of the cached token's apparent expiry.

        access_token() only refreshes when its own clock says expired; a 401
        means WHOOP revoked the grant, which the clock can't know. Loading the
        persisted token and calling Authenticator.refresh() on it directly
        forces a real network refresh -- and refresh() already updates
        Authenticator's own cache, so the next ordinary access_token() call
        sees the result too.
        """
        store = build_store(self._config)
        token = store.load()
        if token is None or token.refresh_token is None:
            raise AuthError("no refresh token available to retry with; run whoop_login")
        new_token = await self._auth.refresh(token)
        return new_token.access_token

    async def _get(
        self,
        path: str,
        params: dict[str, str] | None = None,
        *,
        priority: RequestPriority = RequestPriority.INTERACTIVE,
    ) -> dict[str, Any]:
        """GET a path, with a bearer token attached and errors normalised."""
        token = await self._auth.access_token()
        await self._rate_limiter.acquire(priority)
        response = await self._request(path, params, token)
        self._rate_limiter.reconcile(response.headers)

        if response.status_code == 401:
            token = await self._force_refresh()
            await self._rate_limiter.acquire(priority)
            response = await self._request(path, params, token)
            self._rate_limiter.reconcile(response.headers)

        attempt = 0
        while response.status_code == 429 and attempt < _MAX_429_RETRIES:
            retry_after = _parse_retry_after_seconds(response)
            wait_seconds = retry_after if retry_after is not None else _backoff_seconds(attempt)
            await _wait_seconds(self._clock, wait_seconds)
            attempt += 1
            await self._rate_limiter.acquire(priority)
            response = await self._request(path, params, token)
            self._rate_limiter.reconcile(response.headers)

        if response.status_code == 429:
            raise RateLimitedError(
                _error_message(response), retry_after=_reset_seconds(response.headers)
            )

        if not response.is_success:
            raise WhoopAPIError(response.status_code, _error_message(response))

        return response.json()

    async def _get_page(
        self,
        path: str,
        params: dict[str, str],
        *,
        priority: RequestPriority = RequestPriority.INTERACTIVE,
    ) -> Page:
        """GET one page of a collection."""
        data = await self._get(path, params, priority=priority)
        return Page(records=data.get("records", []), next_token=data.get("next_token"))

    async def paginate(
        self,
        path: str,
        params: dict[str, str],
        *,
        max_records: int = 1000,
        priority: RequestPriority = RequestPriority.INTERACTIVE,
    ) -> AsyncIterator[dict[str, Any]]:
        """Walk a collection, following ``nextToken`` until it runs out.

        Default cap of 1000: at MAX_PAGE_SIZE (25) records/page that's 40
        requests, comfortably inside the 100/minute budget for a single tool
        call.
        """
        fetched = 0
        current_params = dict(params)
        while True:
            page = await self._get_page(path, current_params, priority=priority)
            for record in page.records:
                if fetched >= max_records:
                    return
                yield record
                fetched += 1
            if page.next_token is None or fetched >= max_records:
                return
            current_params = {**params, "nextToken": page.next_token}

    # -- user --------------------------------------------------------------

    async def get_profile(self) -> dict[str, Any]:
        """GET /v2/user/profile/basic -- user id, email, first and last name."""
        return await self._get("/v2/user/profile/basic")

    async def get_body_measurement(self) -> dict[str, Any]:
        """GET /v2/user/measurement/body -- height, weight, max heart rate."""
        return await self._get("/v2/user/measurement/body")

    # -- cycles ------------------------------------------------------------

    async def get_cycle(self, cycle_id: int) -> dict[str, Any]:
        """GET /v2/cycle/{cycleId} -- one physiological cycle."""
        return await self._get(f"/v2/cycle/{cycle_id}")

    async def list_cycles(self, **kwargs: Any) -> Page:
        """GET /v2/cycle -- cycles with strain and average heart rate."""
        return await self._get_page("/v2/cycle", build_collection_params(**kwargs))

    async def get_cycle_sleep(self, cycle_id: int) -> dict[str, Any]:
        """GET /v2/cycle/{cycleId}/sleep -- the sleep belonging to a cycle."""
        return await self._get(f"/v2/cycle/{cycle_id}/sleep")

    async def get_cycle_recovery(self, cycle_id: int) -> dict[str, Any]:
        """GET /v2/cycle/{cycleId}/recovery -- the recovery scored for a cycle."""
        return await self._get(f"/v2/cycle/{cycle_id}/recovery")

    # -- recovery ----------------------------------------------------------

    async def list_recoveries(self, **kwargs: Any) -> Page:
        """GET /v2/recovery -- recovery score, HRV and resting heart rate."""
        return await self._get_page("/v2/recovery", build_collection_params(**kwargs))

    # -- sleep -------------------------------------------------------------

    async def get_sleep(self, sleep_id: str) -> dict[str, Any]:
        """GET /v2/activity/sleep/{sleepId} -- one sleep, by v2 UUID."""
        return await self._get(f"/v2/activity/sleep/{sleep_id}")

    async def list_sleeps(self, **kwargs: Any) -> Page:
        """GET /v2/activity/sleep -- sleep performance and stage durations."""
        return await self._get_page("/v2/activity/sleep", build_collection_params(**kwargs))

    # -- workouts ----------------------------------------------------------

    async def get_workout(self, workout_id: str) -> dict[str, Any]:
        """GET /v2/activity/workout/{workoutId} -- one workout, by v2 UUID."""
        return await self._get(f"/v2/activity/workout/{workout_id}")

    async def list_workouts(self, **kwargs: Any) -> Page:
        """GET /v2/activity/workout -- workout strain and heart-rate metrics."""
        return await self._get_page("/v2/activity/workout", build_collection_params(**kwargs))
