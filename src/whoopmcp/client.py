"""Thin async client over the WHOOP API v2.

Read-only by design: the only non-GET endpoint WHOOP exposes to an OAuth
client is ``DELETE /v2/user/access``, and this client deliberately does not
call it -- revoking a grant is something a user should do from WHOOP's own
settings, not something an LLM should be able to trigger.

Docs: https://developer.whoop.com/api/
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx

from whoopmcp.auth import Authenticator
from whoopmcp.config import Config

BASE_URL = "https://api.prod.whoop.com/developer"

#: WHOOP caps a page at 25 records regardless of what you ask for.
MAX_PAGE_SIZE = 25

#: Documented default limits: 100 requests/minute and 10,000/day, signalled
#: by X-RateLimit-* headers and a 429 on breach.
RATE_LIMIT_PER_MINUTE = 100
RATE_LIMIT_PER_DAY = 10_000


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


class WhoopClient:
    """Async WHOOP v2 client. One instance per server process.

    Every method maps to exactly one documented endpoint; the shaping of that
    data into something an LLM can reason about happens in ``analysis``, not
    here.
    """

    def __init__(self, config: Config, auth: Authenticator) -> None:
        self._config = config
        self._auth = auth
        self._http: httpx.AsyncClient | None = None

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

    async def _get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        """GET a path, with a bearer token attached and errors normalised.

        TODO(#2): attach `Authorization: Bearer {await self._auth.access_token()}`,
        raise RateLimitedError on 429 honouring X-RateLimit-Reset, retry once
        on 401 after a forced refresh, and map every other 4xx/5xx onto
        WhoopAPIError.
        """
        raise NotImplementedError("_get is not implemented yet -- see issue #2")

    async def _get_page(self, path: str, params: dict[str, str]) -> Page:
        """GET one page of a collection.

        TODO(#2): unwrap the `{"records": [...], "next_token": ...}` envelope.
        """
        raise NotImplementedError("_get_page is not implemented yet -- see issue #2")

    async def paginate(
        self, path: str, params: dict[str, str], *, max_records: int | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        """Walk a collection, following ``nextToken`` until it runs out.

        TODO(#2): loop on _get_page, stop at max_records or a null next_token.
        Bound this -- an unbounded walk over years of data will blow both the
        rate limit and the model's context window.
        """
        raise NotImplementedError("paginate is not implemented yet -- see issue #2")
        yield {}  # pragma: no cover - makes this an async generator for mypy

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
