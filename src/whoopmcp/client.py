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

from whoopmcp.auth import Authenticator, AuthError, build_store
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

    async def _get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        """GET a path, with a bearer token attached and errors normalised."""
        token = await self._auth.access_token()
        response = await self._request(path, params, token)

        if response.status_code == 401:
            token = await self._force_refresh()
            response = await self._request(path, params, token)

        if response.status_code == 429:
            retry_after: float | None = None
            reset_header = response.headers.get("X-RateLimit-Reset")
            if reset_header is not None:
                try:
                    retry_after = float(reset_header)
                except ValueError:
                    retry_after = None
            raise RateLimitedError(_error_message(response), retry_after=retry_after)

        if not response.is_success:
            raise WhoopAPIError(response.status_code, _error_message(response))

        return response.json()

    async def _get_page(self, path: str, params: dict[str, str]) -> Page:
        """GET one page of a collection."""
        data = await self._get(path, params)
        return Page(records=data.get("records", []), next_token=data.get("next_token"))

    async def paginate(
        self, path: str, params: dict[str, str], *, max_records: int = 1000
    ) -> AsyncIterator[dict[str, Any]]:
        """Walk a collection, following ``nextToken`` until it runs out.

        Default cap of 1000: at MAX_PAGE_SIZE (25) records/page that's 40
        requests, comfortably inside the 100/minute budget for a single tool
        call.
        """
        fetched = 0
        current_params = dict(params)
        while True:
            page = await self._get_page(path, current_params)
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
