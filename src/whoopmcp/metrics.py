"""Prometheus exposition (#31): sync lag, webhook health, rate budget, token failures.

Never import server.py (would cycle). member_ref is keyed HMAC-SHA256 of the WHOOP user id,
truncated, never raw/unsalted (ids are enumerable) -- withheld if metrics_member_salt unset.
Counters/gauges are process-local; a multi-worker scrape sees only one worker's copy.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from whoopmcp import store
from whoopmcp.config import Config

#: Fixed vocabulary for `whoopmcp_token_refresh_failures_total{cause}`.
#: `auth._do_refresh`'s failure sites, in the order they're checked there.
TOKEN_REFRESH_FAILURE_CAUSES: tuple[str, ...] = (
    "invalid_grant",
    "token_endpoint_error",
    "malformed_response",
    "network_error",
)

#: Fixed vocabulary for `whoopmcp_webhook_signature_failures_total{reason}`.
#: From header presence/timestamp skew only -- never the secret or body (no leak to a forger).
WEBHOOK_REJECTION_REASONS: tuple[str, ...] = (
    "missing_header",
    "stale_timestamp",
    "bad_signature",
)

#: Hex chars kept from the keyed HMAC in `member_ref` (long enough not to weaken it).
_MEMBER_REF_LENGTH = 16

Labels = dict[str, str]
_CoverageFn = Callable[[sqlite3.Connection, int], tuple[str | None, str | None]]

#: (entity label, store accessor) pairs behind `whoopmcp_data_freshness_seconds`.
#: sleep/cycle/workout use nullable `end`, so an in-progress record is invisible to MAX(end).
_FRESHNESS_SOURCES: tuple[tuple[str, _CoverageFn], ...] = (
    ("recovery", store.get_recovery_coverage),
    ("sleep", store.get_sleep_coverage),
    ("cycle", store.get_cycle_coverage),
    ("workout", store.get_workout_coverage),
)


@dataclass(frozen=True, slots=True)
class RateBudget:
    """A `client.RateLimiter` budget snapshot, as published by `publish_rate_budget`."""

    minute_remaining: int
    minute_limit: int
    day_remaining: int
    day_limit: int


@dataclass(slots=True)
class _Counters:
    """Process-local state. A fresh instance is what `reset()` swaps in."""

    signature_failures: dict[str, int] = field(
        default_factory=lambda: dict.fromkeys(WEBHOOK_REJECTION_REASONS, 0)
    )
    webhooks_accepted: int = 0
    rate_limited: int = 0
    rate_limit_exhausted: int = 0
    refresh_failures: dict[str, int] = field(
        default_factory=lambda: dict.fromkeys(TOKEN_REFRESH_FAILURE_CAUSES, 0)
    )
    refresh_success: int = 0
    rate_budget: RateBudget | None = None


_counters = _Counters()


def reset() -> None:
    """Drop every process-local counter/gauge back to its initial state.

    For test isolation -- nothing here resets automatically between requests/tests.
    """
    global _counters
    _counters = _Counters()


def record_webhook_signature_failure(reason: str) -> None:
    """Called from `webhooks.py`'s single rejection point."""
    _counters.signature_failures[reason] = _counters.signature_failures.get(reason, 0) + 1


def record_webhook_accepted() -> None:
    """Called from `webhooks.py`'s success path -- the failure rate's denominator."""
    _counters.webhooks_accepted += 1


def record_rate_limited() -> None:
    """Called per retried 429 from `client.py`'s retry loop -- noise, not an incident."""
    _counters.rate_limited += 1


def record_rate_limit_exhausted() -> None:
    """Called from `client.py`'s `RateLimitedError` raise: retries gave up."""
    _counters.rate_limit_exhausted += 1


def record_token_refresh_failure(cause: str) -> None:
    """Called from `auth.py`'s `_do_refresh` failure sites only -- never `_raise_for_token_error`
    (would conflate login failures) or a fresh-install `GrantAlreadyGoneError`."""
    _counters.refresh_failures[cause] = _counters.refresh_failures.get(cause, 0) + 1


def record_token_refresh_success() -> None:
    _counters.refresh_success += 1


def publish_rate_budget(
    *, minute_remaining: int, minute_limit: int, day_remaining: int, day_limit: int
) -> None:
    """How the live `RateLimiter` hands its budget to the exporter.

    `custom_route` handlers can't reach `AppContext`/the lifespan `RateLimiter`, so the limiter
    pushes its budget here at the end of `acquire()`/`reconcile()` instead of being pulled.
    """
    _counters.rate_budget = RateBudget(minute_remaining, minute_limit, day_remaining, day_limit)


def member_ref(whoop_user_id: int, salt: str) -> str:
    """The only member-derived string in exposition output: truncated, keyed HMAC-SHA256 of the id.

    Keyed, not a plain digest -- WHOOP ids are small ints, so unsalted hashing is reversible by
    enumeration in seconds (the leak #31 forbids). Stable per (id, salt) for time-series continuity.
    """
    digest = hmac.new(salt.encode("utf-8"), str(whoop_user_id).encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()[:_MEMBER_REF_LENGTH]


def _parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _age_seconds(now: datetime, timestamp: str) -> float:
    """Seconds between `timestamp` and `now`, floored at 0.

    A negative value means clock skew, never "delivered in the future" -- clamped rather than
    surfaced as a broken-looking negative gauge.
    """
    return max(0.0, (now - _parse_iso(timestamp)).total_seconds())


def _format_value(value: float) -> str:
    if value.is_integer():
        return str(int(value))
    return repr(value)


def _format_sample(name: str, labels: Labels, value: float) -> str:
    if not labels:
        return f"{name} {_format_value(value)}"
    rendered_labels = ",".join(f'{key}="{val}"' for key, val in labels.items())
    return f"{name}{{{rendered_labels}}} {_format_value(value)}"


class _Renderer:
    """Accumulates exposition lines; one metric block per `emit` call."""

    def __init__(self) -> None:
        self._lines: list[str] = []

    def emit(
        self, name: str, type_: str, help_text: str, samples: Iterable[tuple[Labels, float]]
    ) -> None:
        materialized = list(samples)
        if not materialized:
            return
        self._lines.append(f"# HELP {name} {help_text}")
        self._lines.append(f"# TYPE {name} {type_}")
        for labels, value in materialized:
            self._lines.append(_format_sample(name, labels, value))

    def render(self) -> str:
        return "\n".join(self._lines) + "\n" if self._lines else ""


def render(conn: sqlite3.Connection, config: Config, *, now: datetime | None = None) -> str:
    """The whole exposition text: every counter/gauge this process holds, plus store-backed
    gauges read fresh from `conn`.

    Fixed-vocab counters/rate-budget gauges always export (pre-initialised to 0) for a zero
    baseline. Per-member gauges are the exception: omitted with no record, since a 0 there
    would misread as "just delivered".
    """
    current = now if now is not None else datetime.now(UTC)
    renderer = _Renderer()
    linked_members = store.all_linked_whoop_user_ids(conn)
    salt = config.metrics_member_salt

    renderer.emit(
        "whoopmcp_linked_members",
        "gauge",
        "Distinct WHOOP member ids this store has ever linked (principal_members "
        "is never pruned, so a re-authorised store can still list an id with no "
        "live grant).",
        [({}, float(len(linked_members)))],
    )
    renderer.emit(
        "whoopmcp_member_metrics_enabled",
        "gauge",
        "1 if WHOOPMCP_METRICS_SALT is configured and per-member series are "
        "exported below, else 0. Lets a dashboard tell 'salt not configured' "
        "apart from 'no members linked', which otherwise look identical.",
        [({}, 1.0 if salt else 0.0)],
    )
    renderer.emit(
        "whoopmcp_webhook_signature_failures_total",
        "counter",
        "Webhook requests rejected by signature verification, broken out by reason.",
        [
            ({"reason": reason}, float(count))
            for reason, count in _counters.signature_failures.items()
        ],
    )
    renderer.emit(
        "whoopmcp_webhooks_accepted_total",
        "counter",
        "Webhook requests that passed signature verification -- the failure rate's denominator.",
        [({}, float(_counters.webhooks_accepted))],
    )
    renderer.emit(
        "whoopmcp_rate_limited_total",
        "counter",
        "WHOOP API 429 responses that were retried (recovered -- noise, not an incident).",
        [({}, float(_counters.rate_limited))],
    )
    renderer.emit(
        "whoopmcp_rate_limit_exhausted_total",
        "counter",
        "WHOOP API 429 responses after every retry was exhausted (RateLimitedError raised).",
        [({}, float(_counters.rate_limit_exhausted))],
    )

    budget = _counters.rate_budget
    if budget is None:
        # No snapshot published yet -- fall back to configured budget for a zero baseline.
        minute_remaining = minute_limit = config.rate_limit_per_minute
        day_remaining = day_limit = config.rate_limit_per_day
    else:
        minute_remaining, minute_limit = budget.minute_remaining, budget.minute_limit
        day_remaining, day_limit = budget.day_remaining, budget.day_limit

    renderer.emit(
        "whoopmcp_rate_limit_remaining",
        "gauge",
        "Requests remaining in the current window, per RateLimiter.reconcile(). "
        "The 'day' value is this process's local accounting only -- WHOOP's "
        "X-RateLimit-* headers reconcile the 'minute' window but never the day budget.",
        [
            ({"window": "minute"}, float(minute_remaining)),
            ({"window": "day"}, float(day_remaining)),
        ],
    )
    renderer.emit(
        "whoopmcp_rate_limit_limit",
        "gauge",
        "The window's request budget. 'minute' is overwritten at runtime from "
        "WHOOP's X-RateLimit-Limit header, so 'near exhaustion' must be computed "
        "as remaining/limit, not a hard-coded threshold. 'day' is local accounting only.",
        [
            ({"window": "minute"}, float(minute_limit)),
            ({"window": "day"}, float(day_limit)),
        ],
    )
    renderer.emit(
        "whoopmcp_token_refresh_failures_total",
        "counter",
        "Token refresh failures, broken out by cause -- 'invalid_grant' means the "
        "member must re-authorise; the others are typically transient.",
        [({"cause": cause}, float(count)) for cause, count in _counters.refresh_failures.items()],
    )
    renderer.emit(
        "whoopmcp_token_refresh_success_total",
        "counter",
        "Successful token refreshes -- the refresh-failure rate's denominator.",
        [({}, float(_counters.refresh_success))],
    )

    freshness_samples: list[tuple[Labels, float]] = []
    sync_samples: list[tuple[Labels, float]] = []
    webhook_samples: list[tuple[Labels, float]] = []
    if salt:
        for whoop_user_id in sorted(linked_members):
            ref = member_ref(whoop_user_id, salt)
            for entity, coverage in _FRESHNESS_SOURCES:
                _earliest, latest = coverage(conn, whoop_user_id)
                if latest is not None:
                    freshness_samples.append(
                        ({"member_ref": ref, "entity": entity}, _age_seconds(current, latest))
                    )
            for row in store.get_all_sync_state_for_member(conn, whoop_user_id):
                sync_samples.append(
                    (
                        {"member_ref": ref, "entity": row["entity"]},
                        _age_seconds(current, row["last_run_at"]),
                    )
                )
            last_delivered = store.get_last_webhook_delivery(conn, whoop_user_id)
            if last_delivered is not None:
                webhook_samples.append(({"member_ref": ref}, _age_seconds(current, last_delivered)))

    renderer.emit(
        "whoopmcp_data_freshness_seconds",
        "gauge",
        "Age, in seconds, of the newest live record per member and entity -- "
        "'the single most useful number in the system'. recovery uses "
        "created_at; sleep/cycle/workout use end, so an in-progress record "
        "(end IS NULL) is invisible and the number reflects the newest "
        "completed record instead. Omitted for a member/entity with no live "
        "records. Withheld entirely if WHOOPMCP_METRICS_SALT is unset.",
        freshness_samples,
    )
    renderer.emit(
        "whoopmcp_sync_last_run_age_seconds",
        "gauge",
        "Age, in seconds, of sync_state.last_run_at per member and raw entity "
        "key (including the ':incremental' namespace, passed through verbatim). "
        "Distinct from whoopmcp_data_freshness_seconds: a sync that runs "
        "successfully but legitimately finds nothing new advances this without "
        "advancing that one. Withheld entirely if WHOOPMCP_METRICS_SALT is unset.",
        sync_samples,
    )
    renderer.emit(
        "whoopmcp_webhook_last_delivery_age_seconds",
        "gauge",
        "Age, in seconds, since the last successfully-processed webhook "
        "delivery for this member. Omitted for a member with none recorded -- "
        "a 0 here would read as 'just delivered'. Withheld entirely if "
        "WHOOPMCP_METRICS_SALT is unset; see whoopmcp_webhook_seconds_since_any_delivery "
        "for the fleet-wide backstop that survives an unset salt.",
        webhook_samples,
    )

    overall_samples: list[tuple[Labels, float]] = []
    deliveries = [
        timestamp
        for whoop_user_id in linked_members
        if (timestamp := store.get_last_webhook_delivery(conn, whoop_user_id)) is not None
    ]
    if deliveries:
        newest = max(deliveries, key=_parse_iso)
        overall_samples.append(({}, _age_seconds(current, newest)))
    renderer.emit(
        "whoopmcp_webhook_seconds_since_any_delivery",
        "gauge",
        "Age, in seconds, of the most recent webhook delivery across every "
        "linked member -- carries no member-derived label, so unlike "
        "whoopmcp_webhook_last_delivery_age_seconds it is exported even when "
        "WHOOPMCP_METRICS_SALT is unset. The fleet-wide backstop: a single "
        "healthy member keeps this quiet while a per-member alert still fires. "
        "Omitted if no delivery has ever been recorded for any member.",
        overall_samples,
    )

    return renderer.render()
