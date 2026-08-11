"""Observability tests: sync lag, webhook health, rate budget, token failures (issue #31).

Written before ``whoopmcp/metrics.py`` exists, so this file doubles as the
specification of that module's public surface. Every name imported from
``whoopmcp.metrics`` below is part of the contract:

``reset()``
    Drop every process-local counter/gauge back to its initial state. Exists
    for test isolation; the module is process-local by design (see the
    multi-worker caveat the brief requires in its docstring).
``record_webhook_signature_failure(reason)`` / ``record_webhook_accepted()``
    Called from ``webhooks.py``'s single rejection point and its success path.
``record_rate_limited()`` / ``record_rate_limit_exhausted()``
    Called from ``client.py``'s two distinct 429 sites: the retry loop body
    (recovered, noise) and the ``RateLimitedError`` raise (gave up, incident).
``record_token_refresh_failure(cause)`` / ``record_token_refresh_success()``
    Called from ``auth.py``'s ``_do_refresh`` failure sites, never from the
    shared ``_raise_for_token_error`` (which ``exchange_code`` also uses, so a
    counter there would conflate first-login failures with refresh failures).
``publish_rate_budget(...)``
    How the live ``RateLimiter`` hands its budget to the exporter. A
    ``custom_route`` handler cannot reach ``AppContext`` (see
    ``server._check_token_store_reachable``) and therefore cannot reach the
    ``RateLimiter`` built in ``lifespan()``, so the limiter pushes into this
    module's process-local state rather than the exporter pulling.
``member_ref(whoop_user_id, salt)``
    D3's keyed, truncated HMAC. The only member-derived string that may ever
    appear in exposition output.
``render(conn, config, *, now=None)``
    The whole exposition text.

The security-critical test here is ``test_no_exported_label_carries_member_
identifying_data``: it enumerates labels out of really-rendered output and
checks them against a deny-list *and* an allow-by-shape vocabulary, so a
future metric added with a bad label fails without anyone editing a list of
"things we remembered to check". Health data in a metric label is a real
leak, not a cardinality nuisance.

No real member data, token, or secret appears in any fixture here.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import sqlite3
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from mcp.server.transport_security import TransportSecuritySettings

from whoopmcp import metrics
from whoopmcp.auth import TOKEN_URL, Authenticator, AuthError, Token
from whoopmcp.client import RateLimiter
from whoopmcp.config import Config
from whoopmcp.server import build_server
from whoopmcp.store import (
    link_principal_to_member,
    open_store,
    record_webhook_delivery,
    set_sync_state,
    upsert_cycle,
    upsert_recovery,
    upsert_sleep,
    upsert_workout,
)
from whoopmcp.webhooks import SIGNATURE_HEADER, TIMESTAMP_HEADER

REPO_ROOT = Path(__file__).resolve().parents[1]

#: D4's rules file. Its location is the implementation's choice within this
#: directory; the test finds it rather than hard-coding one filename, so
#: ``ops/alerts.yml`` and ``ops/alerts.yaml`` are both acceptable.
ALERT_RULES_DIR = REPO_ROOT / "ops"

#: A fake member. Nine digits, so it cannot appear by coincidence inside a
#: hex ``member_ref``, which lets the deny-list test assert on substrings.
MEMBER_ID = 987654321
OTHER_MEMBER_ID = 123456789

#: Fake, and never a real address: the deny-list test asserts this string
#: (and any '@' at all) is absent from exposition output.
FAKE_EMAIL = "not-a-real-person@example.invalid"

METRICS_TOKEN = "metrics-bearer-token-for-tests"
METRICS_SALT = "metrics-salt-for-tests"
CLIENT_SECRET = "test-secret-key"

#: Fixed "now" for every gauge assertion, so ages are exact numbers rather
#: than a range around wall-clock time.
NOW = datetime(2026, 8, 11, 12, 0, 0, tzinfo=UTC)

#: Metric names the exporter must emit unconditionally -- including when the
#: store holds nothing and no counter has ever been incremented. A counter
#: that only appears after its first increment has no zero baseline, so
#: ``rate()`` over the window in which the very first failure happens has
#: nothing to compare against; every fixed-vocabulary label combination is
#: therefore pre-initialised to 0.
ALWAYS_EXPORTED_METRICS = frozenset(
    {
        "whoopmcp_webhook_signature_failures_total",
        "whoopmcp_webhooks_accepted_total",
        "whoopmcp_rate_limited_total",
        "whoopmcp_rate_limit_exhausted_total",
        "whoopmcp_rate_limit_remaining",
        "whoopmcp_rate_limit_limit",
        "whoopmcp_token_refresh_failures_total",
        "whoopmcp_token_refresh_success_total",
        "whoopmcp_member_metrics_enabled",
        "whoopmcp_linked_members",
    }
)

#: Metric names that only exist when the store actually holds the thing they
#: measure. Deliberately omitted rather than zero-filled: a 0 on
#: "seconds since the last webhook delivery" reads as "delivered a moment
#: ago", i.e. exactly the healthy-looking silence this issue exists to kill.
STORE_BACKED_METRICS = frozenset(
    {
        "whoopmcp_data_freshness_seconds",
        "whoopmcp_sync_last_run_age_seconds",
        "whoopmcp_webhook_last_delivery_age_seconds",
        "whoopmcp_webhook_seconds_since_any_delivery",
    }
)

ALL_METRICS = ALWAYS_EXPORTED_METRICS | STORE_BACKED_METRICS

#: Every label *value* the exporter is allowed to emit that is not a
#: ``member_ref``. Kept as a closed vocabulary on purpose: the deny-list test
#: below rejects any value outside it, so a new label carrying free-form data
#: (a sport name, a score, a resource id, an email) fails automatically.
ALLOWED_FIXED_LABEL_VALUES = frozenset(
    {
        # freshness entities
        "recovery",
        "sleep",
        "cycle",
        "workout",
        # sync_state entity keys: backfill.BACKFILL_ENTITIES names, plus
        # sync.py's f"{name}:incremental" namespace.
        "recoveries",
        "sleeps",
        "cycles",
        "workouts",
        "recoveries:incremental",
        "sleeps:incremental",
        "cycles:incremental",
        "workouts:incremental",
        # rate-budget windows
        "minute",
        "day",
        # token-refresh failure causes
        "invalid_grant",
        "token_endpoint_error",
        "malformed_response",
        "network_error",
        # webhook rejection reasons
        "missing_header",
        "stale_timestamp",
        "bad_signature",
    }
)

#: Label *names* that must never appear, whatever their value.
DENIED_LABEL_NAMES = frozenset(
    {
        "client_id",
        "email",
        "issuer",
        "mail",
        "member",
        "member_email",
        "member_id",
        "name",
        "principal",
        "resource_id",
        "sub",
        "subject",
        "user",
        "user_email",
        "user_id",
        "username",
        "whoop_user_id",
    }
)


# -- exposition-format parsing (derives everything from real output) ---------


@dataclass(frozen=True)
class Sample:
    name: str
    labels: dict[str, str]
    value: float


_SAMPLE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{(?P<labels>[^}]*)\})?"
    r"[ \t]+(?P<value>[^ \t]+)[ \t]*$"
)
_LABEL_RE = re.compile(r'(?P<key>[a-zA-Z_][a-zA-Z0-9_]*)="(?P<value>(?:[^"\\]|\\.)*)"')


def parse_samples(text: str) -> list[Sample]:
    """Parse Prometheus text exposition into samples.

    Deliberately a real parser over the rendered bytes rather than a peek at
    the exporter's internal registry: every assertion in this file is about
    what a scrape actually receives.
    """
    samples: list[Sample] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _SAMPLE_RE.match(line)
        assert match is not None, f"unparsable exposition line: {raw_line!r}"
        labels = {
            m.group("key"): m.group("value") for m in _LABEL_RE.finditer(match["labels"] or "")
        }
        samples.append(Sample(match["name"], labels, float(match["value"])))
    return samples


def metric_names(text: str) -> set[str]:
    return {sample.name for sample in parse_samples(text)}


def sample_value(text: str, name: str, **labels: str) -> float:
    """The single sample of ``name`` matching every label in ``labels``."""
    matches = [
        sample
        for sample in parse_samples(text)
        if sample.name == name and all(sample.labels.get(k) == v for k, v in labels.items())
    ]
    assert len(matches) == 1, f"expected exactly one {name}{labels}, got {matches!r}\n{text}"
    return matches[0].value


def metric_total(text: str, name: str, **labels: str) -> float:
    """``name``'s value summed over every label combination present.

    Used wherever a test cares that a counter moved but not how the
    implementation chose to break it down -- so adding or removing a
    ``reason``/``cause`` dimension does not break an unrelated assertion.
    """
    return sum(
        sample.value
        for sample in parse_samples(text)
        if sample.name == name and all(sample.labels.get(k) == v for k, v in labels.items())
    )


def declared_types(text: str) -> dict[str, str]:
    return {
        match["name"]: match["type"]
        for match in re.finditer(r"^# TYPE (?P<name>\S+) (?P<type>\S+)$", text, flags=re.MULTILINE)
    }


def declared_help(text: str) -> dict[str, str]:
    return {
        match["name"]: match["text"]
        for match in re.finditer(r"^# HELP (?P<name>\S+) (?P<text>.*)$", text, flags=re.MULTILINE)
    }


# -- fixtures ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_metrics() -> Iterator[None]:
    """Process-local counters are module state; isolate every test from it."""
    metrics.reset()
    yield
    metrics.reset()


def make_config(tmp_path: Path, **extra: str) -> Config:
    env = {
        "WHOOP_CLIENT_ID": "cid",
        "WHOOP_CLIENT_SECRET": CLIENT_SECRET,
        "WHOOP_REDIRECT_URI": "https://localhost:8443/callback",
        "WHOOPMCP_STATE_DIR": str(tmp_path),
        "WHOOPMCP_CACHE": "true",
        "WHOOPMCP_METRICS_TOKEN": METRICS_TOKEN,
        "WHOOPMCP_METRICS_SALT": METRICS_SALT,
    }
    env.update(extra)
    return Config.from_env(env)


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return make_config(tmp_path)


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    connection = open_store(":memory:")
    try:
        yield connection
    finally:
        connection.close()


def seed_member(
    connection: sqlite3.Connection,
    whoop_user_id: int = MEMBER_ID,
    *,
    recovery_created_at: str = "2026-08-10T12:00:00+00:00",
    sleep_end: str = "2026-08-09T12:00:00+00:00",
    cycle_end: str = "2026-08-08T12:00:00+00:00",
    workout_end: str = "2026-08-07T12:00:00+00:00",
    sync_last_run_at: str = "2026-08-11T11:00:00+00:00",
    webhook_delivered: bool = True,
) -> None:
    """Link a member and give them one live record per entity.

    ``resource_id`` values are deliberately distinctive strings so the
    deny-list test can assert they never reach exposition output; the raw
    records also carry a fake email, for the same reason.
    """
    link_principal_to_member(
        connection,
        client_id="__local__",
        issuer=None,
        subject=str(whoop_user_id),
        whoop_user_id=whoop_user_id,
    )
    upsert_recovery(
        connection,
        whoop_user_id,
        {
            "cycle_id": f"recovery-resource-{whoop_user_id}",
            "created_at": recovery_created_at,
            "score_state": "SCORED",
            "score": {"recovery_score": 61.0},
            "user_email": FAKE_EMAIL,
        },
    )
    upsert_sleep(
        connection,
        whoop_user_id,
        {
            "id": f"sleep-resource-{whoop_user_id}",
            "start": "2026-08-09T04:00:00+00:00",
            "end": sleep_end,
            "score_state": "SCORED",
        },
    )
    upsert_cycle(
        connection,
        whoop_user_id,
        {
            "id": f"cycle-resource-{whoop_user_id}",
            "start": "2026-08-08T04:00:00+00:00",
            "end": cycle_end,
            "score_state": "SCORED",
        },
    )
    upsert_workout(
        connection,
        whoop_user_id,
        {
            "id": f"workout-resource-{whoop_user_id}",
            "start": "2026-08-07T04:00:00+00:00",
            "end": workout_end,
            "score_state": "SCORED",
            "sport_name": "cycling",
        },
    )
    set_sync_state(
        connection,
        whoop_user_id,
        "recoveries:incremental",
        cursor=None,
        last_run_at=sync_last_run_at,
        outcome="complete",
    )
    if webhook_delivered:
        record_webhook_delivery(connection, whoop_user_id)


def ref(whoop_user_id: int = MEMBER_ID) -> str:
    return metrics.member_ref(whoop_user_id, METRICS_SALT)


# -- every metric is exported, with HELP and TYPE ----------------------------


def test_every_always_on_metric_is_exported_from_an_empty_store(
    conn: sqlite3.Connection, config: Config
) -> None:
    """An empty store still exports every counter and rate gauge, at zero.

    A counter that springs into existence on its first increment gives
    ``rate()`` nothing to compare the first failure against -- so every
    fixed-vocabulary series is pre-initialised. The store-backed gauges are
    the deliberate exception (see STORE_BACKED_METRICS' own comment).
    """
    text = metrics.render(conn, config, now=NOW)

    assert metric_names(text) == set(ALWAYS_EXPORTED_METRICS)
    assert sample_value(text, "whoopmcp_linked_members") == 0.0


def test_every_metric_is_exported_from_a_populated_store(
    conn: sqlite3.Connection, config: Config
) -> None:
    seed_member(conn)
    text = metrics.render(conn, config, now=NOW)

    assert metric_names(text) == set(ALL_METRICS)


def test_every_exported_metric_declares_help_and_type(
    conn: sqlite3.Connection, config: Config
) -> None:
    seed_member(conn)
    text = metrics.render(conn, config, now=NOW)

    types = declared_types(text)
    helps = declared_help(text)
    for name in metric_names(text):
        assert name in types, f"{name} has no # TYPE line"
        assert name in helps, f"{name} has no # HELP line"
        assert helps[name].strip(), f"{name}'s # HELP line is empty"
        expected = "counter" if name.endswith("_total") else "gauge"
        assert types[name] == expected, f"{name} declared {types[name]}, expected {expected}"


def test_exposition_ends_with_a_single_trailing_newline(
    conn: sqlite3.Connection, config: Config
) -> None:
    seed_member(conn)
    text = metrics.render(conn, config, now=NOW)

    assert text.endswith("\n")
    assert not text.endswith("\n\n")


def test_freshness_help_text_names_the_timestamp_each_entity_actually_uses(
    conn: sqlite3.Connection, config: Config
) -> None:
    """The four coverage accessors are not uniform and the HELP must say so.

    ``get_recovery_coverage`` returns ``MAX(created_at)``; the other three
    return ``MAX(end)`` over a *nullable* ``end``, so for sleep/cycle/workout
    the number is the newest *completed* record and an in-progress one is
    invisible to it. An operator reading "age of the newest record" would
    misdiagnose that as staleness.
    """
    seed_member(conn)
    text = metrics.render(conn, config, now=NOW)

    help_text = declared_help(text)["whoopmcp_data_freshness_seconds"].lower()
    assert "created_at" in help_text
    assert "end" in help_text
    assert "complet" in help_text


def test_day_rate_budget_help_says_it_is_local_accounting_only(
    conn: sqlite3.Connection, config: Config
) -> None:
    """``RateLimiter.reconcile`` only ever touches the *minute* window.

    ``_day_remaining``/``_per_day_limit`` are never reconciled against a
    WHOOP header -- they are purely local, resetting at UTC midnight. An
    operator paging on "day budget near exhaustion" needs to know that number
    is this process's estimate, not WHOOP's truth.
    """
    text = metrics.render(conn, config, now=NOW)

    help_text = declared_help(text)["whoopmcp_rate_limit_remaining"].lower()
    assert "local" in help_text


# -- sync lag: per member, reflects the newest record -----------------------


def test_data_freshness_is_per_member_and_reflects_the_newest_record(
    conn: sqlite3.Connection, config: Config
) -> None:
    """Two members, different freshness, one series each.

    The issue's own reason for insisting on per-member: an aggregate hides
    the one member whose connection died three weeks ago behind everyone
    else's healthy median. So the stale member's own series must show the
    stale number, unaffected by the healthy member's.
    """
    seed_member(conn, MEMBER_ID, recovery_created_at="2026-08-11T11:00:00+00:00")
    seed_member(conn, OTHER_MEMBER_ID, recovery_created_at="2026-07-21T12:00:00+00:00")

    text = metrics.render(conn, config, now=NOW)

    fresh = sample_value(
        text, "whoopmcp_data_freshness_seconds", member_ref=ref(MEMBER_ID), entity="recovery"
    )
    stale = sample_value(
        text, "whoopmcp_data_freshness_seconds", member_ref=ref(OTHER_MEMBER_ID), entity="recovery"
    )
    assert fresh == 3600.0
    assert stale == timedelta(days=21).total_seconds()
    assert sample_value(text, "whoopmcp_linked_members") == 2.0


def test_data_freshness_tracks_the_newest_of_several_records(
    conn: sqlite3.Connection, config: Config
) -> None:
    """ "Newest", not "oldest" and not "the one written last".

    The three recoveries below are inserted out of chronological order on
    purpose: an implementation reading ``updated_at`` (sync bookkeeping) or
    the last-written row instead of ``MAX(created_at)`` passes a
    single-record test and fails this one.
    """
    seed_member(conn, recovery_created_at="2026-08-01T12:00:00+00:00")
    upsert_recovery(
        conn,
        MEMBER_ID,
        {"cycle_id": "recovery-resource-newest", "created_at": "2026-08-10T12:00:00+00:00"},
    )
    upsert_recovery(
        conn,
        MEMBER_ID,
        {"cycle_id": "recovery-resource-middle", "created_at": "2026-08-05T12:00:00+00:00"},
    )

    text = metrics.render(conn, config, now=NOW)

    assert (
        sample_value(text, "whoopmcp_data_freshness_seconds", member_ref=ref(), entity="recovery")
        == timedelta(days=1).total_seconds()
    )


def test_freshness_moves_as_the_newest_record_gets_newer(
    conn: sqlite3.Connection, config: Config
) -> None:
    seed_member(conn, recovery_created_at="2026-08-01T12:00:00+00:00")
    before = sample_value(
        metrics.render(conn, config, now=NOW),
        "whoopmcp_data_freshness_seconds",
        member_ref=ref(),
        entity="recovery",
    )

    upsert_recovery(
        conn,
        MEMBER_ID,
        {"cycle_id": "recovery-resource-fresh", "created_at": "2026-08-11T11:00:00+00:00"},
    )
    after = sample_value(
        metrics.render(conn, config, now=NOW),
        "whoopmcp_data_freshness_seconds",
        member_ref=ref(),
        entity="recovery",
    )

    assert before == timedelta(days=10).total_seconds()
    assert after == 3600.0


def test_freshness_for_sleep_cycle_workout_ignores_an_in_progress_record(
    conn: sqlite3.Connection, config: Config
) -> None:
    """``MAX(end)`` over a nullable ``end`` cannot see an unfinished record.

    Asserted rather than left implicit: an in-progress sleep must not be
    silently treated as fresh data (which would mask a real stall), and the
    exported number must equal the newest *completed* record's end.
    """
    seed_member(conn, sleep_end="2026-08-10T12:00:00+00:00")
    upsert_sleep(
        conn,
        MEMBER_ID,
        {"id": "sleep-resource-in-progress", "start": "2026-08-11T04:00:00+00:00", "end": None},
    )

    text = metrics.render(conn, config, now=NOW)

    assert (
        sample_value(text, "whoopmcp_data_freshness_seconds", member_ref=ref(), entity="sleep")
        == timedelta(days=1).total_seconds()
    )


def test_freshness_series_is_omitted_for_an_entity_with_no_live_records(
    conn: sqlite3.Connection, config: Config
) -> None:
    """No data is not "zero seconds old".

    A member linked but never backfilled holds nothing for any entity; a
    0-valued gauge there would read as perfectly fresh.
    """
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=MEMBER_ID
    )

    text = metrics.render(conn, config, now=NOW)

    assert metric_total(text, "whoopmcp_data_freshness_seconds") == 0.0
    assert not [s for s in parse_samples(text) if s.name == "whoopmcp_data_freshness_seconds"]
    assert sample_value(text, "whoopmcp_linked_members") == 1.0


def test_sync_recency_is_a_separate_metric_from_data_freshness(
    conn: sqlite3.Connection, config: Config
) -> None:
    """The two sync-lag numbers must not be conflated.

    A sync that ran successfully but legitimately found nothing new advances
    ``sync_state.last_run_at`` and not the newest record. Exporting only one
    of these hides a real failure mode in each direction, so a test pins that
    they move independently.
    """
    seed_member(
        conn,
        recovery_created_at="2026-08-01T12:00:00+00:00",
        sync_last_run_at="2026-08-11T11:30:00+00:00",
    )

    text = metrics.render(conn, config, now=NOW)

    assert (
        sample_value(text, "whoopmcp_data_freshness_seconds", member_ref=ref(), entity="recovery")
        == timedelta(days=10).total_seconds()
    )
    assert (
        sample_value(
            text,
            "whoopmcp_sync_last_run_age_seconds",
            member_ref=ref(),
            entity="recoveries:incremental",
        )
        == 1800.0
    )


def test_sync_recency_carries_the_raw_sync_state_entity_key(
    conn: sqlite3.Connection, config: Config
) -> None:
    """``sync_state`` holds two entity-key namespaces per member.

    ``backfill.BACKFILL_ENTITIES`` writes ``"recoveries"``; ``sync.py``'s
    ``_incremental_entity_key`` writes ``"recoveries:incremental"``. They are
    different runs with different meanings, so the label must pass the key
    through verbatim rather than normalising the two into one series.
    """
    link_principal_to_member(
        conn, client_id="__local__", issuer=None, subject=None, whoop_user_id=MEMBER_ID
    )
    set_sync_state(
        conn, MEMBER_ID, "recoveries", cursor=None, last_run_at=NOW.isoformat(), outcome="complete"
    )
    set_sync_state(
        conn,
        MEMBER_ID,
        "recoveries:incremental",
        cursor=None,
        last_run_at="2026-08-11T11:00:00+00:00",
        outcome="complete",
    )

    text = metrics.render(conn, config, now=NOW)

    assert (
        sample_value(
            text, "whoopmcp_sync_last_run_age_seconds", member_ref=ref(), entity="recoveries"
        )
        == 0.0
    )
    assert (
        sample_value(
            text,
            "whoopmcp_sync_last_run_age_seconds",
            member_ref=ref(),
            entity="recoveries:incremental",
        )
        == 3600.0
    )


# -- webhook delivery silence, per member and overall -----------------------


def test_webhook_silence_is_exported_per_member_and_overall(
    conn: sqlite3.Connection, config: Config
) -> None:
    seed_member(conn, MEMBER_ID, webhook_delivered=False)
    seed_member(conn, OTHER_MEMBER_ID, webhook_delivered=False)
    conn.execute(
        "INSERT INTO webhook_delivery_state (whoop_user_id, last_delivered_at) VALUES (?, ?)",
        (MEMBER_ID, "2026-08-11T11:00:00+00:00"),
    )
    conn.execute(
        "INSERT INTO webhook_delivery_state (whoop_user_id, last_delivered_at) VALUES (?, ?)",
        (OTHER_MEMBER_ID, "2026-07-12T12:00:00+00:00"),
    )
    conn.commit()

    text = metrics.render(conn, config, now=NOW)

    assert (
        sample_value(text, "whoopmcp_webhook_last_delivery_age_seconds", member_ref=ref(MEMBER_ID))
        == 3600.0
    )
    assert (
        sample_value(
            text, "whoopmcp_webhook_last_delivery_age_seconds", member_ref=ref(OTHER_MEMBER_ID)
        )
        == timedelta(days=30).total_seconds()
    )
    # Overall = the most recent delivery anywhere, so a single healthy member
    # keeps the fleet-wide backstop quiet while the per-member rule fires.
    assert sample_value(text, "whoopmcp_webhook_seconds_since_any_delivery") == 3600.0


def test_webhook_silence_series_are_omitted_when_nothing_has_ever_been_delivered(
    conn: sqlite3.Connection, config: Config
) -> None:
    """Never-delivered is not "delivered zero seconds ago"."""
    seed_member(conn, webhook_delivered=False)

    text = metrics.render(conn, config, now=NOW)

    exported = metric_names(text)
    assert "whoopmcp_webhook_last_delivery_age_seconds" not in exported
    assert "whoopmcp_webhook_seconds_since_any_delivery" not in exported


def test_webhook_delivery_recorded_now_moves_the_silence_gauge(
    conn: sqlite3.Connection, config: Config
) -> None:
    seed_member(conn, webhook_delivered=False)
    conn.execute(
        "INSERT INTO webhook_delivery_state (whoop_user_id, last_delivered_at) VALUES (?, ?)",
        (MEMBER_ID, "2026-08-04T12:00:00+00:00"),
    )
    conn.commit()
    before = sample_value(
        metrics.render(conn, config, now=NOW),
        "whoopmcp_webhook_last_delivery_age_seconds",
        member_ref=ref(),
    )

    record_webhook_delivery(conn, MEMBER_ID)
    after = sample_value(
        metrics.render(conn, config, now=datetime.now(UTC)),
        "whoopmcp_webhook_last_delivery_age_seconds",
        member_ref=ref(),
    )

    assert before == timedelta(days=7).total_seconds()
    assert after < 60.0


# -- counters move: webhook signature failures ------------------------------


def test_webhook_signature_failure_counter_moves(conn: sqlite3.Connection, config: Config) -> None:
    before = metric_total(
        metrics.render(conn, config, now=NOW), "whoopmcp_webhook_signature_failures_total"
    )
    metrics.record_webhook_signature_failure("bad_signature")
    after = metric_total(
        metrics.render(conn, config, now=NOW), "whoopmcp_webhook_signature_failures_total"
    )

    assert before == 0.0
    assert after == 1.0


def test_accepted_webhook_counter_gives_the_failure_rate_a_denominator(
    conn: sqlite3.Connection, config: Config
) -> None:
    """The issue asks for a failure *rate*, which needs both terms.

    Failures alone cannot distinguish "one forged request against a busy
    endpoint" from "every delivery now rejected because the secret rotated".
    """
    metrics.record_webhook_accepted()
    metrics.record_webhook_accepted()
    metrics.record_webhook_signature_failure("bad_signature")

    text = metrics.render(conn, config, now=NOW)

    assert sample_value(text, "whoopmcp_webhooks_accepted_total") == 2.0
    assert metric_total(text, "whoopmcp_webhook_signature_failures_total") == 1.0


# -- counters move: 429s and rate budget ------------------------------------


def test_retried_and_exhausted_429s_are_counted_separately(
    conn: sqlite3.Connection, config: Config
) -> None:
    """A retried 429 is noise; giving up is an incident.

    ``client._get`` has two distinct 429 sites -- the retry loop body and the
    ``RateLimitedError`` raise after ``_MAX_429_RETRIES``. One counter across
    both cannot tell an operator whether any request actually failed.
    """
    metrics.record_rate_limited()
    metrics.record_rate_limited()
    metrics.record_rate_limit_exhausted()

    text = metrics.render(conn, config, now=NOW)

    assert sample_value(text, "whoopmcp_rate_limited_total") == 2.0
    assert sample_value(text, "whoopmcp_rate_limit_exhausted_total") == 1.0


def test_rate_limiter_exposes_its_budget_through_a_public_accessor() -> None:
    """Item C: ``metrics.py`` must never read ``_minute_remaining``."""
    limiter = RateLimiter(per_minute=5, per_day=50)

    snapshot = limiter.budget_snapshot()

    assert snapshot.minute_remaining == 5
    assert snapshot.minute_limit == 5
    assert snapshot.day_remaining == 50
    assert snapshot.day_limit == 50


async def test_rate_budget_gauges_move_as_the_real_limiter_spends_budget(
    conn: sqlite3.Connection, config: Config
) -> None:
    """Driven through the real ``RateLimiter``, not a hand-set gauge.

    The limiter pushes its budget into this module (``publish_rate_budget``)
    because a ``custom_route`` handler can reach neither ``AppContext`` nor
    the ``RateLimiter`` that ``lifespan()`` builds -- see this file's own
    module docstring.
    """
    limiter = RateLimiter(per_minute=5, per_day=50)
    await limiter.acquire()
    await limiter.acquire()

    text = metrics.render(conn, config, now=NOW)

    assert sample_value(text, "whoopmcp_rate_limit_remaining", window="minute") == 3.0
    assert sample_value(text, "whoopmcp_rate_limit_remaining", window="day") == 48.0
    assert sample_value(text, "whoopmcp_rate_limit_limit", window="minute") == 5.0
    assert sample_value(text, "whoopmcp_rate_limit_limit", window="day") == 50.0


def test_rate_limit_limit_follows_the_header_reported_limit(
    conn: sqlite3.Connection, config: Config
) -> None:
    """``reconcile`` overwrites ``_per_minute_limit`` from ``X-RateLimit-Limit``.

    So the limit is mutable at runtime and must be exported rather than
    hard-coded into an alert threshold: "near exhaustion" has to be
    ``remaining / limit``, or the rule silently breaks the day WHOOP changes
    the limit.
    """
    limiter = RateLimiter(per_minute=100, per_day=10_000)
    limiter.reconcile(httpx.Headers({"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "7"}))

    text = metrics.render(conn, config, now=NOW)

    assert sample_value(text, "whoopmcp_rate_limit_limit", window="minute") == 60.0
    assert sample_value(text, "whoopmcp_rate_limit_remaining", window="minute") == 7.0


# -- counters move: token refresh failures by cause -------------------------


def test_token_refresh_failure_causes_are_broken_out(
    conn: sqlite3.Connection, config: Config
) -> None:
    metrics.record_token_refresh_failure("invalid_grant")
    metrics.record_token_refresh_failure("network_error")
    metrics.record_token_refresh_success()

    text = metrics.render(conn, config, now=NOW)

    assert sample_value(text, "whoopmcp_token_refresh_failures_total", cause="invalid_grant") == 1.0
    assert sample_value(text, "whoopmcp_token_refresh_failures_total", cause="network_error") == 1.0
    assert (
        sample_value(text, "whoopmcp_token_refresh_failures_total", cause="token_endpoint_error")
        == 0.0
    )
    assert sample_value(text, "whoopmcp_token_refresh_success_total") == 1.0


def test_every_declared_refresh_failure_cause_has_a_preinitialised_series(
    conn: sqlite3.Connection, config: Config
) -> None:
    text = metrics.render(conn, config, now=NOW)

    causes = {
        sample.labels["cause"]
        for sample in parse_samples(text)
        if sample.name == "whoopmcp_token_refresh_failures_total"
    }
    assert causes == set(metrics.TOKEN_REFRESH_FAILURE_CAUSES)
    assert "invalid_grant" in causes


# -- the three real conditions each move the metric their alert watches -----


def test_a_stalled_sync_moves_the_metric_its_alert_watches(
    conn: sqlite3.Connection, config: Config
) -> None:
    """Both sync-lag alerts, driven from the store rather than from a counter.

    "Stalled" here means the two independent shapes of stall: the sync itself
    stopped running (``sync_last_run_age``), and the sync keeps running but
    data stopped arriving (``data_freshness``).
    """
    seed_member(
        conn,
        recovery_created_at="2026-07-12T12:00:00+00:00",
        sync_last_run_at="2026-07-12T12:00:00+00:00",
    )

    text = metrics.render(conn, config, now=NOW)

    thirty_days = timedelta(days=30).total_seconds()
    assert (
        sample_value(text, "whoopmcp_data_freshness_seconds", member_ref=ref(), entity="recovery")
        == thirty_days
    )
    assert (
        sample_value(
            text,
            "whoopmcp_sync_last_run_age_seconds",
            member_ref=ref(),
            entity="recoveries:incremental",
        )
        == thirty_days
    )


async def test_a_bad_signature_over_http_moves_the_signature_failure_counter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, conn: sqlite3.Connection
) -> None:
    """Driven through the real route, not by calling the counter directly.

    A test that increments the counter itself proves the exporter works and
    proves nothing about whether ``webhooks.py`` is wired to it.
    """
    _set_http_env(monkeypatch, tmp_path)
    config = Config.from_env()
    app = build_server().streamable_http_app(
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/webhooks/whoop",
            content=b'{"event_type": "recovery.updated"}',
            headers={
                SIGNATURE_HEADER: base64.b64encode(b"not-the-right-signature").decode("ascii"),
                TIMESTAMP_HEADER: str(int(time.time() * 1000)),
            },
        )

    assert response.status_code == 400
    assert (
        metric_total(
            metrics.render(conn, config, now=NOW), "whoopmcp_webhook_signature_failures_total"
        )
        == 1.0
    )


async def test_a_valid_signature_over_http_moves_the_accepted_counter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, conn: sqlite3.Connection
) -> None:
    _set_http_env(monkeypatch, tmp_path)
    config = Config.from_env()
    body = b'{"event_type": "recovery.updated"}'
    timestamp = str(int(time.time() * 1000))
    signature = base64.b64encode(
        hmac.new(CLIENT_SECRET.encode(), timestamp.encode() + body, hashlib.sha256).digest()
    ).decode("ascii")
    app = build_server().streamable_http_app(
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/webhooks/whoop",
            content=body,
            headers={SIGNATURE_HEADER: signature, TIMESTAMP_HEADER: timestamp},
        )

    assert response.status_code == 200
    text = metrics.render(conn, config, now=NOW)
    assert sample_value(text, "whoopmcp_webhooks_accepted_total") == 1.0
    assert metric_total(text, "whoopmcp_webhook_signature_failures_total") == 0.0


@pytest.mark.parametrize(
    ("reason", "headers"),
    [
        ("missing_header", {}),
        ("stale_timestamp", {SIGNATURE_HEADER: "c2ln", TIMESTAMP_HEADER: "1000"}),
        (
            "bad_signature",
            {SIGNATURE_HEADER: "c2ln", TIMESTAMP_HEADER: str(int(time.time() * 1000))},
        ),
    ],
)
async def test_rejection_reason_is_broken_out_without_revealing_it_to_the_caller(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    conn: sqlite3.Connection,
    reason: str,
    headers: dict[str, str],
) -> None:
    """The operator learns which check failed; the caller does not.

    ``verify_webhook_request`` collapses all three causes into one ``False``,
    so the reason is re-derived at the rejection site from header presence
    and ``_timestamp_within_skew`` -- neither of which touches the signing
    secret. The response body stays the same generic ``invalid_signature``
    for every cause, so a forger still gets no oracle.
    """
    _set_http_env(monkeypatch, tmp_path)
    config = Config.from_env()
    app = build_server().streamable_http_app(
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post("/webhooks/whoop", content=b"{}", headers=headers)

    assert response.status_code == 400
    assert response.json() == {"error": "invalid_signature"}
    text = metrics.render(conn, config, now=NOW)
    assert sample_value(text, "whoopmcp_webhook_signature_failures_total", reason=reason) == 1.0
    assert metric_total(text, "whoopmcp_webhook_signature_failures_total") == 1.0


@respx.mock
async def test_a_revoked_token_moves_the_invalid_grant_counter(
    conn: sqlite3.Connection, config: Config
) -> None:
    """A real refresh against a real ``invalid_grant`` response.

    ``_do_refresh``'s 400/``_is_invalid_grant`` branch is the only
    refresh-side ``GrantAlreadyGoneError`` site; ``access_token``'s "no
    stored credentials" raise of the same class is not a refresh failure and
    must not be counted as one.
    """
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            400, json={"error": "invalid_grant", "error_description": "Refresh token is expired."}
        )
    )
    auth = Authenticator(config)

    with pytest.raises(AuthError):
        await auth.refresh(Token("old-access", expires_at=1000.0, refresh_token="old-refresh"))

    text = metrics.render(conn, config, now=NOW)
    assert sample_value(text, "whoopmcp_token_refresh_failures_total", cause="invalid_grant") == 1.0
    assert metric_total(text, "whoopmcp_token_refresh_failures_total") == 1.0
    assert sample_value(text, "whoopmcp_token_refresh_success_total") == 0.0


@respx.mock
async def test_a_non_invalid_grant_refresh_failure_is_counted_under_its_own_cause(
    conn: sqlite3.Connection, config: Config
) -> None:
    """A 500 from the token endpoint is transient; ``invalid_grant`` is not.

    Same counter, different cause, because only one of the two means "this
    member must re-authorise" and only one of them should page anybody.
    """
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(500, json={"error": "server_error"}))
    auth = Authenticator(config)

    with pytest.raises(AuthError):
        await auth.refresh(Token("old-access", expires_at=1000.0, refresh_token="old-refresh"))

    text = metrics.render(conn, config, now=NOW)
    assert (
        sample_value(text, "whoopmcp_token_refresh_failures_total", cause="token_endpoint_error")
        == 1.0
    )
    assert sample_value(text, "whoopmcp_token_refresh_failures_total", cause="invalid_grant") == 0.0


@respx.mock
async def test_a_network_error_during_refresh_is_counted_as_network_error(
    conn: sqlite3.Connection, config: Config
) -> None:
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    auth = Authenticator(config)

    with pytest.raises(httpx.ConnectError):
        await auth.refresh(Token("old-access", expires_at=1000.0, refresh_token="old-refresh"))

    text = metrics.render(conn, config, now=NOW)
    assert sample_value(text, "whoopmcp_token_refresh_failures_total", cause="network_error") == 1.0


@respx.mock
async def test_a_successful_refresh_moves_the_success_counter_and_no_failure_counter(
    conn: sqlite3.Connection, config: Config
) -> None:
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "expires_in": 3600,
                "scope": "offline",
            },
        )
    )
    auth = Authenticator(config)

    await auth.refresh(Token("old-access", expires_at=1000.0, refresh_token="old-refresh"))

    text = metrics.render(conn, config, now=NOW)
    assert sample_value(text, "whoopmcp_token_refresh_success_total") == 1.0
    assert metric_total(text, "whoopmcp_token_refresh_failures_total") == 0.0


@respx.mock
async def test_access_token_with_no_stored_credentials_is_not_a_refresh_failure(
    conn: sqlite3.Connection, config: Config
) -> None:
    """``GrantAlreadyGoneError`` is raised at two sites; only one is a failure.

    ``access_token()`` raising it means "nothing stored yet, run whoop_login"
    -- a fresh install, not a revoked grant. Counting it would make
    ``invalid_grant`` page on every un-authorised deployment.
    """
    auth = Authenticator(config)

    with pytest.raises(AuthError):
        await auth.access_token()

    assert (
        metric_total(metrics.render(conn, config, now=NOW), "whoopmcp_token_refresh_failures_total")
        == 0.0
    )


# -- the label deny-list (the security-critical test) -----------------------


def test_no_exported_label_carries_member_identifying_data(
    conn: sqlite3.Connection, config: Config
) -> None:
    """Enumerated from really-rendered output, not from a list of what I
    remembered to check.

    Three independent checks, so a future metric added with a bad label fails
    here without anyone editing this test:

    1. no label *name* is an identity-shaped name (deny-list);
    2. every label *value* is either a member_ref or a member of the closed
       fixed vocabulary -- so free-form data (a sport name, a resource id, an
       email, a score) fails by default rather than needing to be predicted;
    3. no known-sensitive string appears anywhere in the whole body, label or
       not: the raw whoop_user_id, the fake email, the signing secret, the
       metrics token, the salt, the seeded resource ids.

    Health data in a metric label is a real leak; cardinality is the lesser
    problem. This test is the line.
    """
    seed_member(conn, MEMBER_ID)
    seed_member(conn, OTHER_MEMBER_ID)
    for cause in metrics.TOKEN_REFRESH_FAILURE_CAUSES:
        metrics.record_token_refresh_failure(cause)
    for reason in metrics.WEBHOOK_REJECTION_REASONS:
        metrics.record_webhook_signature_failure(reason)
    metrics.record_webhook_accepted()
    metrics.record_rate_limited()
    metrics.record_rate_limit_exhausted()
    metrics.record_token_refresh_success()
    metrics.publish_rate_budget(
        minute_remaining=7, minute_limit=60, day_remaining=900, day_limit=10_000
    )

    text = metrics.render(conn, config, now=NOW)
    samples = parse_samples(text)
    assert samples, "nothing rendered -- the deny-list test would pass vacuously"

    known_refs = {ref(MEMBER_ID), ref(OTHER_MEMBER_ID)}

    # (1) label names
    seen_names = {key for sample in samples for key in sample.labels}
    assert seen_names, "no labels at all -- per-member series should be present here"
    assert not (seen_names & DENIED_LABEL_NAMES), (
        f"identity-shaped label name(s) exported: {sorted(seen_names & DENIED_LABEL_NAMES)}"
    )

    # (2) label values, allow-by-shape
    for sample in samples:
        for key, value in sample.labels.items():
            if key == "member_ref":
                assert value in known_refs, f"unexpected member_ref {value!r}"
                continue
            assert value in ALLOWED_FIXED_LABEL_VALUES, (
                f"{sample.name} label {key}={value!r} is outside the closed vocabulary; "
                "a new label must be a fixed, non-member-derived value"
            )

    # (3) no sensitive string anywhere in the body
    forbidden = [
        str(MEMBER_ID),
        str(OTHER_MEMBER_ID),
        FAKE_EMAIL,
        "@",
        CLIENT_SECRET,
        METRICS_TOKEN,
        METRICS_SALT,
        f"recovery-resource-{MEMBER_ID}",
        f"workout-resource-{MEMBER_ID}",
        "cycling",
    ]
    for needle in forbidden:
        assert needle not in text, f"exposition output leaks {needle!r}"


def test_member_ref_is_keyed_so_it_cannot_be_brute_forced_from_the_id_alone() -> None:
    """An unsalted hash of a WHOOP user id is not opaque.

    WHOOP user ids are modest integers, so an unkeyed digest is reversible by
    enumeration in seconds -- which would defeat the whole point of the
    label. The ref must be a keyed HMAC, must differ under a different key,
    and must not be any plain digest of the id.
    """
    with_key = metrics.member_ref(MEMBER_ID, METRICS_SALT)
    with_other_key = metrics.member_ref(MEMBER_ID, "a-different-salt")

    assert re.fullmatch(r"[0-9a-f]{12,64}", with_key), with_key
    assert with_key != with_other_key
    assert with_key != str(MEMBER_ID)
    assert str(MEMBER_ID) not in with_key
    # Not a plain digest: those are computable without the key.
    plain = hashlib.sha256(str(MEMBER_ID).encode()).hexdigest()
    assert not plain.startswith(with_key)
    assert (
        with_key
        == hmac.new(
            METRICS_SALT.encode("utf-8"), str(MEMBER_ID).encode("utf-8"), hashlib.sha256
        ).hexdigest()[: len(with_key)]
    )


def test_member_ref_is_stable_for_the_same_id_and_salt() -> None:
    """A ref that changed per scrape would make every per-member series a new
    one-sample time series -- and the baseline comparison the issue asks for
    would have no history to compare against."""
    assert metrics.member_ref(MEMBER_ID, METRICS_SALT) == metrics.member_ref(
        MEMBER_ID, METRICS_SALT
    )
    assert metrics.member_ref(MEMBER_ID, METRICS_SALT) != metrics.member_ref(
        OTHER_MEMBER_ID, METRICS_SALT
    )


def test_per_member_series_are_withheld_entirely_when_the_salt_is_unset(
    tmp_path: Path, conn: sqlite3.Connection
) -> None:
    """D3 fails closed: no salt means no per-member series, not a weaker id.

    Falling back to a raw id or an unkeyed hash would be exactly the leak the
    issue forbids, so the whole per-member surface disappears instead -- and
    ``whoopmcp_member_metrics_enabled`` goes to 0 so a dashboard can tell
    "salt not configured" apart from "no members linked", which is otherwise
    the same silent failure this issue exists to eliminate.
    """
    config = Config.from_env(
        {
            "WHOOP_CLIENT_ID": "cid",
            "WHOOP_CLIENT_SECRET": CLIENT_SECRET,
            "WHOOP_REDIRECT_URI": "https://localhost:8443/callback",
            "WHOOPMCP_STATE_DIR": str(tmp_path),
            "WHOOPMCP_CACHE": "true",
            "WHOOPMCP_METRICS_TOKEN": METRICS_TOKEN,
        }
    )
    seed_member(conn)

    text = metrics.render(conn, config, now=NOW)

    assert config.metrics_member_salt is None
    assert sample_value(text, "whoopmcp_member_metrics_enabled") == 0.0
    assert not [sample for sample in parse_samples(text) if "member_ref" in sample.labels]
    for name in (
        "whoopmcp_data_freshness_seconds",
        "whoopmcp_sync_last_run_age_seconds",
        "whoopmcp_webhook_last_delivery_age_seconds",
    ):
        assert name not in metric_names(text)
    # The fleet-wide backstop and the counters survive: they carry no
    # member-derived label, so there is nothing to fail closed about.
    assert sample_value(text, "whoopmcp_webhook_seconds_since_any_delivery") >= 0.0
    assert sample_value(text, "whoopmcp_linked_members") == 1.0
    assert str(MEMBER_ID) not in text


def test_member_metrics_enabled_is_one_when_the_salt_is_configured(
    conn: sqlite3.Connection, config: Config
) -> None:
    assert sample_value(metrics.render(conn, config, now=NOW), "whoopmcp_member_metrics_enabled")


# -- config -----------------------------------------------------------------


def test_metrics_settings_are_off_unless_explicitly_configured(tmp_path: Path) -> None:
    """Same "off unless configured" precedent as ``webhooks_enabled``."""
    config = Config.from_env(
        {
            "WHOOP_CLIENT_ID": "cid",
            "WHOOP_CLIENT_SECRET": CLIENT_SECRET,
            "WHOOP_REDIRECT_URI": "https://localhost:8443/callback",
            "WHOOPMCP_STATE_DIR": str(tmp_path),
        }
    )

    assert config.metrics_token is None
    assert config.metrics_member_salt is None


def test_metrics_settings_are_read_from_the_environment(tmp_path: Path) -> None:
    config = make_config(tmp_path)

    assert config.metrics_token == METRICS_TOKEN
    assert config.metrics_member_salt == METRICS_SALT


def test_the_metrics_salt_is_not_the_client_secret(tmp_path: Path) -> None:
    """Reusing ``WHOOP_CLIENT_SECRET`` as the salt would tie every metrics
    time series to the webhook signing secret, so rotating that secret would
    silently reset every ``member_ref`` at the same moment webhooks broke --
    two incidents, one cause, no way to tell them apart."""
    config = make_config(tmp_path)

    assert config.metrics_member_salt != config.client_secret


# -- the endpoint's authentication ------------------------------------------


def _set_http_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **extra: str) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", CLIENT_SECRET)
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://localhost:8443/callback")
    monkeypatch.setenv("WHOOPMCP_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("WHOOPMCP_CACHE", "true")
    monkeypatch.setenv("WHOOPMCP_WEBHOOKS_ENABLED", "true")
    for name, value in extra.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def metrics_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_http_env(
        monkeypatch,
        tmp_path,
        WHOOPMCP_METRICS_TOKEN=METRICS_TOKEN,
        WHOOPMCP_METRICS_SALT=METRICS_SALT,
    )


async def _get_metrics(
    app: Any, headers: dict[str, str] | None = None, *, path: str = "/metrics"
) -> httpx.Response:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.get(path, headers=headers or {})


async def test_metrics_endpoint_is_404_and_exports_nothing_when_no_token_is_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Fail closed: unconfigured means absent, exactly like ``webhooks_enabled``.

    ``custom_route`` handlers "will not require authorization" (the SDK's own
    docstring), so an unauthenticated ``/metrics`` would hand per-member
    health telemetry to anyone who can reach the port. The 404 is the same
    response an unregistered path gives, so its existence isn't advertised
    either.
    """
    _set_http_env(monkeypatch, tmp_path, WHOOPMCP_METRICS_SALT=METRICS_SALT)
    monkeypatch.delenv("WHOOPMCP_METRICS_TOKEN", raising=False)
    app = build_server().streamable_http_app()

    response = await _get_metrics(app)

    assert response.status_code == 404
    assert "whoopmcp_" not in response.text


async def test_metrics_endpoint_is_404_even_with_a_bearer_token_when_unconfigured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Off means off -- a caller cannot turn it on by guessing a token."""
    _set_http_env(monkeypatch, tmp_path, WHOOPMCP_METRICS_SALT=METRICS_SALT)
    monkeypatch.delenv("WHOOPMCP_METRICS_TOKEN", raising=False)
    app = build_server().streamable_http_app()

    response = await _get_metrics(app, {"Authorization": f"Bearer {METRICS_TOKEN}"})

    assert response.status_code == 404
    assert "whoopmcp_" not in response.text


@pytest.mark.parametrize(
    "raw_header",
    [
        b"Bearer \xe9\xe9\xe9",
        b"Bearer " + METRICS_TOKEN.encode() + b"\xff",
        b"\xe9",
    ],
)
async def test_metrics_endpoint_is_401_for_a_non_ascii_authorization_header(
    metrics_env: None, raw_header: bytes
) -> None:
    """A non-ASCII Authorization header must 401, not raise.

    ``hmac.compare_digest`` raises ``TypeError`` on a ``str`` holding any
    non-ASCII character rather than returning ``False``, and Starlette decodes
    raw header bytes as latin-1 -- so these bytes arrive as a ``str`` the
    comparison refuses to touch. Without an ``isascii()`` guard ahead of it
    the handler raises, turning a 401 into an unhandled 500 on the auth path
    of the one route standing between the internet and per-member health data.

    Sent as raw bytes deliberately: httpx encodes ``str`` header values as
    ASCII and would reject these before they ever left the client, so a
    ``str`` parameter cannot reach the code path this pins.
    """
    app = build_server().streamable_http_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/metrics", headers=[(b"authorization", raw_header)])

    assert response.status_code == 401
    assert "whoopmcp_" not in response.text


async def test_metrics_endpoint_unconfigured_404_is_indistinguishable_from_an_unknown_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The 404 body must match an unregistered path's byte-for-byte.

    Failing closed is only half of "its existence isn't advertised": a
    distinctive body (a JSON ``{"error": ...}``, say) still tells a prober
    that ``/metrics`` is a route this build knows about and that it is merely
    switched off -- which is exactly the fact worth probing for.
    """
    _set_http_env(monkeypatch, tmp_path, WHOOPMCP_METRICS_SALT=METRICS_SALT)
    monkeypatch.delenv("WHOOPMCP_METRICS_TOKEN", raising=False)
    app = build_server().streamable_http_app()

    metrics_response = await _get_metrics(app)
    unknown_response = await _get_metrics(app, path="/definitely-not-a-registered-route")

    assert metrics_response.status_code == unknown_response.status_code == 404
    assert metrics_response.text == unknown_response.text
    assert metrics_response.headers.get("content-type") == unknown_response.headers.get(
        "content-type"
    )


async def test_metrics_endpoint_is_401_without_an_authorization_header(
    metrics_env: None,
) -> None:
    app = build_server().streamable_http_app()

    response = await _get_metrics(app)

    assert response.status_code == 401
    assert "whoopmcp_" not in response.text


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer",
        "Bearer ",
        "Bearer wrong-token",
        f"Bearer {METRICS_TOKEN}x",
        f"Bearer {METRICS_TOKEN[:-1]}",
        METRICS_TOKEN,
        f"Basic {METRICS_TOKEN}",
        f"bearer {METRICS_TOKEN}",
    ],
)
async def test_metrics_endpoint_is_401_for_a_bad_authorization_header(
    metrics_env: None, header: str
) -> None:
    """Includes near-miss tokens: a prefix and a suffix of the real one, so a
    length-only or ``startswith`` comparison fails here."""
    app = build_server().streamable_http_app()

    response = await _get_metrics(app, {"Authorization": header})

    assert response.status_code == 401
    assert "whoopmcp_" not in response.text


async def test_metrics_endpoint_serves_exposition_with_a_valid_bearer_token(
    metrics_env: None,
) -> None:
    app = build_server().streamable_http_app()

    response = await _get_metrics(app, {"Authorization": f"Bearer {METRICS_TOKEN}"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    names = metric_names(response.text)
    assert names >= ALWAYS_EXPORTED_METRICS


async def test_metrics_endpoint_never_echoes_its_own_token_or_salt(
    metrics_env: None,
) -> None:
    """``doctor.py``'s redaction discipline applies here too: no token,
    signing secret, or key value may appear in output."""
    app = build_server().streamable_http_app()

    response = await _get_metrics(app, {"Authorization": f"Bearer {METRICS_TOKEN}"})

    assert METRICS_TOKEN not in response.text
    assert METRICS_SALT not in response.text
    assert CLIENT_SECRET not in response.text


async def test_metrics_endpoint_over_http_carries_no_member_identifying_label(
    metrics_env: None, tmp_path: Path
) -> None:
    """The deny-list, re-run against the real HTTP surface.

    The unit-level test renders through ``metrics.render`` directly; this one
    proves the route does not add a label of its own on the way out.
    """
    config = Config.from_env()
    connection = open_store(config.cache_path)
    try:
        seed_member(connection, MEMBER_ID)
    finally:
        connection.close()
    app = build_server().streamable_http_app()

    response = await _get_metrics(app, {"Authorization": f"Bearer {METRICS_TOKEN}"})

    assert response.status_code == 200
    samples = parse_samples(response.text)
    assert samples
    seen_names = {key for sample in samples for key in sample.labels}
    assert not (seen_names & DENIED_LABEL_NAMES)
    assert str(MEMBER_ID) not in response.text
    assert FAKE_EMAIL not in response.text
    assert "@" not in response.text
    assert (
        sample_value(
            response.text, "whoopmcp_data_freshness_seconds", member_ref=ref(), entity="recovery"
        )
        > 0.0
    )


# -- D4: the alert rules file -----------------------------------------------


def _alert_rules_text() -> str:
    candidates = sorted(ALERT_RULES_DIR.glob("*.y*ml")) if ALERT_RULES_DIR.is_dir() else []
    assert candidates, f"no Prometheus rules file found under {ALERT_RULES_DIR}"
    return "\n".join(path.read_text(encoding="utf-8") for path in candidates)


def _exported_metric_names() -> set[str]:
    """Every name the exporter can emit, from real rendered output."""
    connection = open_store(":memory:")
    try:
        seed_member(connection, MEMBER_ID)
        config = Config.from_env(
            {
                "WHOOP_CLIENT_ID": "cid",
                "WHOOP_CLIENT_SECRET": CLIENT_SECRET,
                "WHOOP_REDIRECT_URI": "https://localhost:8443/callback",
                "WHOOPMCP_CACHE": "true",
                "WHOOPMCP_METRICS_TOKEN": METRICS_TOKEN,
                "WHOOPMCP_METRICS_SALT": METRICS_SALT,
            }
        )
        return metric_names(metrics.render(connection, config, now=NOW))
    finally:
        connection.close()


def test_every_metric_named_by_an_alert_rule_is_really_exported() -> None:
    """The mechanical form of the acceptance criterion.

    Renaming a metric without updating the rules file orphans an alert
    silently -- the rule keeps evaluating, just never fires. This is what
    catches that.
    """
    referenced = set(re.findall(r"\bwhoopmcp_[a-z0-9_]+\b", _alert_rules_text()))

    assert referenced, "the rules file references no whoopmcp_ metric at all"
    missing = referenced - _exported_metric_names()
    assert not missing, (
        f"alert rules reference metrics the exporter never exports: {sorted(missing)}"
    )


def test_the_rules_file_has_a_rule_for_each_alert_the_issue_names() -> None:
    """Four alerts: sync lag, sustained signature failures, ``invalid_grant``
    on any member, rate budget near exhaustion."""
    text = _alert_rules_text()
    referenced = set(re.findall(r"\bwhoopmcp_[a-z0-9_]+\b", text))

    assert len(re.findall(r"^\s*-\s*alert:\s*\S+", text, flags=re.MULTILINE)) >= 4
    assert "whoopmcp_data_freshness_seconds" in referenced
    assert "whoopmcp_webhook_signature_failures_total" in referenced
    assert "whoopmcp_token_refresh_failures_total" in referenced
    assert 'cause="invalid_grant"' in text or "cause='invalid_grant'" in text
    assert {"whoopmcp_rate_limit_remaining", "whoopmcp_rate_limit_limit"} <= referenced


def test_the_webhook_silence_rule_compares_against_the_members_own_baseline() -> None:
    """A dead webhook integration and a member on holiday look identical.

    So the silence rule has to be a comparison against that member's own
    history, not a fixed threshold -- which means a range-vector aggregation
    over ``whoopmcp_webhook_last_delivery_age_seconds`` rather than a bare
    ``> 86400``.
    """
    text = _alert_rules_text()
    silence_rules = [
        block
        for block in re.split(r"^\s*-\s*alert:", text, flags=re.MULTILINE)
        if "whoopmcp_webhook_last_delivery_age_seconds" in block
    ]

    assert silence_rules, "no alert rule watches per-member webhook silence"
    for block in silence_rules:
        assert "_over_time" in block, (
            "the webhook-silence rule must compare against the member's own baseline "
            f"(a range-vector aggregation), not an absolute threshold:\n{block}"
        )


def test_no_alert_rule_hard_codes_a_member_reference() -> None:
    """A rule pinned to one ``member_ref`` would mean the exporter's opaque
    ids had leaked into version control, and would stop alerting the moment
    the salt rotated."""
    text = _alert_rules_text()

    assert not re.search(r'member_ref\s*=~?\s*"[0-9a-f]{6,}"', text)
    assert str(MEMBER_ID) not in text
