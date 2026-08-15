"""``whoopmcp doctor`` (#35): one-pass health check for a local-mode install.

Reports configuration, credentials, store, and sync state as one sentence
each; every check that can run does, even after an earlier one fails.
Never surfaces a token, signing secret, or encryption key -- messages use
only safe data (check name, exception type, timestamp).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from whoopmcp.auth import AuthError, build_store
from whoopmcp.config import Config, ConfigError
from whoopmcp.store import all_linked_whoop_user_ids, get_all_sync_state_for_member, open_store


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One diagnosed fact: a name, whether it's fine, and one sentence why."""

    name: str
    ok: bool
    message: str


def run_checks(config: Config | None = None) -> list[DoctorCheck]:
    """Run every doctor check that can meaningfully run, in order.

    ``config`` defaults to ``Config.from_env()`` (tests may pass one directly).
    A missing/malformed config stops everything after it -- no store path, no
    credentials to check. An unopenable store likewise stops the sync check.
    """
    checks: list[DoctorCheck] = []

    if config is None:
        try:
            config = Config.from_env()
        except ConfigError as exc:
            # Shown in full (unlike other checks): naming the bad variable is
            # the point. config.py must never quote a secret in a ConfigError.
            checks.append(DoctorCheck(name="configuration", ok=False, message=str(exc)))
            return checks
    checks.append(
        DoctorCheck(
            name="configuration", ok=True, message="configuration loaded from the environment"
        )
    )

    checks.append(_check_credentials(config))

    conn, store_check = _check_store(config)
    checks.append(store_check)
    if conn is None:
        return checks
    try:
        checks.append(_check_sync(conn))
    finally:
        conn.close()

    return checks


def _check_credentials(config: Config) -> DoctorCheck:
    """Token present and not expired -- store read only, no network call.

    Reuses ``auth.build_store(config).load()`` (same path as
    ``whoop_auth_status``). An unreadable store is reported by exception type
    only -- its message may include the token file's absolute path.
    """
    try:
        token = build_store(config).load()
    except AuthError as exc:
        return DoctorCheck(
            name="credentials",
            ok=False,
            message=f"the token store could not be read ({type(exc).__name__})",
        )

    if token is None:
        return DoctorCheck(
            name="credentials",
            ok=False,
            message="no WHOOP token stored; run whoop_login to authenticate",
        )

    expiry = datetime.fromtimestamp(token.expires_at, tz=UTC).isoformat()
    if token.expired:
        return DoctorCheck(
            name="credentials",
            ok=False,
            message=f"stored token expired at {expiry}; run whoop_login again",
        )
    return DoctorCheck(
        name="credentials",
        ok=True,
        message=f"token present, valid until {expiry}",
    )


def _check_store(config: Config) -> tuple[sqlite3.Connection | None, DoctorCheck]:
    """The local cache/store opens and migrates cleanly.

    Failures report exception type only, never path or traceback. In default
    local mode (no ``WHOOPMCP_CACHE``, no existing file), this must NOT call
    ``open_store`` -- doing so would create ``cache.sqlite3`` itself, breaking
    PRIVACY.md's "off by default" promise. Proceeds normally if a file already
    exists.
    """
    if config.store_is_ephemeral and not config.cache_path.exists():
        return None, DoctorCheck(
            name="store",
            ok=True,
            message=(
                "the local store is in-memory only in default local mode "
                "(WHOOPMCP_CACHE is not set); nothing is persisted to disk"
            ),
        )
    try:
        conn = open_store(config.cache_path)
    except Exception as exc:
        return None, DoctorCheck(
            name="store",
            ok=False,
            message=f"the local store could not be opened ({type(exc).__name__})",
        )
    return conn, DoctorCheck(name="store", ok=True, message="store opened successfully")


def _check_sync(conn: sqlite3.Connection) -> DoctorCheck:
    """Report actual sync_state rows, honestly -- never invent a schedule.

    No sync is scheduled yet (#15 not merged), so an empty state for the
    linked member is expected/healthy, not staleness. Existing rows are
    reported verbatim, no judgment added.
    """
    linked = all_linked_whoop_user_ids(conn)
    if not linked:
        return DoctorCheck(
            name="sync", ok=True, message="no member has ever been linked; nothing to check yet"
        )
    if len(linked) > 1:
        return DoctorCheck(
            name="sync",
            ok=True,
            message=(
                "more than one member has ever been linked; cannot determine which "
                "member's sync state to check"
            ),
        )

    (whoop_user_id,) = linked
    rows = get_all_sync_state_for_member(conn, whoop_user_id)
    if not rows:
        return DoctorCheck(
            name="sync",
            ok=True,
            message=(
                "no sync has ever run for this member -- local mode has no scheduled "
                "incremental sync yet (#15 is not merged); data is fetched live on "
                "each tool call"
            ),
        )

    summary = "; ".join(
        f"{row['entity']}: {row['outcome']} at {row['last_run_at']}" for row in rows
    )
    return DoctorCheck(name="sync", ok=True, message=f"last recorded sync state -- {summary}")
