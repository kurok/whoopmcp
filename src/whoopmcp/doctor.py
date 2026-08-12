"""``whoopmcp doctor`` (#35): one-pass health check for a local-mode install.

Local mode has no operator dashboard and no scheduler watching it -- the
person running it IS the operator. ``doctor`` is the whole diagnostic
surface: configuration, credentials, the local store, and sync state, each
reported as one honest sentence. Every check that *can* run does, even after
an earlier one fails, so an operator sees the whole picture in one pass
(mirroring ``server.py``'s own collect-then-report ``/ready`` pattern) --
except where a later check has nothing to run against at all (no ``Config``
means no store to open; no open store means nothing to read sync state
from), in which case it is left out entirely rather than fabricated.

Never prints, logs, or otherwise surfaces a token value, a signing secret, or
an encryption key -- every message below is built from data already known to
be safe (a check's own name, an exception's type name, an ISO timestamp), the
same redaction precedent ``server._check_token_store_reachable`` established
for a corrupt-token-store read.
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

    ``config`` is normally left ``None`` so this builds its own
    ``Config.from_env()`` -- the same call ``__main__.py`` makes for every
    other subcommand -- but a caller (a test, mainly) may supply one
    directly. A missing/malformed configuration stops everything after it:
    there is no store path, no token backend, nothing to check credentials
    or the store against. An unopenable store stops the sync check the same
    way, for the same reason: there is no connection to read
    ``sync_state`` from.
    """
    checks: list[DoctorCheck] = []

    if config is None:
        try:
            config = Config.from_env()
        except ConfigError as exc:
            # Unlike the credentials/store checks below, this one reports the
            # full exception text rather than just the type name -- naming
            # WHICH variable is missing or malformed is the entire value of
            # the check. That is safe by construction, not by luck: every
            # ConfigError raise site in config.py interpolates variable
            # *names* or non-secret values (a redirect URI, a backend name,
            # a key-version pointer), never a credential, and
            # crypto.parse_key_env_value's wrapped errors never embed key
            # bytes. A raise site added later that quotes a secret value
            # would leak here -- keep config.py to that rule.
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
    """Token present, and not expired -- read from the store, no network call.

    Reusing ``auth.build_store(config).load()`` -- the same call
    ``whoop_auth_status`` and ``server._check_token_store_reachable`` already
    make -- keeps this check to the same cheap, already-tested code path
    rather than inventing a new one. A store that fails to read at all (a
    corrupt or undecryptable token file) is reported by exception type only,
    the same redaction ``_check_token_store_reachable`` uses: ``FileTokenStore``'s
    own error text includes the token file's absolute path.
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

    Any failure is reported by exception type only, never the path or a
    traceback -- same precedent as the credentials check above.

    In default local mode (``WHOOPMCP_CACHE`` unset) ``lifespan()`` now opens
    an in-memory store instead of ``config.cache_path`` (#74), so that
    PRIVACY.md's "nothing but the token" promise holds for the running
    server. If this check went ahead and called ``open_store(config
    .cache_path)`` unconditionally anyway, ``doctor`` itself would become the
    *only* thing that ever creates ``cache.sqlite3`` on disk in that mode --
    an operator who reads the promise, then runs `doctor`, would find the
    file the document says isn't there. So when there is no cache opt-in and
    no such file already exists (e.g. left over from a past
    ``WHOOPMCP_CACHE=true`` period), report the true, in-memory state instead
    of creating one just to check it. If a file *does* already exist, the
    check proceeds exactly as before -- that store is real and worth
    opening.
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

    Local mode has no scheduled incremental sync today (#15 is not merged),
    so an empty ``sync_state`` for the one linked member is the expected,
    healthy state, not staleness against a schedule that does not exist. If
    rows do exist (possible today only via webhook processing), the most
    recent outcome is reported verbatim with no judgment added.
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
