"""Runtime configuration, resolved from the environment.

Everything the server needs to know is read once at startup. MCP servers are
launched by the client (Claude Desktop, Cursor, ...) as a subprocess with no
TTY, so environment variables are the only configuration channel that works
everywhere -- there is nowhere to prompt.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from whoopmcp.crypto import parse_key_env_value

TokenBackend = Literal["file", "keyring", "encrypted-file"]
Transport = Literal["stdio", "streamable-http"]

#: Matches WHOOPMCP_TOKEN_ENCRYPTION_KEY_V<N>, capturing N. Only consulted
#: when token_backend == "encrypted-file" -- the file/keyring backends have
#: no key material and are unaffected by these variables being unset.
_KEY_VERSION_VAR_RE = re.compile(r"^WHOOPMCP_TOKEN_ENCRYPTION_KEY_V(\d+)$")

#: Scopes requested during authorisation. ``offline`` is what makes WHOOP
#: return a refresh token; without it the grant dies after one hour and the
#: user has to re-authorise through the browser every session.
DEFAULT_SCOPES: tuple[str, ...] = (
    "read:profile",
    "read:body_measurement",
    "read:cycles",
    "read:recovery",
    "read:sleep",
    "read:workout",
    "offline",
)


class ConfigError(RuntimeError):
    """Raised when the environment cannot produce a usable configuration."""


def _default_state_dir() -> Path:
    """Per-user state directory, XDG on Linux and the usual spot elsewhere."""
    if xdg := os.environ.get("XDG_STATE_HOME"):
        return Path(xdg) / "whoopmcp"
    return Path.home() / ".local" / "state" / "whoopmcp"


@dataclass(frozen=True, slots=True)
class Config:
    """Resolved server configuration.

    Attributes:
        client_id: OAuth client id from the WHOOP developer dashboard.
        client_secret: OAuth client secret. WHOOP does not document PKCE
            support, so the secret is required for the code exchange.
        redirect_uri: Must match a redirect URL registered on the WHOOP app
            exactly. WHOOP documents ``https://`` and custom-scheme URIs only.
        scopes: Scopes to request at authorisation time.
        token_backend: Where the refresh token lives.
        state_dir: Directory for the token file and any cache.
        cache_enabled: Whether responses may be cached on disk.
        request_timeout: Per-request timeout in seconds.
        rate_limit_per_minute: Local budget for requests/minute, mirroring
            WHOOP's documented default.
        rate_limit_per_day: Local budget for requests/day, mirroring WHOOP's
            documented default.
        transport: "stdio" (default, what MCP clients launch) or
            "streamable-http" (#27).
        http_host: Bind host for the streamable-http transport.
        http_port: Bind port for the streamable-http transport.
        webhooks_enabled: Whether the `/webhooks/whoop` receiver (#17) is
            registered at all. Off by default: the route is public and
            unauthenticated by construction, so an operator who hasn't set
            up a WHOOP webhook subscription shouldn't have it exposed.
        webhook_timestamp_skew_seconds: How far a webhook's
            `X-WHOOP-Signature-Timestamp` may drift from now, in either
            direction, before it's rejected even with a valid signature.
            Bounds the window a captured, correctly-signed request can be
            replayed in.
        webhook_rate_limit_per_minute: Cap on `/webhooks/whoop` requests per
            minute, checked before the body is read or the signature
            verified -- independent of `rate_limit_per_minute` above, which
            is the outbound WHOOP budget; a shared counter would let an
            inbound flood spend that budget too (#17). `120` is roughly
            2/sec sustained: comfortably above legitimate WHOOP volume even
            at a ten-member cap with retries and simultaneous multi-member
            events, while still blunting a flood. `0` or negative disables
            inbound limiting entirely.
        token_encryption_keys: Key-version -> 32-byte AES-256-GCM key,
            parsed from `WHOOPMCP_TOKEN_ENCRYPTION_KEY_V<N>` variables.
            Only populated (and only required) when `token_backend` is
            `"encrypted-file"`. Every version named here must stay present
            for as long as any on-disk record was sealed under it -- see
            `auth.EncryptedFileTokenStore`, which re-seals a record under
            the current version lazily, on its next read.
        token_encryption_key_version: Which version in
            `token_encryption_keys` new writes seal under. Only meaningful
            alongside `token_backend == "encrypted-file"`.
        backfill_floor_date: Inclusive lower bound for `whoopmcp backfill`
            (#14), an ISO 8601 date or datetime string passed straight
            through as the WHOOP API's own `start` parameter. Unset (the
            default) means no floor: walk until history is exhausted. Kept
            as a string because `client.build_collection_params` and the
            store's convention throughout is ISO strings, not datetimes.
        metrics_token: Bearer token required on `/metrics` (#31). Unset (the
            default) means the route 404s and exports nothing -- off unless
            explicitly configured, the same precedent `webhooks_enabled`
            establishes, since `/metrics` would otherwise hand per-member
            health telemetry to anyone who can reach the port.
        metrics_member_salt: HMAC key for deriving `/metrics`' opaque
            `member_ref` label from a WHOOP user id (#31). Deliberately not
            `client_secret`: that value is also the webhook signing secret,
            so rotating it would silently reset every metrics time series at
            the same moment it broke webhooks. Unset means every per-member
            series is withheld entirely -- an unkeyed hash of a WHOOP user id
            (a modest integer) would be reversible by enumeration in
            seconds, which is not opaque, so there is no weaker fallback.
    """

    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    token_backend: TokenBackend = "file"
    state_dir: Path = field(default_factory=_default_state_dir)
    cache_enabled: bool = False
    request_timeout: float = 30.0
    rate_limit_per_minute: int = 100
    rate_limit_per_day: int = 10_000
    transport: Transport = "stdio"
    http_host: str = "127.0.0.1"
    http_port: int = 8000
    webhooks_enabled: bool = False
    webhook_timestamp_skew_seconds: float = 300.0
    webhook_rate_limit_per_minute: int = 120
    token_encryption_keys: Mapping[int, bytes] = field(default_factory=dict)
    token_encryption_key_version: int | None = None
    backfill_floor_date: str | None = None
    metrics_token: str | None = None
    metrics_member_salt: str | None = None

    @property
    def token_path(self) -> Path:
        return self.state_dir / "token.json"

    @property
    def cache_path(self) -> Path:
        return self.state_dir / "cache.sqlite3"

    @property
    def store_is_ephemeral(self) -> bool:
        """Whether this configuration's store may only ever live in memory.

        PRIVACY.md promises that in default local mode the only thing this
        software persists is your token. ``server.lifespan()`` opening
        ``cache_path`` unconditionally broke that promise by creating
        ``cache.sqlite3`` and writing a principal link plus a tool-call audit
        row into it (#74). PR #63 settled the direction: the document is the
        contract and the code bends. So default local stdio -- no
        ``WHOOPMCP_CACHE``, no webhooks -- gets an in-memory store instead.

        Every other combination legitimately persists and keeps its
        pre-#74 on-disk behaviour: hosted mode holds other members' data,
        ``WHOOPMCP_CACHE`` is an explicit opt-in, and the webhook consumer
        must survive a restart to be worth anything.

        Lives here rather than in ``server.py`` because it is a pure question
        about configuration, and both consumers (``server.lifespan`` and
        ``doctor``) already depend on this module -- putting it in
        ``server.py`` would make ``whoopmcp doctor`` import the entire MCP
        server surface to answer it. Keys off ``transport``, not off which
        ASGI app was constructed: configuration decides, not construction.
        """
        return self.transport == "stdio" and not self.cache_enabled and not self.webhooks_enabled

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Config:
        """Build a config from environment variables.

        Raises:
            ConfigError: if a required variable is missing or malformed.
        """
        src = os.environ if env is None else env

        missing = [
            name
            for name in ("WHOOP_CLIENT_ID", "WHOOP_CLIENT_SECRET", "WHOOP_REDIRECT_URI")
            if not src.get(name)
        ]
        if missing:
            raise ConfigError(
                f"missing required environment variable(s): {', '.join(missing)}. "
                "See https://github.com/kurok/whoopmcp/blob/main/docs/SETUP.md"
            )

        redirect_uri = src["WHOOP_REDIRECT_URI"]
        if redirect_uri.startswith("http://"):
            # WHOOP's dashboard rejects plain http, including http://localhost.
            # Failing here beats failing halfway through a browser round-trip.
            raise ConfigError(
                f"WHOOP_REDIRECT_URI must not use http:// (got {redirect_uri!r}). "
                "WHOOP accepts https:// or a custom scheme such as whoopmcp://callback."
            )

        backend = src.get("WHOOPMCP_TOKEN_BACKEND", "file")
        if backend not in ("file", "keyring", "encrypted-file"):
            raise ConfigError(
                "WHOOPMCP_TOKEN_BACKEND must be 'file', 'keyring', or 'encrypted-file', "
                f"got {backend!r}"
            )

        token_encryption_keys, token_encryption_key_version = _parse_token_encryption_keys(
            src, required=backend == "encrypted-file"
        )

        scopes = (
            tuple(src["WHOOPMCP_SCOPES"].split()) if src.get("WHOOPMCP_SCOPES") else DEFAULT_SCOPES
        )

        transport = src.get("WHOOPMCP_TRANSPORT", "stdio")
        if transport not in ("stdio", "streamable-http"):
            raise ConfigError(
                f"WHOOPMCP_TRANSPORT must be 'stdio' or 'streamable-http', got {transport!r}"
            )

        state_dir = (
            Path(src["WHOOPMCP_STATE_DIR"]).expanduser()
            if src.get("WHOOPMCP_STATE_DIR")
            else _default_state_dir()
        )

        # Validated up front, like the redirect_uri and token-backend checks
        # above: a malformed floor should fail at startup naming the
        # variable, not partway through a multi-minute backfill.
        backfill_floor_date = src.get("WHOOPMCP_BACKFILL_FLOOR_DATE") or None
        if backfill_floor_date is not None:
            try:
                datetime.fromisoformat(backfill_floor_date)
            except ValueError as exc:
                raise ConfigError(
                    "WHOOPMCP_BACKFILL_FLOOR_DATE must be an ISO 8601 date or "
                    f"datetime, got {backfill_floor_date!r}"
                ) from exc

        return cls(
            client_id=src["WHOOP_CLIENT_ID"],
            client_secret=src["WHOOP_CLIENT_SECRET"],
            redirect_uri=redirect_uri,
            scopes=scopes,
            token_backend=backend,  # type: ignore[arg-type]
            state_dir=state_dir,
            cache_enabled=_as_bool(src.get("WHOOPMCP_CACHE", "false")),
            request_timeout=float(src.get("WHOOPMCP_TIMEOUT", "30")),
            rate_limit_per_minute=int(src.get("WHOOPMCP_RATE_LIMIT_PER_MINUTE", "100")),
            rate_limit_per_day=int(src.get("WHOOPMCP_RATE_LIMIT_PER_DAY", "10000")),
            transport=transport,  # type: ignore[arg-type]
            http_host=src.get("WHOOPMCP_HTTP_HOST", "127.0.0.1"),
            http_port=int(src.get("WHOOPMCP_HTTP_PORT", "8000")),
            webhooks_enabled=_as_bool(src.get("WHOOPMCP_WEBHOOKS_ENABLED", "false")),
            webhook_timestamp_skew_seconds=float(
                src.get("WHOOPMCP_WEBHOOK_TIMESTAMP_SKEW_SECONDS", "300")
            ),
            webhook_rate_limit_per_minute=int(
                src.get("WHOOPMCP_WEBHOOK_RATE_LIMIT_PER_MINUTE", "120")
            ),
            token_encryption_keys=token_encryption_keys,
            token_encryption_key_version=token_encryption_key_version,
            backfill_floor_date=backfill_floor_date,
            metrics_token=src.get("WHOOPMCP_METRICS_TOKEN") or None,
            metrics_member_salt=src.get("WHOOPMCP_METRICS_SALT") or None,
        )


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_token_encryption_keys(
    src: Mapping[str, str], *, required: bool
) -> tuple[dict[int, bytes], int | None]:
    """Collect every `WHOOPMCP_TOKEN_ENCRYPTION_KEY_V<N>` present into a
    version -> key mapping, plus the `WHOOPMCP_TOKEN_ENCRYPTION_KEY_VERSION`
    pointer naming which one is current.

    This parsing only becomes mandatory when ``required`` is true (i.e.
    ``token_backend == "encrypted-file"``) -- operators on the plain "file"
    or "keyring" backends are unaffected by these variables being unset,
    matching every other backend-specific setting in this module.
    """
    keys: dict[int, bytes] = {}
    for name, raw in src.items():
        match = _KEY_VERSION_VAR_RE.match(name)
        if match is None or not raw:
            continue
        version = int(match.group(1))
        try:
            keys[version] = parse_key_env_value(raw, var_name=name)
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc

    if not required:
        current_raw = src.get("WHOOPMCP_TOKEN_ENCRYPTION_KEY_VERSION")
        if not current_raw:
            return keys, None
        try:
            return keys, int(current_raw)
        except ValueError as exc:
            raise ConfigError(
                f"WHOOPMCP_TOKEN_ENCRYPTION_KEY_VERSION must be an integer, got {current_raw!r}"
            ) from exc

    if not keys:
        raise ConfigError(
            "WHOOPMCP_TOKEN_BACKEND=encrypted-file requires at least one "
            "WHOOPMCP_TOKEN_ENCRYPTION_KEY_V<N> variable (base64-encoded, 32 bytes)"
        )

    current_raw = src.get("WHOOPMCP_TOKEN_ENCRYPTION_KEY_VERSION")
    if not current_raw:
        raise ConfigError(
            "WHOOPMCP_TOKEN_BACKEND=encrypted-file requires "
            "WHOOPMCP_TOKEN_ENCRYPTION_KEY_VERSION to name which key version is current"
        )
    try:
        current_version = int(current_raw)
    except ValueError as exc:
        raise ConfigError(
            f"WHOOPMCP_TOKEN_ENCRYPTION_KEY_VERSION must be an integer, got {current_raw!r}"
        ) from exc
    if current_version not in keys:
        raise ConfigError(
            f"WHOOPMCP_TOKEN_ENCRYPTION_KEY_VERSION={current_version} has no matching "
            f"WHOOPMCP_TOKEN_ENCRYPTION_KEY_V{current_version} variable"
        )
    return keys, current_version
