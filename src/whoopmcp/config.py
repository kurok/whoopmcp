"""Runtime configuration, resolved from the environment.

Read once at startup. MCP servers run as a subprocess with no TTY, so env
vars are the only configuration channel that works everywhere.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from whoopmcp.crypto import parse_key_env_value

TokenBackend = Literal["file", "keyring", "encrypted-file"]
Transport = Literal["stdio", "streamable-http"]

#: Matches WHOOPMCP_TOKEN_ENCRYPTION_KEY_V<N>, capturing N. Only consulted
#: when token_backend == "encrypted-file".
_KEY_VERSION_VAR_RE = re.compile(r"^WHOOPMCP_TOKEN_ENCRYPTION_KEY_V(\d+)$")

#: Scopes requested during authorisation. `offline` is required for WHOOP to
#: return a refresh token; without it the grant dies in an hour.
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
    """Resolved server configuration. See field comments for non-obvious ones."""

    client_id: str
    client_secret: str = field(repr=False)
    redirect_uri: str
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    token_backend: TokenBackend = "file"  # noqa: S105 -- a backend name, not a credential value
    state_dir: Path = field(default_factory=_default_state_dir)
    cache_enabled: bool = False
    request_timeout: float = 30.0
    rate_limit_per_minute: int = 100
    rate_limit_per_day: int = 10_000
    transport: Transport = "stdio"
    http_host: str = "127.0.0.1"
    http_port: int = 8000
    #: Off by default: `/webhooks/whoop` (#17) is public/unauthenticated, so
    #: it must be explicitly enabled to be exposed.
    webhooks_enabled: bool = False
    #: How far a webhook timestamp may drift from now before rejection --
    #: bounds the window a captured, signed request can be replayed in.
    webhook_timestamp_skew_seconds: float = 300.0
    #: Inbound cap on /webhooks/whoop, checked pre-signature-verification.
    #: Independent of rate_limit_per_minute (outbound budget), so a flood
    #: can't spend that too (#17). 0/negative disables inbound limiting.
    webhook_rate_limit_per_minute: int = 120
    #: Key-version -> AES-256-GCM key (encrypted-file backend only). Every
    #: version referenced by an on-disk record must stay present as long as
    #: that record exists -- see `auth.EncryptedFileTokenStore`.
    token_encryption_keys: Mapping[int, bytes] = field(default_factory=dict, repr=False)
    token_encryption_key_version: int | None = None
    backfill_floor_date: str | None = None
    #: Bearer token required on /metrics (#31). Unset means the route 404s --
    #: off unless configured, since it would otherwise expose per-member
    #: health telemetry to anyone reaching the port.
    metrics_token: str | None = field(default=None, repr=False)
    #: HMAC key deriving /metrics' opaque member_ref (#31). Deliberately not
    #: `client_secret` (rotating that would also reset metrics + break
    #: webhooks). Unset withholds every per-member series -- an unkeyed hash
    #: of a WHOOP user id would be reversible by enumeration.
    metrics_member_salt: str | None = field(default=None, repr=False)

    @property
    def token_path(self) -> Path:
        return self.state_dir / "token.json"

    @property
    def cache_path(self) -> Path:
        return self.state_dir / "cache.sqlite3"

    @property
    def store_is_ephemeral(self) -> bool:
        """Whether this config's store may only ever live in memory.

        PRIVACY.md promises default local mode persists only the token
        (#74); default stdio with no cache/webhooks gets an in-memory store.
        Every other combination (hosted, WHOOPMCP_CACHE opt-in, webhooks)
        legitimately persists. Keys off `transport`, not the constructed ASGI
        app -- configuration decides, not construction.
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
            # WHOOP rejects plain http (even localhost); fail here, not
            # halfway through a browser round-trip.
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

        # Validated up front: a malformed floor should fail at startup, not
        # partway through a multi-minute backfill.
        backfill_floor_date = src.get("WHOOPMCP_BACKFILL_FLOOR_DATE") or None
        if backfill_floor_date is not None:
            try:
                datetime.fromisoformat(backfill_floor_date)
            except ValueError as exc:
                raise ConfigError(
                    "WHOOPMCP_BACKFILL_FLOOR_DATE must be an ISO 8601 date or "
                    f"datetime, got {backfill_floor_date!r}"
                ) from exc

        # Range-checked where a bad value is worse than a startup failure --
        # see _require_positive for the outbound rate limits' deadlock case (#200).
        request_timeout = _numeric_env(src, "WHOOPMCP_TIMEOUT", "30", parse=float)
        _require_positive("WHOOPMCP_TIMEOUT", request_timeout)
        rate_limit_per_minute = _numeric_env(
            src, "WHOOPMCP_RATE_LIMIT_PER_MINUTE", "100", parse=int
        )
        _require_positive("WHOOPMCP_RATE_LIMIT_PER_MINUTE", rate_limit_per_minute)
        rate_limit_per_day = _numeric_env(src, "WHOOPMCP_RATE_LIMIT_PER_DAY", "10000", parse=int)
        _require_positive("WHOOPMCP_RATE_LIMIT_PER_DAY", rate_limit_per_day)
        http_port = _numeric_env(src, "WHOOPMCP_HTTP_PORT", "8000", parse=int)
        if not 1 <= http_port <= 65535:
            raise ConfigError(f"WHOOPMCP_HTTP_PORT must be between 1 and 65535, got {http_port}")

        return cls(
            client_id=src["WHOOP_CLIENT_ID"],
            client_secret=src["WHOOP_CLIENT_SECRET"],
            redirect_uri=redirect_uri,
            scopes=scopes,
            token_backend=backend,  # type: ignore[arg-type]
            state_dir=state_dir,
            cache_enabled=_as_bool(src.get("WHOOPMCP_CACHE", "false")),
            request_timeout=request_timeout,
            rate_limit_per_minute=rate_limit_per_minute,
            rate_limit_per_day=rate_limit_per_day,
            transport=transport,  # type: ignore[arg-type]
            http_host=src.get("WHOOPMCP_HTTP_HOST", "127.0.0.1"),
            http_port=http_port,
            webhooks_enabled=_as_bool(src.get("WHOOPMCP_WEBHOOKS_ENABLED", "false")),
            # Range deliberately NOT checked here: 0/negative disables
            # inbound limiting by convention, and skew has no deadlock mode.
            webhook_timestamp_skew_seconds=_numeric_env(
                src, "WHOOPMCP_WEBHOOK_TIMESTAMP_SKEW_SECONDS", "300", parse=float
            ),
            webhook_rate_limit_per_minute=_numeric_env(
                src, "WHOOPMCP_WEBHOOK_RATE_LIMIT_PER_MINUTE", "120", parse=int
            ),
            token_encryption_keys=token_encryption_keys,
            token_encryption_key_version=token_encryption_key_version,
            backfill_floor_date=backfill_floor_date,
            metrics_token=src.get("WHOOPMCP_METRICS_TOKEN") or None,
            metrics_member_salt=src.get("WHOOPMCP_METRICS_SALT") or None,
        )


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _numeric_env(
    src: Mapping[str, str],
    name: str,
    default: str,
    *,
    parse: Callable[[str], float] | Callable[[str], int],
) -> Any:
    """Parse a numeric env var, or raise `ConfigError` naming it (#200).

    Safe for `doctor` to relay: every variable routed through here is a
    timeout/port/rate number, never key material, so the message never
    quotes a secret.
    """
    raw = src.get(name, default)
    try:
        return parse(raw)
    except ValueError as exc:
        raise ConfigError(
            f"{name} must be a number, got {raw!r}. See "
            "https://github.com/kurok/whoopmcp/blob/main/docs/SETUP.md"
        ) from exc


def _require_positive(name: str, value: float) -> None:
    """Reject a non-positive numeric variable with a `ConfigError` naming it.

    Sharp case (#200): a 0 outbound rate limit builds a `RateLimiter` that can
    never grant, hanging every request silently forever. Deliberately NOT
    applied to `webhook_rate_limit_per_minute`, whose convention is the
    opposite (0/negative disables inbound limiting).
    """
    if value <= 0:
        raise ConfigError(f"{name} must be greater than 0, got {value}")


def _parse_token_encryption_keys(
    src: Mapping[str, str], *, required: bool
) -> tuple[dict[int, bytes], int | None]:
    """Collect every `WHOOPMCP_TOKEN_ENCRYPTION_KEY_V<N>` into a version->key
    mapping, plus which version is current.

    Mandatory only when `required` (token_backend == "encrypted-file");
    file/keyring backends are unaffected by these being unset.
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
