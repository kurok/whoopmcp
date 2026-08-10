"""Runtime configuration, resolved from the environment.

Everything the server needs to know is read once at startup. MCP servers are
launched by the client (Claude Desktop, Cursor, ...) as a subprocess with no
TTY, so environment variables are the only configuration channel that works
everywhere -- there is nowhere to prompt.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

TokenBackend = Literal["file", "keyring"]

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

    @property
    def token_path(self) -> Path:
        return self.state_dir / "token.json"

    @property
    def cache_path(self) -> Path:
        return self.state_dir / "cache.sqlite3"

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
        if backend not in ("file", "keyring"):
            raise ConfigError(
                f"WHOOPMCP_TOKEN_BACKEND must be 'file' or 'keyring', got {backend!r}"
            )

        scopes = (
            tuple(src["WHOOPMCP_SCOPES"].split()) if src.get("WHOOPMCP_SCOPES") else DEFAULT_SCOPES
        )

        state_dir = (
            Path(src["WHOOPMCP_STATE_DIR"]).expanduser()
            if src.get("WHOOPMCP_STATE_DIR")
            else _default_state_dir()
        )

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
        )


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}
