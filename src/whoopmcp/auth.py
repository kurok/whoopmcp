"""OAuth 2.0 against WHOOP, plus local token storage.

WHOOP implements the authorization-code grant. Its docs describe no PKCE
support, so the client secret is required for the code exchange and this
server is a *confidential* client running on the user's own machine. Access
tokens last one hour; a refresh token is only issued when the ``offline``
scope is part of the authorisation request.

Docs: https://developer.whoop.com/docs/developing/oauth/
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlencode

from whoopmcp.config import Config

AUTHORIZE_URL = "https://api.prod.whoop.com/oauth/oauth2/auth"
TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token"

logger = logging.getLogger("whoopmcp.auth")

#: Refresh this many seconds before the token actually expires, so a request
#: that is in flight when the clock ticks over does not 401.
EXPIRY_SKEW_SECONDS = 60


class AuthError(RuntimeError):
    """Authorisation failed, or no usable credentials are available."""


@dataclass(frozen=True, slots=True)
class Token:
    """An access token and everything needed to renew it."""

    access_token: str
    expires_at: float
    refresh_token: str | None = None
    scopes: tuple[str, ...] = ()

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at - EXPIRY_SKEW_SECONDS

    @classmethod
    def from_response(cls, payload: dict[str, object], *, now: float | None = None) -> Token:
        """Build a token from a WHOOP token-endpoint response body."""
        issued_at = time.time() if now is None else now
        try:
            access = str(payload["access_token"])
            expires_in = float(payload["expires_in"])  # type: ignore[arg-type]
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthError(f"malformed token response: {exc}") from exc

        raw_scope = payload.get("scope")
        scopes = tuple(str(raw_scope).split()) if raw_scope else ()
        refresh = payload.get("refresh_token")

        return cls(
            access_token=access,
            expires_at=issued_at + expires_in,
            refresh_token=str(refresh) if refresh else None,
            scopes=scopes,
        )

    def to_json(self) -> str:
        return json.dumps(
            {
                "access_token": self.access_token,
                "expires_at": self.expires_at,
                "refresh_token": self.refresh_token,
                "scopes": list(self.scopes),
            }
        )

    @classmethod
    def from_json(cls, raw: str) -> Token:
        data = json.loads(raw)
        return cls(
            access_token=data["access_token"],
            expires_at=float(data["expires_at"]),
            refresh_token=data.get("refresh_token"),
            scopes=tuple(data.get("scopes", ())),
        )


class TokenStore(Protocol):
    """Somewhere a token can be kept between server restarts."""

    def load(self) -> Token | None: ...

    def save(self, token: Token) -> None: ...

    def clear(self) -> None: ...


class FileTokenStore:
    """Stores the token as JSON in the state directory, mode 0600.

    The directory is created 0700. This is the default because it works with
    no extra dependencies, but it does mean a plaintext refresh token on disk
    -- see PRIVACY.md, and prefer ``KeyringTokenStore`` where available.

    **On Windows this offers no protection.** Windows uses ACLs, not POSIX
    modes, and ``Path.touch(mode=...)`` is effectively ignored there -- the
    file lands at 0666. Use ``WHOOPMCP_TOKEN_BACKEND=keyring`` on Windows;
    ``save`` warns once if you do not.
    """

    #: POSIX modes are advisory at best on Windows, so the 0600 promise below
    #: holds only off it.
    _MODES_ENFORCED = os.name != "nt"

    def __init__(self, path: Path) -> None:
        self._path = path
        self._warned = False

    def load(self) -> Token | None:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        try:
            return Token.from_json(raw)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise AuthError(f"token file at {self._path} is unreadable: {exc}") from exc

    def save(self, token: Token) -> None:
        if not self._MODES_ENFORCED and not self._warned:
            self._warned = True
            logger.warning(
                "%s cannot be protected by file permissions on Windows; the refresh token "
                "is readable by any process running as you. Set WHOOPMCP_TOKEN_BACKEND=keyring "
                "(pip install 'whoopmcp[keyring]') to store it in the Windows Credential Manager.",
                self._path,
            )

        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Write-then-rename so a crash mid-write cannot truncate a good token,
        # and create the temp file 0600 so the secret is never world-readable
        # even for the instant before the rename.
        tmp = self._path.with_suffix(".tmp")
        tmp.touch(mode=0o600, exist_ok=True)
        tmp.write_text(token.to_json(), encoding="utf-8")
        tmp.replace(self._path)

    def clear(self) -> None:
        self._path.unlink(missing_ok=True)


class KeyringTokenStore:
    """Stores the token in the OS keychain via the optional ``keyring`` extra."""

    SERVICE = "whoopmcp"
    USERNAME = "default"

    def __init__(self) -> None:
        try:
            import keyring
        except ImportError as exc:  # pragma: no cover - depends on the extra
            raise AuthError(
                "WHOOPMCP_TOKEN_BACKEND=keyring requires the extra: pip install 'whoopmcp[keyring]'"
            ) from exc
        self._keyring = keyring

    def load(self) -> Token | None:
        raw = self._keyring.get_password(self.SERVICE, self.USERNAME)
        return Token.from_json(raw) if raw else None

    def save(self, token: Token) -> None:
        self._keyring.set_password(self.SERVICE, self.USERNAME, token.to_json())

    def clear(self) -> None:
        # Every keyring backend spells "no such entry" differently, and a
        # logout that fails because there was nothing to remove has still
        # achieved what the caller wanted.
        try:
            self._keyring.delete_password(self.SERVICE, self.USERNAME)
        except Exception as exc:
            logger.debug("keyring delete_password failed during logout: %s", exc)


def build_store(config: Config) -> TokenStore:
    """Pick a token store based on configuration."""
    if config.token_backend == "keyring":
        return KeyringTokenStore()
    return FileTokenStore(config.token_path)


def build_authorize_url(config: Config, *, state: str | None = None) -> tuple[str, str]:
    """Return ``(url, state)`` for the browser step of the OAuth flow.

    The caller must retain ``state`` and reject any callback that does not
    echo it back -- that check is what stops a third party from feeding us
    their own authorization code.
    """
    state = state or secrets.token_urlsafe(32)
    query = urlencode(
        {
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(config.scopes),
            "state": state,
        }
    )
    return f"{AUTHORIZE_URL}?{query}", state


class Authenticator:
    """Owns the token lifecycle: exchange, refresh, persist, revoke."""

    def __init__(self, config: Config, store: TokenStore | None = None) -> None:
        self._config = config
        self._store = store or build_store(config)
        self._token: Token | None = None
        self._pending_state: str | None = None

    def start_login(self) -> str:
        """Begin a login and return the URL the user must open."""
        url, state = build_authorize_url(self._config)
        self._pending_state = state
        return url

    def verify_state(self, state: str) -> None:
        """Reject a callback whose ``state`` does not match the pending login."""
        if self._pending_state is None:
            raise AuthError("no login in progress; call start_login first")
        if not secrets.compare_digest(state, self._pending_state):
            raise AuthError("state mismatch; discarding this authorization code")

    async def exchange_code(self, code: str) -> Token:
        """Trade an authorization code for a token, and persist it.

        TODO(#1): POST to TOKEN_URL with grant_type=authorization_code,
        code, client_id, client_secret and redirect_uri as form-encoded body;
        wrap the response with Token.from_response and self._store.save.
        """
        raise NotImplementedError("exchange_code is not implemented yet -- see issue #1")

    async def refresh(self, token: Token) -> Token:
        """Renew an expired token using its refresh token.

        TODO(#1): POST to TOKEN_URL with grant_type=refresh_token,
        refresh_token, client_id, client_secret and scope=offline. WHOOP
        rotates refresh tokens, so the new one must replace the stored one.
        """
        raise NotImplementedError("refresh is not implemented yet -- see issue #1")

    async def access_token(self) -> str:
        """Return a valid access token, refreshing it if necessary.

        TODO(#1): load from the store on first call, refresh when expired,
        and raise AuthError with a "run whoop_login" hint when there is
        nothing to refresh.
        """
        raise NotImplementedError("access_token is not implemented yet -- see issue #1")

    def logout(self) -> None:
        """Forget the local token. Does not revoke it server-side."""
        self._store.clear()
        self._token = None
        self._pending_state = None
