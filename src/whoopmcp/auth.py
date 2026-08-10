"""OAuth 2.0 against WHOOP, plus local token storage.

WHOOP implements the authorization-code grant. Its docs describe no PKCE
support, so the client secret is required for the code exchange and this
server is a *confidential* client running on the user's own machine. Access
tokens last one hour; a refresh token is only issued when the ``offline``
scope is part of the authorisation request.

Docs: https://developer.whoop.com/docs/developing/oauth/
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlencode

import httpx

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
        # No atomicity guarantee of our own here, unlike FileTokenStore's
        # write-then-replace: this passes straight through to the OS keychain's
        # own set_password, and keyring's API doesn't document a swap-on-success
        # contract the way a filesystem rename gives us. Whatever atomicity this
        # has comes from the backend, not from anything written here.
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


def _raise_for_token_error(response: httpx.Response) -> None:
    """Turn a non-2xx token-endpoint response into an AuthError.

    Only WHOOP's own ``error``/``error_description`` fields are echoed back
    -- never the request we sent, since that is where the client secret and
    any refresh/authorization code live.
    """
    if response.is_success:
        return
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    error = payload.get("error", "unknown_error") if isinstance(payload, dict) else "unknown_error"
    description = payload.get("error_description") if isinstance(payload, dict) else None
    message = f"WHOOP token endpoint returned {response.status_code} ({error})"
    if description:
        message += f": {description}"
    raise AuthError(message)


def _is_invalid_grant(response: httpx.Response) -> bool:
    try:
        payload = response.json()
    except ValueError:
        return False
    return isinstance(payload, dict) and payload.get("error") == "invalid_grant"


class RefreshLock(Protocol):
    """Serialises concurrent refreshes to exactly one in flight at a time.

    Deliberately just a mutex, not asyncio.Lock by name: hosted mode (#27,
    #30) needs one that holds across processes, and should be able to
    supply it here without any change to Authenticator.

    Caution for whoever builds that cross-process implementation (#27
    prototyped one, SQLite-file-lock backed, and removed it before merge):
    a lock alone is not sufficient. refresh() below coordinates within one
    process via a private asyncio.Future -- the lock only guards "is a
    refresh already in flight," and is released before the network call
    completes, relying on that Future (with no cross-process equivalent)
    to make every other in-process caller await the SAME request rather
    than starting their own. A cross-process RefreshLock that is merely
    held-then-released around that same check, without also covering the
    network call itself, does not stop two separate processes from each
    independently completing a refresh with the same about-to-rotate
    refresh token -- which reproduces the exact credential-destroying race
    this whole mechanism exists to prevent, just across processes instead
    of within one. Closing that gap for real means either holding the lock
    across the network request (a change to this method, which the
    original ask for this Protocol explicitly wanted to avoid) or a
    compare-and-swap against a shared store keyed on the token's own
    identity (needs #13). See #27 for the discovery and reasoning.
    """

    async def acquire(self) -> None: ...

    def release(self) -> None: ...


class InProcessRefreshLock:
    """The default: a plain asyncio.Lock, sufficient for one server process."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        await self._lock.acquire()

    def release(self) -> None:
        self._lock.release()


class Authenticator:
    """Owns the token lifecycle: exchange, refresh, persist, revoke."""

    def __init__(
        self,
        config: Config,
        store: TokenStore | None = None,
        *,
        refresh_lock: RefreshLock | None = None,
    ) -> None:
        self._config = config
        self._store = store or build_store(config)
        self._token: Token | None = None
        self._pending_state: str | None = None
        self._refresh_lock: RefreshLock = refresh_lock or InProcessRefreshLock()
        self._inflight_refresh: asyncio.Task[Token] | None = None

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
        """Trade an authorization code for a token, and persist it."""
        async with httpx.AsyncClient(timeout=self._config.request_timeout) as client:
            response = await client.post(
                TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": self._config.client_id,
                    "client_secret": self._config.client_secret,
                    "redirect_uri": self._config.redirect_uri,
                },
            )
        _raise_for_token_error(response)
        token = Token.from_response(response.json())
        self._store.save(token)
        self._token = token
        return token

    async def refresh(self, token: Token) -> Token:
        """Renew an expired token using its refresh token.

        Single-flighted two ways. A store-recheck after acquiring
        self._refresh_lock short-circuits a caller that arrives once a PRIOR
        round has already resolved successfully -- another caller may have
        refreshed past `token` while this one waited for the lock, and
        re-reading the shared store (rather than an in-process cache) is what
        will let a future cross-process lock (#27, #30) work here too without
        changing this method, since a different process's win is only
        visible through the store. But a store-recheck alone only catches a
        *successful* prior round: a failed one clears the store to None,
        which leaves a caller arriving mid-flight nothing to short-circuit
        on. So callers who arrive WHILE a round is still running instead
        coalesce onto self._inflight_refresh, a shared asyncio.Task --
        awaiting it delivers the winner's exception to every waiter just as
        it would the winner's result, so a failed refresh (e.g.
        invalid_grant) does not get retried by everyone who was waiting on
        it.

        The lock is only held for the brief "check the store, then
        create-or-reuse the shared task" step -- the network call itself
        happens with the lock released, so waiters merely await the same
        task rather than blocking each other on it. Clearing the finished
        task back out of self._inflight_refresh does not need the lock
        either: it is plain synchronous code with no `await` between the
        identity check and the assignment, so nothing can interleave between
        them -- whichever waiter's continuation runs first clears it, and the
        rest see it is already gone.
        """
        await self._refresh_lock.acquire()
        try:
            current = self._store.load()
            if current is not None and current != token and not current.expired:
                self._token = current
                return current
            if self._inflight_refresh is None:
                self._inflight_refresh = asyncio.ensure_future(self._do_refresh(token))
            inflight = self._inflight_refresh
        finally:
            self._refresh_lock.release()

        try:
            return await inflight
        finally:
            if self._inflight_refresh is inflight:
                self._inflight_refresh = None

    async def _do_refresh(self, token: Token) -> Token:
        async with httpx.AsyncClient(timeout=self._config.request_timeout) as client:
            response = await client.post(
                TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": token.refresh_token,
                    "client_id": self._config.client_id,
                    "client_secret": self._config.client_secret,
                    "scope": "offline",
                },
            )
        if response.status_code == 400 and _is_invalid_grant(response):
            self._store.clear()
            self._token = None
            raise AuthError(
                "WHOOP rejected the refresh token (invalid_grant); it will not become valid "
                "on retry -- run whoop_login to re-authorise"
            )
        _raise_for_token_error(response)
        new_token = Token.from_response(response.json())
        self._store.save(new_token)
        self._token = new_token
        return new_token

    async def access_token(self) -> str:
        """Return a valid access token, refreshing it if necessary."""
        if self._token is None:
            self._token = self._store.load()
        token = self._token
        if token is None:
            raise AuthError("no stored credentials found; run whoop_login to authenticate")
        if token.expired:
            if token.refresh_token is None:
                raise AuthError(
                    "stored token is expired and has no refresh token; run whoop_login "
                    "to authenticate"
                )
            token = await self.refresh(token)
        return token.access_token

    def logout(self) -> None:
        """Forget the local token. Does not revoke it server-side."""
        self._store.clear()
        self._token = None
        self._pending_state = None
