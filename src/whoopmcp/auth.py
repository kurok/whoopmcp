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
import contextlib
import json
import logging
import os
import secrets
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlencode

import httpx

from whoopmcp import metrics
from whoopmcp.config import Config
from whoopmcp.crypto import SealError, seal, unseal

AUTHORIZE_URL = "https://api.prod.whoop.com/oauth/oauth2/auth"
TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token"  # noqa: S105 -- an endpoint URL, not a credential value  # nosec B105
#: The one non-GET endpoint WHOOP exposes to an OAuth client. Lives here,
#: not in client.py -- see revoke_upstream's docstring for why.
USER_ACCESS_URL = "https://api.prod.whoop.com/developer/v2/user/access"

logger = logging.getLogger("whoopmcp.auth")

#: Refresh this many seconds before the token actually expires, so a request
#: that is in flight when the clock ticks over does not 401.
EXPIRY_SKEW_SECONDS = 60


class AuthError(RuntimeError):
    """Authorisation failed, or no usable credentials are available."""


class GrantAlreadyGoneError(AuthError):
    """An ``AuthError`` raised only when there is nothing left to revoke.

    Two producing sites, both below: ``access_token`` when there is no
    stored token at all, and ``_do_refresh`` when WHOOP rejects the refresh
    token as ``invalid_grant`` (the member revoked the grant in WHOOP's own
    app settings, or an operator already ran ``whoop_logout``/``logout``).
    Both mean the upstream grant is already gone -- not that revocation
    failed -- so a caller of ``revoke_and_forget`` that wants "nothing to
    revoke" to count as revoke-step success (issue #65: ``__main__.py``'s
    ``_delete_member``/``_erase_member``) can catch this narrower type
    specifically and continue, while still treating a plain ``AuthError``
    (e.g. ``revoke_upstream``'s own non-2xx-response path, a genuine
    transport failure) as a real failure that must abort.

    Subclassing ``AuthError`` rather than introducing an unrelated type
    means every existing ``except AuthError`` elsewhere in this codebase
    keeps catching this exactly as before -- this widens the taxonomy
    without changing what any current call site sees.
    """


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

    def load(self) -> Token | None:
        pass

    def save(self, token: Token) -> None:
        pass

    def clear(self) -> None:
        pass


def atomic_write_text(path: Path, contents: str) -> None:
    """Write ``contents`` to ``path`` atomically, mode 0600.

    Not auth-specific despite living here: ``FileTokenStore`` and
    ``EncryptedFileTokenStore`` share it below so the write-then-rename
    atomicity -- and the 0600 permissions that are the whole point of both
    classes' promise -- exist in exactly one place, and ``__main__.py``'s
    ``_export_member`` (#68) reuses it too, for the same reason: a
    data-subject export is the same category of sensitive text as a token,
    and deserves the same no-world-readable-window guarantee rather than a
    second, duplicated implementation of it.

    Write-then-rename means a crash mid-write cannot truncate a good
    record. The temp file's name must be unpredictable, not just its
    permissions: for ``_export_member`` the parent directory is whatever
    the operator passed to ``--out``, which may be shared or world-writable,
    and a guessable name (e.g. one derived from ``path`` itself) lets
    another user pre-create it -- as a symlink, before this call ever
    runs -- and have the content delivered wherever they point it instead.
    ``tempfile.mkstemp`` closes that: it picks a name nothing else could
    have predicted and creates it with ``O_EXCL`` at mode 0600 in one
    atomic step, so pre-creation can't win and no separate chmod is needed.
    The content is written through that file descriptor directly, never by
    reopening ``path`` or the temp name -- reopening by path would
    reintroduce the same symlink-following race this exists to close.
    ``os.replace`` then swaps the temp file onto ``path`` as an atomic,
    non-dereferencing rename: if ``path`` itself is already a symlink, the
    symlink is what gets replaced, not the file it points to.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            tmp_file.write(contents)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


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

        atomic_write_text(self._path, token.to_json())

    def clear(self) -> None:
        self._path.unlink(missing_ok=True)


class EncryptedFileTokenStore:
    """Like ``FileTokenStore``, but the token is sealed (AES-256-GCM, via
    ``crypto.seal``/``unseal``) before it touches disk, so what's actually
    written is an envelope -- key version, nonce, ciphertext -- never the
    plaintext ``Token`` JSON ``FileTokenStore`` writes.

    Rotation is lazy, not big-bang: ``load`` re-seals a record under
    ``current_version`` immediately after successfully reading one sealed
    under an older version, so a record migrates to the new key the next
    time it's read rather than needing a forced bulk pass. Both the old and
    new key simply need to stay present in ``keys`` for as long as any
    record sealed under the old one hasn't yet been read -- there is no
    other downtime requirement.

    This is a new, explicit ``token_backend`` value (``"encrypted-file"``)
    rather than a change to plain ``"file"``, because it requires key
    material ``"file"`` does not: an operator who wants it opts in by
    setting the key env vars and flipping the backend.
    """

    _MODES_ENFORCED = os.name != "nt"

    #: Bound into the AEAD tag so a sealed *token* envelope can never be
    #: swapped for some other record type sealed with the same key and have
    #: it still authenticate -- defense in depth beyond the key-version
    #: binding crypto.seal already does on its own.
    _ASSOCIATED_DATA = b"whoopmcp.token"

    def __init__(self, path: Path, keys: Mapping[int, bytes], current_version: int) -> None:
        self._path = path
        self._keys = keys
        self._current_version = current_version
        self._warned = False
        #: Separate from `_warned` above on purpose -- that flag belongs to
        #: `save`'s Windows-mode warning. Sharing it would let either
        #: warning suppress the other the first time either condition
        #: fires.
        self._reseal_warned = False

    def load(self) -> Token | None:
        """Return the stored token, or ``None`` if nothing is stored.

        A record sealed under an older key version is normally re-sealed
        under ``current_version`` before being returned (see the lazy
        rotation note below). If that re-seal itself fails -- most likely
        because the operator has not yet supplied the current version's key
        -- the record is still perfectly decryptable, so it is returned
        unrotated rather than turning a half-configured key set into an
        outage. That failure is logged (once per instance) naming the
        missing version so it is diagnosable; it never raises out of
        `load`, and never touches the file, unlike a direct `save` call
        (see `save`'s own docstring note).
        """
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None

        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuthError(f"token file at {self._path} is unreadable: {exc}") from exc

        try:
            plaintext = unseal(envelope, self._keys, associated_data=self._ASSOCIATED_DATA)
        except SealError as exc:
            # SealError never carries the plaintext or the key (see
            # crypto.unseal's own contract) -- neither does this message.
            raise AuthError(f"token file at {self._path} failed to decrypt") from exc

        try:
            token = Token.from_json(plaintext.decode("utf-8"))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise AuthError(f"token file at {self._path} is unreadable: {exc}") from exc

        if envelope.get("v") != self._current_version:
            # Lazy rotation: this record was sealed under an older key
            # version than the one now current. Re-seal it right away so
            # every read after this one uses the new key -- no forced bulk
            # re-encrypt pass, no downtime; the old key just needs to
            # remain in `keys` until every such record has been touched
            # once.
            try:
                self.save(token)
            except SealError:
                # The current key is missing (e.g. a half-completed key
                # rotation, or a misconfigured environment). The token we
                # just decrypted is still valid -- availability wins here:
                # serve it unrotated rather than raise, and try again on
                # the next load. Contrast with `save` itself, which must
                # keep raising for a direct caller (see its docstring).
                if not self._reseal_warned:
                    self._reseal_warned = True
                    logger.warning(
                        "could not re-seal token at %s under key version %s: the current "
                        "key is not available. Serving the existing token unrotated; "
                        "supply the missing key to complete rotation.",
                        self._path,
                        self._current_version,
                    )

        return token

    def save(self, token: Token) -> None:
        """Seal ``token`` and write it to disk.

        Unlike the lazy re-seal inside `load` above, a `SealError` here --
        e.g. the current key version is missing -- is never swallowed: it
        propagates. A direct `save` (as `Authenticator.exchange_code` makes
        right after a successful token exchange) is the only copy of a
        freshly obtained token there is; degrading that to a warning would
        silently lose it instead of merely deferring a rotation.
        """
        if not self._MODES_ENFORCED and not self._warned:
            self._warned = True
            logger.warning(
                "%s cannot be protected by file permissions on Windows; the sealed token "
                "is readable by any process running as you, though its contents remain "
                "encrypted. Set WHOOPMCP_TOKEN_BACKEND=keyring "
                "(pip install 'whoopmcp[keyring]') to store it in the Windows Credential "
                "Manager instead.",
                self._path,
            )
        envelope = seal(
            plaintext=token.to_json().encode("utf-8"),
            keys=self._keys,
            current_version=self._current_version,
            associated_data=self._ASSOCIATED_DATA,
        )
        atomic_write_text(self._path, json.dumps(envelope))

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
    if config.token_backend == "keyring":  # noqa: S105 -- a backend name, not a credential value  # nosec B105
        return KeyringTokenStore()
    if config.token_backend == "encrypted-file":  # noqa: S105 -- a backend name, not a credential value  # nosec B105
        if config.token_encryption_key_version is None:
            # Config.from_env() already refuses to produce a config with
            # token_backend="encrypted-file" and no key version, so this
            # only fires for a Config built by hand rather than from_env.
            raise AuthError(
                "token_backend='encrypted-file' requires token_encryption_key_version "
                "and at least one entry in token_encryption_keys"
            )
        return EncryptedFileTokenStore(
            config.token_path,
            keys=config.token_encryption_keys,
            current_version=config.token_encryption_key_version,
        )
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


def _supersedes(current: Token, token: Token) -> bool:
    """Whether ``current`` (freshly read from the store) represents a
    genuinely different grant than ``token`` (the caller's own copy) --
    i.e. whether someone else has already won a refresh race `token`'s
    caller is only now catching up to.

    Compared by credential identity (access token + refresh token) rather
    than full ``Token`` equality on purpose: ``expires_at`` is *expected*
    to differ between a caller's about-to-expire copy and a genuinely
    fresher store entry for the exact same grant, and a caller does not
    always reconstruct ``scopes`` byte-for-byte. Comparing every field
    would make this fire on a caller's own, not-yet-superseded token
    purely because time has passed since they last read it; only the
    credential itself changing means someone else has actually refreshed.
    """
    current_credential = (current.access_token, current.refresh_token)
    token_credential = (token.access_token, token.refresh_token)
    return current_credential != token_credential


async def revoke_upstream(access_token: str, config: Config) -> None:
    """``DELETE /v2/user/access``: revoke this grant on WHOOP's side.

    client.py's own module docstring explains why ``WhoopClient`` deliberately
    never calls this: revoking a grant is a decision a user makes for
    themselves, through WHOOP's own settings, not something an LLM-driven
    tool should be able to trigger. That reasoning holds for the MCP tool
    surface -- it does NOT hold for an *operator*-initiated deletion, which
    is the only caller of this function (via ``Authenticator
    .revoke_and_forget``, itself only reachable from the ``delete-member``
    CLI subcommand in ``__main__.py``, never a tool ``server.py`` registers).
    Living here rather than on ``WhoopClient`` is what keeps this call out
    of reach of the MCP tool surface, structurally -- not an oversight.
    """
    async with httpx.AsyncClient(timeout=config.request_timeout) as client:
        response = await client.delete(
            USER_ACCESS_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if not response.is_success:
        # Never echo the request back -- that is where the bearer token lives.
        raise AuthError(f"WHOOP user/access endpoint returned {response.status_code}")


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

    async def acquire(self) -> None:
        pass

    def release(self) -> None:
        pass


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
            if current is not None and not current.expired and _supersedes(current, token):
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
            try:
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
            except httpx.RequestError:
                # #31: a refresh that never got a response at all -- never
                # counted as invalid_grant/token_endpoint_error, both of
                # which need an actual response to classify.
                metrics.record_token_refresh_failure("network_error")
                raise
        if response.status_code == 400 and _is_invalid_grant(response):
            self._store.clear()
            self._token = None
            metrics.record_token_refresh_failure("invalid_grant")
            # GrantAlreadyGoneError, not plain AuthError: the grant is gone,
            # not merely unreachable -- see that class's own docstring.
            raise GrantAlreadyGoneError(
                "WHOOP rejected the refresh token (invalid_grant); it will not become valid "
                "on retry -- run whoop_login to re-authorise"
            )
        try:
            _raise_for_token_error(response)
        except AuthError:
            # #31: any other non-2xx from the token endpoint. Not inside
            # _raise_for_token_error itself -- exchange_code shares that
            # helper, and a counter there would conflate first-login
            # failures with refresh failures.
            metrics.record_token_refresh_failure("token_endpoint_error")
            raise
        try:
            new_token = Token.from_response(response.json())
        except (AuthError, ValueError):
            # #31: a 2xx response whose body isn't the token shape expected
            # -- either response.json() itself failing (not JSON at all) or
            # Token.from_response's own AuthError for a JSON body missing
            # the fields it needs.
            metrics.record_token_refresh_failure("malformed_response")
            raise
        self._store.save(new_token)
        self._token = new_token
        metrics.record_token_refresh_success()
        return new_token

    async def access_token(self) -> str:
        """Return a valid access token, refreshing it if necessary."""
        if self._token is None:
            self._token = self._store.load()
        token = self._token
        if token is None:
            # GrantAlreadyGoneError, not plain AuthError: see that class's
            # own docstring -- this is "nothing to revoke", not a failure.
            raise GrantAlreadyGoneError(
                "no stored credentials found; run whoop_login to authenticate"
            )
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

    async def revoke_and_forget(self) -> None:
        """Revoke this grant upstream, then forget the local token.

        The operator-initiated counterpart to ``logout``: where ``logout``
        only forgets, this also calls ``revoke_upstream`` first, so the
        grant is actually revoked rather than merely no-longer-remembered
        here. Deliberately unreachable from the MCP tool surface -- see
        ``revoke_upstream``'s own docstring -- so its only caller is the
        ``delete-member`` CLI subcommand (``__main__.py``), never a tool
        ``server.py`` registers.

        Refreshes first if the stored token is expired, since WHOOP's
        revoke endpoint needs a live access token, not a dead one -- the
        whole point of deleting a member is to kill the grant, not to fail
        quietly because the access token had already expired.
        """
        access_token = await self.access_token()
        await revoke_upstream(access_token, self._config)
        self.logout()
