"""OAuth 2.0 against WHOOP, plus local token storage.

WHOOP requires the client secret (no PKCE) -- this is a confidential client.
Access tokens last 1 hour; a refresh token needs the ``offline`` scope.
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
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import urlencode

import httpx

from whoopmcp import metrics
from whoopmcp.config import Config
from whoopmcp.crypto import SealError, seal, unseal

AUTHORIZE_URL = "https://api.prod.whoop.com/oauth/oauth2/auth"
TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token"  # noqa: S105 -- URL, not a credential  # nosec B105
#: The one non-GET endpoint WHOOP exposes; lives here, not client.py (see revoke_upstream).
USER_ACCESS_URL = "https://api.prod.whoop.com/developer/v2/user/access"

logger = logging.getLogger("whoopmcp.auth")

#: Refresh this many seconds early so an in-flight request doesn't 401 at expiry.
EXPIRY_SKEW_SECONDS = 60


class AuthError(RuntimeError):
    """Authorisation failed, or no usable credentials are available."""


class GrantAlreadyGoneError(AuthError):
    """An ``AuthError`` raised only when there is nothing left to revoke.

    Raised by ``access_token`` (no stored token) and ``_do_refresh``
    (WHOOP rejects refresh as ``invalid_grant``) -- the grant is already
    gone, not that revocation failed. Lets ``revoke_and_forget`` callers
    (#65) treat "nothing to revoke" as success while still catching a plain
    ``AuthError`` as a real failure. Subclasses ``AuthError`` so existing
    ``except AuthError`` sites keep working unchanged.
    """


@dataclass(frozen=True, slots=True)
class Token:
    """An access token and everything needed to renew it."""

    access_token: str = field(repr=False)
    expires_at: float
    refresh_token: str | None = field(default=None, repr=False)
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

    Shared by the token stores and ``_export_member`` (#68). Uses ``mkstemp``
    (unpredictable name, O_EXCL) so a symlink can't be pre-planted at the temp
    path; writes go through that fd only, never reopening ``path``, and
    ``os.replace`` doesn't follow symlinks. fsyncs data before rename, and the
    directory after (#136, POSIX-only) for crash/power-loss durability.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            tmp_file.write(contents)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_name, path)
        if os.name != "nt":
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


class FileTokenStore:
    """Stores the token as JSON in the state directory, mode 0600.

    Default backend: no extra deps, but the refresh token sits in plaintext
    on disk (see PRIVACY.md; prefer ``KeyringTokenStore``). **Windows: no
    protection** -- ACLs ignore the POSIX mode, file lands at 0666; use
    ``WHOOPMCP_TOKEN_BACKEND=keyring`` there instead (``save`` warns once).
    """

    #: POSIX modes are advisory on Windows; the 0600 promise holds only off it.
    _MODES_ENFORCED = os.name != "nt"

    def __init__(self, path: Path) -> None:
        self._path = path
        self._warned = False

    def load(self) -> Token | None:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            # Missing file means not logged in, which is normal.
            return None
        except (OSError, UnicodeDecodeError) as exc:
            # Unreadable (perm denied, is a dir, etc.) -> AuthError so callers
            # (doctor, export-member) can catch it; contract matches #137.
            raise AuthError(f"token file at {self._path} is unreadable: {exc}") from exc
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


#: One re-entrant lock per token path, shared by every ``EncryptedFileTokenStore``
#: on that path in this process (#132): without it, ``load``'s background
#: re-seal can race a concurrent refresh's ``save`` and overwrite it with a
#: stale token. Re-entrant since ``_reseal_if_unchanged`` holds it across
#: ``save``. Keyed by ``Path``; registry is never pruned (few paths per process).
_TOKEN_PATH_LOCKS: dict[Path, threading.RLock] = {}
_TOKEN_PATH_LOCKS_GUARD = threading.Lock()


def _lock_for_token_path(path: Path) -> threading.RLock:
    """The lock guarding writes to ``path`` within this process."""
    with _TOKEN_PATH_LOCKS_GUARD:
        lock = _TOKEN_PATH_LOCKS.get(path)
        if lock is None:
            lock = threading.RLock()
            _TOKEN_PATH_LOCKS[path] = lock
        return lock


class EncryptedFileTokenStore:
    """Like ``FileTokenStore``, but sealed (AES-256-GCM) before it touches disk --
    the envelope carries key version/nonce/ciphertext, never plaintext JSON.

    Rotation is lazy: ``load`` re-seals a record under ``current_version``
    right after reading an older-versioned one; both keys must stay in
    ``keys`` until every old-sealed record is read once. Separate
    ``token_backend="encrypted-file"`` value since it needs key material
    ``"file"`` doesn't.
    """

    _MODES_ENFORCED = os.name != "nt"

    #: Binds the AEAD tag to "token" so a same-keyed envelope of another
    #: record type can't be swapped in and still authenticate (defense in depth).
    _ASSOCIATED_DATA = b"whoopmcp.token"

    def __init__(self, path: Path, keys: Mapping[int, bytes], current_version: int) -> None:
        self._path = path
        self._keys = keys
        self._current_version = current_version
        self._warned = False
        #: Separate from `_warned` (save's Windows warning) so one warning
        #: firing doesn't suppress the other.
        self._reseal_warned = False

    def load(self) -> Token | None:
        """Return the stored token, or ``None`` if nothing is stored.

        A record sealed under an older key version is re-sealed under
        ``current_version`` before returning. If that re-seal fails (e.g.
        missing key), the record is still returned unrotated -- never raises
        out of `load` -- rather than turning a half-configured key set into
        an outage. Logged once per instance.
        """
        try:
            raw_bytes = self._path.read_bytes()
        except FileNotFoundError:
            # Missing file means not logged in, which is normal.
            return None
        except OSError as exc:
            # Unreadable (perm denied, is a dir, etc.) -> AuthError so callers
            # (doctor, export-member) can catch it; contract matches #137.
            raise AuthError(f"token file at {self._path} is unreadable: {exc}") from exc

        # Bytes not text: the later compare needs byte-exact data, and
        # read_text's UnicodeDecodeError wouldn't match this class's AuthError contract.
        try:
            raw = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuthError(f"token file at {self._path} is unreadable: {exc}") from exc

        try:
            envelope = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuthError(f"token file at {self._path} is unreadable: {exc}") from exc

        try:
            plaintext = unseal(envelope, self._keys, associated_data=self._ASSOCIATED_DATA)
        except SealError as exc:
            # SealError never carries plaintext/key (crypto.unseal's contract);
            # neither does this message.
            raise AuthError(f"token file at {self._path} failed to decrypt") from exc

        try:
            token = Token.from_json(plaintext.decode("utf-8"))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise AuthError(f"token file at {self._path} is unreadable: {exc}") from exc

        if envelope.get("v") != self._current_version:
            # Lazy rotation: re-seal under current_version now so future reads
            # use the new key; old key stays in `keys` until all are touched.
            try:
                self._reseal_if_unchanged(token, raw_bytes)
            except (SealError, OSError) as exc:
                # Missing key or write failure (#135): availability wins --
                # serve unrotated, retry next load. Contrast `save`, which raises.
                if not self._reseal_warned:
                    self._reseal_warned = True
                    logger.warning(
                        "could not re-seal token at %s under key version %s (%s): "
                        "serving the existing token unrotated. Supply the missing key, "
                        "or make the state directory writable, to complete rotation.",
                        self._path,
                        self._current_version,
                        type(exc).__name__,
                    )

        return token

    def _reseal_if_unchanged(self, token: Token, raw_at_read: bytes) -> None:
        """Re-seal ``token`` only if the file still holds the bytes ``load`` read (#132).

        Prevents: loader reads X, a refresh saves Y, loader's re-seal
        overwrites Y with stale X. Same-process races are fully closed by
        ``_TOKEN_PATH_LOCKS``; cross-process is only a best-effort byte
        compare -- the window between compare and ``save``'s rename is NOT
        closed cross-process (multi-process refresh is already unsound,
        see ``RefreshLock``). Skipping is always safe: a later ``load``
        re-seals it, and re-seal is never required for correctness.
        """
        with _lock_for_token_path(self._path):
            try:
                current = self._path.read_bytes()
            except FileNotFoundError:
                # Deleted under us (logout, or state cleared) -- don't resurrect it.
                logger.debug(
                    "skipping lazy re-seal at %s: the file is gone, so re-creating it "
                    "would resurrect a credential something just removed",
                    self._path,
                )
                return
            if current != raw_at_read:
                logger.debug(
                    "skipping lazy re-seal at %s: file changed since it was read, "
                    "so another writer's token is newer than the one in hand",
                    self._path,
                )
                return
            self.save(token)

    def save(self, token: Token) -> None:
        """Seal ``token`` and write it to disk.

        Unlike `load`'s lazy re-seal, a `SealError` here (e.g. missing key)
        is never swallowed -- it propagates, since a direct `save` may be
        the only copy of a freshly obtained token.
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
        # Held across the write so a concurrent re-seal can't land mid-save
        # (#132). See `_TOKEN_PATH_LOCKS`.
        with _lock_for_token_path(self._path):
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
        except ImportError as exc:
            # Deterministic since #198: tests stub sys.modules["keyring"]=None,
            # not dependent on the environment's actual extras.
            raise AuthError(
                "WHOOPMCP_TOKEN_BACKEND=keyring requires the extra: pip install 'whoopmcp[keyring]'"
            ) from exc
        self._keyring = keyring

    def load(self) -> Token | None:
        """Return the stored token, or ``None`` if the keychain holds none.

        A corrupt entry raises ``AuthError`` (matches file-backed stores, #137)
        instead of a raw ``JSONDecodeError``/``KeyError`` escaping. The message
        never includes the offending value -- unlike a file path, the entry
        itself is the credential.
        """
        raw = self._keyring.get_password(self.SERVICE, self.USERNAME)
        if not raw:
            return None
        try:
            return Token.from_json(raw)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise AuthError(
                f"the token in the {self.SERVICE} keychain entry is unreadable: "
                f"{type(exc).__name__}"
            ) from exc

    def save(self, token: Token) -> None:
        # No atomicity of our own (unlike FileTokenStore's write-then-replace):
        # passes straight to set_password; whatever atomicity exists is the backend's.
        self._keyring.set_password(self.SERVICE, self.USERNAME, token.to_json())

    def clear(self) -> None:
        # Every backend spells "no such entry" differently; failing here
        # would be wrong since a logout with nothing to remove still succeeded.
        try:
            self._keyring.delete_password(self.SERVICE, self.USERNAME)
        except Exception as exc:
            logger.debug("keyring delete_password failed during logout: %s", exc)


def build_store(config: Config) -> TokenStore:
    """Pick a token store based on configuration."""
    if config.token_backend == "keyring":  # noqa: S105 -- backend name  # nosec B105
        return KeyringTokenStore()
    if config.token_backend == "encrypted-file":  # noqa: S105 -- backend name  # nosec B105
        if config.token_encryption_key_version is None:
            # Config.from_env() already rejects this combo; only fires for a
            # hand-built Config.
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

    Caller must retain ``state`` and reject any callback that doesn't echo
    it back -- this is what stops a third party feeding us their own code.
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

    Only WHOOP's ``error``/``error_description`` are echoed -- never the
    request itself, which carries the client secret and auth/refresh code.
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
    """Whether ``current`` (from the store) is a genuinely different grant
    than ``token`` -- i.e. someone else already won a refresh race.

    Compares credential identity (access+refresh token), not full equality:
    ``expires_at``/``scopes`` can differ harmlessly for the same grant, so
    comparing every field would misfire on a caller's own token.
    """
    current_credential = (current.access_token, current.refresh_token)
    token_credential = (token.access_token, token.refresh_token)
    return current_credential != token_credential


async def revoke_upstream(access_token: str, config: Config) -> None:
    """``DELETE /v2/user/access``: revoke this grant on WHOOP's side.

    Deliberately never called by ``WhoopClient``/the MCP tool surface --
    revoking a grant is the user's decision via WHOOP's own settings, not an
    LLM-triggerable action. Only reachable from the ``delete-member`` CLI
    subcommand, via ``Authenticator.revoke_and_forget``. Living here (not on
    ``WhoopClient``) keeps it structurally out of tool reach.
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

    Just a mutex (not asyncio.Lock by name) so hosted mode (#27, #30) can
    supply a cross-process one without changing Authenticator.

    Warning for a future cross-process impl: a lock alone is not enough --
    refresh() releases it before the network call, relying on an in-process
    Future to coalesce waiters. A lock not covering the network call lets two
    processes each complete a refresh with the same rotating token, reproducing
    the credential-destroying race this exists to prevent (needs #13 instead).
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
        #: Bumped by logout()/revoke_and_forget() (#123). refresh() captures
        #: this before acquiring the lock, and _do_refresh re-checks it before
        #: persisting -- a mismatch means logout happened mid-flight, so a
        #: stale-by-policy token must not be written back. Must be captured
        #: at refresh() entry, not inside _do_refresh's task, since the task
        #: doesn't start until the event loop schedules it.
        self._credential_epoch = 0

    def start_login(self) -> str:
        """Begin a login and return the URL the user must open."""
        url, state = build_authorize_url(self._config)
        self._pending_state = state
        return url

    def verify_state(self, state: str) -> None:
        """Reject a callback whose ``state`` does not match the pending login.

        State is single-use (#120 BCP): success clears ``_pending_state``, so
        a retry needs a fresh ``start_login()``. A mismatch does NOT clear it
        -- clearing on any wrong guess would let an attacker who can reach the
        callback URL kill someone else's in-flight login (DoS); the 32-byte
        state can't be brute-forced anyway.
        """
        if self._pending_state is None:
            raise AuthError("no login in progress; call start_login first")
        if not secrets.compare_digest(state, self._pending_state):
            raise AuthError("state mismatch; discarding this authorization code")
        self._pending_state = None

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
        # Install before persisting (#134): if save() fails, the grant is
        # still live upstream and usable this session; exception still propagates.
        self._token = token
        self._store.save(token)
        return token

    async def refresh(self, token: Token) -> Token:
        """Renew an expired token using its refresh token.

        Single-flighted two ways: a store-recheck after the lock catches a
        round that already succeeded; concurrent callers instead coalesce
        onto ``self._inflight_refresh`` (a shared Task) so a failed round
        isn't retried by every waiter. The lock covers only the check/create
        step, released before the network call.

        Epoch (#123) is captured here, before the lock -- not inside
        ``_do_refresh``, whose task only starts once scheduled, so a
        same-tick ``logout()`` must still be visible.
        """
        epoch = self._credential_epoch
        await self._refresh_lock.acquire()
        try:
            current = self._store.load()
            refresh_target = token
            if current is not None and _supersedes(current, token):
                if not current.expired:
                    self._token = current
                    return current
                # #122 D1: `current` is fresher but also expired -- refresh it,
                # not `token` (already rotated past). Keep `original`=token for
                # D2's invalid_grant classification below.
                refresh_target = current
            if self._inflight_refresh is None:
                self._inflight_refresh = asyncio.ensure_future(
                    self._do_refresh(refresh_target, epoch, original=token)
                )
            inflight = self._inflight_refresh
        finally:
            self._refresh_lock.release()

        try:
            return await inflight
        finally:
            if self._inflight_refresh is inflight:
                self._inflight_refresh = None

    async def _do_refresh(self, token: Token, epoch: int, *, original: Token) -> Token:
        # `epoch` is captured by refresh() before the lock, not here (see
        # refresh()'s docstring, #123). `token` is what's sent to WHOOP (D1
        # may substitute a fresher-but-expired store token); `original` is
        # always the caller's own, used only for D2's classification below.
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
                # #31: no response at all, so it can't be classified as
                # invalid_grant/token_endpoint_error (both need a response).
                metrics.record_token_refresh_failure("network_error")
                raise
        if response.status_code == 400 and _is_invalid_grant(response):
            metrics.record_token_refresh_failure("invalid_grant")
            # #122: invalid_grant doesn't mean the grant is gone -- WHOOP
            # rotates refresh tokens on use, so this may be a superseded
            # credential. D2 compares the store against `original` (caller's
            # view), not `token` (may be D1's substituted copy), else a
            # substitution misclassifies as "grant gone".
            stored = self._store.load()
            if stored is None or not _supersedes(stored, original):
                # Genuine case: store matches what the caller knew -- the
                # rejection describes the grant itself, so clear it.
                self._store.clear()
                self._token = None
                # GrantAlreadyGoneError: gone, not merely unreachable.
                raise GrantAlreadyGoneError(
                    "WHOOP rejected the refresh token (invalid_grant); it will not become "
                    "valid on retry -- run whoop_login to re-authorise"
                )
            # Store already moved past the caller's view before this call
            # started -- don't clear (could destroy a fresher credential).
            # Must be plain AuthError, not GrantAlreadyGoneError: #65's
            # erase/delete-member would misread that as "revoke succeeded"
            # while the grant is still live.
            raise AuthError(
                "WHOOP rejected a refresh token that the local store has already superseded "
                "with a fresher one; the grant may still be live -- retry the operation"
            )
        try:
            _raise_for_token_error(response)
        except AuthError:
            # #31: counter lives here, not in _raise_for_token_error itself,
            # since exchange_code shares that helper (would conflate login/refresh).
            metrics.record_token_refresh_failure("token_endpoint_error")
            raise
        try:
            new_token = Token.from_response(response.json())
        except (AuthError, ValueError):
            # #31: 2xx but malformed body -- not JSON, or missing fields.
            metrics.record_token_refresh_failure("malformed_response")
            raise
        if epoch == self._credential_epoch:
            self._store.save(new_token)
            self._token = new_token
        else:
            # #123: logout() ran mid-flight. WHOOP already rotated the token
            # upstream, but don't write it back or install it -- a store that
            # repopulates after logout is worse than none. Caller still gets
            # `new_token` (it's genuinely valid); only session state was invalidated.
            logger.info(
                "discarding a token refresh that completed after logout(); "
                "not persisting or installing it"
            )
        metrics.record_token_refresh_success()
        return new_token

    async def access_token(self) -> str:
        """Return a valid access token, refreshing it if necessary."""
        if self._token is None:
            self._token = self._store.load()
        token = self._token
        if token is None:
            # GrantAlreadyGoneError: "nothing to revoke", not a failure.
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
        # #123: bump so any in-flight refresh discards its result on completion.
        # revoke_and_forget calls this method too, so needs no bump of its own (D3).
        self._credential_epoch += 1

    async def revoke_and_forget(self) -> None:
        """Revoke this grant upstream, then forget the local token.

        Operator-only counterpart to ``logout``: also calls ``revoke_upstream``
        first, so the grant is actually revoked, not just forgotten locally.
        Unreachable from the MCP tool surface -- only the ``delete-member``
        CLI subcommand calls it. Refreshes first if expired, since revoke
        needs a live access token.
        """
        access_token = await self.access_token()
        await revoke_upstream(access_token, self._config)
        self.logout()
