"""Envelope encryption for records at rest (issue #30).

A thin wrapper around ``cryptography``'s own AES-256-GCM AEAD primitive --
this module never invents its own ciphertext framing, only the envelope
shape that carries the *key version* a record was sealed under alongside
the nonce and ciphertext. That version is what makes key rotation a lazy,
per-record migration rather than a big-bang re-encrypt: an old record stays
readable for as long as its key is still supplied, and a fresh seal always
uses whichever version its caller names as current.

Generic on purpose, not auth-specific: this is a primitive (bytes in, bytes
out) that ``auth.EncryptedFileTokenStore`` happens to be the first caller
of, not a token-shaped concept in its own right.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: AES-256-GCM: a 32-byte key.
_KEY_LENGTH = 32
#: The standard GCM nonce size. Never reused for a given key -- a fresh one
#: is drawn from `os.urandom` on every `seal` call.
_NONCE_LENGTH = 12


class SealError(RuntimeError):
    """A seal/unseal operation failed.

    Raised instead of letting a `KeyError` (unknown key version) or a
    `cryptography.exceptions.InvalidTag` (tampered ciphertext, tampered
    nonce, or a version-swapped envelope authenticating against the wrong
    key) escape directly -- both fail closed the same way from a caller's
    point of view, and neither message below ever includes the plaintext,
    the ciphertext, or any key material, so a caller that logs this
    exception cannot accidentally leak what it was trying to protect.
    """


def _associated_data(version: int, extra: bytes) -> bytes:
    """Bind the envelope's own claimed key version into the AEAD tag.

    Without this, an attacker could relabel a v1 envelope's "v" field as 2
    and have `unseal` pick key v2 to authenticate a v1 ciphertext against --
    which either fails for an unrelated reason or, worse, could succeed if
    the wrong key happened to validate. Mixing the version into the
    associated data means the tag itself is only valid for the exact
    version it claims, so a relabeled envelope fails authentication rather
    than silently trying a different key.
    """
    return f"whoopmcp.seal.v{version}".encode() + extra


def seal(
    plaintext: bytes,
    keys: Mapping[int, bytes],
    current_version: int,
    *,
    associated_data: bytes = b"",
) -> dict[str, Any]:
    """Encrypt ``plaintext`` under ``keys[current_version]``.

    Returns a JSON-serialisable envelope: ``{"v": <version>, "nonce":
    <b64>, "ct": <b64>}``. ``ct`` is AESGCM's own output, which already
    carries its 16-byte authentication tag -- no separate tag field, no
    custom framing.
    """
    try:
        key = keys[current_version]
    except KeyError as exc:
        raise SealError(f"no key available for version {current_version}") from exc

    nonce = os.urandom(_NONCE_LENGTH)
    ciphertext = AESGCM(key).encrypt(
        nonce, plaintext, _associated_data(current_version, associated_data)
    )
    return {
        "v": current_version,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }


def unseal(
    envelope: Mapping[str, Any],
    keys: Mapping[int, bytes],
    *,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt ``envelope``, using whichever key version it itself declares.

    Raises `SealError` -- never `KeyError`, never
    `cryptography.exceptions.InvalidTag` -- for an unknown key version, a
    tampered nonce or ciphertext, or a version field that does not match
    what the ciphertext was actually sealed under. In every failure case
    this raises before returning anything, so a caller cannot receive
    garbage bytes from a failed decrypt.
    """
    try:
        version = int(envelope["v"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ct"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SealError("malformed envelope") from exc

    try:
        key = keys[version]
    except KeyError as exc:
        raise SealError(f"no key available for version {version}") from exc

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _associated_data(version, associated_data))
    except InvalidTag as exc:
        raise SealError("authentication failed: ciphertext or nonce is not intact") from exc


def parse_key_env_value(raw: str, *, var_name: str) -> bytes:
    """Decode a base64-encoded 32-byte key from an environment variable.

    Shared by `config.Config.from_env` for every `WHOOPMCP_TOKEN_ENCRYPTION_
    KEY_V<N>` variable, so the base64/length validation lives in one place
    rather than being re-derived at each call site.
    """
    try:
        key = base64.b64decode(raw, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{var_name} must be base64-encoded: {exc}") from exc
    if len(key) != _KEY_LENGTH:
        raise ValueError(f"{var_name} must decode to {_KEY_LENGTH} bytes, got {len(key)}")
    return key
