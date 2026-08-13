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


#: Associated-data layouts this module understands, newest first.
#:
#: Format 1 concatenated the key version and the caller's ``associated_data``
#: with nothing between them, which is ambiguous: ``(version=1,
#: extra=b"2whoopmcp.token")`` and ``(version=12, extra=b"whoopmcp.token")``
#: both produce ``b"whoopmcp.seal.v12whoopmcp.token"``. With one caller and one
#: fixed ``extra`` that is unexploitable, but this module advertises itself as a
#: generic primitive, and a second caller whose ``extra`` collided across
#: versions would silently void the version binding this AD exists to provide
#: (#138).
#:
#: Format 2 puts a ``|`` after the version. That is sufficient rather than
#: merely better: a key version is an integer, so it can never contain ``|``,
#: and the first ``|`` therefore always terminates it no matter what the caller
#: passes as ``extra``.
_AD_FORMAT_DELIMITED = 2
_AD_FORMAT_LEGACY_CONCATENATED = 1
_AD_FORMAT_CURRENT = _AD_FORMAT_DELIMITED


def _associated_data(version: int, extra: bytes, *, ad_format: int = _AD_FORMAT_CURRENT) -> bytes:
    """Bind the envelope's own claimed key version into the AEAD tag.

    Without this, an attacker could relabel a v1 envelope's "v" field as 2
    and have `unseal` pick key v2 to authenticate a v1 ciphertext against --
    which either fails for an unrelated reason or, worse, could succeed if
    the wrong key happened to validate. Mixing the version into the
    associated data means the tag itself is only valid for the exact
    version it claims, so a relabeled envelope fails authentication rather
    than silently trying a different key.

    ``ad_format`` selects the layout, because changing it changes the AEAD tag:
    every envelope sealed under the old layout would stop authenticating, which
    for the `encrypted-file` backend means an operator's stored token becomes
    undecryptable and they have to log in again. That is too high a price for a
    hardening fix with no reachable exploit, so the layout is recorded per
    envelope instead and old records keep working. New seals always use the
    current format; see `_AD_FORMAT_DELIMITED`.

    A tampered format marker fails closed on its own, with no extra binding
    needed: the two layouts produce different bytes, so flipping an envelope's
    marker makes `unseal` compute an AD the tag was not made with, and
    authentication fails.
    """
    # `int()` here, not just the type hint: `seal` receives `current_version`
    # from a caller and `unseal` recomputes from `int(envelope["v"])`, so
    # normalising in one place is what keeps the two symmetric. It also makes the
    # delimiter argument above structurally true -- an int's decimal form cannot
    # contain `|` -- rather than contingent on callers honouring the annotation.
    normalised = int(version)
    if ad_format == _AD_FORMAT_LEGACY_CONCATENATED:
        return f"whoopmcp.seal.v{normalised}".encode() + extra
    if ad_format != _AD_FORMAT_DELIMITED:
        raise SealError(f"unsupported associated-data format {ad_format}")
    return f"whoopmcp.seal.v{normalised}|".encode() + extra


def seal(
    plaintext: bytes,
    keys: Mapping[int, bytes],
    current_version: int,
    *,
    associated_data: bytes = b"",
) -> dict[str, Any]:
    """Encrypt ``plaintext`` under ``keys[current_version]``.

    Returns a JSON-serialisable envelope: ``{"v": <key version>, "adv":
    <associated-data format>, "nonce": <b64>, "ct": <b64>}``. ``ct`` is
    AESGCM's own output, which already carries its 16-byte authentication tag
    -- no separate tag field, no custom framing.

    ``adv`` arrived with #138; an envelope without it predates that and is read
    with the legacy associated-data layout. Readers must therefore treat the
    field set as open rather than exact -- which nothing in this repository
    relied on, checked before making the change.
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
        # Which associated-data layout the tag was computed over. Absent means
        # format 1, the pre-#138 concatenation -- that is what makes envelopes
        # written before this field existed still readable.
        "adv": _AD_FORMAT_CURRENT,
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
        # No "adv" means an envelope written before #138 added the field, which
        # by definition used the legacy layout.
        ad_format = int(envelope.get("adv", _AD_FORMAT_LEGACY_CONCATENATED))
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ct"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SealError("malformed envelope") from exc

    try:
        key = keys[version]
    except KeyError as exc:
        raise SealError(f"no key available for version {version}") from exc

    try:
        return AESGCM(key).decrypt(
            nonce, ciphertext, _associated_data(version, associated_data, ad_format=ad_format)
        )
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
