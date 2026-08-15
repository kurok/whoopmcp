"""Envelope encryption for records at rest (#30).

Wraps AES-256-GCM with an envelope carrying key version, nonce, ciphertext --
key rotation is per-record lazy, not a big-bang re-encrypt. Generic
primitive, not auth-specific.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

#: AES-256-GCM key size (bytes).
_KEY_LENGTH = 32
#: GCM nonce size; fresh via os.urandom per seal call, never reused per key.
_NONCE_LENGTH = 12


class SealError(RuntimeError):
    """A seal/unseal operation failed.

    Wraps `KeyError` (unknown key version) and `InvalidTag` (tampered
    ciphertext/nonce, or wrong-key auth) so both fail closed alike. Never
    includes plaintext, ciphertext, or key material in its message.
    """


#: AD layouts, newest first. Format 1 (no separator) is ambiguous and could
#: silently void the version binding (#138); format 2 delimits with "|" safely.
_AD_FORMAT_DELIMITED = 2
_AD_FORMAT_LEGACY_CONCATENATED = 1
_AD_FORMAT_CURRENT = _AD_FORMAT_DELIMITED


def _associated_data(version: int, extra: bytes, *, ad_format: int = _AD_FORMAT_CURRENT) -> bytes:
    """Bind the envelope's key version into the AEAD tag.

    Prevents relabeling a v1 envelope's "v" field as v2 to authenticate
    against the wrong key -- a relabeled envelope fails auth instead.
    ``ad_format`` picks the layout; old envelopes keep their original
    format so rotating it doesn't break already-sealed records.
    """
    # int() (not just type hint) keeps seal/unseal symmetric and guarantees
    # the decimal form can't contain "|", which the delimiter relies on.
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

    Returns ``{"v", "adv", "nonce", "ct"}`` (b64); ``ct`` already carries
    AESGCM's own auth tag. Missing ``adv`` (pre-#138) means the legacy AD layout.
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
        # AD layout the tag used; absent means legacy format 1 (pre-#138).
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
    """Decrypt ``envelope`` using its own declared key version.

    Raises `SealError` (never `KeyError`/`InvalidTag`) on unknown key version,
    tampered ciphertext/nonce, or version mismatch -- never returns partial
    or garbage bytes on failure.
    """
    try:
        version = int(envelope["v"])
        # Missing "adv" predates #138 -> legacy layout.
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

    Shared by `Config.from_env` for every `WHOOPMCP_TOKEN_ENCRYPTION_KEY_V<N>`
    var, keeping base64/length validation in one place.
    """
    try:
        key = base64.b64decode(raw, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{var_name} must be base64-encoded: {exc}") from exc
    if len(key) != _KEY_LENGTH:
        raise ValueError(f"{var_name} must decode to {_KEY_LENGTH} bytes, got {len(key)}")
    return key
