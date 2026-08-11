"""Envelope encryption for tokens at rest (issue #30).

whoopmcp.crypto does not exist yet -- these tests specify its contract
(AES-GCM via the stdlib-adjacent ``cryptography`` package, versioned keys,
no custom AEAD framing) ahead of the implementation, and are expected to
fail on collection/import until it lands.
"""

from __future__ import annotations

import base64
import contextlib
import os

import pytest

from whoopmcp.crypto import SealError, seal, unseal


def _key() -> bytes:
    return os.urandom(32)


# -- round trip --------------------------------------------------------------


def test_seal_unseal_roundtrips_plaintext() -> None:
    key = _key()
    plaintext = b"a-refresh-token-value"

    envelope = seal(plaintext, {1: key}, current_version=1)

    assert unseal(envelope, {1: key}) == plaintext


def test_sealed_envelope_carries_its_key_version() -> None:
    key = _key()

    envelope = seal(b"payload", {1: key}, current_version=1)

    assert envelope["v"] == 1


def test_seal_produces_a_fresh_nonce_each_call() -> None:
    # GCM's one hard requirement: never reuse a nonce under the same key.
    # Reusing plaintext and key across calls isolates that this is about the
    # nonce specifically, not some other field varying.
    key = _key()

    envelopes = [seal(b"same-plaintext", {1: key}, current_version=1) for _ in range(10)]

    nonces = {envelope["nonce"] for envelope in envelopes}
    assert len(nonces) == 10


# -- versioned keys / rotation ------------------------------------------------


def test_record_sealed_under_v1_still_readable_once_v2_is_current() -> None:
    key_v1 = _key()
    key_v2 = _key()
    plaintext = b"a-refresh-token-value"

    envelope = seal(plaintext, {1: key_v1}, current_version=1)

    # v2 becomes current elsewhere; unseal must still work against a record
    # sealed under v1 as long as v1's key is still supplied, with no forced
    # bulk re-encryption required for that to keep working.
    assert unseal(envelope, {1: key_v1, 2: key_v2}) == plaintext


def test_new_seals_use_whichever_version_is_passed_as_current() -> None:
    key_v1 = _key()
    key_v2 = _key()
    keys = {1: key_v1, 2: key_v2}

    envelope = seal(b"payload", keys, current_version=2)

    assert envelope["v"] == 2
    assert unseal(envelope, keys) == b"payload"


def test_unknown_key_version_raises_sealerror_not_keyerror() -> None:
    # A record sealed under a key version this process no longer has (e.g. a
    # retired key removed too early) must fail closed with the module's own
    # error type, not leak a raw KeyError up to the caller.
    envelope = {
        "v": 7,
        "nonce": base64.b64encode(b"n" * 12).decode("ascii"),
        "ct": base64.b64encode(b"c" * 32).decode("ascii"),
    }

    with pytest.raises(SealError):
        unseal(envelope, {1: _key()})


# -- tamper resistance --------------------------------------------------------


def test_tampered_ciphertext_raises_sealerror() -> None:
    key = _key()
    envelope = seal(b"a-refresh-token-value", {1: key}, current_version=1)

    tampered = dict(envelope)
    ct = bytearray(base64.b64decode(tampered["ct"]))
    ct[0] ^= 0xFF
    tampered["ct"] = base64.b64encode(bytes(ct)).decode("ascii")

    with pytest.raises(SealError):
        unseal(tampered, {1: key})


def test_tampered_nonce_raises_sealerror() -> None:
    key = _key()
    envelope = seal(b"a-refresh-token-value", {1: key}, current_version=1)

    tampered = dict(envelope)
    nonce = bytearray(base64.b64decode(tampered["nonce"]))
    nonce[0] ^= 0xFF
    tampered["nonce"] = base64.b64encode(bytes(nonce)).decode("ascii")

    with pytest.raises(SealError):
        unseal(tampered, {1: key})


def test_version_swapped_envelope_fails_authentication_rather_than_using_wrong_key() -> None:
    # If a tamperer relabels a v1 envelope's "v" field as 2 to make unseal
    # pick a different key, that must fail closed rather than either
    # crashing on an unrelated error or, worse, silently "succeeding" by
    # authenticating against the wrong key's tag. This is only guaranteed if
    # the key version is bound into the AEAD's own associated data, not just
    # used to pick which key to try.
    key_v1 = _key()
    key_v2 = _key()
    envelope = seal(b"a-refresh-token-value", {1: key_v1}, current_version=1)

    swapped = dict(envelope)
    swapped["v"] = 2

    with pytest.raises(SealError):
        unseal(swapped, {1: key_v1, 2: key_v2})


def test_tampered_ciphertext_never_decrypts_to_garbage_bytes() -> None:
    # Belt-and-suspenders on the "fails authentication rather than decrypting
    # to garbage" requirement: unseal must raise, not return anything at all,
    # for a tampered envelope.
    key = _key()
    envelope = seal(b"a-refresh-token-value", {1: key}, current_version=1)

    tampered = dict(envelope)
    ct = bytearray(base64.b64decode(tampered["ct"]))
    ct[-1] ^= 0xFF
    tampered["ct"] = base64.b64encode(bytes(ct)).decode("ascii")

    result = None
    with contextlib.suppress(SealError):
        result = unseal(tampered, {1: key})

    assert result is None


# -- no leakage on failure ----------------------------------------------------


def test_sealerror_never_includes_the_plaintext_or_the_key() -> None:
    key = _key()
    secret_plaintext = b"super-secret-refresh-token-xyz123"
    envelope = seal(secret_plaintext, {1: key}, current_version=1)

    tampered = dict(envelope)
    ct_len = len(base64.b64decode(tampered["ct"]))
    tampered["ct"] = base64.b64encode(b"\x00" * ct_len).decode("ascii")

    with pytest.raises(SealError) as exc_info:
        unseal(tampered, {1: key})

    message = str(exc_info.value)
    assert secret_plaintext.decode() not in message
    assert base64.b64encode(key).decode("ascii") not in message
    assert key.hex() not in message
