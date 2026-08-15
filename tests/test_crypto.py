"""Envelope encryption for tokens at rest (issue #30)."""

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


# -- #138: the associated data must be unambiguous, without stranding envelopes
# already on disk ------------------------------------------------------------


def _legacy_envelope(key: bytes, plaintext: bytes, version: int, extra: bytes) -> dict:
    """An envelope exactly as the pre-#138 code produced: AD is the key version
    concatenated to `extra` with nothing between, and no `adv` field."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, f"whoopmcp.seal.v{version}".encode() + extra)
    return {
        "v": version,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }


def test_version_and_caller_associated_data_cannot_collide() -> None:
    """The ambiguity #138 is about, asserted on the AD bytes directly."""
    from whoopmcp.crypto import _associated_data

    assert _associated_data(1, b"2whoopmcp.token") != _associated_data(12, b"whoopmcp.token")

    # The general property, not just the one pair from the issue: over a grid of
    # versions and digit-leading extras, no two distinct inputs share an AD.
    seen: dict[bytes, tuple[int, bytes]] = {}
    for version in (1, 2, 12, 21, 112):
        for extra in (
            b"",
            b"1",
            b"2x",
            b"12x",
            b"whoopmcp.token",
            b"2whoopmcp.token",
            # Extras containing the delimiter itself, and one embedding a whole
            # fake prefix. Omitted from the first version of this grid, which
            # made it less adversarial than it looked: the delimiter argument is
            # precisely that the FIRST `|` terminates the version, so an extra
            # that also contains `|` is the case that has to be exercised.
            b"|",
            b"||",
            b"|whoopmcp.token",
            b"2|whoopmcp.token",
            b"whoopmcp.seal.v3|whoopmcp.token",
        ):
            ad = _associated_data(version, extra)
            assert ad not in seen, f"{(version, extra)} collides with {seen[ad]}"
            seen[ad] = (version, extra)


def test_envelopes_written_before_the_fix_still_decrypt() -> None:
    """The reason the layout is recorded per envelope instead of just changed."""
    key = _key()
    legacy = _legacy_envelope(key, b"still-readable", 1, b"whoopmcp.token")

    assert "adv" not in legacy
    assert unseal(legacy, {1: key}, associated_data=b"whoopmcp.token") == b"still-readable"


def test_new_envelopes_record_the_layout_they_used() -> None:
    """Without the stamp there is nothing for `unseal` to dispatch on, so a
    future third layout could not be introduced the same way."""
    key = _key()
    envelope = seal(b"payload", {1: key}, 1, associated_data=b"whoopmcp.token")

    assert envelope["adv"] == 2
    assert unseal(envelope, {1: key}, associated_data=b"whoopmcp.token") == b"payload"


def test_tampering_with_the_layout_marker_fails_closed() -> None:
    """The marker needs no separate binding into the tag, and this is why."""
    key = _key()
    current = seal(b"payload", {1: key}, 1, associated_data=b"whoopmcp.token")
    legacy = _legacy_envelope(key, b"payload", 1, b"whoopmcp.token")

    with pytest.raises(SealError):  # downgrade to the ambiguous layout
        unseal(dict(current, adv=1), {1: key}, associated_data=b"whoopmcp.token")

    with pytest.raises(SealError):  # upgrade a legacy envelope
        unseal(dict(legacy, adv=2), {1: key}, associated_data=b"whoopmcp.token")

    for unknown in (0, 3, 99, -1):
        with pytest.raises(SealError):
            unseal(dict(current, adv=unknown), {1: key}, associated_data=b"whoopmcp.token")


def test_a_legacy_envelope_cannot_be_replayed_as_another_callers_record() -> None:
    """The version binding still holds for legacy envelopes, so leaving them on"""
    key = _key()
    legacy = _legacy_envelope(key, b"caller-a-record", 1, b"whoopmcp.token")

    with pytest.raises(SealError):
        unseal(legacy, {1: key}, associated_data=b"whoopmcp.other-record-type")
