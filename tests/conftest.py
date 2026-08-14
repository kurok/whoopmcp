"""Repo-wide test fixtures.

One job today: keep every test off the developer's real OS keychain (#198).
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _no_real_os_keychain(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Forbid the real ``keyring`` backend for every test, unconditionally.

    ``keyring`` is an optional extra, so CI never has it installed and the
    suite historically leaned on that absence. On a developer machine with
    ``whoopmcp[keyring]`` installed, though, any test that reaches
    ``KeyringTokenStore``'s real code path talks to the actual OS keychain
    (macOS Keychain, Windows Credential Manager, SecretService) under the
    fixed ``whoopmcp``/``default`` entry -- reading, or worse writing over,
    a real credential if the developer uses that backend themselves (#198).

    Tests that want keyring behaviour already have sanctioned fakes:
    ``tests/test_auth.py``'s ``_FakeKeyring`` (attribute injection, no real
    import) and ``tests/test_data_subject_rights.py``'s
    ``_make_keyring_unavailable`` (a ``sys.modules`` stub that makes the
    import itself fail). This guard exists for the test that forgets: it
    replaces the three module-level functions ``KeyringTokenStore`` calls
    with an immediate, named failure, so an accidental escape to the real
    backend fails the test instead of touching the keychain. A no-op when
    the extra is not installed, which is why CI is unaffected.
    """
    try:
        import keyring
    except ImportError:
        yield
        return

    def _forbid(*_args: object, **_kwargs: object) -> None:
        raise AssertionError(
            "a test reached the real OS keychain; stub keyring instead -- see "
            "tests/conftest.py::_no_real_os_keychain"
        )

    monkeypatch.setattr(keyring, "get_password", _forbid)
    monkeypatch.setattr(keyring, "set_password", _forbid)
    monkeypatch.setattr(keyring, "delete_password", _forbid)
    yield
