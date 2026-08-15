"""Repo-wide test fixtures."""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _no_real_os_keychain(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Forbid the real ``keyring`` backend for every test, unconditionally."""
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
