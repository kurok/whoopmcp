"""PRIVACY.md's local-mode promise, enforced as tests (issue #74).

PRIVACY.md §2 tells a local-mode user that "the only thing this software
persists is your token" and that `cache.sqlite3` is off unless
`WHOOPMCP_CACHE=true`. `lifespan()` opened `config.cache_path`
unconditionally, so a default local stdio session created that database,
wrote a `principal_members` row on login, and wrote a `tool_call_audit` row
on every data-tool call. PR #63 settled the direction for exactly this kind
of disagreement: the document is the contract and the code bends to it.

So these tests are written from the document, not from the implementation:

- the headline regression -- `$WHOOPMCP_STATE_DIR/cache.sqlite3` must not
  exist after a *complete* default-local session (principal resolved, login
  completed, data tool called);
- a structural guard on the connection itself (`PRAGMA database_list`), so a
  future edit that reintroduces `open_store(config.cache_path)` fails here
  rather than silently re-breaking the promise;
- the restart case, which is the whole reason the in-memory store has to
  seed a `principal_members` row: `resolve_member_id` requires a real row
  and has no fallback to `AppContext.principal`, so an unseeded ephemeral
  store would make every data tool raise `UnresolvedPrincipalError` after a
  restart while the token on disk is still perfectly valid;
- and both of the paths that legitimately do persist -- `WHOOPMCP_CACHE=true`
  and hosted (`streamable-http`) mode -- pinned so the local fix cannot leak
  into them.

Every test here drives the real `lifespan()`. The `app_context` fixture in
test_server.py deliberately bypasses it (hand-built `AppContext` over
`open_store(":memory:")`), which is precisely the code path that cannot
observe this bug.
"""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from test_server import call_tool, profile_fixture, recovery_fixture
from whoopmcp.auth import TOKEN_URL, FileTokenStore, Token
from whoopmcp.client import BASE_URL
from whoopmcp.server import AppContext, Principal, build_server, lifespan
from whoopmcp.store import get_member_for_principal, upsert_recovery

#: `_principal_key(None)`'s sentinel: under stdio there is no request, so
#: every tool call resolves identity under this one fixed key. Spelled out
#: rather than imported so a rename of the private constant cannot silently
#: change what these tests assert about.
LOCAL_CLIENT_ID = "__local__"

#: The one file PRIVACY.md says a default local-mode session may leave behind.
TOKEN_FILE = "token.json"

#: Every `WHOOPMCP_*` variable `Config.from_env()` reads that could otherwise
#: leak in from the developer's own shell and quietly move a test off the
#: default-local path (a stray `WHOOPMCP_CACHE=true` would make the headline
#: test pass for the wrong reason). Cleared before each test; the ones a test
#: needs are then set explicitly.
_WHOOPMCP_VARS = (
    "WHOOPMCP_TOKEN_BACKEND",
    "WHOOPMCP_TOKEN_ENCRYPTION_KEY_VERSION",
    "WHOOPMCP_SCOPES",
    "WHOOPMCP_TRANSPORT",
    "WHOOPMCP_STATE_DIR",
    "WHOOPMCP_CACHE",
    "WHOOPMCP_TIMEOUT",
    "WHOOPMCP_RATE_LIMIT_PER_MINUTE",
    "WHOOPMCP_RATE_LIMIT_PER_DAY",
    "WHOOPMCP_HTTP_HOST",
    "WHOOPMCP_HTTP_PORT",
    "WHOOPMCP_WEBHOOKS_ENABLED",
    "WHOOPMCP_WEBHOOK_TIMESTAMP_SKEW_SECONDS",
    "WHOOPMCP_METRICS_TOKEN",
    "WHOOPMCP_METRICS_SALT",
    "WHOOPMCP_BACKFILL_FLOOR_DATE",
)

#: A range wide enough to contain `recovery_fixture()`'s own `created_at`
#: regardless of the day the suite runs: `list_recoveries` otherwise defaults
#: to the last 7 days, which the fixture's fixed date drifts out of.
RANGE = {"start": "2026-01-01T00:00:00Z", "end": "2027-01-01T00:00:00Z"}


@pytest.fixture
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A pristine `$WHOOPMCP_STATE_DIR` on the real environment.

    `lifespan()` calls `Config.from_env()` with no argument, so it reads
    `os.environ` itself -- an explicitly-built `Config` (as test_server.py's
    `config` fixture makes) cannot be handed to it. These tests therefore
    have to set the real environment, and clear the rest of it first.
    """
    for name in _WHOOPMCP_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://localhost:8443/callback")
    monkeypatch.setenv("WHOOPMCP_STATE_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def logged_in(state_dir: Path) -> Path:
    """A valid token already on disk, as a restarted process would find.

    This is the state that makes the D2 seeding requirement real: the token
    is usable, so `_resolve_principal`'s profile call succeeds and
    `AppContext.principal` is populated, but no login has run *in this
    process* to write a `principal_members` row.
    """
    FileTokenStore(state_dir / TOKEN_FILE).save(
        Token("fake-access-token", expires_at=time.time() + 3600, refresh_token="fake-refresh")
    )
    return state_dir


def mock_profile() -> None:
    """Mock the one live call `lifespan()` makes: `GET /v2/user/profile/basic`."""
    respx.get(f"{BASE_URL}/v2/user/profile/basic").mock(
        return_value=httpx.Response(200, json=profile_fixture())
    )


def mock_token_exchange() -> None:
    """Mock the code-for-token exchange `whoop_complete_login` performs."""
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "fake-access-token",
                "expires_in": 3600,
                "refresh_token": "fake-refresh-token",
                "scope": "read:sleep read:recovery offline",
            },
        )
    )


def cache_file(state_dir: Path) -> Path:
    return state_dir / "cache.sqlite3"


def database_files(conn: sqlite3.Connection) -> list[str]:
    """The filename backing each attached database, per `PRAGMA database_list`.

    An in-memory database reports the empty string; a file-backed one reports
    its absolute path. This is the structural check the guard test rests on:
    it interrogates the connection itself, so it cannot be satisfied by a
    file merely being absent at the moment the test looks.
    """
    return [str(row[2]) for row in conn.execute("PRAGMA database_list").fetchall()]


async def complete_login(server: Any, app: AppContext) -> str:
    """Run the real two-step login against `app`, returning the final message.

    `whoop_login` stashes the pending `state` on `app.auth`, which
    `whoop_complete_login` then verifies, so the two calls have to share one
    AppContext -- the one `lifespan()` yielded.
    """
    login_result = await call_tool(server, "whoop_login", {}, app)
    login_text = str(login_result["result"])
    url_match = re.search(r"https://api\.prod\.whoop\.com\S+", login_text)
    assert url_match, f"Expected an authorize URL in the response, got: {login_text}"
    state = parse_qs(urlparse(url_match.group(0)).query)["state"][0]

    complete_result = await call_tool(
        server,
        "whoop_complete_login",
        {"code": "fake-auth-code", "state": state},
        app,
    )
    return str(complete_result["result"])


def linked_member(path: Path) -> int | None:
    """The member the *on-disk* store links the local sentinel to, if any.

    Opened read-only through a fresh `sqlite3` connection rather than
    `open_store`, so this observes the file exactly as it was left on disk
    and cannot itself create or migrate it.
    """
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return get_member_for_principal(conn, client_id=LOCAL_CLIENT_ID, issuer=None, subject=None)
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def _no_real_whoop_calls() -> Iterator[None]:
    """Every test here is mocked; an unmocked call must fail, not go out."""
    with respx.mock:
        yield


# -- the headline regression ------------------------------------------------


async def test_default_local_mode_leaves_nothing_but_the_token_on_disk(logged_in: Path) -> None:
    """The regression #74 exists for: a full default-local session, no store file.

    "Full" is the point. Each of the three writes the issue names happens at
    a different moment -- the database is *created* when `lifespan()` opens
    the store, the `principal_members` row is written by
    `whoop_complete_login`, and a `tool_call_audit` row is written by
    `resolve_member_id` on every data-tool call -- so a session that only
    started up would miss two of them. This drives all three and then
    asserts that `$WHOOPMCP_STATE_DIR` holds the token and nothing else.
    """
    mock_profile()
    mock_token_exchange()
    server = build_server()

    async with lifespan(server) as app:
        assert app.principal == Principal(user_id=profile_fixture()["user_id"])
        await complete_login(server, app)
        result = await call_tool(server, "list_recoveries", dict(RANGE), app)
        # The data tool really ran (and so really audited the call) rather
        # than failing in a way a bare "no exception" assertion would miss.
        assert result["count"] == 0

    assert not cache_file(logged_in).exists(), (
        "PRIVACY.md promises a default local-mode session persists nothing but the token, "
        f"but {cache_file(logged_in)} exists"
    )
    # Not just the database: sqlite's transient -journal sidecar must not be
    # left behind either, and nothing else may appear in the state dir.
    assert sorted(p.name for p in logged_in.iterdir()) == [TOKEN_FILE]


async def test_default_local_mode_store_is_not_backed_by_a_file(logged_in: Path) -> None:
    """Structural guard: `AppContext.store_conn` must be an in-memory database.

    The test above can be satisfied by accident -- delete the file on
    shutdown, never open it in the first place, or open it somewhere the test
    isn't looking -- and would then pass while the promise was broken again.
    This one asks the live connection what backs it, so any future edit that
    reintroduces `open_store(config.cache_path)` in `lifespan()`'s default
    local branch fails right here.
    """
    mock_profile()

    async with lifespan(build_server()) as app:
        assert app.store_conn is not None, "default local mode still needs a working store"
        assert database_files(app.store_conn) == [""], (
            "default local mode's store must be in-memory (PRAGMA database_list reports an "
            f"empty filename), got {database_files(app.store_conn)}"
        )
    assert not cache_file(logged_in).exists()


# -- nothing may break while the writes go away ----------------------------


async def test_whoop_complete_login_still_reports_success_in_default_local_mode(
    logged_in: Path,
) -> None:
    """Login is unchanged from the user's side, store file or not."""
    mock_profile()
    mock_token_exchange()
    server = build_server()

    async with lifespan(server) as app:
        message = await complete_login(server, app)

    assert "Login complete" in message
    assert "read:recovery" in message
    assert "fake-access-token" not in message
    assert "fake-refresh-token" not in message
    assert not cache_file(logged_in).exists()


async def test_data_tool_resolves_the_member_after_a_restart_without_a_login(
    logged_in: Path,
) -> None:
    """The D2 guard: a valid token and *no login in this process* still serves data.

    This is the trap the fix has to avoid. `resolve_member_id` requires a
    real `principal_members` row and, by design (#29 depends on it), has no
    fallback to `AppContext.principal` -- so moving the store into memory
    without seeding that row from the already-resolved live grant would make
    every data tool raise `UnresolvedPrincipalError` on every restart, while
    `whoop_auth_status` cheerfully reported the user logged in. Nothing here
    calls `whoop_login`: the only thing linking the local sentinel to a
    member is startup itself.
    """
    mock_profile()
    server = build_server()

    async with lifespan(server) as app:
        assert app.store_conn is not None
        assert (
            get_member_for_principal(
                app.store_conn, client_id=LOCAL_CLIENT_ID, issuer=None, subject=None
            )
            == profile_fixture()["user_id"]
        ), (
            "startup must seed the principal->member link the ephemeral store cannot inherit "
            "from the previous process, or every data tool breaks after a restart"
        )

        # Real records, not just a successful empty read: this proves the
        # resolved member id is the one the stored rows are keyed on, so a
        # seed under the wrong member would fail here rather than pass
        # silently on an empty store.
        upsert_recovery(app.store_conn, profile_fixture()["user_id"], recovery_fixture())
        result = await call_tool(server, "list_recoveries", dict(RANGE), app)

    assert result["count"] == 1
    assert result["records"][0]["recovery_score"] == 65.0


# -- the paths that legitimately persist -----------------------------------


async def test_cache_opt_in_still_persists_the_store_and_the_principal_link(
    logged_in: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`WHOOPMCP_CACHE=true` keeps today's on-disk behaviour, link and all.

    The opt-in path is what PRIVACY.md says moves the store to disk, so it
    must not be collateral damage of fixing the default.
    """
    monkeypatch.setenv("WHOOPMCP_CACHE", "true")
    mock_profile()
    mock_token_exchange()
    server = build_server()

    async with lifespan(server) as app:
        assert app.store_conn is not None
        assert database_files(app.store_conn) == [str(cache_file(logged_in))]
        await complete_login(server, app)

    assert cache_file(logged_in).exists()
    assert linked_member(cache_file(logged_in)) == profile_fixture()["user_id"]


async def test_hosted_mode_still_opens_the_store_on_disk(
    logged_in: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hosted mode persists unconditionally; the local fix must not reach it.

    PRIVACY.md's hosted paragraph documents hosted mode as storing
    materially more, unconditionally -- and hosted mode holds several
    members' links, so an ephemeral store there would be a functional
    regression, not a privacy win. Note the predicate keys off
    `WHOOPMCP_TRANSPORT`, i.e. configuration, not which ASGI app happens to
    have been constructed.
    """
    monkeypatch.setenv("WHOOPMCP_TRANSPORT", "streamable-http")
    mock_profile()

    async with lifespan(build_server()) as app:
        assert app.store_conn is not None
        assert database_files(app.store_conn) == [str(cache_file(logged_in))]

    assert cache_file(logged_in).exists()


async def test_webhooks_enabled_still_opens_the_store_on_disk(
    logged_in: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Webhooks persist too: a consumer whose work vanishes on restart is pointless.

    The third leg of the D1 predicate. Kept separate from the transport case
    so a fix that gates on only two of the three conditions fails a test that
    names the missing one.
    """
    monkeypatch.setenv("WHOOPMCP_WEBHOOKS_ENABLED", "true")
    mock_profile()

    async with lifespan(build_server()) as app:
        assert app.store_conn is not None
        assert database_files(app.store_conn) == [str(cache_file(logged_in))]

    assert cache_file(logged_in).exists()


# -- the not-logged-in case -------------------------------------------------


async def test_no_token_seeds_no_link_and_still_writes_nothing(state_dir: Path) -> None:
    """With nobody logged in, startup seeds nothing and tools say so.

    The seed is a real row derived from a live grant, not a fallback: when
    `_resolve_principal` returns `None` there is no grant to derive one from,
    so `principal_members` must stay empty and a data tool must keep
    reporting "run whoop_login" rather than silently resolving to somebody.
    """
    # No token file at all -- FileTokenStore.load() returns None for that,
    # so _resolve_principal degrades to None without any HTTP call.
    async with lifespan(build_server()) as app:
        assert app.principal is None
        assert app.store_conn is not None
        assert (
            get_member_for_principal(
                app.store_conn, client_id=LOCAL_CLIENT_ID, issuer=None, subject=None
            )
            is None
        )
        assert database_files(app.store_conn) == [""]

    assert not cache_file(state_dir).exists()
    assert list(state_dir.iterdir()) == []
