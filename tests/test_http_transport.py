"""Streamable-HTTP transport tests (issue #27).

Covers what test_server.py's in-process `call_tool()` path cannot: the actual
ASGI app returned by `streamable_http_app()`, the `/health` and `/ready`
routes registered on it, and the registered tool set as seen over a real MCP
JSON-RPC exchange against that app rather than the in-process call path.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from mcp.server.transport_security import TransportSecuritySettings

from test_server import EXPECTED_TOOLS
from whoopmcp.server import build_server


@pytest.fixture
def http_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://localhost:8443/callback")
    monkeypatch.setenv("WHOOPMCP_STATE_DIR", str(tmp_path))


# -- /health and /ready -------------------------------------------------


async def test_health_returns_ok(http_env: None) -> None:
    app = build_server().streamable_http_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_ready_returns_ok_when_token_store_is_reachable(http_env: None) -> None:
    # No token has been saved -- FileTokenStore.load() cleanly returns None
    # for that case rather than raising, so this must still report ready.
    app = build_server().streamable_http_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {
        "ready": True,
        "checks": [{"name": "token_store_reachable", "ok": True, "detail": "ok"}],
    }


async def test_ready_returns_503_when_token_store_raises(http_env: None, tmp_path: Path) -> None:
    # A real, portable trigger: FileTokenStore.load() already has its own
    # test (test_auth.py::test_file_store_reports_a_corrupt_token_file)
    # proving a corrupt token file raises AuthError, cross-platform, no
    # permissions trickery needed. Reuse that same trigger here rather than
    # mocking build_store, so this test exercises the real store's real
    # failure mode, not a stand-in for it.
    (tmp_path / "token.json").write_text("{not json", encoding="utf-8")
    app = build_server().streamable_http_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False
    assert body["checks"] == [
        {
            "name": "token_store_reachable",
            "ok": False,
            # Just the exception's type, not its message: AuthError's own
            # text includes the token file's absolute path, which /ready
            # must not hand to an unauthenticated caller.
            "detail": "AuthError",
        }
    ]


async def test_liveness_and_readiness_are_computed_independently(
    http_env: None, tmp_path: Path
) -> None:
    """/health stays 200 while /ready reports 503 at the same time.

    Proves the two are genuinely separate checks, not one aliasing the
    other: liveness ("the process can respond") must hold even while
    readiness ("this dependency is reachable") does not.
    """
    (tmp_path / "token.json").write_text("{not json", encoding="utf-8")
    app = build_server().streamable_http_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        health_response = await client.get("/health")
        ready_response = await client.get("/ready")

    assert health_response.status_code == 200
    assert health_response.json() == {"status": "ok"}
    assert ready_response.status_code == 503
    assert ready_response.json()["ready"] is False


# -- the tool set over a real MCP session on the ASGI app -------------------


async def test_tool_set_matches_expected_over_the_streamable_http_asgi_app(
    http_env: None,
) -> None:
    """The same EXPECTED_TOOLS registry, reachable over real HTTP JSON-RPC.

    The installed mcp SDK does ship its own streamable-http client machinery
    (mcp.client.streamable_http.streamable_http_client + mcp.client.session),
    but its only entry point takes an ``httpx2.AsyncClient`` -- httpx2 is a
    separate PyPI package from httpx (confirmed: both live side by side under
    .venv/lib/*/site-packages/, with their own independent ASGITransport
    classes), present here only because ``mcp`` pulls it in transitively.
    Wiring the SDK's client into this in-process ASGI test would mean
    constructing an ``httpx2.AsyncClient(transport=httpx2.ASGITransport(...))``
    -- exactly the undeclared-dependency reliance this issue's design
    explicitly ruled out for ``starlette.testclient.TestClient``, for the
    same reason. So this drives the wire protocol directly over httpx (the
    project's own declared dependency): a real `initialize` handshake,
    `notifications/initialized`, then `tools/list` -- the same three calls
    any MCP client makes, just without the SDK's client-side plumbing on top.

    ``json_response=True`` sidesteps SSE-stream parsing, which nothing here
    needs to exercise. DNS-rebinding protection is disabled because it
    validates the request's Host header against real hostnames -- meaningless
    for an in-process ASGI transport that never opens a socket -- verified
    empirically: the default (host="127.0.0.1") rejects httpx's default
    "http://test" base_url with a 421.

    Starlette's own lifespan isn't driven by httpx.ASGITransport (it only
    ever sends "http" scope messages), so the session manager's task group
    would otherwise never start -- entering ``app.router.lifespan_context``
    directly (public Starlette API, not an mcp-internal one) is the
    dependency-free equivalent of what a real ASGI server does before routing
    any request to the app.
    """
    app = build_server().streamable_http_app(
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        init_response = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test-http-transport", "version": "0"},
                },
            },
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        assert init_response.status_code == 200, init_response.text
        session_id = init_response.headers["mcp-session-id"]

        initialized_response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Mcp-Session-Id": session_id,
            },
        )
        assert initialized_response.status_code == 202

        tools_response = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Mcp-Session-Id": session_id,
            },
        )

    assert tools_response.status_code == 200, tools_response.text
    tools = tools_response.json()["result"]["tools"]
    assert {tool["name"] for tool in tools} == EXPECTED_TOOLS
