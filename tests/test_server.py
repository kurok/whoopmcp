"""Checks on the MCP surface itself: what tools exist and how they are declared.

These matter more than they look. The tool list and its annotations are the
contract an MCP client sees, and a tool that quietly loses `readOnlyHint` is
a tool a client may stop asking permission for.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError

from whoopmcp.auth import TOKEN_URL, Authenticator, FileTokenStore, Token
from whoopmcp.client import WhoopClient
from whoopmcp.config import Config
from whoopmcp.server import AppContext, build_server

#: Every tool the server promises. Adding one here without registering it, or
#: registering one without listing it here, fails the suite.
EXPECTED_TOOLS = {
    "whoop_auth_status",
    "whoop_login",
    "whoop_complete_login",
    "whoop_logout",
    "get_profile",
    "get_body_measurement",
    "list_recoveries",
    "list_sleeps",
    "list_cycles",
    "list_workouts",
    "get_sleep",
    "get_workout",
    "summarize_period",
    "metric_trend",
    "correlate_metrics",
    "compare_periods",
}

#: The only tools allowed to change anything. Everything else is a read.
MUTATING_TOOLS = {"whoop_complete_login", "whoop_logout"}


@pytest.fixture
async def tools() -> dict[str, object]:
    listed = await build_server().list_tools()
    return {tool.name: tool for tool in listed}


# -- fixtures for auth tool testing ----------------------------------------


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config.from_env(
        {
            "WHOOP_CLIENT_ID": "cid",
            "WHOOP_CLIENT_SECRET": "csecret",
            "WHOOP_REDIRECT_URI": "whoopmcp://callback",  # exercise the custom-scheme path
            "WHOOPMCP_STATE_DIR": str(tmp_path),
        }
    )


@pytest.fixture
def app_context(config: Config) -> AppContext:
    auth = Authenticator(config)
    client = WhoopClient(
        config, auth
    )  # not entered as a context manager -- these tools never touch it
    return AppContext(config=config, auth=auth, client=client)


@pytest.fixture
def server() -> object:
    return build_server()


# -- helper for calling tools with lifespan context -------------------------


async def call_tool(server: object, name: str, arguments: dict, app_context: AppContext):
    """Call a registered tool with a given lifespan context.

    Bypasses the need for a live client/session.
    """
    request_context = ServerRequestContext(
        session=None,  # type: ignore[arg-type]  -- not exercised by these tools
        lifespan_context=app_context,
        protocol_version="2025-06-18",
        method="tools/call",
    )
    context = Context(request_context=request_context, mcp_server=server)  # type: ignore[arg-type]
    return await server.call_tool(name, arguments, context=context)  # type: ignore[union-attr]


async def test_registers_exactly_the_expected_tools(tools: dict[str, object]) -> None:
    assert set(tools) == EXPECTED_TOOLS


async def test_data_tools_are_annotated_read_only(tools: dict[str, object]) -> None:
    not_read_only = {
        name
        for name, tool in tools.items()
        if name not in MUTATING_TOOLS and not getattr(tool.annotations, "read_only_hint", False)  # type: ignore[attr-defined]
    }

    assert not_read_only == set()


async def test_only_logout_is_destructive(tools: dict[str, object]) -> None:
    destructive = {
        name
        for name, tool in tools.items()
        if getattr(tool.annotations, "destructive_hint", False)  # type: ignore[attr-defined]
    }

    assert destructive == {"whoop_logout"}


async def test_every_tool_has_a_description(tools: dict[str, object]) -> None:
    # The description is what the model reads to choose a tool; an empty one
    # makes the tool effectively invisible.
    undescribed = {
        name
        for name, tool in tools.items()
        if not (getattr(tool, "description", "") or "").strip()  # type: ignore[attr-defined]
    }

    assert undescribed == set()


async def test_server_carries_usage_instructions() -> None:
    instructions = build_server().instructions or ""

    assert "cycle" in instructions.lower()
    assert "not clinical" in instructions.lower()


# -- auth tool tests (issue #4) -----------------------------------------------


async def test_whoop_auth_status_never_logged_in(server: object, app_context: AppContext) -> None:
    """Test whoop_auth_status when no token has ever been saved."""
    result = await call_tool(server, "whoop_auth_status", {}, app_context)

    assert not result.is_error, f"Expected success, got error: {result.content}"
    # For a dict return, check structured_content; fallback to parsing content text
    if result.structured_content is not None:
        status_dict = result.structured_content
    else:
        # Fallback: if content is a list of TextBlocks, parse the first one
        import json

        status_dict = json.loads(result.content[0].text)

    # Must clearly distinguish this state from "token expired" or "token valid".
    assert status_dict == {"logged_in": False}, status_dict


async def test_whoop_auth_status_token_expired(
    server: object, config: Config, app_context: AppContext
) -> None:
    """Test whoop_auth_status when a token has expired but a refresh_token exists."""
    # Pre-save an expired token with a refresh token
    expired_token = Token(
        "fake-expired-access",
        expires_at=time.time() - 1000,  # well in the past
        refresh_token="fake-refresh",
        scopes=("read:sleep", "offline"),
    )
    FileTokenStore(config.token_path).save(expired_token)

    result = await call_tool(server, "whoop_auth_status", {}, app_context)

    assert not result.is_error, f"Expected success, got error: {result.content}"
    if result.structured_content is not None:
        status_dict = result.structured_content
    else:
        import json

        status_dict = json.loads(result.content[0].text)

    # Must distinguish "expired" from both "never logged in" and "valid" --
    # logged_in True (there IS a token) but expired True (it can't be used
    # as-is), with the granted scopes still visible.
    assert status_dict["logged_in"] is True, status_dict
    assert status_dict["expired"] is True, status_dict
    assert set(status_dict["scopes"]) == {"read:sleep", "offline"}
    # And never the never-logged-in shape.
    assert status_dict != {"logged_in": False}


async def test_whoop_auth_status_valid_token_with_scopes(
    server: object, config: Config, app_context: AppContext
) -> None:
    """Test whoop_auth_status with a valid, non-expired token and scopes."""
    # Pre-save a non-expired token with specific scopes
    valid_token = Token(
        "fake-access-token",
        expires_at=time.time() + 3600,  # expires in 1 hour
        refresh_token="fake-refresh-token",
        scopes=("read:sleep", "offline"),
    )
    FileTokenStore(config.token_path).save(valid_token)

    result = await call_tool(server, "whoop_auth_status", {}, app_context)

    assert not result.is_error, f"Expected success, got error: {result.content}"
    if result.structured_content is not None:
        status_dict = result.structured_content
    else:
        import json

        status_dict = json.loads(result.content[0].text)

    # Result should report the scopes and that it's not expired
    assert isinstance(status_dict, dict)
    # Convert the entire result to string and check that it does NOT contain
    # the literal token values
    result_str = str(status_dict)
    assert "fake-access-token" not in result_str, "Result must not expose the access token"
    assert "fake-refresh-token" not in result_str, "Result must not expose the refresh token"
    # The result should mention the scopes somewhere
    result_str_lower = result_str.lower()
    assert "read:sleep" in result_str_lower or "scopes" in result_str_lower


async def test_whoop_login(server: object, app_context: AppContext) -> None:
    """Test whoop_login returns a URL with the expected structure."""
    result = await call_tool(server, "whoop_login", {}, app_context)

    assert not result.is_error, f"Expected success, got error: {result.content}"
    # whoop_login returns a string
    url_text = result.content[0].text if result.content else str(result.structured_content or "")
    url_text = str(url_text)

    # Result should contain the authorize URL, hosted at the real WHOOP host --
    # parse it out and check the actual hostname rather than a raw substring
    # search over the whole message (CodeQL flags that as incomplete URL
    # sanitization: "https://evil.example/api.prod.whoop.com" would also
    # contain the substring without actually being the WHOOP host).
    # Anchored to the real host, not a bare "https://\S+" -- this message's
    # prose itself mentions "https://" in a parenthetical earlier on
    # ("...other than https://)..."), which a loose pattern would match first.
    url_match = re.search(r"https://api\.prod\.whoop\.com\S+", url_text)
    assert url_match, f"Expected an authorization URL in the response, got: {url_text}"
    assert urlparse(url_match.group(0)).hostname == "api.prod.whoop.com", (
        f"Expected the authorization URL's host to be api.prod.whoop.com, got: {url_text}"
    )
    # Result should mention the custom-scheme redirect (whoopmcp://)
    # and indicate that an error page is expected
    assert "error" in url_text.lower() or "browser" in url_text.lower(), (
        f"Expected result to mention browser/error page for custom-scheme redirect, got: {url_text}"
    )


async def test_whoop_complete_login_happy_path(
    server: object, config: Config, app_context: AppContext
) -> None:
    """Test whoop_complete_login succeeds with valid code and state."""
    # Step 1: Call whoop_login to set up the pending state
    login_result = await call_tool(server, "whoop_login", {}, app_context)
    assert not login_result.is_error
    login_text = login_result.content[0].text if login_result.content else ""

    # Pull the URL out of the surrounding instructional prose -- whoop_login's
    # response is a message, not a bare URL, so extract the substring rather
    # than urlparse-ing the whole text (which only works by accident if the
    # URL happens to be the last thing in the string).
    url_match = re.search(r"https://api\.prod\.whoop\.com\S+", login_text)
    assert url_match, f"Expected an authorize URL in the response, got: {login_text}"
    query = parse_qs(urlparse(url_match.group(0)).query)
    assert "state" in query, f"Expected 'state' in URL, got: {login_text}"
    state = query["state"][0]

    # Step 2: Mock TOKEN_URL to return a successful token response
    with respx.mock:
        respx.post(TOKEN_URL).mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "access_token": "fake-access-token",
                    "expires_in": 3600,
                    "refresh_token": "fake-refresh-token",
                    "scope": "read:sleep offline",
                },
            )
        )

        # Step 3: Call whoop_complete_login with the code and state
        complete_result = await call_tool(
            server,
            "whoop_complete_login",
            {"code": "fake-auth-code", "state": state},
            app_context,
        )

    # The tool should succeed (not error)
    assert not complete_result.is_error, f"Expected success, got error: {complete_result.content}"

    # Extract the result text
    if complete_result.structured_content is not None:
        result_dict = complete_result.structured_content
        result_str = str(result_dict)
    else:
        result_str = complete_result.content[0].text if complete_result.content else ""

    result_str = str(result_str)

    # Result should NOT contain the literal token values
    assert "fake-access-token" not in result_str, "Result must not expose the access token"
    assert "fake-refresh-token" not in result_str, "Result must not expose the refresh token"

    # Result should report the granted scopes
    assert "read:sleep" in result_str.lower() or "scopes" in result_str.lower(), (
        f"Expected result to mention granted scopes, got: {result_str}"
    )


async def test_whoop_complete_login_state_mismatch(
    server: object, config: Config, app_context: AppContext
) -> None:
    """Test whoop_complete_login fails when state doesn't match.

    MCPServer.call_tool() (Tool.run(), specifically) catches any exception
    raised by a tool body and re-raises it wrapped as ToolError -- it does
    NOT surface as a CallToolResult with is_error=True. That conversion
    happens one layer up, in the protocol-level request handler, which this
    test harness bypasses entirely. So the mismatch (Authenticator.verify_state
    raising AuthError) must be asserted as a raised ToolError here.
    """
    # Step 1: Call whoop_login to set up a pending state
    login_result = await call_tool(server, "whoop_login", {}, app_context)
    assert not login_result.is_error

    # Step 2: Call whoop_complete_login with a WRONG state
    # This should fail because the state won't match the one set by start_login
    with pytest.raises(ToolError, match="state mismatch"):
        await call_tool(
            server,
            "whoop_complete_login",
            {"code": "fake-auth-code", "state": "attacker-supplied-wrong-state"},
            app_context,
        )


async def test_whoop_logout(server: object, config: Config, app_context: AppContext) -> None:
    """Test whoop_logout clears the token and reports success."""
    # Step 1: Pre-save a token
    token = Token(
        "fake-access-token",
        expires_at=time.time() + 3600,
        refresh_token="fake-refresh-token",
        scopes=("read:sleep", "offline"),
    )
    FileTokenStore(config.token_path).save(token)

    # Verify the token is there
    assert FileTokenStore(config.token_path).load() is not None

    # Step 2: Call whoop_logout
    result = await call_tool(server, "whoop_logout", {}, app_context)

    # The tool should succeed
    assert not result.is_error, f"Expected success, got error: {result.content}"

    # Step 3: Verify the token is now gone
    assert FileTokenStore(config.token_path).load() is None, "Token should be cleared after logout"

    # Step 4: Check response mentions "whoop" and grant NOT being revoked
    logout_text = result.content[0].text if result.content else str(result.structured_content or "")
    logout_text = str(logout_text)
    assert "whoop" in logout_text.lower(), (
        f"Expected response to mention 'whoop', got: {logout_text}"
    )
    # Response should indicate grant is NOT revoked on WHOOP's servers.
    # Common patterns: "revoke", "still", "server", etc.
    assert (
        "revoke" in logout_text.lower()
        or "still" in logout_text.lower()
        or "server" in logout_text.lower()
    ), f"Expected response to indicate grant is NOT revoked server-side, got: {logout_text}"
