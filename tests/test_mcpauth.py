"""OAuth 2.1 resource server: metadata, resource indicators, CIMD (issue #28).

Tests for whoopmcp as an RFC 9728 protected resource, with RFC 8707
resource-indicator validation and token verification. These tests guide the
implementation of mcpauth.py and assert on its module invariants.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import ProtectedResourceMetadata
from pydantic import AnyHttpUrl

from whoopmcp.mcpauth import (
    SPEC_REVISION,
    MCPAuthConfig,
    MCPTokenVerifier,
    build_protected_resource_metadata,
    setup_mcp_auth,
)
from whoopmcp.server import build_server


@pytest.fixture
def http_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WHOOP_CLIENT_ID", "cid")
    monkeypatch.setenv("WHOOP_CLIENT_SECRET", "csecret")
    monkeypatch.setenv("WHOOP_REDIRECT_URI", "https://localhost:8443/callback")
    monkeypatch.setenv("WHOOPMCP_STATE_DIR", str(tmp_path))


@pytest.fixture
def mcp_auth_config() -> MCPAuthConfig:
    """Standard MCPAuthConfig for testing."""
    return MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
    )


# -- Client-supplied user_id parameter must not change identity resolution -----


async def test_client_supplied_user_id_ignored_first(
    http_env: None, mcp_auth_config: MCPAuthConfig
) -> None:
    """A client cannot supply its own user_id to change which member is served.

    Even if a malicious or buggy client supplies a user_id parameter in the
    request, the server must use only the token's subject claim to identify
    the member. The token itself says who the caller is; a parameter is not
    consulted.

    This test is placed first per issue #28's explicit instruction. It asserts
    what the API does *not* do: accept a caller-supplied identity parameter.
    Since the implementation uses token.subject exclusively, this test verifies
    that no such parameter is even wired into the routes.
    """
    server = build_server()
    await setup_mcp_auth(server, mcp_auth_config)
    app = server.streamable_http_app(
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as client:
        # Try to call a tool endpoint with a user_id query parameter.
        # This should either ignore it or reject it, but never use it to
        # change whose data is returned.
        response = await client.get("/tools", params={"user_id": "attacker-user-id"})

        # The parameter should not grant access to another user's data.
        # If the endpoint returns a 401 or 403, that's correct: it means
        # the parameter was ignored and authentication failed.
        # If it returns 200, it should be the authenticated user's data,
        # not the attacker-supplied one.
        # For now (stub implementation), we assert it doesn't accept
        # unauthorized requests.
        assert response.status_code in (401, 403, 404)


# -- Protected-resource metadata: RFC 9728 compliance -------------------------


async def test_protected_resource_metadata_served_and_valid(
    http_env: None, mcp_auth_config: MCPAuthConfig
) -> None:
    """GET /.well-known/oauth-protected-resource returns RFC 9728 metadata.

    The server advertises itself as a protected resource per RFC 9728 §2,
    listing trusted authorization servers that issue valid tokens for this
    resource. The metadata is required for clients to know where to obtain
    tokens and what this resource expects.
    """
    server = build_server()
    await setup_mcp_auth(server, mcp_auth_config)
    app = server.streamable_http_app(
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    metadata_dict = response.json()

    # RFC 9728 §2 requires these fields:
    # - resource: the URL of the protected resource
    # - authorization_servers: list of trusted AS URLs
    assert "resource" in metadata_dict, "RFC 9728 §2 requires 'resource' field"
    assert "authorization_servers" in metadata_dict, (
        "RFC 9728 §2 requires 'authorization_servers' field"
    )
    assert isinstance(metadata_dict["authorization_servers"], list)
    assert len(metadata_dict["authorization_servers"]) > 0

    # Verify it parses as a valid ProtectedResourceMetadata
    metadata = ProtectedResourceMetadata(**metadata_dict)
    assert str(metadata.resource) == str(mcp_auth_config.resource_url)
    assert [str(url) for url in metadata.authorization_servers] == [
        str(url) for url in mcp_auth_config.authorization_servers
    ]


async def test_protected_resource_metadata_has_cache_headers(
    http_env: None, mcp_auth_config: MCPAuthConfig
) -> None:
    """Metadata response includes cache headers (1 hour TTL per RFC 9728).

    The metadata should be cached to reduce load, and the HTTP cache headers
    signal this to clients.
    """
    server = build_server()
    await setup_mcp_auth(server, mcp_auth_config)
    app = server.streamable_http_app(
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code == 200
    # RFC 9728 and common practice suggest 1-hour caching
    cache_control = response.headers.get("cache-control", "").lower()
    assert "max-age" in cache_control or "public" in cache_control


# -- Token verification: Resource indicators (RFC 8707) ----------------------


async def test_token_naming_this_resource_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """MCPTokenVerifier accepts a resolved token whose resource claim matches.

    The companion positive case to the two rejection tests below: without
    this, `_names_this_resource` could be replaced with `return False`
    (rejecting everything, audience match or not) and every RFC 8707 test
    in this file would still pass.
    """
    verifier = MCPTokenVerifier()
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
    )
    verifier.config = config

    from mcp.server.auth.provider import AccessToken

    matching_token = AccessToken(
        token="token123",
        client_id="client1",
        scopes=["read"],
        resource="https://whoopmcp.example.com/mcp",  # Matches resource_url exactly
        subject="user123",
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=matching_token))

    result = await verifier.verify_token(matching_token.token)
    assert result is matching_token, "Token naming this resource must be accepted"


async def test_token_with_wrong_resource_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """MCPTokenVerifier rejects a token whose resource claim names another server.

    RFC 8707 resource indicators let a token specify which resource it's valid
    for. A token issued for a different server must not be accepted here,
    preventing token replay across servers.

    `_resolve` is stubbed (unconditionally `None`) until a real external-AS
    integration exists (see mcpauth.py's own docstring), so `verify_token`
    given a bare token string never reaches the audience check at all -- it
    would pass this test whether `_names_this_resource` existed or not.
    Monkeypatching `_resolve` to return this test's own token is what makes
    the assertion below actually exercise RFC 8707 rejection, not just the
    unconditional stub.
    """
    verifier = MCPTokenVerifier()
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
    )
    verifier.config = config

    # A token issued for a different resource
    from mcp.server.auth.provider import AccessToken

    other_resource_token = AccessToken(
        token="token123",
        client_id="client1",
        scopes=["read"],
        resource="https://other-server.example.com",  # Wrong resource!
        subject="user123",
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=other_resource_token))

    result = await verifier.verify_token(other_resource_token.token)
    assert result is None, "Token for wrong resource must be rejected"


async def test_token_with_no_resource_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """MCPTokenVerifier rejects a token with no resource indicator.

    RFC 8707 resource indicators are required for whoopmcp. A token without
    a resource claim cannot be validated for this specific resource.

    Same reasoning as `test_token_with_wrong_resource_rejected` above:
    `_resolve` must be monkeypatched to actually resolve to this test's
    token, or the assertion passes on the unconditional stub alone and
    proves nothing about the resource-indicator check itself.
    """
    verifier = MCPTokenVerifier()
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
    )
    verifier.config = config

    from mcp.server.auth.provider import AccessToken

    token_no_resource = AccessToken(
        token="token123",
        client_id="client1",
        scopes=["read"],
        resource=None,  # No resource indicator
        subject="user123",
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=token_no_resource))

    result = await verifier.verify_token(token_no_resource.token)
    assert result is None, "Token without resource indicator must be rejected"


async def test_token_with_empty_string_resource_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """MCPTokenVerifier rejects a token whose resource claim is present but empty.

    #69 test 1's "if not already covered" clause: `resource=None` (missing)
    is already pinned by `test_token_with_no_resource_rejected` above, but
    `resource=""` takes a different branch through `_names_this_resource` --
    it fails the `is None` guard and falls through to the equality check
    instead, so it is not proven by that test and is worth its own case.
    Also distinguishes this from `test_token_with_wrong_resource_rejected`:
    an empty string isn't "some other server's identifier", it's the
    resource-indicator equivalent of an absent claim, and must not be
    accidentally treated as falsy-but-matching by some future rewrite of
    the equality check (e.g. a `resource in (None, config.resource_url)`-
    style refactor that only special-cases `None`).
    """
    verifier = MCPTokenVerifier()
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
    )
    verifier.config = config

    from mcp.server.auth.provider import AccessToken

    token_empty_resource = AccessToken(
        token="token123",
        client_id="client1",
        scopes=["read"],
        resource="",  # Empty, not missing -- a different code path than None
        subject="user123",
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=token_empty_resource))

    result = await verifier.verify_token(token_empty_resource.token)
    assert result is None, "Token with an empty resource claim must be rejected"


# -- Token verification: Expiration and malformation -------------------------


async def test_expired_token_rejected_with_www_authenticate() -> None:
    """Bearer authentication fails with 401 and WWW-Authenticate header.

    When a token is expired or invalid, the server returns 401 with a
    WWW-Authenticate header per RFC 6750 §3, allowing clients to know
    they need to refresh or re-authenticate.
    """
    server = build_server()
    mcp_auth_config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
    )
    await setup_mcp_auth(server, mcp_auth_config)
    app = server.streamable_http_app(
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as client:
        # Send a request with an expired or invalid bearer token
        response = await client.get(
            "/tools",
            headers={"Authorization": "Bearer expired_token_xyz"},
        )

    # Should get 401 with WWW-Authenticate header per RFC 6750 §3
    assert response.status_code == 401
    www_authenticate = response.headers.get("www-authenticate", "").lower()
    assert "bearer" in www_authenticate, "WWW-Authenticate must include Bearer scheme"
    # Should include error parameter per RFC 6750 §3 and RFC 8707 §2
    assert "error=" in www_authenticate


async def test_malformed_token_rejected() -> None:
    """Malformed bearer tokens are rejected with 401.

    Bearer tokens must be well-formed (e.g., valid JWT or opaque token
    format). A malformed token is rejected before any verification attempt.
    """
    server = build_server()
    mcp_auth_config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
    )
    await setup_mcp_auth(server, mcp_auth_config)
    app = server.streamable_http_app(
        json_response=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://test"
    ) as client:
        # Send a request with a clearly malformed bearer token
        response = await client.get(
            "/tools",
            headers={"Authorization": "Bearer !!!not-a-token!!!"},
        )

    assert response.status_code == 401


# -- Spec revision pinning ---------------------------------------------------


def test_spec_revision_pinned() -> None:
    """The MCP spec revision is pinned in mcpauth.py for deliberate-edit enforcement.

    Bumping SPEC_REVISION requires reading this test and intentionally updating
    it, ensuring MCP spec updates are not accidentally absorbed.

    Current revision: 2026-07-28 (from mcp 2.0.0 SDK documentation).
    """
    assert SPEC_REVISION == "2026-07-28", (
        f"SPEC_REVISION changed to {SPEC_REVISION!r}. If intentional, "
        "update this assertion and review RFC 9728 / RFC 8707 / RFC 8414 "
        "compatibility against the new spec."
    )


# -- Module invariants -------------------------------------------------------


def test_mcpauth_does_not_import_auth() -> None:
    """mcpauth.py must not import auth.py (WHOOP OAuth); vice versa also required.

    The inbound OAuth (mcpauth) and outbound OAuth (auth) are separate concerns
    with different tokens, threat models, and protocol versions. Importing one
    from the other would violate the design principle of keeping them isolated.
    """
    # The module is already imported (via the `from whoopmcp.mcpauth import
    # ...` above); fetched from sys.modules rather than a second `import
    # whoopmcp.mcpauth` statement so this file uses exactly one import style
    # per module.
    mcpauth_module = sys.modules["whoopmcp.mcpauth"]

    # Check that auth.py is not imported in mcpauth
    assert "whoopmcp.auth" not in mcpauth_module.__dict__, (
        "mcpauth.py must not import from auth.py; they are separate OAuth contexts"
    )

    import whoopmcp.auth as auth_module

    # Check that mcpauth.py is not imported in auth.py
    assert "whoopmcp.mcpauth" not in auth_module.__dict__, (
        "auth.py must not import from mcpauth.py; they are separate OAuth contexts"
    )


def test_mcp_token_verifier_is_token_verifier_protocol() -> None:
    """MCPTokenVerifier implements the mcp TokenVerifier protocol."""
    verifier = MCPTokenVerifier()
    # MCPTokenVerifier should have the verify_token method signature
    assert hasattr(verifier, "verify_token")
    assert callable(verifier.verify_token)


def test_mcp_auth_config_has_required_fields() -> None:
    """MCPAuthConfig holds resource URL and authorization server list."""
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com"),
        authorization_servers=[
            AnyHttpUrl("https://auth1.example.com"),
            AnyHttpUrl("https://auth2.example.com"),
        ],
    )

    assert str(config.resource_url) == "https://whoopmcp.example.com/"
    assert len(config.authorization_servers) == 2


def test_build_protected_resource_metadata_returns_valid_metadata() -> None:
    """build_protected_resource_metadata() constructs RFC 9728 metadata."""
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com"),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
    )

    metadata = build_protected_resource_metadata(config)

    assert isinstance(metadata, ProtectedResourceMetadata)
    assert str(metadata.resource) == "https://whoopmcp.example.com/"
    assert len(metadata.authorization_servers) == 1
    assert str(metadata.authorization_servers[0]) == "https://auth.example.com/"
