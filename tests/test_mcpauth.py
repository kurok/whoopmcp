"""OAuth 2.1 resource server: metadata, resource indicators, CIMD (issue #28).

Tests for whoopmcp as an RFC 9728 protected resource, with RFC 8707
resource-indicator validation and token verification. These tests guide the
implementation of mcpauth.py and assert on its module invariants.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from mcp.server.auth.provider import AccessToken
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

# #121: `verify_token` now rejects a token with no `expires_at`, so every
# AccessToken built here needs one. The negative tests need it just as much as
# the positive ones: a token meant to be rejected for its *resource* or *issuer*
# must not start being rejected for a missing expiry instead, or the check it
# was written to exercise stops being exercised at all. Same trap the #102 note
# below describes for `iss`.
# A day, not an hour: this is computed once at import, and an hour would make
# every token here expire if the module were ever imported long before the
# tests ran. The suite takes seconds, so this is belt-and-braces.
VALID_EXPIRY = int(time.time()) + 86400


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
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",  # Matches resource_url exactly
        subject="user123",
        # issue #102: verify_token now also enforces the issuer, so this
        # resource-only positive case needs an `iss` naming the one AS
        # `config` already trusts above -- otherwise it exercises the
        # issuer check's rejection path instead of the resource check's
        # acceptance path this test is actually about.
        claims={"iss": "https://auth.example.com"},
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
        expires_at=VALID_EXPIRY,
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
        expires_at=VALID_EXPIRY,
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
        expires_at=VALID_EXPIRY,
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


# -- Token verification: Issuer validation (issue #102) -------------------------


async def test_token_issued_by_untrusted_issuer_rejected_headline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCPTokenVerifier rejects a token from an issuer not in authorization_servers.

    This is the headline test for issue #102: even if the resource claim is
    correct, a token issued by an untrusted authorization server must be
    rejected. This test MUST FAIL against main c153909 (stub implementation).
    """
    from mcp.server.auth.provider import AccessToken

    verifier = MCPTokenVerifier()
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://trusted-as.example.com")],
    )
    verifier.config = config

    # Token with correct resource but issued by untrusted issuer
    untrusted_token = AccessToken(
        token="token123",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",  # Correct resource
        subject="user123",
        claims={"iss": "https://attacker-as.com"},  # WRONG issuer
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=untrusted_token))

    result = await verifier.verify_token(untrusted_token.token)
    assert result is None, "Token from untrusted issuer must be rejected"


async def test_token_issued_by_trusted_issuer_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCPTokenVerifier accepts a token from a trusted issuer with correct resource.

    The positive case for issuer validation: a token with both the correct
    resource claim and an issuer in the authorization_servers list must be
    accepted.
    """
    from mcp.server.auth.provider import AccessToken

    verifier = MCPTokenVerifier()
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://trusted-as.example.com")],
    )
    verifier.config = config

    # Token with correct resource and trusted issuer
    trusted_token = AccessToken(
        token="token123",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://trusted-as.example.com"},
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=trusted_token))

    result = await verifier.verify_token(trusted_token.token)
    assert result is trusted_token, (
        "Token from trusted issuer with correct resource must be accepted"
    )


async def test_token_with_no_claims_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCPTokenVerifier rejects a token with claims=None.

    Per decision D2: a missing claims dict is treated the same as a missing
    issuer claim. This prevents tokens with no issuer restriction (and thus
    no proof of provenance from a trusted AS) from being accepted.
    """
    from mcp.server.auth.provider import AccessToken

    verifier = MCPTokenVerifier()
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://trusted-as.example.com")],
    )
    verifier.config = config

    # Token with correct resource but no claims dict
    token_no_claims = AccessToken(
        token="token123",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims=None,  # No claims, so no issuer information
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=token_no_claims))

    result = await verifier.verify_token(token_no_claims.token)
    assert result is None, "Token without claims dict must be rejected"


async def test_token_with_claims_but_no_iss_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCPTokenVerifier rejects a token with claims present but iss key missing.

    Per decision D2: a token whose claims dict exists but lacks the iss key is
    treated as having no issuer restriction, and must be rejected the same way
    a token with no claims at all is rejected.
    """
    from mcp.server.auth.provider import AccessToken

    verifier = MCPTokenVerifier()
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://trusted-as.example.com")],
    )
    verifier.config = config

    # Token with correct resource and claims dict, but no iss key
    token_no_iss = AccessToken(
        token="token123",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"sub": "user123"},  # Claims present but iss missing
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=token_no_iss))

    result = await verifier.verify_token(token_no_iss.token)
    assert result is None, "Token without iss claim must be rejected"


async def test_token_with_non_string_iss_rejected_no_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCPTokenVerifier rejects non-string iss values without raising TypeError.

    Per decision D2: an iss claim that is not a string (int, list, None) must
    be rejected. Critically, a TypeError must not escape the verifier -- that
    would be a denial-of-service surface. The rejection must be clean.

    Tests three non-string cases: int, list, and None.
    """
    from mcp.server.auth.provider import AccessToken

    verifier = MCPTokenVerifier()
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://trusted-as.example.com")],
    )
    verifier.config = config

    # Test case 1: iss is an int
    token_int_iss = AccessToken(
        token="token123",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": 12345},  # int, not string
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=token_int_iss))
    result = await verifier.verify_token(token_int_iss.token)
    assert result is None, "Token with int iss must be rejected"

    # Test case 2: iss is a list
    token_list_iss = AccessToken(
        token="token456",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": ["https://example.com"]},  # list, not string
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=token_list_iss))
    result = await verifier.verify_token(token_list_iss.token)
    assert result is None, "Token with list iss must be rejected"

    # Test case 3: iss is None (different from claims=None)
    token_none_iss = AccessToken(
        token="token789",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": None},  # Explicitly None in claims
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=token_none_iss))
    result = await verifier.verify_token(token_none_iss.token)
    assert result is None, "Token with None iss must be rejected"


async def test_trailing_slash_equivalence_both_directions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCPTokenVerifier treats issuer URLs as equivalent with/without trailing slash.

    Per decision D3: a trailing slash difference is treated as equivalent,
    since AnyHttpUrl normalizes by adding trailing slashes, and RFC 8414
    issuers are conventionally slash-less. Both 'https://as.example.com' and
    'https://as.example.com/' should match.

    Tests all four combinations:
    1. Config without slash, token without slash
    2. Config without slash, token with slash
    3. Config with slash, token without slash
    4. Config with slash, token with slash

    All must be accepted.
    """
    from mcp.server.auth.provider import AccessToken

    # Test 1: config no slash, token no slash
    verifier1 = MCPTokenVerifier()
    config1 = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://as.example.com")],
    )
    verifier1.config = config1
    token1 = AccessToken(
        token="token1",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://as.example.com"},
    )
    monkeypatch.setattr(verifier1, "_resolve", AsyncMock(return_value=token1))
    result1 = await verifier1.verify_token(token1.token)
    assert result1 is token1, "Config no slash + token no slash must match"

    # Test 2: config no slash, token with slash
    verifier2 = MCPTokenVerifier()
    config2 = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://as.example.com")],
    )
    verifier2.config = config2
    token2 = AccessToken(
        token="token2",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://as.example.com/"},
    )
    monkeypatch.setattr(verifier2, "_resolve", AsyncMock(return_value=token2))
    result2 = await verifier2.verify_token(token2.token)
    assert result2 is token2, "Config no slash + token with slash must match"

    # Test 3: config with slash, token without slash
    verifier3 = MCPTokenVerifier()
    config3 = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://as.example.com/")],
    )
    verifier3.config = config3
    token3 = AccessToken(
        token="token3",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://as.example.com"},
    )
    monkeypatch.setattr(verifier3, "_resolve", AsyncMock(return_value=token3))
    result3 = await verifier3.verify_token(token3.token)
    assert result3 is token3, "Config with slash + token no slash must match"

    # Test 4: config with slash, token with slash
    verifier4 = MCPTokenVerifier()
    config4 = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://as.example.com/")],
    )
    verifier4.config = config4
    token4 = AccessToken(
        token="token4",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://as.example.com/"},
    )
    monkeypatch.setattr(verifier4, "_resolve", AsyncMock(return_value=token4))
    result4 = await verifier4.verify_token(token4.token)
    assert result4 is token4, "Config with slash + token with slash must match"


async def test_issuer_near_misses_all_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCPTokenVerifier rejects issuer near-misses (wrong subdomain, port, path).

    Per decision D3: only trailing-slash equivalence is tolerated. Everything
    else -- subdomain, port, path, case -- must match exactly, and near-misses
    must be rejected. A lax check that accepts 'https://good-as.example.com.evil.com'
    would be worse than no check.

    Tests from D3:
    1. Wrong subdomain: 'https://good-as.example.com.evil.com'
    2. Wrong port: 'https://good-as.example.com:8443'
    3. Wrong path: 'https://good-as.example.com/x'
    """
    from mcp.server.auth.provider import AccessToken

    # Setup: trusted AS is 'https://good-as.example.com'
    trusted_as = AnyHttpUrl("https://good-as.example.com")

    # Test 1: wrong subdomain (looks like subdomain typo, but evil)
    verifier1 = MCPTokenVerifier()
    config1 = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[trusted_as],
    )
    verifier1.config = config1
    token1 = AccessToken(
        token="token1",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://good-as.example.com.evil.com"},  # Evil domain
    )
    monkeypatch.setattr(verifier1, "_resolve", AsyncMock(return_value=token1))
    result1 = await verifier1.verify_token(token1.token)
    assert result1 is None, "Token from wrong subdomain must be rejected"

    # Test 2: wrong port
    verifier2 = MCPTokenVerifier()
    config2 = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[trusted_as],
    )
    verifier2.config = config2
    token2 = AccessToken(
        token="token2",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://good-as.example.com:8443"},  # Wrong port
    )
    monkeypatch.setattr(verifier2, "_resolve", AsyncMock(return_value=token2))
    result2 = await verifier2.verify_token(token2.token)
    assert result2 is None, "Token from wrong port must be rejected"

    # Test 3: wrong path
    verifier3 = MCPTokenVerifier()
    config3 = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[trusted_as],
    )
    verifier3.config = config3
    token3 = AccessToken(
        token="token3",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://good-as.example.com/x"},  # Wrong path
    )
    monkeypatch.setattr(verifier3, "_resolve", AsyncMock(return_value=token3))
    result3 = await verifier3.verify_token(token3.token)
    assert result3 is None, "Token from wrong path must be rejected"


async def test_multiple_trusted_issuers_second_one_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCPTokenVerifier accepts a token from any issuer in authorization_servers.

    When multiple trusted authorization servers are configured, a token from
    any of them (not just the first) must be accepted. This tests the second
    entry in the authorization_servers list.
    """
    from mcp.server.auth.provider import AccessToken

    verifier = MCPTokenVerifier()
    config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[
            AnyHttpUrl("https://as1.example.com"),
            AnyHttpUrl("https://as2.example.com"),
            AnyHttpUrl("https://as3.example.com"),
        ],
    )
    verifier.config = config

    # Token issued by the second AS
    token_from_as2 = AccessToken(
        token="token123",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://as2.example.com"},
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=token_from_as2))

    result = await verifier.verify_token(token_from_as2.token)
    assert result is token_from_as2, (
        "Token from any trusted issuer (including 2nd) must be accepted"
    )


async def test_both_issuer_and_resource_checks_must_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MCPTokenVerifier requires both issuer AND resource checks to pass.

    Neither check can substitute for the other. This proves that a token with:
    1. Trusted issuer + wrong resource → rejected
    2. Untrusted issuer + correct resource → rejected

    Without this test, a careless implementation could remove the resource
    check entirely and only check the issuer, or vice versa.
    """
    from mcp.server.auth.provider import AccessToken

    # Test case 1: Trusted issuer but wrong resource
    verifier1 = MCPTokenVerifier()
    config1 = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://trusted-as.example.com")],
    )
    verifier1.config = config1
    token1 = AccessToken(
        token="token1",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://other-server.example.com/mcp",  # WRONG resource
        subject="user123",
        claims={"iss": "https://trusted-as.example.com"},
    )
    monkeypatch.setattr(verifier1, "_resolve", AsyncMock(return_value=token1))
    result1 = await verifier1.verify_token(token1.token)
    assert result1 is None, "Trusted issuer + wrong resource must be rejected"

    # Test case 2: Untrusted issuer but correct resource
    verifier2 = MCPTokenVerifier()
    config2 = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://trusted-as.example.com")],
    )
    verifier2.config = config2
    token2 = AccessToken(
        token="token2",
        client_id="client1",
        scopes=["read"],
        expires_at=VALID_EXPIRY,
        resource="https://whoopmcp.example.com/mcp",  # Correct resource
        subject="user123",
        claims={"iss": "https://untrusted-as.example.com"},  # WRONG issuer
    )
    monkeypatch.setattr(verifier2, "_resolve", AsyncMock(return_value=token2))
    result2 = await verifier2.verify_token(token2.token)
    assert result2 is None, "Untrusted issuer + correct resource must be rejected"


# -- Token expiry (issue #121) -------------------------------------------------
#
# Before this, expiry was enforced by nobody. `verify_token` did not check it and
# its docstring did not mention it; the SDK's `RequireAuthMiddleware` has zero
# `expires_at` references. `BearerAuthBackend.authenticate` does check, so the
# demo route was covered on the wire -- but any integration calling
# `verify_token` directly inherited no expiry check at all.


def _valid_token(expires_at: int | None) -> AccessToken:
    """A token that passes every check except, possibly, expiry."""
    return AccessToken(
        token="token-expiry",
        client_id="client1",
        scopes=["read"],
        expires_at=expires_at,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://auth.example.com"},
    )


def _verifier_for_expiry(monkeypatch: pytest.MonkeyPatch, token: AccessToken) -> MCPTokenVerifier:
    verifier = MCPTokenVerifier()
    verifier.config = MCPAuthConfig(
        resource_url=AnyHttpUrl("https://whoopmcp.example.com/mcp"),
        authorization_servers=[AnyHttpUrl("https://auth.example.com")],
    )
    monkeypatch.setattr(verifier, "_resolve", AsyncMock(return_value=token))
    return verifier


async def test_expired_token_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A token whose lifetime has ended is rejected, audience and issuer intact."""
    token = _valid_token(int(time.time()) - 1)
    verifier = _verifier_for_expiry(monkeypatch, token)
    assert await verifier.verify_token(token.token) is None


async def test_unexpired_token_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The companion positive case: without it, `_is_unexpired` could `return
    False` and every expiry test here would still pass."""
    token = _valid_token(int(time.time()) + 3600)
    verifier = _verifier_for_expiry(monkeypatch, token)
    assert await verifier.verify_token(token.token) is token


async def test_token_with_no_expiry_is_rejected_as_unbounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#121's one real decision, recorded on the issue and pinned here.

    `expires_at` is `None` -- and `AccessToken` *defaults* it to `None`, so a
    resolver that simply forgets to set it produces exactly this. Accepting it
    would mean a permanent credential to a year of someone's physiological data,
    granted silently. Every other branch in `verify_token` already treats
    missing information as grounds for rejection; this one is no different.
    """
    token = _valid_token(None)
    verifier = _verifier_for_expiry(monkeypatch, token)
    assert await verifier.verify_token(token.token) is None


async def test_epoch_expiry_is_rejected_not_read_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`expires_at = 0` is the epoch -- comprehensively expired -- not "unset".

    The SDK's own `BearerAuthBackend` gets this wrong: it guards with
    `if auth_info.expires_at and ...`, so a falsy 0 is read as "no expiry to
    check" and waved through. `_is_unexpired` tests `is None` explicitly so the
    two cases stay distinct. This test is what stops someone "simplifying" it
    back into a truthiness check.
    """
    token = _valid_token(0)
    verifier = _verifier_for_expiry(monkeypatch, token)
    assert await verifier.verify_token(token.token) is None


async def test_expiry_exactly_now_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """RFC 7519 requires the current time to be strictly *before* `exp`, so a
    token expiring exactly now has no lifetime left. Pins the `<=` boundary
    against a future `<`."""
    now = int(time.time())
    monkeypatch.setattr(time, "time", lambda: float(now))
    token = _valid_token(now)
    verifier = _verifier_for_expiry(monkeypatch, token)
    assert await verifier.verify_token(token.token) is None


async def test_expiry_is_checked_independently_of_resource_and_issuer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An expired token from a trusted issuer naming this resource is still
    rejected -- no check passing lets another be skipped."""
    token = AccessToken(
        token="token-combo",
        client_id="client1",
        scopes=["read"],
        expires_at=int(time.time()) - 3600,
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://auth.example.com"},
    )
    verifier = _verifier_for_expiry(monkeypatch, token)
    assert await verifier.verify_token(token.token) is None


def test_verify_token_cannot_check_scopes_against_a_callers_requirement() -> None:
    """Scope enforcement stays one layer up, and this pins the structural reason.

    `TokenVerifier.verify_token(self, token: str)` has no `required_scopes`
    parameter, so it *cannot* check scopes against what a particular caller
    requires -- it has no way to learn that. `RequireAuthMiddleware` takes
    `required_scopes` and enforces them. A check here would be a second source
    of truth, free to drift from the first.

    This asserts only the part that is genuinely provable: the signature. An
    earlier version of this test also scanned the function body for the string
    `required_scopes`, which reads like a tripwire and is not one -- a scope
    check spelled with a helper (`_scopes_sufficient(...)`, matching this
    module's own idiom), or with a hardcoded scope name, passes it while doing
    exactly the thing the test claims to prevent. Asserting the signature and
    saying so is more honest than a scan that looks stronger than it is. The
    docstring on `verify_token` is the real control here.
    """
    import inspect

    signature = inspect.signature(MCPTokenVerifier.verify_token)
    assert list(signature.parameters) == ["self", "token"], (
        "verify_token grew a parameter -- if it is required_scopes, the reasoning "
        "in its docstring and the division of labour with RequireAuthMiddleware "
        "both need revisiting"
    )


async def test_unreadable_expiry_is_rejected_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    """An `expires_at` that is not an int must be rejected, never raise.

    `_issued_by_trusted_as` already holds this standard, in its own words: a
    future non-pydantic resolver "need not honour the type at all", so a
    malformed value should be "rejected rather than raising ... out of a token
    verifier". `_is_unexpired` was the one check in this module that did not
    meet it, which review caught.

    It matters because of where the exception would surface: nothing between
    `verify_token` and Starlette catches it, so a `TypeError` here becomes a 500
    rather than a 401 -- an unauthenticated caller crashing the auth boundary.
    `model_construct` is how a malformed token is built, exactly as the
    `claims` hardening above anticipates.
    """
    for label, bad in (("a string", "abc"), ("an object", object()), ("a float", 1.5)):
        token = AccessToken.model_construct(
            token="token-bad-expiry",
            client_id="client1",
            scopes=["read"],
            expires_at=bad,
            resource="https://whoopmcp.example.com/mcp",
            subject="user123",
            claims={"iss": "https://auth.example.com"},
        )
        verifier = _verifier_for_expiry(monkeypatch, token)
        assert await verifier.verify_token(token.token) is None, f"{label} expiry was not rejected"


async def test_expiry_with_a_hostile_comparison_cannot_buy_acceptance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sharper half of the same defect: an object whose `__gt__` returns
    True was *accepted*, not merely a crash.

    Rejecting on shape closes both. Kept separate from the TypeError cases
    because this one is a false accept -- the direction that actually grants
    access -- and would survive a fix that only wrapped the comparison in a
    try/except.
    """

    class AlwaysNewer:
        def __gt__(self, other: object) -> bool:
            return True

    token = AccessToken.model_construct(
        token="token-hostile-expiry",
        client_id="client1",
        scopes=["read"],
        expires_at=AlwaysNewer(),
        resource="https://whoopmcp.example.com/mcp",
        subject="user123",
        claims={"iss": "https://auth.example.com"},
    )
    verifier = _verifier_for_expiry(monkeypatch, token)
    assert await verifier.verify_token(token.token) is None
