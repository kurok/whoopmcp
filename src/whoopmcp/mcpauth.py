"""OAuth 2.1 resource server: metadata, resource indicators (issue #28).

Inbound only -- separate from auth.py's outbound WHOOP grant (different protocol/token/threat
model); neither module imports the other. No parameter here lets a caller name a member (#29's
job); resource server ONLY, never an authorization server (see SPEC_REVISION for spec pinning).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.handlers.metadata import ProtectedResourceMetadataHandler
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.mcpserver import MCPServer
from mcp.shared.auth import ProtectedResourceMetadata
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

#: MCP spec revision this module implements RFC 9728 + RFC 8707 against. A pinned literal,
#: not re-exported from the SDK; changing it is a deliberate edit (asserted by test).
SPEC_REVISION = "2026-07-28"

#: RFC 9728 §3.1's fixed well-known path -- whoopmcp serves exactly one protected resource.
#: Not the SDK's build_resource_metadata_url, which adds a segment for multi-resource servers.
METADATA_PATH = "/.well-known/oauth-protected-resource"

#: Test-only GET route proving `MCPTokenVerifier`/RFC 6750 error shape over real HTTP.
#: Not the MCP wire protocol -- `/mcp` itself is deliberately left untouched (a #29 decision).
DEMO_PROTECTED_PATH = "/tools"


@dataclass(frozen=True, slots=True)
class MCPAuthConfig:
    """Which authorization servers whoopmcp trusts, and its own resource identity.

    ``resource_url``: the audience `MCPTokenVerifier` must match. ``authorization_servers``: the
    RFC 9728 trusted issuers -- unlike the SDK's single ``issuer_url``, supports more than one.
    """

    resource_url: AnyHttpUrl
    authorization_servers: list[AnyHttpUrl]
    required_scopes: list[str] | None = None


def build_protected_resource_metadata(config: MCPAuthConfig) -> ProtectedResourceMetadata:
    """Construct RFC 9728 §2 protected-resource metadata from `config`.

    ``bearer_methods_supported`` defaults to ``["header"]`` -- MCP only ever sends a bearer
    token via the Authorization header, never as a query param or form body.
    """
    return ProtectedResourceMetadata(
        resource=config.resource_url,
        authorization_servers=config.authorization_servers,
        scopes_supported=config.required_scopes,
    )


def _well_known_metadata_url(config: MCPAuthConfig) -> AnyHttpUrl:
    """This resource's own metadata URL, for a rejected request's `WWW-Authenticate`.

    Built from `config.resource_url`'s origin only, not its path -- METADATA_PATH is fixed and
    origin-relative regardless of the resource identifier's own path.
    """
    resource = config.resource_url
    netloc = resource.host or ""
    if resource.port is not None:
        netloc = f"{netloc}:{resource.port}"
    return AnyHttpUrl(f"{resource.scheme}://{netloc}{METADATA_PATH}")


def _names_this_resource(access_token: AccessToken, config: MCPAuthConfig) -> bool:
    """RFC 8707: true only when `access_token.resource` exactly names `config.resource_url`.

    Missing claim and wrong-server claim are rejected identically -- both would let a token
    minted for another audience be replayed here.
    """
    if access_token.resource is None:
        return False
    return access_token.resource == str(config.resource_url)


def _issued_by_trusted_as(access_token: AccessToken, config: MCPAuthConfig) -> bool:
    """True only when `access_token`'s issuer is one of `config.authorization_servers`.

    `iss` lives in `claims["iss"]` (`claims` may be `None`/malformed) -- missing, non-str, or
    empty is rejected same as a wrong issuer. Tolerates exactly one trailing slash (AnyHttpUrl
    appends one); nothing else is normalised, so a lookalike host, port, or path never matches.
    """
    claims = access_token.claims
    # `model_construct` bypasses pydantic validation, so `claims` may not match its declared
    # type -- checked here so malformed input is rejected, not an AttributeError crash.
    if not isinstance(claims, dict):
        return False
    iss = claims.get("iss")
    if not isinstance(iss, str) or not iss:
        return False
    return any(
        _without_one_trailing_slash(str(as_url)) == _without_one_trailing_slash(iss)
        for as_url in config.authorization_servers
    )


def _is_unexpired(access_token: AccessToken) -> bool:
    """Whether `access_token` carries a bounded lifetime that has not ended.

    False for expired, and for `expires_at is None` (absent is invalid, not unbounded -- #121).
    Requires strictly `expires_at > now` (RFC 7519). Checks `is None` explicitly, not truthiness,
    since `expires_at = 0` is a real expired value (the SDK's own `BearerAuthBackend` has that
    falsy-check bug); also checks `int` shape since `model_construct` can bypass validation.
    """
    expires_at = access_token.expires_at
    if not isinstance(expires_at, int):
        return False
    return expires_at > int(time.time())


def _without_one_trailing_slash(url: str) -> str:
    """`url` with a single trailing slash removed, if it has one.

    Not `rstrip("/")`, which strips every trailing slash (`https://x//` -> `https://x`) --
    harmless since the host is already trusted, but this tolerates exactly one slash (what
    `AnyHttpUrl` appends) and no more.
    """
    return url[:-1] if url.endswith("/") else url


class MCPTokenVerifier(TokenVerifier):
    """Validates an inbound bearer token's audience and issuer for this MCP server.

    Fail-closed, unconditionally: `_resolve` is a stub (no JWT/JWKS or RFC 7662 introspection
    wired in -- neither the issue nor the SDK names which AS/mechanism to use), so every token
    is rejected today. `_names_this_resource`/`_issued_by_trusted_as` are real RFC 8707/9728
    logic already, so a future resolver plugged into `_resolve` gets both checks for free.
    """

    def __init__(self, config: MCPAuthConfig | None = None) -> None:
        self.config = config

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify `token` and return its claims, or `None` if it must be rejected.

        Rejects if `self.config` is unset, the token can't be resolved (`_resolve`), its
        resource claim doesn't name this server (RFC 8707), its issuer isn't trusted
        (RFC 9728), or -- since #121 -- it is expired or carries no expiry at all
        (`AccessToken.expires_at` defaults to `None`; a token with no expiry is rejected, not
        given a permanent pass). Every check runs unconditionally; none skips another.

        No clock skew is tolerated (deliberate). No scope check here -- `RequireAuthMiddleware`
        already enforces `required_scopes`, which this layer never receives.
        """
        if self.config is None:
            return None
        access_token = await self._resolve(token)
        if access_token is None:
            return None
        if not _names_this_resource(access_token, self.config):
            return None
        if not _issued_by_trusted_as(access_token, self.config):
            return None
        if not _is_unexpired(access_token):
            return None
        return access_token

    async def _resolve(self, token: str) -> AccessToken | None:
        """Resolve an opaque bearer string into its claims.

        Stub pending a real external-AS integration (see class docstring). `token` is unused
        but the parameter stays so a real resolver's signature doesn't need to change.

        A real resolver inherits `verify_token`'s issuer/audience/expiry checks for free by
        populating `claims["iss"]`, `resource`, `expires_at` faithfully.

        **Not inherited: the cryptographic binding.** This method must verify the JWT signature
        against the AS's JWKS, or introspect per RFC 7662, before returning claims --
        `verify_token` trusts `resource`/`claims["iss"]` as plain data by that point. A resolver
        that skips signature verification (or accepts `alg: none`) lets an attacker forge a
        trusted `iss` and a matching `resource`, passing every downstream check.
        """
        del token
        return None


def _unauthorized_response(
    error: str, description: str, resource_metadata_url: AnyHttpUrl
) -> Response:
    """RFC 6750 §3 `WWW-Authenticate` for a rejected bearer token.

    Mirrors the header shape `RequireAuthMiddleware` sends for `/mcp`, so a client sees the
    same error surface regardless of which route rejected it.
    """
    www_authenticate = (
        f'Bearer error="{error}", error_description="{description}", '
        f'resource_metadata="{resource_metadata_url}"'
    )
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=401,
        headers={"WWW-Authenticate": www_authenticate},
    )


async def setup_mcp_auth(server: MCPServer[Any], config: MCPAuthConfig) -> None:
    """Register RFC 9728 metadata and a token-gated proof route on `server`.

    Typed against ``MCPServer[Any]`` to avoid a circular import on ``whoopmcp.server.AppContext``
    (mirrors ``webhooks.register_webhook_routes``).

    Registers `METADATA_PATH` (unauthenticated, must be fetchable pre-token) and
    `DEMO_PROTECTED_PATH` (authenticates inline via `BearerAuthBackend`, same as `/mcp`'s own
    middleware, without requiring global `AuthenticationMiddleware`).
    """
    verifier = MCPTokenVerifier(config)
    metadata_handler = ProtectedResourceMetadataHandler(build_protected_resource_metadata(config))
    resource_metadata_url = _well_known_metadata_url(config)

    @server.custom_route(METADATA_PATH, methods=["GET"])
    async def oauth_protected_resource_metadata(request: Request) -> Response:
        return await metadata_handler.handle(request)

    @server.custom_route(DEMO_PROTECTED_PATH, methods=["GET"])
    async def list_tools_protected(request: Request) -> Response:
        """Prove the resource-server boundary end-to-end over real HTTP.

        Reads nothing from `request.query_params` -- deliberate, not an oversight (see module
        docstring).
        """
        authenticated = await BearerAuthBackend(verifier).authenticate(request)
        if authenticated is None:
            return _unauthorized_response(
                "invalid_token", "Authentication required", resource_metadata_url
            )
        _, user = authenticated
        return JSONResponse({"client_id": user.access_token.client_id})
