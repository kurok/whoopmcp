"""OAuth 2.1 resource server: metadata, resource indicators (issue #28).

    MCP client --OAuth 2.1, whoopmcp is the resource server--> whoopmcp
    whoopmcp --OAuth 2, auth.py--> WHOOP

This module is the *inbound* half only: it decides whether a bearer token an
MCP client presents to whoopmcp is one this server should honour. It says
nothing about *outbound* auth (whoopmcp's own WHOOP grant, in ``auth.py``) --
different protocol, different token, different threat model, and neither
module imports the other (enforced by ``test_mcpauth_does_not_import_auth``).

It also says nothing about *which WHOOP member* an inbound token belongs to.
That join -- the actual security boundary between MCP principals and WHOOP
members -- is issue #29's job. Everything here answers exactly one question:
"is this token valid for *this* MCP server", never "whose data should this
return". There is deliberately no parameter anywhere in this module that
lets a caller name a member; `list_tools_protected` below reads nothing from
`request.query_params` for that reason, and its own test
(`test_client_supplied_user_id_ignored_first`) is written first in the test
file, per the issue's own instruction, to say so.

Spec revision pinned: 2026-07-28. This is ``mcp_types.version.LATEST_PROTOCOL_VERSION``
in the installed SDK (``mcp==2.0.0``) at the time this module was written --
not invented, read from ``.venv/.../mcp_types/version.py``. ``SPEC_REVISION``
below is a hardcoded literal, not a re-export of that constant: importing it
would make this module silently track whatever spec revision a future ``mcp``
upgrade happens to bring, defeating the whole point of pinning (bumping it
should be a deliberate, reviewed edit -- see ``test_spec_revision_pinned``).

Role: whoopmcp is a resource server ONLY, never an authorization server. The
issue frames it that way ("you are the resource server"), and the installed
SDK's own structure confirms it has to be read that way here: acting as an AS
too means implementing ``OAuthAuthorizationServerProvider`` and passing it as
``auth_server_provider=`` to ``MCPServer(...)``, which is also the ONLY thing
that turns on the SDK's Dynamic Client Registration route
(``mcp.server.auth.handlers.register``, gated behind
``ClientRegistrationOptions.enabled`` inside ``create_auth_routes``). This
module never supplies an ``auth_server_provider``, so that route -- and DCR
generally -- is structurally unreachable here, which is exactly what "DCR is
deprecated, support it only for free, build nothing new on it" means in
practice. Client ID Metadata Documents are the same story one level further
out: CIMD is how the *external* authorization server identifies an OAuth
client, a concern between the MCP client and that AS. A pure resource server
never registers clients and has no CIMD role to play -- there is nothing for
whoopmcp to wire up here, and inventing something would be scope creep onto
the authorization server's job, not this server's.
"""

from __future__ import annotations

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

#: MCP authorisation spec revision this module implements RFC 9728 (protected
#: resource metadata) and RFC 8707 (resource indicators) against. A literal,
#: not derived from the installed SDK -- see the module docstring for why.
#: Asserted by ``test_spec_revision_pinned``; changing it is a deliberate edit.
SPEC_REVISION = "2026-07-28"

#: RFC 9728 §3.1's fixed well-known path. whoopmcp serves exactly one
#: protected resource, so this is the single canonical metadata document --
#: not the SDK's own ``build_resource_metadata_url``, which inserts the
#: resource's own path segment (e.g. ``.../oauth-protected-resource/mcp``)
#: for servers hosting more than one distinct protected resource per origin.
METADATA_PATH = "/.well-known/oauth-protected-resource"

#: A GET route that requires a valid bearer token, registered purely so this
#: issue's tests can drive a real HTTP request through `MCPTokenVerifier` and
#: see the RFC 6750 error shape a client actually gets. Not part of the MCP
#: wire protocol itself -- tool listing travels over JSON-RPC on `/mcp`, which
#: this module deliberately leaves alone (see the module docstring: turning on
#: enforcement for the real MCP endpoint is a decision for whoever wires this
#: into a deployment, once #29 exists to make an authenticated request usable
#: for something).
DEMO_PROTECTED_PATH = "/tools"


@dataclass(frozen=True, slots=True)
class MCPAuthConfig:
    """Which authorization servers whoopmcp trusts, and its own resource identity.

    ``resource_url`` is this MCP server's own identifier -- what a token's
    resource/audience claim must name for `MCPTokenVerifier` to accept it.
    ``authorization_servers`` is the full RFC 9728 list of ASes trusted to
    issue such tokens; unlike the SDK's own ``AuthSettings`` (single
    ``issuer_url``), this preserves the general RFC 9728 §2 case of more than
    one trusted AS.
    """

    resource_url: AnyHttpUrl
    authorization_servers: list[AnyHttpUrl]
    required_scopes: list[str] | None = None


def build_protected_resource_metadata(config: MCPAuthConfig) -> ProtectedResourceMetadata:
    """Construct RFC 9728 §2 protected-resource metadata from `config`.

    ``bearer_methods_supported`` is left at the model's own default
    (``["header"]``): MCP only ever presents a bearer token via the
    ``Authorization`` header, never as a query parameter or form body.
    """
    return ProtectedResourceMetadata(
        resource=config.resource_url,
        authorization_servers=config.authorization_servers,
        scopes_supported=config.required_scopes,
    )


def _well_known_metadata_url(config: MCPAuthConfig) -> AnyHttpUrl:
    """This resource's own metadata URL, for a rejected request's `WWW-Authenticate`.

    Built from `config.resource_url`'s own origin, not its path -- METADATA_PATH
    is fixed and origin-relative regardless of what path the resource identifier
    itself carries (e.g. a resource of ``https://host/mcp`` still publishes
    metadata at ``https://host/.well-known/oauth-protected-resource``).
    """
    resource = config.resource_url
    netloc = resource.host or ""
    if resource.port is not None:
        netloc = f"{netloc}:{resource.port}"
    return AnyHttpUrl(f"{resource.scheme}://{netloc}{METADATA_PATH}")


def _names_this_resource(access_token: AccessToken, config: MCPAuthConfig) -> bool:
    """RFC 8707: true only when `access_token.resource` exactly names `config.resource_url`.

    A missing resource claim and a claim naming some other server are both
    rejected the same way -- either lets a token minted for a different
    audience (or with no audience restriction at all) be replayed here.
    """
    if access_token.resource is None:
        return False
    return access_token.resource == str(config.resource_url)


class MCPTokenVerifier(TokenVerifier):
    """Validates an inbound bearer token's audience for this MCP server.

    Deliberately fail-closed and, today, unconditionally so: resolving an
    opaque bearer string into its claims means either verifying a JWT against
    an external AS's JWKS or calling that AS's RFC 7662 introspection
    endpoint, and neither the issue nor the installed SDK (`mcp.server.auth`
    ships the `TokenVerifier` protocol itself, not a concrete implementation
    for either mechanism -- its own docstring only points at an uninstalled
    example) names which one whoopmcp should use or against which AS. Adding
    either now would mean guessing an unresolved external integration rather
    than reading it off the SDK's structure or the issue's own text, so
    `_resolve` is left a stub that resolves nothing, and every token is
    rejected. `_names_this_resource` is nonetheless implemented as real,
    independently callable RFC 8707 logic: the moment a future issue plugs
    a real resolver into `_resolve`, `verify_token` already applies it.
    """

    def __init__(self, config: MCPAuthConfig | None = None) -> None:
        self.config = config

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify `token` and return its claims, or `None` if it must be rejected.

        Rejects unconditionally if `self.config` was never set (nothing to
        validate an audience against), if the token cannot be resolved at all
        (see `_resolve`), or if the resolved token's resource claim does not
        name this server (RFC 8707).
        """
        if self.config is None:
            return None
        access_token = await self._resolve(token)
        if access_token is None:
            return None
        if not _names_this_resource(access_token, self.config):
            return None
        return access_token

    async def _resolve(self, token: str) -> AccessToken | None:
        """Resolve an opaque bearer string into its claims.

        Stub pending a real external-AS integration -- see the class
        docstring for why that choice is not this issue's to make. `token`
        is unused for now; the parameter stays so a real resolver's signature
        doesn't need to change to plug in here.
        """
        del token
        return None


def _unauthorized_response(
    error: str, description: str, resource_metadata_url: AnyHttpUrl
) -> Response:
    """RFC 6750 §3 `WWW-Authenticate` for a rejected bearer token.

    Mirrors the header shape `mcp.server.auth.middleware.bearer_auth
    .RequireAuthMiddleware` sends for the real `/mcp` endpoint, so a client
    sees the same error surface regardless of which route rejected it.
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

    Typed against ``MCPServer[Any]``, not a concrete lifespan-context type,
    mirroring ``webhooks.register_webhook_routes`` for the same reason: this
    module has no need to know the shape of `server`'s lifespan context, and
    depending on ``whoopmcp.server.AppContext`` here would invert the natural
    wiring direction and create a circular import.

    Registers two public routes via ``server.custom_route`` -- no reach into
    ``MCPServer``'s private route list is needed, since both handlers do
    their own request handling rather than requiring the decorator itself to
    enforce anything:

    - `METADATA_PATH`, unauthenticated by design (RFC 9728 metadata has to be
      fetchable before a client has a token).
    - `DEMO_PROTECTED_PATH`, which authenticates the request itself, inline,
      by calling `BearerAuthBackend.authenticate` (the same bearer-parsing and
      expiry check the SDK's own middleware uses for `/mcp`) rather than
      requiring `server`'s Starlette app to carry `AuthenticationMiddleware`
      globally. See `DEMO_PROTECTED_PATH`'s own docstring for why this route
      exists at all and why `/mcp` itself is untouched.
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

        Reads nothing from `request.query_params` -- see the module and
        `DEMO_PROTECTED_PATH` docstrings for why that omission is the point,
        not an oversight.
        """
        authenticated = await BearerAuthBackend(verifier).authenticate(request)
        if authenticated is None:
            return _unauthorized_response(
                "invalid_token", "Authentication required", resource_metadata_url
            )
        _, user = authenticated
        return JSONResponse({"client_id": user.access_token.client_id})
