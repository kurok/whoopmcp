# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/kurok/whoopmcp/security/advisories/new).

Please include the version, what an attacker gains, and the smallest set of
steps that shows it. A proof of concept helps; use throwaway credentials, not
your real WHOOP account.

This is a volunteer project, so expect an acknowledgement within a few days
rather than hours. If a report is valid you will be credited in the advisory
unless you would rather not be. Please give a fix a reasonable window before
disclosing publicly.

## Supported versions

Pre-1.0: only the latest release gets fixes.

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ |

## Scope

**In scope** — anything in this repository:

- Token leakage: exposure in logs, error messages, crash output, or files
  with permissions wider than `0600`.
- OAuth flow flaws: `state` not verified, an authorization code accepted from
  a mismatched callback, redirect handling that allows interception.
- Sending data anywhere other than `api.prod.whoop.com`.
- A tool annotated `readOnlyHint` that is not, in fact, read-only.
- Prompt-injection paths where WHOOP-returned content could steer a client
  into an action the user did not ask for.
- Dependency vulnerabilities that are actually reachable from this code.

**Out of scope:**

- Vulnerabilities in the WHOOP API itself — report those to
  [WHOOP](https://www.whoop.com/) directly.
- Vulnerabilities in MCP clients or in model providers.
- The fact that your MCP client forwards tool results to a model provider.
  That is inherent to MCP and documented in [PRIVACY.md](PRIVACY.md); it is a
  property of the protocol, not a bug in this server.
- Anything requiring an attacker who already has read access to your user
  account on your machine. Such an attacker can read the token file, and no
  local storage scheme defends against that.
- Missing hardening with no demonstrated impact.

## Design notes relevant to security

Deliberate choices, so you can tell a decision from an oversight:

- **No shared credentials.** Every user registers their own WHOOP app. There
  is no client secret in this repository and never should be.
- **No write path.** The only mutating endpoint WHOOP exposes to an OAuth
  client is `DELETE /v2/user/access`; it is not implemented, so a model
  cannot revoke your grant. `whoop_logout` only deletes your local token.
- **Least privilege by scope.** `WHOOPMCP_SCOPES` lets you narrow what the
  server can read at the WHOOP authorisation boundary, which is stronger than
  any check this code could perform on itself.
- **Tokens at `0600`, written then renamed,** so a crash mid-write cannot
  truncate a good token and the secret is never briefly world-readable.
- **`state` is compared with `secrets.compare_digest`** against a
  `token_urlsafe(32)` value generated per login.
- **Logs go to stderr,** never stdout: on stdio transport stdout carries the
  JSON-RPC framing.
