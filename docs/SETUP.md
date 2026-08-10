# Setup

Getting `whoopmcp` talking to your WHOOP account. Budget ten minutes.

You need your own WHOOP developer app. This project ships no shared
credentials on purpose — a shared client would mean every user's data flowing
through one registration.

---

## 1. Create a WHOOP app

1. Sign in at [developer.whoop.com](https://developer.whoop.com/) with your
   WHOOP account and open the dashboard.
2. Create an application. Name it whatever you like.
3. Select the scopes you want. Requesting fewer is a real security control,
   not a formality — a scope you never grant is data this server can never
   read:

   | Scope | Grants |
   | --- | --- |
   | `read:recovery` | Recovery score, HRV, resting heart rate |
   | `read:cycles` | Day strain, average heart rate |
   | `read:sleep` | Sleep performance, stage durations |
   | `read:workout` | Workout strain, heart-rate metrics |
   | `read:body_measurement` | Height, weight, max heart rate |
   | `read:profile` | **Your name and email** |
   | `offline` | Refresh tokens — see below |

   Include **`offline`**. Without it WHOOP issues no refresh token, the access
   token dies after an hour, and you re-authorise through a browser every
   time. Consider *excluding* `read:profile`: it is the one scope carrying
   directly identifying information, and nothing here needs it.

4. Register a **Redirect URL** (next section).
5. Copy the **Client ID** and **Client Secret**.

## 2. Choose a redirect URI

This trips people up. **WHOOP does not accept `http://` redirect URLs — including
`http://localhost`.** Its docs specify `https://` or a custom scheme.

Three options that work:

**Custom scheme (simplest).** Register `whoopmcp://callback`. Your browser
will fail to open it and show an error page — that is fine and expected. The
URL bar still contains `whoopmcp://callback?code=...&state=...`, and you copy
those two values into `whoop_complete_login`. No local server, no
certificates.

```bash
export WHOOP_REDIRECT_URI="whoopmcp://callback"
```

**HTTPS on localhost.** Register `https://localhost:8443/callback` and
terminate TLS locally with a self-signed certificate. You will click through
a browser warning each time. More moving parts, marginally less copying.

**A tunnel.** `cloudflared` or `ngrok` gives you a public HTTPS URL to
register. Convenient, but it means your authorization code transits a third
party. Do not use this with a real account unless you understand that.

The value must match what you registered **exactly** — trailing slashes
included.

## 3. Configure your MCP client

### Claude Desktop

Edit the config file:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```jsonc
{
  "mcpServers": {
    "whoop": {
      "command": "uvx",
      "args": ["whoopmcp"],
      "env": {
        "WHOOP_CLIENT_ID": "your-client-id",
        "WHOOP_CLIENT_SECRET": "your-client-secret",
        "WHOOP_REDIRECT_URI": "whoopmcp://callback",
        "WHOOPMCP_SCOPES": "read:recovery read:sleep read:cycles read:workout offline"
      }
    }
  }
}
```

Restart Claude Desktop. Note that your client secret now sits in a plaintext
config file — that is how MCP client configuration works today, so give the
file the same care you would an SSH key.

### Claude Code

```bash
claude mcp add whoop \
  --env WHOOP_CLIENT_ID=your-client-id \
  --env WHOOP_CLIENT_SECRET=your-client-secret \
  --env WHOOP_REDIRECT_URI=whoopmcp://callback \
  -- uvx whoopmcp
```

### Any other client

Launch `uvx whoopmcp` over stdio with those variables in its environment.
Full variable list is in the [README](../README.md#configuration).

## 4. Log in

Ask your client to run **`whoop_login`**. It returns a URL.

1. Open the URL in a browser and approve the WHOOP consent screen.
2. You are redirected. With a custom scheme the browser shows an error page —
   expected. Read the URL bar.
3. Copy the `code` and `state` query parameters.
4. Ask your client to run **`whoop_complete_login`** with both.

`state` is verified against the pending login, so a code from a different
flow is rejected. Confirm with **`whoop_auth_status`**.

## 5. Try it

> "What was my average recovery over the last two weeks?"

> "Compare my sleep performance in July against June."

> "Is my HRV correlated with total sleep time this month?"

---

## Troubleshooting

**`missing required environment variable(s)`** — the client is not passing
the variables through. They belong in the `env` block of the MCP server
entry, not your shell profile; the client spawns the server itself and does
not inherit your interactive shell.

**`WHOOP_REDIRECT_URI must not use http://`** — see step 2. WHOOP would
reject it too; failing early beats failing after a consent screen.

**`state mismatch`** — the `state` does not match the pending login. Usually
means a stale URL from an earlier `whoop_login`. Run it again and use the
fresh one.

**`invalid_client` at the token step** — client ID or secret is wrong, or the
redirect URI does not match the registration byte for byte.

**`401` on a data tool after it previously worked** — the refresh token was
rejected, typically because the grant was revoked in the WHOOP app or
`offline` was never granted. Run `whoop_logout`, then `whoop_login` again.

**`429`** — WHOOP's limits are 100 requests/minute and 10,000/day. Narrow
your date range; collections page at 25 records maximum, so a year of history
is roughly 15 requests per collection.

**A tool raises `NotImplementedError`** — expected in 0.1.x. The scaffold is
published; the internals are not implemented yet. The error names the issue
tracking it, and the [roadmap](../README.md#roadmap) lists them.
