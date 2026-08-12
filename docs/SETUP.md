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

4. **Know the cap before you invite anyone else to use it.** Every WHOOP
   developer app — including the one you just created — is limited to **ten
   authorised members** (confirmed with WHOOP). That's a platform limit on
   *your* app, not something this project imposes or can raise. It rarely
   matters for a single-person local-mode install, but it surprises people
   the moment they try to share one app registration across a household or a
   small team.
5. Register a **Redirect URL** (next section).
6. Copy the **Client ID** and **Client Secret**.

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

**Preferred: run `whoopmcp login` in a terminal.** It prints the authorize
URL, waits for you to paste back the redirect (or just its `code` and
`state` query parameters), and exchanges them itself. This is preferred
over the in-chat steps below because the authorization code never has to
travel through your MCP client or its model provider on its way to the
exchange.

1. Run `whoopmcp login`. It prints a URL.
2. Open the URL in a browser and approve the WHOOP consent screen.
3. You are redirected. With a custom scheme the terminal shows an error
   page — expected. Paste that page's URL back at the prompt (a bare
   `code=...&state=...` fragment also works; if neither parses, it asks for
   `code` and `state` separately).

If your MCP client has no terminal you can reach, use the in-chat pair
instead:

1. Ask your client to run **`whoop_login`**. It returns a URL.
2. Open the URL in a browser and approve the WHOOP consent screen.
3. You are redirected. With a custom scheme the browser shows an error page —
   expected. Read the URL bar.
4. Copy the `code` and `state` query parameters.
5. Ask your client to run **`whoop_complete_login`** with both.

Either way, `state` is verified against the pending login, so a code from a
different flow is rejected. Confirm with **`whoop_auth_status`**.

**On data freshness:** local mode has no scheduled incremental sync today —
that's #15, and it hasn't merged yet. Every tool call fetches live from
WHOOP rather than reading a background-refreshed cache, so there's no
"stale cache" problem to worry about, at the cost of spending more of your
app's shared rate-limit budget (see the `429` note below) on repeated
fetches for the same data across a session.

## 5. Try it

> "What was my average recovery over the last two weeks?"

> "Compare my sleep performance in July against June."

> "Is my HRV correlated with total sleep time this month?"

## 6. Webhooks (optional)

Webhooks let WHOOP push a change instead of this server having to poll for
one. They are an optimisation over polling, **never a replacement for it** --
see the reconciliation backstop below.

### Registering the endpoint

1. In the WHOOP developer dashboard, on the same app you created in step 1,
   find the webhook endpoint URL field and point it at this server's
   publicly-reachable `https://<host>/webhooks/whoop`.
2. That route only responds to anything other than a `404` when the server
   is actually serving it. It needs all three of:
   - `--transport streamable-http` (webhooks arrive as an ordinary inbound
     HTTP POST; `stdio` has nothing listening for one),
   - `WHOOPMCP_WEBHOOKS_ENABLED=true`,
   - `WHOOPMCP_CACHE=true` -- webhook processing writes the fetched
     resource into the persistent store; without it there is nowhere for
     the result to go.
3. `/webhooks/whoop` also enforces its own inbound rate limit, independent
   of the outbound WHOOP API budget above -- checked before the body is
   even read, so a flood costs neither that nor a signature check.
   `WHOOPMCP_WEBHOOK_RATE_LIMIT_PER_MINUTE` (default `120`) caps requests
   per minute; set it to `0` or a negative number to disable inbound
   limiting entirely. Under more than one uvicorn worker, each process
   holds its own counter, so the effective limit is per worker, not
   fleet-wide.

### Rotating the signing secret

**The signing secret is not a separate value -- it is `WHOOP_CLIENT_SECRET`,
the same client secret step 1 gave you for the OAuth token exchange.**
Rotating it to fix a compromised webhook secret is therefore a full-outage
operation, not a quiet webhook-only fix: it simultaneously breaks the OAuth
refresh flow every already-linked member depends on. Concretely, rotating:

1. Rotate the secret in the WHOOP developer dashboard.
2. Update `WHOOP_CLIENT_SECRET` everywhere it is configured (every MCP
   client config, every environment this server runs in).
3. Every already-issued refresh token starts failing immediately with
   `invalid_client` -- this is expected, not a bug.
4. Every user who was logged in needs to run `whoop_logout` then
   `whoop_login` again to re-authorise against the new secret.

There is no way to rotate only the webhook half of this secret; plan the
rotation as a scheduled outage for every linked member, not a background fix.

### Local development: replaying a stored event

`whoopmcp replay-webhook --trace-id ID` re-runs a previously-received
event (looked up in `webhook_events` by `trace_id`) through the same
processing pipeline a live delivery would go through. It never re-POSTs to
`/webhooks/whoop` and never re-signs anything -- it calls straight into the
processing code with the event's own stored body, so a code change can be
tested against a real, previously-captured event without a deploy per
change. Replaying an event already marked `success` (or `dead_letter`) is a
safe no-op; a `pending` row (mid-retry, or an event that arrived before its
member had logged in) is genuinely reprocessed.

### The reconciliation backstop

Webhooks are best-effort: WHOOP does not guarantee delivery, and a lost
`*.deleted` event leaves a permanent hole that #15's own incremental sync
can never notice by itself (a forward `updated_at` walk has no way to
detect that a record disappeared). `whoopmcp reconcile-webhooks
--whoop-user-id ID [--window-days N]` (default `--window-days 30`) is the
backstop: it re-lists the last N days directly from WHOOP and soft-deletes
any locally-held record that listing no longer mentions.

There is no in-process scheduler in this server (see the `doctor`
subcommand's own notes) -- wire this into cron or a systemd timer, the same
way `enforce-retention` documents:

```cron
# Nightly at 03:00
0 3 * * * WHOOPMCP_CACHE=true whoopmcp reconcile-webhooks --whoop-user-id 12345678
```

Run it alongside your existing `whoop_sync`/backfill schedule, not instead
of it -- reconciliation only ever closes deletion holes; it does not pick up
new or updated records the way #15's sync does.

### Per-user last-delivery time

Every successfully-processed webhook delivery advances a per-member "last
delivered at" timestamp. Besides being visible inside the document
`whoopmcp export-member` produces (under `webhook_delivery_state`), it now
also backs `whoopmcp_webhook_last_delivery_age_seconds` on `/metrics` --
see [Metrics](#7-metrics) below -- so a member who has gone quiet relative
to their *own* baseline (a dead integration and a user on holiday look
identical otherwise) can be alerted on rather than discovered by a support
ticket.

---

## 7. Metrics

`/metrics` (#31) exposes Prometheus-format observability: sync lag per
member, webhook delivery silence (per member and fleet-wide), webhook
signature-verification failure rate, WHOOP API 429s and remaining rate
budget, and token refresh failures by cause with `invalid_grant` broken
out. `ops/alerts.yml` ships one Prometheus alerting rule per alert the
issue names, including a baseline (not a fixed threshold) for webhook
silence.

Off by default, same precedent as `WHOOPMCP_WEBHOOKS_ENABLED`:

- `WHOOPMCP_METRICS_TOKEN` unset -> the route 404s and exports nothing.
  Set it, and every request needs `Authorization: Bearer <token>`; a
  missing or wrong token gets `401`.
- `WHOOPMCP_METRICS_SALT` unset -> the token-gated endpoint still serves,
  but every series labelled by member is withheld entirely, and
  `whoopmcp_member_metrics_enabled` reads `0` so a dashboard can tell "salt
  not configured" apart from "no members linked". Set it to a value that
  is **not** `WHOOP_CLIENT_SECRET` -- that value is also the webhook
  signing secret, so rotating it would silently reset every metrics series
  at the same moment it broke webhooks (see the rotation notes above).
  The per-member label itself (`member_ref`) is a keyed HMAC-SHA256 of the
  WHOOP user id, never the id, an email, or an unsalted hash -- WHOOP ids
  are modest integers, and an unsalted digest is reversible by enumeration
  in seconds.

Both require `WHOOPMCP_CACHE=true`: the gauges are read from the same
persistent store every other cache-backed tool uses.

Every worker process under a multi-worker streamable-http deployment holds
its own counters; a single scrape only ever sees whichever worker answered
it. There is no cross-process aggregation here, deliberately -- see
`whoopmcp/metrics.py`'s own module docstring.

The backfill queue depth and oldest-queued-job age the issue's Scope also
asks for are not implemented: there is no backfill queue anywhere in this
codebase to measure (`whoopmcp backfill` is a synchronous, CLI-invoked run
with no persistent job record).

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

**`429`** — WHOOP's limits are 100 requests/minute and 10,000/day, **per
application**, shared across every member who has authorised it (confirmed
with WHOOP, #9) — not a separate budget per member. Narrow your date range;
collections page at 25 records maximum, so a year of history is roughly 15
requests per collection.

**Not sure what's actually wrong?** Run `whoopmcp doctor`. It checks your
configuration, stored credentials, the local store, and sync state in one
pass and reports each in a sentence, exiting non-zero if anything needs
attention.
