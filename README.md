# whoopmcp

[![CI](https://github.com/kurok/whoopmcp/actions/workflows/ci.yml/badge.svg)](https://github.com/kurok/whoopmcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.13+](https://img.shields.io/badge/python-3.13%20%7C%203.14-blue.svg)](https://www.python.org/downloads/)

A read-only [MCP](https://modelcontextprotocol.io) server for the
[WHOOP API v2](https://developer.whoop.com/api/). It lets an MCP client —
Claude Desktop, Claude Code, Cursor, or anything else that speaks the
protocol — read and analyse **your own** WHOOP data: recovery, sleep, strain,
cycles and workouts.

Runs locally by default, and your WHOOP credentials never leave your machine
in that mode. Run with `WHOOPMCP_TRANSPORT=streamable-http` (#27) instead and
that stops being true: the operator of that server now holds other members'
tokens and health data server-side, which makes them a data controller, not
a bystander. See [PRIVACY.md](PRIVACY.md)'s local-mode/hosted-mode split
before hosting this for anyone but yourself.

> **Status: pre-alpha scaffold.** The structure, tool surface, configuration
> and test harness are in place; the network and analysis internals are
> stubbed and raise `NotImplementedError`. See [Roadmap](#roadmap). Nothing
> here talks to WHOOP yet.

> **Not affiliated with WHOOP, Inc.** "WHOOP" is their trademark. This is an
> independent client of their public developer API.

---

## What it does

| Area | Tools |
| --- | --- |
| Auth | `whoop_auth_status`, `whoop_login`, `whoop_complete_login`, `whoop_logout` |
| Profile | `get_profile`, `get_body_measurement` |
| Records | `list_recoveries`, `list_sleeps`, `list_cycles`, `list_workouts`, `get_sleep`, `get_workout` |
| Analysis | `summarize_period`, `metric_trend`, `correlate_metrics`, `compare_periods` |

Every data tool is annotated `readOnlyHint`. There is no write path to your
WHOOP account in this server — the one mutating endpoint WHOOP exposes
(`DELETE /v2/user/access`) is deliberately not wired up, so a model cannot
revoke your grant. `whoop_logout` only deletes the token stored on your own
disk.

Questions it is meant to answer:

- *"How did my recovery trend over the last month?"*
- *"Is my HRV correlated with how long I sleep?"*
- *"Compare my strain in July against June."*

### What it is not

It reports numbers and the sample size behind them. It is not a medical
device, it does not diagnose, and a correlation across a few weeks of your
own data is not a causal finding. Talk to a clinician about health decisions.

---

## Install

Requires **Python 3.13 or 3.14** — the two newest stable releases, which are
the two CI tests.

```bash
uvx whoopmcp          # run without installing
# or
pip install whoopmcp
```

## Setup

You need your own WHOOP developer app — this server ships no shared
credentials, by design. Full walkthrough in **[docs/SETUP.md](docs/SETUP.md)**.
The short version:

1. Create an app at [developer.whoop.com](https://developer.whoop.com/) and
   note the client ID and secret.
2. Register a redirect URL. **WHOOP does not accept `http://`, including
   `http://localhost`** — use `https://` or a custom scheme such as
   `whoopmcp://callback`.
3. Point the server at them via environment variables.

### Claude Desktop / Claude Code

```jsonc
{
  "mcpServers": {
    "whoop": {
      "command": "uvx",
      "args": ["whoopmcp"],
      "env": {
        "WHOOP_CLIENT_ID": "your-client-id",
        "WHOOP_CLIENT_SECRET": "your-client-secret",
        "WHOOP_REDIRECT_URI": "whoopmcp://callback"
      }
    }
  }
}
```

Then ask your client to run `whoop_login`, open the URL it returns, approve
the consent screen, and pass the `code` and `state` from the redirect back
via `whoop_complete_login`.

### Configuration

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `WHOOP_CLIENT_ID` | yes | — | OAuth client ID from the WHOOP dashboard |
| `WHOOP_CLIENT_SECRET` | yes | — | OAuth client secret |
| `WHOOP_REDIRECT_URI` | yes | — | Must match a registered redirect URL exactly |
| `WHOOPMCP_SCOPES` | no | all read scopes + `offline` | Space-separated scope list |
| `WHOOPMCP_TOKEN_BACKEND` | no | `file` | `file` or `keyring` |
| `WHOOPMCP_STATE_DIR` | no | `~/.local/state/whoopmcp` | Token and cache location |
| `WHOOPMCP_CACHE` | no | `false` | Cache responses on disk |
| `WHOOPMCP_TIMEOUT` | no | `30` | Per-request timeout, seconds |

The `offline` scope is requested by default. Without it WHOOP issues no
refresh token and you would re-authorise through a browser every hour.

For a token in your OS keychain rather than a file on disk:

```bash
pip install 'whoopmcp[keyring]'
export WHOOPMCP_TOKEN_BACKEND=keyring
```

**Recommended on Windows**, where the default file backend cannot protect the
token: Windows uses ACLs rather than POSIX modes, so the `0600` the file
backend requests is ignored and the token lands world-readable. The server
warns when it first writes one.

---

## Privacy

Read **[PRIVACY.md](PRIVACY.md)** before connecting real data — it is split
into local-mode and hosted-mode sections, since they are not the same
document. The essential points:

- **This server sends nothing to its maintainers.** No telemetry, no
  analytics, no phone-home. Traffic goes to `api.prod.whoop.com` and nowhere
  else.
- **Your MCP client does send your data onward.** Anything a tool returns is
  passed to whatever model your client is configured to use — Anthropic,
  OpenAI, a local model — under *that provider's* terms, not this project's.
  This is inherent to how MCP works, and it is health data. Know where it is
  going.
- Tokens are stored locally at mode `0600`, or in your OS keychain. **On
  Windows file modes are not enforced** — use the keychain backend there.
- **Local mode:** delete everything with `whoop_logout`, then remove
  `WHOOPMCP_STATE_DIR`, then revoke the app in the WHOOP app under Settings.
- **Hosted mode:** an operator holds other members' health data server-side
  (#13) and is a data controller for it (GDPR Article 9). Per-member export
  and erasure are operator-run CLI commands, deliberately not MCP tools —
  `whoopmcp export-member --whoop-user-id N` and
  `whoopmcp erase-member --whoop-user-id N` (the latter also revokes the
  WHOOP grant upstream) — and `whoopmcp enforce-retention --max-age-days N`
  deletes data past a configured age when an operator schedules it. This
  project takes no backups of its own in either mode.

---

## Rate limits

WHOOP's documented defaults are **100 requests/minute** and **10,000/day**,
with `X-RateLimit-*` headers and a `429` on breach. Collections page at 25
records maximum. Ask for explicit date ranges; an unbounded walk over years
of history will exhaust the quota and the model's context window alike.

Confirmed with WHOOP: the limit is **per application** (your `client_id`),
shared across every member who has authorised it — not a separate budget
per member. Running this locally for one person, that distinction is
invisible. Hosting it for several, it is the whole budget: one member's
two-year backfill is roughly 110 requests, about a minute of the *entire*
app's per-minute quota (#9).

---

## Development

```bash
git clone https://github.com/kurok/whoopmcp
cd whoopmcp
uv venv && uv pip install -e '.[dev,lint]'

pytest              # tests
ruff check . && ruff format --check .
mypy                # strict on src/
```

Built on the official Python SDK's `MCPServer` — the class FastMCP became
when the SDK went to 2.0. The layering is deliberate:

```
config.py     environment -> Config, validated once at startup
auth.py       OAuth 2.0 flow + token storage (file or keychain)
client.py     one method per documented WHOOP endpoint, nothing more
analysis.py   pure functions over already-fetched records
server.py     MCP tool definitions; the only file that knows about MCP
```

`analysis.py` holds no network code and `client.py` holds no statistics, so
each can be tested without the other.

## Roadmap

The scaffold is complete and CI is green; these are the tracked gaps.

| Issue | Work |
| --- | --- |
| #1 | OAuth token exchange and refresh |
| #2 | HTTP transport: bearer auth, 429 handling, pagination |
| #3 | Record shaping: metric extraction, summaries, trends, correlation |
| #4 | Auth tools |
| #5 | Data tools |
| #6 | Analysis tools |

Each stub raises `NotImplementedError` naming its issue, and the test suite
pins the contract each one must satisfy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and PRs welcome; by
participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). To
report a security issue, follow [SECURITY.md](SECURITY.md) rather than
opening a public issue.

## Prior art

Several other WHOOP MCP servers exist — among them
[AshwanthramKL/whoop-mcp](https://github.com/AshwanthramKL/whoop-mcp),
[shashankswe2020-ux/whoop-mcp](https://github.com/shashankswe2020-ux/whoop-mcp)
and [JedPattersonn/whoop-mcp](https://github.com/JedPattersonn/whoop-mcp).
If one of them already does what you need, use it.

## License

[MIT](LICENSE).
