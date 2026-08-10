# Privacy Policy

**Last updated:** 2026-08-10 · **Applies to:** `whoopmcp` (all versions)

## Summary

`whoopmcp` is software you run on your own computer. It is not a hosted
service. **The maintainers of this project operate no servers, receive no
data from you, and cannot see your WHOOP data.**

There is, however, one thing you should understand before you connect real
health data, and it is not obvious: **your MCP client forwards tool results
to whichever AI model it is configured to use.** That is how MCP works. The
data leaves your machine at that point, under that provider's terms — not
under this project's. [Details below.](#3-your-mcp-client-and-its-model-provider)

---

## 1. Who is responsible for what

This project has no legal entity behind it and does not act as a data
controller or processor, because it never receives your data. In GDPR terms,
when you run `whoopmcp` on your own machine for your own purposes you are
handling your own personal data.

The parties that *do* process your data are:

| Party | Role | Governed by |
| --- | --- | --- |
| **WHOOP, Inc.** | Holds your health data; you authorise access | [WHOOP's privacy policy](https://www.whoop.com/privacy/) |
| **You** | Run the software, hold the tokens | — |
| **Your MCP client's model provider** | Receives whatever tool results your client sends it | That provider's terms |

Read WHOOP's policy and your model provider's policy. This document only
covers what the software in this repository does.

## 2. What the software does with your data

**Data it touches.** Whatever the WHOOP scopes you grant allow: profile
(name, email, user ID), body measurements (height, weight, max heart rate),
recovery (score, HRV, resting heart rate), sleep (duration, stages,
performance), cycles (strain, heart rate, energy) and workouts (sport,
strain, heart-rate zones).

This is **health data** — a special category under GDPR Article 9 and
comparable regimes. Treat it accordingly.

**Where it goes.** Network traffic goes to exactly two hosts, both WHOOP's:

- `api.prod.whoop.com/oauth/oauth2/*` — authorisation and token refresh
- `api.prod.whoop.com/developer/*` — data reads

There is no third host. No analytics endpoint, no error-reporting service, no
update check, no maintainer-operated server. You can verify this: the base
URLs are the only ones in the source, in `auth.py` and `client.py`.

**What is stored, and where.**

| Item | Location | Protection |
| --- | --- | --- |
| Access + refresh token | `$WHOOPMCP_STATE_DIR/token.json`, default `~/.local/state/whoopmcp/` | File mode `0600`, directory `0700` |
| Access + refresh token (alternative) | OS keychain | Whatever your OS provides |
| Cached responses | `$WHOOPMCP_STATE_DIR/cache.sqlite3` | **Off by default**; only written if you set `WHOOPMCP_CACHE=true` |
| Logs | stderr only | Never written to a file by this software |

By default, the only thing this software persists is your token. WHOOP
records are fetched, returned, and forgotten.

**Retention.** Nothing expires on its own, because nothing is stored on a
server. Files persist until you delete them ([see below](#5-deleting-your-data)).

## 3. Your MCP client and its model provider

This is the part worth reading twice.

When a tool returns your recovery scores, those scores are handed to your MCP
client (Claude Desktop, Claude Code, Cursor, …), which includes them in the
conversation it sends to its model provider. Depending on that provider and
your settings there, the data may be transmitted to their servers, retained
for some period, logged for abuse monitoring, or — under some consumer
plans — used to improve their models.

`whoopmcp` cannot control, inspect, or prevent any of that. It happens
downstream of this software entirely.

Practical mitigations, in rough order of effectiveness:

- **Grant only the scopes you need.** `WHOOPMCP_SCOPES="read:recovery offline"`
  means a compromised or over-eager client cannot read your workouts at all.
  This is the strongest control you have.
- **Skip `read:profile`** if you do not need it — it is the scope that carries
  your name and email. Everything else is comparatively de-identified.
- **Check your provider's data-retention settings** before connecting real
  data, particularly whether your plan trains on your conversations.
- **Prefer narrow date ranges.** A month of recovery scores is less exposure
  than three years of them.

## 4. What the software never does

- Send data to the maintainers or any third party other than WHOOP.
- Collect telemetry, analytics, crash reports, or usage statistics.
- Write your WHOOP data to a file, unless you explicitly enable the cache.
- Modify anything in your WHOOP account. Every data tool is read-only, and
  the one mutating endpoint WHOOP exposes to OAuth clients is not wired up.
- Include tokens or health data in log output.

## 5. Deleting your data

1. **Forget the local token** — run the `whoop_logout` tool, or delete
   `~/.local/state/whoopmcp/token.json` (or the `whoopmcp` keychain entry).
2. **Remove everything else** — `rm -rf ~/.local/state/whoopmcp` clears the
   cache too.
3. **Revoke the grant at WHOOP** — in the WHOOP app under Settings, remove
   this application's authorisation. Step 1 does not do this; until you
   revoke, the authorisation still exists on WHOOP's side.
4. **Your data at WHOOP and at your model provider** is theirs to delete;
   use their respective controls. Nothing in this repository can reach it.

## 6. Children

The WHOOP developer platform is not intended for children, and neither is
this software. Do not use it to process a child's data.

## 7. Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md) —
not in a public issue.

## 8. Changes

This policy is versioned in git. Material changes will be noted in
[CHANGELOG.md](CHANGELOG.md) and the date above updated. History is at
`git log PRIVACY.md`.

## 9. Contact

Open an issue at https://github.com/kurok/whoopmcp/issues for questions about
this document. Do not include personal or health data in an issue — it is
public. For anything concerning your WHOOP account or the data WHOOP holds,
contact WHOOP directly; the maintainers of this project have no access to it
and cannot help.
