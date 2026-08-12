# Privacy Policy

**Last updated:** 2026-08-11 · **Applies to:** `whoopmcp` (all versions)

## Summary

`whoopmcp` can run in one of two modes, and this policy is different for
each:

- **Local mode** (the default): software you run on your own computer. It is
  not a hosted service. **The maintainers of this project operate no
  servers, receive no data from you, and cannot see your WHOOP data.**
- **Hosted mode** (`WHOOPMCP_TRANSPORT=streamable-http`, #27): someone —
  possibly you, possibly a third party — runs `whoopmcp` as a persistent
  server that other people's MCP clients connect to. That operator's
  process now holds *other people's* health data in its own SQLite store
  (#13). Once that is true, the operator is a data **controller** of
  special-category personal data (GDPR Article 9), not a bystander. If you
  are that operator, this document's hosted-mode sections are about you, not
  about the maintainers of this repository.

Every section below is split where the two modes actually differ. Where a
section isn't split, the same statement is true of both.

There is, however, one thing every mode shares and that you should
understand before you connect real health data: **your MCP client forwards
tool results to whichever AI model it is configured to use.** That is how
MCP works. The data leaves the machine running the server at that point,
under that provider's terms — not under this project's.
[Details below.](#3-your-mcp-client-and-its-model-provider)

---

## 1. Who is responsible for what

### Local mode

This project has no legal entity behind it and does not act as a data
controller or processor, because it never receives your data. In GDPR terms,
when you run `whoopmcp` on your own machine for your own purposes you are
handling your own personal data.

### Hosted mode

If you run `whoopmcp` as a server other people's MCP clients connect to, you
— the operator — are the data controller for whatever this software stores
about them (see §2's hosted-mode row). This project having no legal entity
behind *it* does not mean nobody is a controller: it means the maintainers
of this repository are not, and your own deployment is your own legal
responsibility, including registering as a controller where your
jurisdiction requires it.

### Both modes

The parties that *do* process personal data are:

| Party | Role | Governed by |
| --- | --- | --- |
| **WHOOP, Inc.** | Holds the underlying health data; access is authorised per member | [WHOOP's privacy policy](https://www.whoop.com/privacy/) |
| **You (local mode) / the operator (hosted mode)** | Runs the software, holds the tokens and any stored data | — |
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
| Access + refresh token | `$WHOOPMCP_STATE_DIR/token.json`, default `~/.local/state/whoopmcp/` | File mode `0600`, directory `0700` — **macOS and Linux only**; encrypted at rest with `WHOOPMCP_TOKEN_BACKEND=encrypted-file` |
| Access + refresh token (alternative) | OS keychain | Whatever your OS provides |

> **Windows:** file modes are not enforced — Windows uses ACLs, and the token
> file, the database and any data-subject export end up readable by any
> process running as you. The server logs a warning the first time it writes
> a token or the database. Use the keychain backend instead:
> `pip install 'whoopmcp[keyring]'` and `WHOOPMCP_TOKEN_BACKEND=keyring`,
> which stores the token in the Windows Credential Manager — it does not
> cover the database or an export, which have no keychain equivalent.
| Cached responses (local mode only) | `$WHOOPMCP_STATE_DIR/cache.sqlite3` | **Not written to disk by default.** By default the store — the principal/member link and the tool-call audit trail described below — lives **in memory only**, for the life of the running process, and `cache.sqlite3` is never created. It moves to disk, with the same protection as the token above (file mode `0600`, directory `0700` — **macOS and Linux only** — including the mechanism that protects sqlite's transient `-journal` sidecar; this software never enables WAL, so `-wal`/`-shm` never exist), only if you set `WHOOPMCP_CACHE=true` or enable webhooks (`WHOOPMCP_WEBHOOKS_ENABLED=true`) |
| Data-subject export (`export-member --out`) | Wherever you point `--out` | File mode `0600` — **macOS and Linux only** |
| Logs | stderr only | Never written to a file by this software |

By default in **local mode**, the only thing this software writes to
`$WHOOPMCP_STATE_DIR` is your token. The server also keeps, in memory only,
for the life of the running process: the link between your MCP session and
your WHOOP member id, and a tool-call audit trail (tool name and timestamp
only, never arguments or results) — both vanish when the process exits, and
neither is ever written to disk. **No WHOOP health record is fetched live**:
every data and analysis tool answers only from the local store, and each of
the three things that can put a record into that store is off by default —
`whoop_sync` and the operator-run `whoopmcp backfill` command both refuse to
run unless `WHOOPMCP_CACHE=true`, and the webhook receiver, which is the one
path where WHOOP pushes records to you rather than you pulling them, does
nothing unless `WHOOPMCP_WEBHOOKS_ENABLED=true`. So by
default, no WHOOP health record (recovery, sleep, cycle, workout) is ever
fetched from WHOOP or held anywhere, on disk or in memory, and every data
tool reports "not synced yet" until you opt in. The one live call outside
login is `GET /v2/user/profile/basic` at startup, to resolve which member
your token belongs to; only the resulting member id is kept, in memory, for
the life of the process. Setting `WHOOPMCP_CACHE=true` moves the principal
link and audit trail to `cache.sqlite3` on disk, where they persist across
restarts, and enables `whoop_sync`/`backfill` to populate it with the WHOOP
records tools then answer from; enabling webhooks
(`WHOOPMCP_WEBHOOKS_ENABLED=true`) also moves the store to disk, since a
webhook consumer whose work vanished on every restart would be pointless —
and note that webhooks write WHOOP health records (recovery, sleep and
workout) into that store as WHOOP pushes them, independently of
`WHOOPMCP_CACHE`, so enabling webhooks alone is enough to put health data on
your disk.

**Hosted mode stores materially more, unconditionally — not opt-in.** The
same SQLite store (`$WHOOPMCP_STATE_DIR/cache.sqlite3`) that is an optional
cache in local mode is where a hosted server keeps, for every linked member:
profile, body measurements, recovery, sleep, cycle and workout records
(every table `src/whoopmcp/store.py` defines), the webhook event log, and a
tool-call audit trail (member id, tool name, and timestamp only — never
arguments or results). This is health data held server-side, for people who
are not the operator, which is exactly the situation that makes the operator
a GDPR controller (see §1). Access tokens live in the same encrypted or
plaintext file described above regardless of mode.

**Retention.**

- *Local mode:* nothing expires on its own, because nothing is stored on a
  server. Files persist until you delete them
  ([see below](#5-deleting-your-data)).
- *Hosted mode:* nothing expires automatically inside the running process
  either — but an operator can run `whoopmcp enforce-retention
  --max-age-days N` (defaulting to 730, i.e. two years) to delete rows past a
  configured age from every table named above. This only happens when an
  operator schedules it (their own cron or systemd timer, since this project
  ships no scheduler of its own); it is a real, verified-at-the-database-level
  deletion when it runs, not merely a documented promise.

**Backups.** This project takes no backups of its own and implements no
backup mechanism, in either mode — there is no backup script, scheduled job,
or external storage configuration anywhere in this codebase. If an operator
running this software configures backups of the underlying token file or
SQLite database as part of their own infrastructure, that is entirely their
own decision and outside anything this document can describe or control.

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
- Modify anything in your WHOOP account through any MCP tool. Every data
  tool is read-only, and the one mutating endpoint WHOOP exposes to OAuth
  clients (`DELETE /v2/user/access`) is never registered as an MCP tool — no
  model can call it. It is reachable only from a terminal on the machine
  running the server, as the operator-run `whoopmcp delete-member
  --whoop-user-id N` (§5, below).
- Include tokens or health data in log output.

## 5. Deleting your data

### Local mode

1. **Forget the local token** — run the `whoop_logout` tool, or delete
   `~/.local/state/whoopmcp/token.json` (or the `whoopmcp` keychain entry).
2. **Remove everything else** — `rm -rf ~/.local/state/whoopmcp` clears the
   cache too.
3. **Revoke the grant at WHOOP** — in the WHOOP app under Settings, remove
   this application's authorisation. Step 1 does not do this; until you
   revoke, the authorisation still exists on WHOOP's side. If you have
   terminal access to the machine running the server, `whoopmcp
   delete-member --whoop-user-id N` does the same revocation without
   opening the app — but you need your own WHOOP user id first (it's in
   your profile) and this is a CLI-only operator command, never an MCP
   tool, so no model can run it on your behalf.
4. **Your data at WHOOP and at your model provider** is theirs to delete;
   use their respective controls. Nothing in this repository can reach it.

### Hosted mode

A hosted member's export and erasure rights are exercised by the **operator**
running two CLI commands — deliberately operator-run, not self-serve from
inside a chat: an LLM-driven tool call must never be able to trigger a
member's own irreversible export or erasure, or another member's, so neither
capability is exposed as an MCP tool.

- **Export** — `whoopmcp export-member --whoop-user-id N` writes one JSON
  document containing every entity this store holds for member `N` (profile,
  body measurements, recovery, sleep, cycle and workout records, webhook
  events, tool-call audit rows, and the principal links recording what was
  authorised and when) and nothing belonging to any other member.
- **Erasure** — `whoopmcp erase-member --whoop-user-id N` revokes the
  member's WHOOP grant upstream, then permanently `DELETE`s every one of
  those rows for member `N` — a real removal, not a flag — plus their token
  and principal link. The database file is then compacted via `VACUUM` so
  those bytes are no longer present in the database file.

Ask the operator running your `whoopmcp` instance to run these on your
behalf if you want your data or its removal; there is no in-app self-service
path today.

**Consent and scope transparency.** The export document above states which
WHOOP scopes were granted and whether a token is currently stored
(`Token.scopes`, never the token itself), plus when each MCP client was
linked (`principal_members.linked_at`). There is exactly one token file per
server, so scopes are reported only when the store has ever linked exactly
one distinct WHOOP member — if more than one has ever been linked (e.g. an
operator re-authorised against a different WHOOP account), nothing local
records which member the stored token belongs to, and the export says so
honestly instead of guessing. Withdrawing consent is the same as erasure
above, or revoking the app directly in WHOOP's own Settings.

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
