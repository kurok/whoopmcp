# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Authenticator.exchange_code`, `.refresh`, and `.access_token` now talk to WHOOP:
  form-encoded POSTs to the token endpoint wrapped into `Token` and persisted via
  the configured store, with `access_token()` refreshing an expired token automatically
  and persisting WHOOP's rotated refresh token.
- `extract_metric`, `summarize`, `trend`, and `correlate` in `analysis.py` now
  turn raw WHOOP records into numbers: friendly metric names resolve onto
  WHOOP's nested `score` paths, unscored records are dropped rather than read
  as zero, `trend` orders by each record's own timestamp rather than list
  position, and `correlate` joins on `cycle_id` (falling back to a Cycle
  record's own `id`, and then to calendar day) before computing Pearson's r.
- `WhoopClient._get`, `._get_page`, and `.paginate` now talk to WHOOP's v2 API:
  bearer auth attached per request, a single forced-refresh retry on a 401,
  `RateLimitedError` on 429 (carrying `X-RateLimit-Reset` as `retry_after` when
  present), and `.paginate` walks `nextToken` bounded by a `max_records` default
  of 1000 rather than an unbounded default that could exhaust the daily quota.
- The four analysis tools (`summarize_period`, `metric_trend`, `correlate_metrics`,
  `compare_periods`) are now wired to `analysis.py`. `summarize_period` fetches
  each of the recovery/sleep/cycle collections exactly once regardless of how
  many of the six metrics map to it, and a metric with too little data gets its
  own `insufficient_data` entry rather than failing the other five; `correlate_metrics`
  reuses one fetch when both metrics share a collection. Every result carries its
  sample size, and the reported period reflects the timestamps actually returned
  across every collection fetched, not the range requested.
- The eight data tools (`get_profile`, `get_body_measurement`, `list_recoveries`,
  `list_sleeps`, `list_cycles`, `list_workouts`, `get_sleep`, `get_workout`) are
  now wired to `WhoopClient`. Each trims a raw WHOOP record down to the fields
  its own docstring promises, keeping `score_state` even on an unscored record;
  the four list tools gained a `next_token` parameter, surface WHOOP's cursor
  and a note when a range was truncated, and default to the last 7 days when
  both `start` and `end` are omitted (skipped on a continuation call, so a
  `next_token` isn't paired with a freshly-generated date window). A
  `RateLimitedError` now returns a retry hint instead of a raw traceback.
- The four auth tools (`whoop_auth_status`, `whoop_login`, `whoop_complete_login`,
  `whoop_logout`) are now wired to `Authenticator`. `whoop_auth_status` reads the
  token store directly rather than through `access_token()`, so checking status
  never triggers a side-effect refresh; `whoop_complete_login` verifies `state`
  before exchanging the code and reports the scopes WHOOP actually granted. No
  tool returns an access or refresh token value in any field.
- Every tool now carries a measured context-budget ceiling (`context_budget.TOOL_CEILINGS`),
  asserted in `tests/test_context_budget.py` against a worst-case fixture (a dense
  25-record page for the 8 data tools -- the most one call can return, since WHOOP
  caps a page there regardless of range -- and a >1,100-record, >2-year collection
  for the 4 analysis tools) and discovered by enumerating the live tool registry, so
  a tool added later with no declared ceiling fails CI rather than going unnoticed.
  `list_sleeps`/`list_workouts` gained a `detail` parameter (`"summary"` by default,
  `"full"` on request) that drops the millisecond stage/zone breakdown from the
  default response; when kept, that breakdown's unit is now declared once in a
  `units` envelope field rather than once per record (`stage_durations_milli` /
  `zone_durations_milli` are renamed to `stage_durations` / `zone_durations`
  accordingly). Every data tool strips null-valued fields from each record before
  returning it. The four analysis tools now report `truncated`/a retry-narrower-range
  note whenever the 1,000-record-per-collection cap they already had was actually hit,
  instead of returning a quietly incomplete summary. Measured before/after on
  `list_sleeps`: 1440 tokens (`detail="summary"`) vs 2014 (`detail="full"`).
- `WhoopClient._get` now sits behind an async token bucket (`RateLimiter`) so a
  backfill can no longer saturate WHOOP's 100/minute and 10,000/day limits
  without noticing. Per-minute and per-day counters, the daily one resetting
  on a UTC calendar boundary rather than a rolling 24h window; every response
  reconciles the bucket against WHOOP's own `X-RateLimit-Limit`,
  `X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers, which take priority
  over local accounting since the budget may be shared across callers this
  process doesn't know about (#9). A 429 now honours `Retry-After` exactly and
  falls back to capped exponential backoff with jitter only when that header
  is absent, giving up after 5 attempts and raising `RateLimitedError`. Two
  priority classes, `INTERACTIVE` and `BACKFILL`, so an interactive tool call
  is never queued behind a backfill that got there first; nothing issues
  `BACKFILL` yet (that's #14). Both limits are configurable via
  `WHOOPMCP_RATE_LIMIT_PER_MINUTE` / `WHOOPMCP_RATE_LIMIT_PER_DAY` for when
  WHOOP grants an increase.
- New `store.py`: a `sqlite3` persistence layer, making `Config.cache_path`/
  `.cache_enabled` real (previously declared, never read). Six tables --
  cycles, sleeps, recoveries, workouts, body measurements, profile -- each
  keyed by `(whoop_user_id, resource_id)` (or `whoop_user_id` alone for the
  two singleton tables), storing the extracted columns other modules
  already read alongside the full raw JSON payload, plus a `sync_state`
  table (user, entity, cursor, last run, outcome) and a `deleted_at` column
  on every entity table reserved for #18. Schema versioning via a
  `PRAGMA user_version` ladder, applied forward on every open. Every write
  is an upsert keyed on the primary key -- a recovery WHOOP rescores days
  later updates in place rather than duplicating -- and every read function
  requires `whoop_user_id` as its first argument, with no default and a
  runtime check behind the type hint. Not yet wired into `server.py` or
  `client.py`; this issue is the data layer only, importing from neither.
- Every tool that reads data now takes its caller's identity from a `Principal`
  carried on `AppContext` (`_ensure_principal`) rather than trusting whatever
  token happens to be loaded process-wide. Resolved once at startup from the
  authenticated profile and again right after `whoop_complete_login`, never
  from an environment variable; a tool invoked with no resolved principal
  raises a typed error naming `whoop_login` before making any network call,
  and `whoop_logout` clears it back to unresolved. This is a shape change,
  not a feature -- no database, no session store -- so that a second user
  (#29) becomes a change to one resolver rather than a rewrite of every tool.
- `Config` gains `transport` (`stdio`/`streamable-http`), `http_host` and
  `http_port`, configurable via `WHOOPMCP_TRANSPORT`/`WHOOPMCP_HTTP_HOST`/
  `WHOOPMCP_HTTP_PORT` and overridable per invocation with `__main__.py`'s
  new `--host`/`--port` flags. `/health` and `/ready` are now registered on
  the streamable-http ASGI app (`server.py`'s `_register_health_routes`,
  via the SDK's own `custom_route`): liveness always answers `200`, never
  touching the lifespan, so a downstream problem can't take it down too;
  readiness runs a small, extensible list of named checks (today: is the
  configured token store readable) and reports `503` with per-check detail
  when one fails -- verified to disagree with liveness in a real request
  against the actual ASGI app, not just in theory. A new
  `create_streamable_http_app()` factory lets an operator run more than one
  worker via `uvicorn ... --factory --workers N` instead of the single-
  process default. The same 16 tools are proven to answer identically over
  both transports, including a real MCP JSON-RPC exchange against the
  streamable-HTTP app, not just the existing in-process test path.

  **Known limitation, not resolved in this change and reported on #27
  rather than guessed at:** a token refresh is not yet safe across more
  than one worker process. A cross-process lock was built and then removed
  before merge -- `Authenticator.refresh()` releases its lock before the
  network call completes (coordinating within one process via a private
  future with no cross-process equivalent), so a lock alone cannot stop
  two workers from each completing a refresh with the same about-to-rotate
  token, which destroys the credential. Fixing this needs either a change
  to `Authenticator` (which conflicts with this issue's own "don't change
  Authenticator" requirement) or a compare-and-swap against a shared store
  (needs #13, not yet merged). Run one worker for token refresh, or accept
  that a concurrent refresh under multiple workers can force a re-login,
  until this is resolved.
- `analysis.Summary`/`summarize_period` now report `median` (a better centre
  than the mean for the skewed distributions recovery and sleep produce)
  and `days_missing` -- the requested period's length in days minus the
  number of *unique calendar dates* actually covered, not minus the raw
  record count, so a metric with two scored records on the same day
  doesn't look more complete than it is. `compare_periods` adds a
  standardised effect size (Cohen's d, via pooled standard deviation) per
  metric alongside the existing delta, falling back to `None` rather than
  raising when it's undefined (fewer than two observations on either
  side, or both periods perfectly constant), and a `coverage_asymmetric`
  flag per metric when the two periods' day-coverage fractions differ by
  more than 0.5 -- coverage asymmetry is usually the real explanation for
  a delta, not the thing being measured. A new top-level
  `period_length_note` on `compare_periods` names when either period's
  length isn't a multiple of seven, since a Monday-to-Friday window and
  one spanning a weekend aren't like-for-like. No p-value anywhere: these
  are small, autocorrelated daily samples, and an effect size with an
  explicit `n` is honest where a p-value would be a false credential.
- `correlate_metrics` now sweeps a range of day-offsets instead of reporting
  one correlation, and every point in the sweep carries both Pearson's r
  and Spearman's rho (`analysis.spearman`, ranks-based, ties resolved by
  average rank) rather than Pearson alone. `lag_days` (default 3, capped at
  14) sets the sweep radius; a positive lag means `metric_a`'s date
  precedes `metric_b`'s. The whole sweep is always returned, never just
  its best lag, and a lag with too few surviving pairs is reported as
  refused rather than silently dropped. This path joins the two metrics by
  calendar date rather than `correlate()`'s existing cycle_id join -- lag
  arithmetic is fundamentally a date operation, and the tool's docstring
  and `INSTRUCTIONS` now both say so, since the two joins do not coincide
  in general (a Recovery is created hours after the Cycle it belongs to,
  which can shift the "physiologically aligned" pairing by a day). This is
  a breaking change to `correlate_metrics`' response shape -- no flat,
  single-correlation mode remains.
- `analysis.Trend`/`metric_trend` now report fit quality alongside the slope,
  as a number (`r_squared`, reusing the existing `pearson` primitive on the
  same day-offset/value series already fed to `linear_slope`) and as a word
  (`fit_quality`: "strong"/"moderate"/"weak"/"negligible", with the bands
  stated in code so the word never hides the number). `trend()` now refuses
  below `MIN_TREND_SAMPLES` (8, mirroring `MIN_CORRELATION_SAMPLES`) rather
  than returning a slope from too few points, and a metric with zero
  variance now correctly refuses too (r² is undefined for a constant
  series, where the slope alone wouldn't have caught it). Also new:
  `rolling_7d`/`rolling_30d`/`rolling_90d`, calendar-day-deduplicated rolling
  means, so the model can describe a trend's shape and not just its
  direction. Windowed by date, not row count, with a minimum-periods rule
  that resets after any gap at least as long as the window itself -- so the
  first points after a long gap in a user's data don't get reported as a
  full window's mean when they're really an average of whatever handful of
  points the gap happened to leave nearby.
- New `webhooks.py`: a `POST /webhooks/whoop` receiver (#17), registered on
  the streamable-http app via `custom_route` alongside `/health`/`/ready`
  rather than a second web framework. Verifies `X-WHOOP-Signature` as
  base64 HMAC-SHA256 of the raw request bytes prefixed with
  `X-WHOOP-Signature-Timestamp`, keyed on `Config.client_secret`, via
  `hmac.compare_digest`; a missing header, a tampered body, a wrong-secret
  signature, or a timestamp more than `WHOOPMCP_WEBHOOK_TIMESTAMP_SKEW_SECONDS`
  (default 300s) from now are all rejected before the body ever reaches a
  JSON decoder, so a replayed capture of a genuine request has a bounded
  window rather than forever. A verified request is handed to an in-process
  `asyncio.Queue` and answered `200` immediately -- WHOOP retries a slow
  endpoint, and a retry of in-flight work is how duplicate processing
  starts; draining the queue is #18's job, not this one. Off by default
  (`WHOOPMCP_WEBHOOKS_ENABLED`), and a request that hits the route while
  disabled gets the same `404` a genuinely unregistered path would. No log
  statement on any path -- accepted, rejected, or disabled -- includes the
  body, the signature, or the secret.
- New `webhook_processor.py`: drains #17's queue and makes it idempotent (#18).
  A new `store.py` schema v2 table, `webhook_events`, keyed uniquely on
  `trace_id`, is written before an event is processed and doubles as a
  replay log; a duplicate delivery is recognised there before a second
  fetch ever happens. Every fetch goes through `WhoopClient`'s own rate
  limiter, one request per event, and an unknown `user_id` is dropped
  (counted, not an error). Handles the v2 API's sharpest trap: `recovery.updated`
  and `recovery.deleted` carry the associated *sleep's* UUID, not a cycle id
  and not a recovery id (recoveries have none) -- resolved by fetching the
  sleep and reading its own `cycle_id`, never by treating the payload's `id`
  as a cycle or recovery id directly. `*.deleted` never fetches (the
  resource is already gone); the recovery variant instead resolves its
  cycle from a sleep already sitting in the store, since a fetch-free
  lookup is the only kind `*.deleted` is allowed. Out-of-order deliveries
  are protected by comparing the fetched record's own `updated_at` against
  what's already stored, so a late delivery of stale data can't clobber a
  newer record. A permanently-failing event retries with capped exponential
  backoff and full jitter before landing in `dead_letter` after 5 attempts,
  so one poisoned event can't wedge the queue for every event behind it.
  The consumer task is started by `server.lifespan` only when
  `webhooks_enabled` is true, reading the queue `build_server()` stashes on
  the server instance it returns (`_webhook_queue`) -- the only channel
  available to reach `build_server()`'s scope from inside `lifespan`, which
  the SDK calls back with just the server itself as its argument.
- New `mcpauth.py`: whoopmcp as an OAuth 2.1 *resource server* for inbound MCP
  requests (#28), separate from `auth.py`'s outbound WHOOP grant -- neither
  module imports the other. Serves RFC 9728 protected-resource metadata at
  `/.well-known/oauth-protected-resource` via `setup_mcp_auth()`, and
  `MCPTokenVerifier` rejects any token whose resource claim doesn't name this
  server (RFC 8707) or has none at all. Pins spec revision `2026-07-28`
  (`mcp_types.version.LATEST_PROTOCOL_VERSION` in the installed SDK) as a
  literal `SPEC_REVISION`, asserted by its own test so bumping it is a
  deliberate edit. No Dynamic Client Registration or CIMD wiring: both are
  authorization-server-side concerns, and whoopmcp supplies no
  `auth_server_provider`, so neither is reachable here. `MCPTokenVerifier`
  resolves no real tokens yet -- verifying an opaque bearer string against an
  external, unspecified authorization server (JWKS or introspection) is a
  decision this issue's text and the installed SDK both leave open, so every
  token is rejected until a later issue wires in a real resolver; the RFC 8707
  check itself is real, independently callable logic waiting for that. Not
  wired into `server.py`: nothing here maps a validated token to a WHOOP
  member (that's #29), so turning on enforcement for the real `/mcp` endpoint
  today would only break existing clients, not protect anything yet.
- New `tests/test_tenancy.py`: pins down issue #29's tenancy contract ahead of
  its implementation. Specifies a `principal_members` mapping table written
  only by a completed WHOOP login, never inferred from a header or accepted
  from a caller-supplied parameter; one `resolve_member_id` edge resolver
  that audits every call and never defaults an unmapped principal;
  database-level scoping proven by a deliberately unscoped query, including
  the sharper case of a completely unfiltered `UPDATE`, which needs an
  internal rollback (not just a raised exception) to actually fail closed
  rather than leaving a pending mutation for a later commit to persist; and
  a registry-driven cross-tenant sweep over `build_server().list_tools()` --
  never a hand-maintained tool name list -- shown during development to
  catch a deliberately unprotected tool before it can leak another member's
  data.
- Issue #29 implements the tenancy contract the entry above specified. A
  `store.py` schema v3 adds `principal_members` (composite key `client_id`/
  `issuer`/`subject`, `''` sentinels rather than `NULL` so two no-subject
  principals can't silently collide) written only by `whoop_complete_login`,
  and `tool_call_audit`, shape-locked to `whoop_user_id`/`tool_name`/
  `called_at` with no column to carry a payload in. `server.resolve_member_id`
  is the one edge resolver every data/analysis tool now calls, through a new
  `_ensure_matches_live_grant` that replaces the old bare `_ensure_principal`
  gate and additionally refuses a resolved member that isn't this process's
  one live WHOOP grant; an unmapped principal raises `UnresolvedPrincipalError`
  rather than defaulting, and a caller-supplied header or query-param identity
  hint is never consulted. Database-level enforcement is a new
  `store._execute_scoped`, built on `sqlite3.Connection.set_authorizer` and
  now the only way any of store.py's seven tenant-scoped tables are read or
  written: a query touching one without reading its own `whoop_user_id`
  column raises `UnscopedQueryError` and rolls back before any row reaches a
  caller, closing the gap where a non-`SELECT` statement has already fully
  executed by the time the violation is caught. `lifespan()` now opens the
  store unconditionally rather than only when webhooks are enabled, so this
  join has something to resolve against outside of tests.
- Issue #30: tokens are now encrypted at rest. New `crypto.py` seals/unseals
  bytes with AES-256-GCM (`cryptography`'s own AEAD, no custom framing),
  binding the key version into the authentication tag so a relabeled
  envelope fails closed instead of authenticating against the wrong key. A
  new `EncryptedFileTokenStore` (`WHOOPMCP_TOKEN_BACKEND=encrypted-file`,
  keyed by `WHOOPMCP_TOKEN_ENCRYPTION_KEY_V<N>` env vars plus a
  `..._VERSION` pointer) re-seals a record under the current key version
  lazily on its next read, so rotation needs no downtime and no forced
  bulk re-encrypt -- both key versions just have to stay set for as long
  as the transition takes. `Authenticator.revoke_and_forget` and a new
  `auth.revoke_upstream` call WHOOP's `DELETE /v2/user/access` before
  forgetting the local token, exposed only via a new `delete-member` CLI
  subcommand (`__main__.py`) and `store.delete_principal_links_for_member`
  -- deliberately not on `client.py` and never registered as an MCP tool,
  so an LLM-driven tool call can never reach it.

- Issue #32: data subject rights -- export, erasure, and a real retention
  job. Three new operator-only CLI subcommands (`__main__.py`), none
  registered as an MCP tool and none touching `client.py`, per #30's own
  precedent: `export-member` writes one JSON document covering every table
  `store.py` defines for one member (health data, webhook events,
  tool-call audit, principal links, plus the scopes actually granted --
  never the token itself); `erase-member` reuses `Authenticator
  .revoke_and_forget` (#30) for the upstream revoke, then permanently
  `DELETE`s every row a new `store.erase_member_data` covers across a new
  `store._ERASURE_TABLES` (`_TENANT_SCOPED_TABLES` plus `webhook_events` and
  `tool_call_audit`) -- a real removal, verified at the database level, and
  a structurally distinct code path from #18's `deleted_at` soft-delete
  (`principal_members` is deliberately excluded, left to the existing
  `delete_principal_links_for_member`); `enforce-retention` deletes rows
  past a configured age (`--max-age-days`, default 730) via a new
  `store.enforce_retention`, a deliberate cross-tenant sweep per table (keyed
  per table by a new `store._RETENTION_TIMESTAMP_COLUMNS` map) rather than a
  scheduler this project does not have -- an operator wires it into their
  own cron or systemd timer. `store._ERASURE_TABLES` is asserted against the
  live schema (`PRAGMA table_list`), not a second hand-maintained list, so a
  future migration that adds a table without erasure coverage fails that
  test rather than shipping silently unprotected. `PRIVACY.md` and
  `README.md` now split every claim that differs between local mode (your
  WHOOP credentials never leave your machine) and hosted mode (`WHOOPMCP_TRANSPORT=streamable-http`,
  #27; an operator holding other members' health data server-side is a GDPR
  controller, not a bystander) into their own sections, including an honest
  statement that this project takes no backups of its own in either mode --
  verified by grepping the repository for one, not assumed.

### Changed

- WHOOP has confirmed the 100/minute and 10,000/day rate limits are **per
  application** (this project's `client_id`), shared across every member
  who has authorised it, not a separate budget per member (#9). No constant
  changes -- `RATE_LIMIT_PER_MINUTE`/`RATE_LIMIT_PER_DAY` already matched --
  but it settles the assumption #11's shared, process-wide `RateLimiter`
  was built on, and confirms #13 through #16 are required rather than
  nice-to-have for a hosted, multi-member deployment. Documented in
  `README.md`, `docs/SETUP.md`, and at the constants themselves. Still
  outstanding, and not something a pull request can close: filing WHOOP's
  rate-limit increase request and recording its status.
- **Support narrowed to the two newest stable Python releases, 3.13 and
  3.14.** `requires-python` was `>=3.10` while CI is the thing that decides
  what actually works, so the floor now matches the matrix instead of
  advertising four versions and vouching for them by inference. Python has no
  LTS track; these two are supported upstream until 2029 and 2030. Users on
  3.10–3.12 should stay on a release made before this change.

### Fixed

- `Authenticator.refresh` is now single-flighted. WHOOP invalidates the old
  refresh token the instant it issues a new one, so two callers racing the
  same refresh previously risked the loser overwriting a live token with a
  dead one, or (once one caller's refresh failed, e.g. `invalid_grant`)
  every other waiting caller independently retrying the same already-killed
  refresh token. Concurrent callers now coalesce onto whichever refresh is
  already in flight and share its result *or* its failure; a lock behind a
  small interface (`RefreshLock`, with an in-process `asyncio.Lock`-backed
  default) coordinates this, so hosted mode's eventual cross-process lock
  (#27, #30) can be supplied without changing `Authenticator`. `invalid_grant`
  now clears the stored token and raises pointing at `whoop_login`, rather
  than leaving a dead credential in place for the next call to trip over.
- The file token store advertised mode `0600` on every platform, but Windows
  does not enforce POSIX modes and the token was landing at `0666`. The
  guarantee is now scoped to macOS and Linux in the docs, and on Windows the
  store logs a one-time warning pointing at the keyring backend, which does
  protect the token there.

## [0.1.0] - 2026-08-10

Initial scaffold. The structure, tool surface, configuration and test harness
are in place; network and analysis internals are stubbed and raise
`NotImplementedError`. Nothing talks to WHOOP yet.

### Added

- Project layout, packaging, and CI (pytest, ruff, mypy, CodeQL, pip-audit).
- `Config` resolved from the environment, with validation — including a
  rejection of `http://` redirect URIs, which the WHOOP dashboard will not
  accept anyway.
- OAuth 2.0 scaffolding: authorisation URL construction, `state` generation
  and constant-time verification, `Token` with expiry skew, and two token
  stores (file at mode `0600`, or the OS keychain via the `keyring` extra).
- WHOOP v2 client surface: one method per documented endpoint, plus query
  parameter normalisation that clamps `limit` to the API's 25-record maximum.
- Analysis primitives: `mean`, `stdev`, `pearson`, `linear_slope`, each
  raising rather than returning a misleading number on degenerate input.
- 16 MCP tools registered on the SDK's `MCPServer`, all data tools annotated
  `readOnlyHint`, with server instructions covering cycle semantics, scoring
  state, and the wellness-not-clinical boundary.
- Documentation: README, `docs/SETUP.md`, `PRIVACY.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.

[Unreleased]: https://github.com/kurok/whoopmcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kurok/whoopmcp/releases/tag/v0.1.0
