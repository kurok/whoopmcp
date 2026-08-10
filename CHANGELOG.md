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
