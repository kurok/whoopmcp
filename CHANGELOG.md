# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Issue #76: a `whoopmcp login` terminal subcommand for the OAuth dance --
  prints the authorize URL, prompts for the pasted redirect (a full URL, or
  a bare `code=...&state=...` fragment, falling back to separate `code`/
  `state` prompts if neither parses), and exchanges them via the same
  `Authenticator` the in-chat `whoop_login`/`whoop_complete_login` pair
  uses. Additive, not a replacement -- that pair stays exactly as it is for
  MCP clients with no terminal a user can reach. Preferred when a terminal
  is reachable, since the authorization code never has to travel through
  the MCP client or its model provider to reach the exchange. No browser
  auto-launch (printing the URL is enough, and a launch adds a failure mode
  for zero benefit on a headless box, SSH session, or container) and no
  localhost listener (WHOOP rejects plain `http://` redirect URIs outright,
  so manual paste is the only mechanism the redirect scheme leaves).
- Issue #17: `/webhooks/whoop` now enforces its own inbound rate limit --
  the one scope bullet the original merge left out. A fixed per-minute
  window, checked after the `webhooks_enabled` 404 but before the body is
  read or the signature verified, so a flood costs neither a body read nor
  an HMAC, and a 429 leaks nothing about signature validity. Deliberately
  independent of `client.RateLimiter`'s outbound WHOOP budget -- sharing a
  counter would let an inbound flood spend it, the exact coupling the issue
  forbids. New config: `WHOOPMCP_WEBHOOK_RATE_LIMIT_PER_MINUTE` (default
  `120`; `0` or negative disables it). Under more than one uvicorn worker
  each process holds its own counter, same per-process caveat as
  `metrics.py` and `create_streamable_http_app` already document.
- Issue #31: a `/metrics` endpoint exposing Prometheus-format observability
  for sync lag per member, webhook delivery silence (per member and
  fleet-wide), webhook signature-verification failure rate, WHOOP API 429s
  and remaining rate budget, and token refresh failures by cause (with
  `invalid_grant` broken out) -- plus a matching `ops/alerts.yml` rules
  file, one rule per alert the issue names. Off by default
  (`WHOOPMCP_METRICS_TOKEN` unset -> 404, same as `webhooks_enabled`'s
  precedent) and fails closed twice over: the endpoint requires a bearer
  token compared with `hmac.compare_digest`, and every per-member series is
  additionally withheld unless `WHOOPMCP_METRICS_SALT` is set, since an
  unsalted hash of a WHOOP user id is reversible by enumeration and would
  defeat the whole point of the `member_ref` label. Backfill queue depth
  was in the issue's own Scope but is intentionally not implemented: there
  is no backfill queue anywhere in this codebase (`backfill.py`'s
  `run_backfill` is a synchronous, CLI-invoked run with no persistent job
  record), and building one would be a substantial feature outside this
  issue's scope.
- Issue #26: three MCP prompts chaining the *analysis* tools rather than
  the raw data tools, so the model sees a composition worth imitating
  instead of an invitation to dump records -- `morning_readiness_briefing`
  (`metric_trend` + `whoop_outliers` on `recovery_score` over the last 14
  days), `weekly_training_review` (`summarize_period` over the last 7 days
  + `correlate_metrics` on `strain` vs `recovery_score` over the last 4
  weeks), and `sleep_debt_investigation` (`metric_trend` +
  `correlate_metrics` on `sleep_performance` -- the nearest available
  proxy, since no sleep-*duration* metric is registered -- vs
  `recovery_score` over the last 30 days). Each instructs stating the
  actual coverage window reasoned over, and stays consistent with
  `INSTRUCTIONS`'s own no-diagnosis, no-causal-claim guidance. Also, the
  issue's four `whoop://user/...` resources (`profile`, `latest-recovery`,
  `latest-sleep`, `latest-cycle`), served as one `whoop://user/{item}`
  template rather than four static resources: a static resource's function
  in the installed SDK (`mcp==2.0.0`) is structurally incapable of
  receiving `Context` at registration time, so the per-user identity gate
  every one of these four requires could never run inside one -- see
  `server.py`'s own `_register_resources` docstring for the full
  verification. The four exact URIs still resolve unchanged; the one
  visible consequence is that they surface via `resources/templates/list`
  rather than `resources/list`. Also: `store.py` gained
  `get_latest_recovery`/`get_latest_sleep`/`get_latest_cycle` (the "most
  recent record" accessors the resources use), and `_tool_name` now falls
  back to a resource's own `uri` when no tool `name` is present, so a
  resource read audits correctly instead of logging as `"<unknown>"`.

- Issue #24: `whoop_outliers(metric, start, end, z=2.0)` and
  `whoop_streaks(metric, start, end, threshold, direction)`. Two new pure
  `analysis.py` functions back them: `rolling_z_scores` (a rolling, not
  global, z-score per day -- a genuine sustained shift in the metric does
  not read as a month of anomalies) and `find_streaks` (maximal
  consecutive-day runs above/below a threshold). `rolling_z_scores` borrows
  `_rolling_means`' own gap-aware "current run of coverage" rule (#22) but
  never drops a day: every warm-up day is tagged `unscored_reason ==
  "warm_up"` and reported under `whoop_outliers`' own `warmup_days`, rather
  than silently absent -- a dropped day reads as a normal one. The tool's
  own outlier *decision* for each warmed-up day scores it against a local
  neighbourhood of up to 14 measured points on each side (`context_window`,
  a new pure helper, at a bigger radius than its own display use below)
  rather than that same trailing window: a strictly-causal window starves
  on sparse coverage (two points 13 days apart, just inside a 14-day
  window, can never produce |z| >= 2 by construction, regardless of how
  extreme the value is), while a wider *trailing* window would instead
  make the seasonal-drift acceptance test's own transition period
  over-flag. Each outlier carries up to 3 nearest-measured-neighbour
  context days either side (`context_window` again, truncated correctly at
  the range's own edges) and, for that day only, whichever of the other 5
  friendly metrics have a value that day -- 5 extra `store.get_metric_series`
  calls total, never one per outlier. `find_streaks` enumerates every
  calendar day in the requested range (not just measured ones), classifying
  each `DayStatus` as `"missing"` (no scored record at all -- e.g. the
  strap wasn't worn), `"failing"` (measured, does not meet the
  threshold/direction), or `"passing"`; both `"missing"` and `"failing"`
  end a streak with no bridging logic, and the full `days` list is
  returned alongside `streaks` so a caller who disagrees with "missing
  breaks a streak" can reconstruct the alternate interpretation itself --
  the issue's own Notes leave that judgement call to the caller, not this
  tool. `direction` is `"above"` (`value >= threshold`) or `"below"`
  (`value <= threshold`), both inclusive of the threshold itself. Both
  tools source their metric via #20's own `store.get_metric_series`/
  `_resolve_metric_timeseries_source`, never a live fetch or a raw-record
  refetch, and never raise `InsufficientDataError` -- an empty or
  single-day range degrades to a coherent, empty-but-honest response
  rather than refusing, a deliberate departure from `metric_trend`/
  `correlate`'s "refuse below N" convention. Registered with the full
  `coverage`/`range_coverage` envelope (#16's own convention), not #20's
  token-cost exception. New `context_budget.TOOL_CEILINGS` entries for
  both, measured against their own worst-case fixtures in
  `tests/test_context_budget.py`.
- Issue #20: `whoop_timeseries(metric, start, end, granularity="day")` --
  one tool replacing per-entity `list_*` calls for "how has X trended"
  questions, returning a flat `[{date, value}, ...]` series with the unit
  declared once in the envelope (direction, e.g. "lower is generally
  better" for resting_heart_rate, lives in the tool's own description
  instead, per the issue's own Notes). Aggregated in SQL (a new
  `store.get_metric_series`, one generic function guarded by its own
  table/column allow-lists, never pandas/numpy) at day/week/month
  granularity; a week bucket's date is the Monday that starts it, a month
  bucket's is the 1st, and multiple records in one bucket are averaged, not
  summed. Missing buckets are absent, never zero; unscored records are
  excluded via the same `score_state = 'SCORED'` rule `extract_metric`
  already applies in Python. Reuses #16's `_METRIC_COLLECTION`/
  `_COLLECTION_TO_ENTITY` and analysis.py's `_METRIC_PATHS` rather than a
  second metric-to-column table; an unknown metric name raises listing all
  6 valid names. Capped at 1000 points per call, reported via
  `truncated`/`note` like the existing analysis tools. Carries a single
  flat `range_coverage` entry (reusing #16's own `_range_coverage_entry`)
  so an absent bucket can never be confused with "this range was never
  synced" -- but deliberately not the fuller `coverage` envelope (earliest/
  latest, backfill status, incremental-sync status) every other repointed
  tool carries (#16): that envelope's fixed bookkeeping cost would defeat
  this tool's own point. Measured, not assumed: `list_sleeps` costs ~4.2x
  `whoop_timeseries`'s tokens over 30 days and ~5.1x over a full year (both
  asserted as regression floors in `tests/test_whoop_timeseries.py`) --
  short of the issue's "order of magnitude" framing, the honest number for
  the design actually shipped. New
  `context_budget.TOOL_CEILINGS["whoop_timeseries"]` entry, measured against
  a 365-day daily fixture.
- Issue #19: webhook registration, local replay and the reconciliation
  backstop. `docs/SETUP.md` gained a "Webhooks (optional)" section covering
  endpoint registration and the signing-secret rotation gotcha -- the
  signing secret verified in `webhooks.py` IS `WHOOP_CLIENT_SECRET`, so
  rotating it also breaks the OAuth token flow for every already-linked
  member, not just webhooks. A new `webhook_processor.replay_webhook_event`
  re-runs a stored `webhook_events` row's own `event_body` through
  `process_webhook_event` directly -- never re-POSTing or re-signing
  anything -- raising a new `UnknownTraceIdError` for a trace_id never seen;
  idempotency (#18) makes replaying an already-`success`/`dead_letter` row a
  safe no-op and a `pending` row a genuine reprocess. A new
  `reconciliation.py` module (`run_reconciliation`) supplies the one thing
  #15's own incremental sync can never catch by construction -- a dropped
  `*.deleted` webhook: it diffs a fresh WHOOP listing of the last
  `--window-days` (default 30) against the store and soft-deletes any
  locally-live recovery/sleep/workout the listing no longer mentions, reusing
  `webhook_processor.set_deleted_at` (promoted from the private
  `_set_deleted_at`) rather than a second mechanism; every fetch goes out at
  `RequestPriority.BACKFILL`. Per-user last-webhook-delivery time is now
  recorded on every successfully-processed delivery, in a new
  `webhook_delivery_state` table (schema v4) via `store.record_webhook_delivery`/
  `get_last_webhook_delivery` (plus `get_webhook_delivery_state_for_member`,
  wired into `export_member_data`), so #31 can later alert on a member who
  has gone quiet relative to their own baseline. Two new CLI-only
  subcommands, neither an MCP tool: `whoopmcp replay-webhook --trace-id ID`
  and `whoopmcp reconcile-webhooks --whoop-user-id ID [--window-days N]` --
  there is no in-process scheduler, so an operator wires the latter into
  cron/systemd, alongside (never instead of) #15's own sync.
- Issue #16: the 8 data tools and 4 analysis tools now answer from the
  local store (#13/#14/#15), not the live WHOOP API -- a miss is a coverage
  gap, reported explicitly, never a live fetch. Every response carries a
  `coverage` envelope (earliest/latest activity date held, last backfill
  outcome, last successful incremental-sync time -- or, for the profile and
  body-measurement singletons, `{synced, last_updated_at}`); every
  date-range tool additionally carries `range_coverage`, flagging a request
  that is wholly or partly outside what has been synced instead of
  returning a silently short result. A new `whoop_data_coverage` tool
  reports this directly for all six entities in one call. `store.py` gained
  `include_deleted`-gated filtering on the four collection getters (soft-
  deleted rows no longer resurface through a repointed tool; a data-subject
  export still sees them, via `include_deleted=True`), single-record
  `get_sleep_by_id`/`get_workout_by_id` lookups, four `get_*_coverage`
  earliest/latest queries keyed off each entity's own activity-date column
  (`created_at` for recoveries, `start`/`end` for sleeps/cycles/workouts --
  never `updated_at`), and `get_profile_updated_at`/
  `get_body_measurement_updated_at`. `client.py` is unchanged: the live API
  path still exists for `whoop_sync` alone.
- Issue #15: incremental sync from an `updated_at` high-water mark. A new
  `sync.py` (`run_sync`) walks the same four collections `backfill.py` (#14)
  does -- recoveries, sleeps, cycles, workouts -- forward from each one's own
  high-water `updated_at` mark (never `created_at`, so a rescored recovery or
  sleep is picked up, not just a newly-created one), upserting every record
  and advancing the cursor only after a page commits, so a crash mid-page
  re-fetches rather than skipping. A ~60s overlap margin is subtracted from
  the stored mark before every request; upsert idempotency absorbs the
  resulting redelivery. Steady state costs one request per collection.
  Progress lives in `sync_state` under its own entity namespace
  (`f"{entity}:incremental"`, e.g. `"cycles:incremental"`) so an interrupted
  backfill's own bare-entity resume cursor is never overwritten or
  reinterpreted, and vice versa. A new `whoop_sync` MCP tool exposes this for
  a user who doesn't want to wait for a schedule (none exists yet -- see
  #35); it is gated on `Config.cache_enabled` like backfill, but -- since,
  unlike backfill, it is sanctioned for the tool surface -- returns a plain
  `{"synced": false, ...}` tool result instead of raising when the store is
  disabled.
- Issue #35: local mode stays a first-class, tested distribution. A new
  `whoopmcp doctor` CLI subcommand (`__main__.py`, backed by a new
  `doctor.py`) checks configuration, stored credentials, the local store,
  and sync state in one pass, one sentence each, exiting non-zero if
  anything needs attention and zero if it's all clean -- dispatched ahead
  of `__main__.py`'s own up-front `Config.from_env()` call, since "missing
  configuration" is one of doctor's own checks. The sync check reports
  honestly that local mode has no scheduled incremental sync yet (#15 is
  not merged) rather than judging staleness against a schedule that
  doesn't exist. CI's `test` job matrix now documents -- with the empirical
  verification behind it -- that every cell already covers both transport
  modes in one run (`tests/test_http_transport.py` always exercises the real
  streamable-http ASGI app; everything else always exercises the stdio
  paths; a `WHOOPMCP_TRANSPORT` matrix axis was measured to produce
  byte-identical per-test outcomes and deliberately NOT added, since it
  would double the cell count while covering nothing). `docs/SETUP.md` now documents
  the ten-authorised-member cap WHOOP places on every developer app
  (confirmed with WHOOP), including your own, and the same live-fetch
  freshness tradeoff `doctor`'s sync check reports.
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
- `whoopmcp backfill --whoop-user-id N` (#14): resumable, throttled history
  import. Walks every collection (recoveries, sleeps, cycles, workouts)
  newest-first at `RequestPriority.BACKFILL` -- the first consumer of #11's
  low-priority class, so an import never starves an interactive question --
  upserts through the persistent store, and checkpoints WHOOP's own
  `nextToken` into `sync_state` after every committed page, so an interrupted
  run resumes exactly where it stopped and never re-requests a committed
  page. Honours a new optional `WHOOPMCP_BACKFILL_FLOOR_DATE` (ISO 8601,
  passed as the API's own `start` lower bound; unset walks until history is
  exhausted, malformed values fail at startup) and refuses to run unless
  `WHOOPMCP_CACHE=true` -- the gate issue #13 anticipated, keeping
  PRIVACY.md's "off by default" promise literally true. Deliberately
  CLI-only, never an MCP tool, per #30/#32's operator-only precedent.

### Changed

- Issue #54: `metric_trend`'s `rolling_7d`/`rolling_30d`/`rolling_90d` are now
  downsampled -- decimated, never averaged -- to whichever of `daily`
  (step 1 calendar day), `weekly` (7), or `monthly` (30) resolution keeps
  every series within a shared 120-point cap, chosen once from the longest
  of the three series and applied to all of them. Every returned point is
  still a real rolling mean `analysis.trend()` actually computed for that
  real date; the most recent point is always kept. The response gains
  `rolling_resolution` (always present) and, only if even monthly overflows
  the cap, `rolling_truncated` plus an explanatory `rolling_note` --
  distinguishable from the pre-existing record-count `truncated`/`note`
  pair, which is unrelated and unchanged. A short range is unaffected:
  `rolling_resolution` is `"daily"` and the response is otherwise identical
  to before. `TOOL_CEILINGS["metric_trend"]` drops from an honestly-measured
  but unprotective 32000 to a measured 5000, now comparable in order of
  magnitude to the other analysis tools' ceilings.
- Issue #67: relocated `webhook_processor.py`'s three raw `conn.execute`
  calls against entity tables (a stored record's `updated_at`, a sleep's
  `cycle_id`, and the `deleted_at` soft-delete write) into `store.py` as
  `get_resource_updated_at`/`get_sleep_cycle_id`/`set_deleted_at`, all
  routed through `_execute_scoped` (#29). A pure relocation -- no behaviour
  change -- closing the one gap `store.py`'s own structural
  no-unwrapped-`conn.execute` test couldn't see into: it only ever parsed
  `store.py` itself, so a sibling module's raw SQL against the same
  tenant-scoped tables went unchecked. A new AST test now asserts
  `webhook_processor.py` contains zero direct `conn.execute`/
  `.executemany` calls.
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

- Issue #104: the `erase-member` CLI subcommand's erasure is now atomic across
  the health-data deletion and principal-link deletion -- either both are
  applied or neither is, ensuring a member is never half-erased. Before: the
  two deletions ran in separate transactions, so if the second failed (raising
  to the operator), the member's health data was already gone while their
  principal link remained, a state with no signal distinguishing it from
  success. The fix batches both deletes in one explicit transaction via a new
  `erase_member_and_links_atomically` function, routed through the same
  `_execute_scoped` enforcement as all other member-touching deletes.
- Issue #101: `delete-member`, `export-member`, `erase-member`, and
  `enforce-retention` each opened `config.cache_path` unconditionally, so in
  default local mode -- the mode #90 made in-memory precisely so
  PRIVACY.md's "the only thing this software writes to
  `$WHOOPMCP_STATE_DIR` is your token" would hold -- all four instead created
  a `cache.sqlite3` on disk, and `enforce-retention` went on to print a
  per-table "retention enforced" summary and exit 0 for work performed
  against a store it had just created. All four now refuse (exit 2, stderr
  only, no mention of enabling the cache) when the store is ephemeral and no
  file exists yet -- the same `store_is_ephemeral and not
  config.cache_path.exists()` check `doctor.py` already used. A leftover
  `cache.sqlite3` from an earlier `WHOOPMCP_CACHE=true` period is still
  opened and operated on exactly as before: refusing on that file would deny
  a data subject their erasure/export right, which the guard's second clause
  exists to avoid.
- Issue #99: `store._execute_scoped` required a restrictive
  `whoop_user_id = ?` equality predicate on `SELECT` only. For a non-`SELECT`
  statement it required merely that the column be *read at all*, so
  `WHERE whoop_user_id != ?`, `> ?` or `IS NOT NULL` all satisfied it on the
  mutation and deletion path -- the higher-impact half, and the opposite of
  what the docstring claimed. The equality requirement now covers `UPDATE`
  and `DELETE` too. `INSERT` is exempt by construction and stays that way:
  an insert has no `WHERE` clause and supplies `whoop_user_id` as a value,
  so every record write here (all upserts) would break under such a
  requirement -- sqlite reports `INSERT ... ON CONFLICT ... DO UPDATE` as
  both an insert and an update on the one table, so the new check ignores
  tables an insert also named. Defence-in-depth: no shipped caller relied on
  the gap, and the universal "must read `whoop_user_id`" check (the
  authorizer-backed one that catches a `WHERE`-less write) is unchanged.
  `enforce_retention`, the codebase's one deliberate all-members sweep, now
  runs its tenant-scoped deletes through `_execute_all_tenant_sweep`: a
  distinctly-named path with exactly one caller (asserted from source)
  rather than an `allow_all_tenants=True` keyword that every call site could
  pass. It waives the equality regex *only* -- the universal check still
  applies through it, so a sweep that never mentions `whoop_user_id` is
  still refused -- and what retention deletes is unchanged, row for row.
  The statement-executing half of `_execute_scoped` moved into a shared
  `_execute_with_tenancy_authorizer` so both paths enforce the universal
  check from one implementation that neither can skip. The equality check
  remains a presence regex, and now says so: it catches a missing or
  non-restrictive comparison, but not a matching fragment `OR`-ed with a
  wider clause, supplied by a subquery, or applying to a different table
  than the one being written. Closing those needs real SQL parsing, which
  would be a large change to the most safety-critical function in the
  package for a shape no caller exhibits -- a follow-up issue, not this one.
- Issue #98: `atomic_write_text`'s temp file was `path.with_suffix(".tmp")`
  -- a predictable name in the destination directory, created via
  `touch`/`chmod`/`write_text`/`replace`, all of which follow symlinks. An
  attacker able to write to that directory (e.g. `/tmp`, for
  `export-member --out`, which sends a member's full health record through
  this helper in plaintext) could pre-create that name as a symlink and
  have the plaintext delivered wherever they pointed it, with the
  destination itself left as a symlink so later reads followed it too. Now
  uses `tempfile.mkstemp(dir=path.parent)` -- `O_EXCL`, an unpredictable
  name, mode 0600 in one atomic step -- and writes through the returned
  file descriptor directly rather than reopening by path, which would have
  reintroduced the same race. `os.replace` performs the final move, so a
  destination that is itself a pre-existing symlink is replaced rather than
  written through. The temp file is now unlinked if the write fails,
  without masking the original exception. Caller-visible behaviour is
  unchanged: same signature, same final mode 0600, same atomic replace,
  same parent creation (`store._secure_db_path`'s own, separate
  parent-tightening was left alone -- its parent is always our own state
  dir, but this helper's is operator-chosen for exports, and tightening an
  operator's shared directory would lock other users out of it).
- Issue #71: CONTRIBUTING.md's "Where things go" map claimed `server.py`
  was "the only file that imports mcp" -- false: `webhooks.py` and
  `mcpauth.py` also do, confirmed by AST across all 18 modules. The map
  itself named only 8 of those 18 files, missing `__init__.py`,
  `__main__.py`, `backfill.py`, `doctor.py`, `mcpauth.py`, `metrics.py`,
  `reconciliation.py`, `sync.py`, `webhook_processor.py`, and `webhooks.py`
  -- now complete. Two new guard tests (`tests/test_module_map.py`) keep
  both facts honest going forward: one asserts every `src/whoopmcp/*.py`
  has a map entry and vice versa, the other asserts via AST that only
  those three files import `mcp`.
- Issue #75: `README.md` and `PRIVACY.md` both claimed the one mutating
  endpoint WHOOP exposes (`DELETE /v2/user/access`) "is not wired up" --
  true before #30, false since: `whoopmcp delete-member --whoop-user-id N`
  calls exactly that endpoint via `Authenticator.revoke_and_forget`. Reworded
  both to the true, narrower claim -- never registered as an MCP tool, so no
  model can revoke your grant, but reachable from a terminal as that
  operator-run command -- and added `delete-member` to the README's
  operator-command list (distinct from `erase-member`, which also erases
  stored data) and to `PRIVACY.md`'s local-mode deletion steps as the
  same-machine alternative to revoking in the WHOOP app. `docs/SETUP.md` now
  points to `whoopmcp --help` for the full operator-command list and names
  `delete-member` explicitly. `whoop_logout`'s return string now names
  `whoopmcp delete-member` alongside the existing WHOOP-app instruction. No
  behaviour change.
- Issue #70: `README.md`'s Install section told users to `uvx whoopmcp` or
  `pip install whoopmcp`, but the package isn't published (#34) -- either
  command fails or, worse, silently installs an unrelated package of a
  similar name. Replaced with the git-clone + editable-install path that
  actually works. The Configuration table's `WHOOPMCP_TOKEN_BACKEND` row
  listed only `file` or `keyring`, omitting the shipped `encrypted-file`
  backend; now lists all three. The table was also missing a
  `WHOOPMCP_TRANSPORT` row despite the README's own intro naming that
  variable -- added, with default `stdio` and values `stdio` or
  `streamable-http`.
- Issue #73: `README.md`'s status banner still called this a pre-alpha
  scaffold whose internals raise `NotImplementedError`, and its Roadmap
  table listed #1–#6 (all closed) as the tracked gaps; `docs/SETUP.md`
  repeated the `NotImplementedError` claim in troubleshooting. Rewritten to
  state what's actually true: local mode works against the real WHOOP v2
  API, the hosted surface is implemented but unaudited (#37, #69), and a
  shared hosted deployment is capped at 10 members until WHOOP approves the
  app (#33). The Roadmap table now lists the genuinely open work (#33, #34,
  #37, #69, #76, #70, #71, #75) instead.
- Issue #74: `lifespan()` opened `cache.sqlite3` unconditionally, so a
  default local stdio session (no `WHOOPMCP_CACHE`, webhooks disabled)
  created the database, linked a principal to a member on login, and wrote a
  `tool_call_audit` row on every data/analysis tool call -- despite
  PRIVACY.md promising that mode persists nothing but the token. The store
  now lives in memory only in that default mode; the principal link is
  seeded at startup from the already-resolved live grant so a valid token
  still resolves after a restart with no re-login required
  (`resolve_member_id` has no fallback to fall back on -- #29 -- so an
  unseeded ephemeral store would otherwise break every data tool). Hosted
  mode, `WHOOPMCP_CACHE=true`, and `WHOOPMCP_WEBHOOKS_ENABLED=true` are
  unaffected and keep writing to disk exactly as before. PRIVACY.md's local
  storage table and prose are corrected to match, including a stale
  "fetched, returned, and forgotten" claim that predated this issue.
- Issue #68: `open_store` created the sqlite database (and `export-member
  --out`'s data-subject export) at the process umask default -- typically
  `0644` -- despite holding the same category of health data
  `auth.FileTokenStore` already goes out of its way to protect at `0600`.
  Both now get that same discipline: the state directory is created (or
  tightened) `0700`, and the database/export file is created `0600` or
  chmod'd to it if a looser one already existed, before it is ever opened
  or written to, so no window at the umask default is ever observable. The
  `0700` directory is what protects sqlite's transient `<db>-journal`
  sidecar too -- untouched by any per-file chmod, since it exists only
  inside a single statement's execution; this codebase never enables WAL,
  so `-wal`/`-shm`, which the issue also named, never exist here at all.
  `auth._atomic_write_text` is now the public `atomic_write_text`. Mode
  enforcement is best-effort and never blocks the store from opening --
  a directory this process cannot chmod is logged, not fatal -- and, as
  with the token store, none of this is enforced on Windows (ACLs, not
  POSIX modes; disclaimed in `PRIVACY.md`, not attempted).
- Issue #65: `delete-member`/`erase-member` gated all local deletion on
  `Authenticator.revoke_and_forget()` succeeding, and revoked *the* stored
  token unconditionally. Both were wrong. (1) Once the stored grant is
  already gone -- the member revoked it in WHOOP's own app settings, or an
  operator already ran `whoop_logout` -- `revoke_and_forget` raised
  `AuthError` and both subcommands returned before deleting anything,
  making erasure permanently impossible in exactly the scenario a data
  subject is most likely to trigger it in. A new `GrantAlreadyGoneError`
  (an `AuthError` subclass, raised at `access_token`'s "no stored
  credentials" site and `_do_refresh`'s `invalid_grant` site) now lets both
  call sites treat "nothing to revoke" as revoke-step success and continue
  to local deletion, while a plain `AuthError` -- a genuine transport
  failure calling WHOOP's revoke endpoint -- still aborts with nothing
  deleted, unchanged. (2) Both subcommands guarded only with
  `principal_is_linked_to_member`, then revoked the one stored token
  regardless of which member it actually belonged to: with members A
  (stale) and B (the token's real owner) both linked,
  `erase-member --whoop-user-id A` revoked B's live grant while A's own
  stayed standing. Both subcommands now reuse `_export_member`'s existing
  `all_linked_whoop_user_ids(conn) == {whoop_user_id}` attribution guard
  verbatim: when it doesn't hold, the upstream revoke is skipped entirely
  (with a message pointing the operator at WHOOP's own app settings) and
  local deletion still completes for the requested member.
- Issue #66: `_apply_event`'s "known member" gate checked `get_profile()`
  against the `profiles` table, which nothing in `src/` writes (webhooks
  and #14's backfill both cover only the four entity collections) -- so a
  webhook event for a member who had completed `whoop_login` but had no
  `profiles` row was dropped, and then *permanently* marked `success` (the
  drop path returned normally, which `process_webhook_event` treats as
  success), so no redelivery of that `trace_id` could ever reach
  `_apply_event` again. The gate now checks
  `principal_is_linked_to_member` against `principal_members` -- the
  identity layer's own "is this a real, linked member" answer, already
  written at login and already used by the `delete-member` CLI guard. A
  drop for a genuinely unlinked member now raises a dedicated
  `MemberNotLinkedError`, which `process_webhook_event` catches separately
  from both the transient-failure retry path and the dead-letter path: the
  row is left `pending` with `attempt_count` untouched, so it neither
  counts toward `max_attempts` nor lands in `("success", "dead_letter")` --
  a later redelivery of the same `trace_id` still reaches `_apply_event`.
  Actually reprocessing rows left in this state is #19's job.
- Issue #64: the webhook replay-window check parsed `X-WHOOP-Signature-Timestamp`
  as unix seconds instead of WHOOP's documented milliseconds, so every real
  webhook missed the skew window by ~55,000 years and got rejected. The
  timestamp is now converted to seconds before comparison; `_signature_matches`
  and the 300s skew default are untouched.
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
