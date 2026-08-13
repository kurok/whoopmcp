# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Issue #37 (automated-gates half): a `bandit -r src/` CI job, wired but
  never run before now despite being declared in the `security` extra since
  #1. Triaged all 19 pre-existing findings (0 high) rather than blanket-
  disabling any check: 8 `B105` "hardcoded password" false positives (a
  URL constant, backend-name string comparisons, and paginator `None`
  defaults) and 9 `B608` "possible SQL injection" sites in `store.py` each
  get a `# nosec` naming what the interpolated value actually is and why
  it's fixed, internal, and never caller-supplied -- `B608` stays enabled
  for any new, less-careful interpolation `store.py` might grow. The 2
  `B311` (non-cryptographic `random`) sites reuse the jitter justification
  already carried by their `# noqa: S311`. Separately, ruff's `S105`/`S106`
  moved from a blanket top-level `ignore` to `per-file-ignores["tests/*"]`
  (test fixtures legitimately assign literal tokens); the 4 real `src/`
  sites this un-ignoring surfaces (`auth.py`'s `TOKEN_URL` and two
  `token_backend` comparisons, `config.py`'s `token_backend` default) each
  get an inline justified `# noqa: S105` instead. `pip-audit` and CodeQL
  were confirmed already enforcing/running, unchanged. No logic changes;
  the nine-area manual security review remains a separate, later pass.
- Issue #34: `server.json`, the MCP registry manifest, declaring
  `io.github.kurok/whoopmcp` and the PyPI package for local (stdio) use.
  Deliberately no `remotes` entry -- #27's streamable-HTTP transport merged,
  but no hosted deployment exists yet, and a registry entry pointing at
  something unmaintained is worse than no entry. `release.yml`'s Trusted
  Publishing wiring (no stored token, SHA-pinned publish action) and the
  manifest's consistency with `pyproject.toml` are now pinned by
  `tests/test_packaging.py`; CI's `build` job additionally installs the
  built wheel into a clean venv and runs `whoopmcp --version` to prove the
  distribution is installable standalone, not just well-formed. Nothing here
  publishes anything -- no tag, no upload, no registry submission -- that
  step still waits on #33.
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

- Issue #125 (#37 audit, P3): the three PyPI tools the workflows invoke are now
  pinned to exact versions -- `build==1.5.0`, `twine==7.0.0`,
  `pip-audit==2.10.1` -- across `release.yml` (2 sites) and `ci.yml` (3). They
  previously resolved whatever was on PyPI at run time, and in `release.yml`
  that is code execution inside the job that produces the distributions which
  are then published, so a compromised `build` or `twine` release would reach
  the artifact before anyone could inspect it. After #119 and #124 pinned every
  action by commit SHA, this was the last unpinned code-execution step on the
  publish path.

  Pinned via `pipx run --spec <package>==<version> <app>`, not the shorter
  `pipx run <package>==<version>`. The short form makes pipx infer the app name
  from the spec, and `build`'s console script is `pyproject-build`, not `build`
  -- verified against a real pipx rather than assumed, because `release.yml`
  only runs on a tag, so a wrong invocation there would not surface until
  release day.

  This pins *which release of each tool* runs, not each tool's own dependency
  closure, which pipx still resolves at run time. That residual is filed as
  #159 rather than implied to be covered.

- Issue #124 (#37 audit, P3): every GitHub-owned action is now pinned by commit
  SHA with its version in a trailing comment, matching the pattern the repo
  already used for third-party actions and stated as the right one. 19 `uses:`
  lines across `ci.yml`, `codeql.yml` and `release.yml` were on moving major
  tags -- `actions/checkout@v7`, `actions/setup-python@v7`,
  `actions/upload-artifact@v7`, `actions/download-artifact@v8`,
  `github/codeql-action/{init,analyze}@v4`. GitHub-owned is lower risk than a
  random third party, not no risk: a major tag is a mutable pointer, and
  `actions/download-artifact` sits between the build job and the PyPI publish,
  where a swapped artifact is a released artifact. Each SHA was resolved from
  the tag and then confirmed to exist in the action's own repository, and the
  precise release it corresponds to (`v7.0.1`, `v7.0.0`, `v7.0.1`, `v8.0.1`,
  `v4.37.6`) is recorded inline. A new test asserts both halves -- the 40-hex
  pin *and* the version comment -- since a bare SHA is unreviewable and
  unupgradeable, which is the practical objection to pinning and the reason
  dependabot needs the comment to bump it. `dependabot.yml` already tracks the
  `github-actions` ecosystem weekly, so the pins get bumped rather than rot.

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

- Issue #126 (#37 audit, P3, reachable in hosted mode): PRIVACY.md's storage table
  said logs go to "stderr only", which was false under
  `--transport streamable-http`. The SDK's `run_streamable_http_async` builds
  `uvicorn.Config` with only host, port and log level -- no `log_config` -- and
  uvicorn's default points the `uvicorn.access` handler at `ext://sys.stdout`. So
  every request line landed on stdout, client IP included, and for
  `/webhooks/whoop` and `/metrics` that is the IP of someone whose health data
  this server holds.

  Rather than only documenting the exception, the behaviour now matches the
  contract: the streamable-http branch redirects uvicorn's access handler to
  stderr before the server starts. There is no parameter for this --
  `MCPServer.run` forwards `**kwargs` to a fixed keyword-only signature that
  accepts no `log_config` -- so the lever is uvicorn's module-level
  `LOGGING_CONFIG`, which `uvicorn.Config.__init__` captures *by reference* as a
  default argument, making an in-place mutation visible to the `dictConfig` call
  uvicorn makes at startup. Verified against the installed uvicorn by identity
  check, not assumed.

  PRIVACY.md's row now also names the carve-out: if you run the ASGI app under
  your own uvicorn or gunicorn rather than `whoopmcp --transport streamable-http`,
  the redirect does not apply and the access log is yours to configure.

  Three tests. One asserts the end state -- every *effective* handler for
  `uvicorn.access` and `uvicorn.error` lands on stderr, walking propagation the
  way `logging` does, since uvicorn gives `access` its own handler but lets
  `error` propagate. One pins that the redirect is actually *called*, and before
  the server starts, because a helper nobody invokes is the same as no fix. The
  third watches the SDK: the redirect only works while the SDK leaves
  `log_config` to uvicorn's default, so that test reads the SDK's source and
  fails if it ever starts passing its own. Each was checked against a mutation
  that should break it -- blanking the helper, deleting the call site, and a
  simulated future SDK that supplies a `log_config`.

  That third test exists because an earlier draft of this change claimed the
  end-state test already covered the SDK case. It does not: a test that builds
  its *own* `uvicorn.Config` cannot observe what the SDK passes. Simulated it,
  and the end-state test passed while access logs really did go to stdout.

  The stdio path is untouched and deliberately so: it never starts uvicorn, and
  its stdout *is* the JSON-RPC channel, where a stray log line would corrupt the
  protocol.

- Issue #163 (found reviewing #121): three tests named for the RFC 8707 audience
  check did not detect its removal. Their tokens carried no `claims`, so
  `_issued_by_trusted_as` rejected them first -- `claims=None` is not a dict --
  and they would have passed identically with `_names_this_resource` stubbed to
  accept everything. Each now carries a trusted `iss`, so the only reason left to
  reject is the resource claim under test. Tests only; the audience check itself
  was always correct and enforced.

  Verified by mutation, which is the only thing that settles it. With
  `_names_this_resource` stubbed to `return True`: **before, one test noticed;
  now, four do.**

  Swept the rest of the file the same way, since the same defect could hide
  anywhere: disabling the issuer check is caught by 6 tests and disabling the
  expiry check by 7, so every check in `verify_token` is now detected by several
  tests named for it and no sibling has the vacuity defect.

  This is the mirror of the file's own #102 note, which explains why the
  resource-*acceptance* test needs a valid `iss`. The rejection tests needed the
  same thing for the opposite reason, and that was missed -- the second instance
  of this class in two iterations, after #143.

- Issue #143 (follow-up to #123): `test_revoke_and_forget_during_refresh_leaves
  _store_empty` asserted the right invariant and could not be made to fail, so it
  documented a guarantee without guarding it. Now it discriminates. Tests only --
  no source change; the interlock itself was already correct.

  The cause was not either candidate the issue guessed. The refresh it started
  was never *created*: it passed a different, expired token, so `refresh()`'s
  store recheck found the live stored token `_supersedes` it, returned that
  immediately, and `_do_refresh` was entered zero times with `_inflight_refresh`
  never set. Nothing could write to the store, so every assertion was trivially
  true. Refreshing with the *same* token the store holds makes `_supersedes`
  false, the recheck does not short-circuit, and the refresh reaches the save the
  epoch check guards.

  Proven by mutation rather than asserted: with `_do_refresh`'s
  `if epoch == self._credential_epoch:` replaced by `if True:`, the old test
  **passes** and the new one **fails**. All four epoch-interlock tests fail under
  that mutant, so none of them is vacuous.

  The test now also asserts `_inflight_refresh is not None` before proceeding,
  which is what stops it silently degrading to a no-op a third time -- the
  original version was vacuous for one reason, its replacement for another.

- Issue #138 (#37 audit, P3, latent): `crypto._associated_data` built the AEAD
  associated data as `f"whoopmcp.seal.v{version}".encode() + extra`, with nothing
  between the two, so `(version=1, extra=b"2whoopmcp.token")` and
  `(version=12, extra=b"whoopmcp.token")` produced identical bytes. Unexploitable
  today -- one caller, one fixed `extra` -- but the module advertises itself as a
  generic primitive, and a second caller whose `extra` began with a digit would
  have silently voided the key-version binding the AD exists to provide. A `|`
  now follows the version, which is sufficient rather than merely better: a key
  version is an integer, so it can never contain `|`, and the first one therefore
  always terminates it whatever the caller passes.

  The AD layout is **recorded per envelope** (`"adv"`) rather than simply
  changed, because changing it changes the AEAD tag: every already-sealed record
  would stop authenticating, which for the `encrypted-file` backend means an
  operator's stored token becomes undecryptable and they have to log in again.
  That is too high a price for a hardening fix with no reachable exploit. An
  envelope without `adv` is pre-#138 by definition and is read with the legacy
  layout, so existing records keep working; new seals always stamp the current
  format.

  A tampered marker needs no separate binding into the tag and gets none: the two
  layouts produce different bytes, so flipping it makes `unseal` compute an AD
  the tag was never made with. Verified in both directions -- downgrading a new
  envelope to the ambiguous layout, and relabelling a legacy one -- plus unknown
  values, which raise `SealError` rather than silently selecting a layout.

  Legacy envelopes are deliberately not migrated, and that is safe rather than
  merely convenient: the version binding still holds for them, so one caller's
  record does not authenticate under another caller's `extra`. The residual
  ambiguity is confined to inputs that would have to collide within a single
  caller's own fixed `extra`, and any second caller writes the new format.

- Issue #139 (#37 audit, P3, latent): a webhook payload's `id` was copied into
  `WebhookEvent.resource_id` with no shape check and interpolated straight into
  an outbound request path -- `client.get_sleep` builds
  `f"/v2/activity/sleep/{sleep_id}"` -- so an `id` of
  `../../v2/user/profile/basic` traverses to a different WHOOP endpoint, fetched
  with the member's own bearer token. `_parse_event` now requires a standard
  hyphenated UUID.

  Reproduced against the unfixed code rather than argued: a stored hostile body
  replayed through `replay_webhook_event` issues **five** real requests to
  `https://api.prod.whoop.com/developer/v2/v2/user/profile/basic` -- the retry
  loop, each attempt a genuine traversal out of the sleep endpoint. Note the
  resolved path: `BASE_URL` ends in `/developer`, so the escape stays inside
  WHOOP's API and cannot reach another host, which is why this is hardening
  rather than an SSRF.

  Still latent: a body only reaches the parser after `verify_webhook_request`'s
  HMAC gate, so forging one needs the client secret. The other route in is
  `replay_webhook_event` re-parsing an already-stored body, which is covered too,
  because validation happens at parse time and both live delivery and replay go
  through `_parse_event`. Rejection is placed before `insert_webhook_event`, so a
  hostile id leaves no row behind for a later replay to pick up.

  All three webhook resources are UUID-keyed, including `recovery`, whose events
  carry the *sleep* UUID. `cycle` -- the one resource keyed by an integer -- is
  deliberately not in `_WEBHOOK_RESOURCES`, and the integer `cycle_id` that
  `_apply_event` does use comes from the store or from WHOOP's own response body,
  never from the payload. So a single UUID rule is correct for everything the
  payload can name.

  Test ids in `test_webhook_processing.py` became real UUIDs via a deterministic
  `uuid5` helper, which keeps the readable label in the source. Without that they
  would have exercised the new rejection path instead of whatever each test is
  about -- the same trap #121 hit with `expires_at`.
- Issue #132 (#37 audit, P3, latent): `EncryptedFileTokenStore.load` is a
  *writer* -- during a pending key rotation it re-seals whatever it just read --
  and `server.py:448` runs it in a thread for every `/ready` poll while a
  refresh may be completing on the event loop. A loader could read token X, a
  refresh save Y, and the loader's re-seal then write X back, leaving a refresh
  token WHOOP had already rotated away and an `invalid_grant` on the next
  restart. Reproduced end to end.

  Closed in-process with a per-path re-entrant lock (`_TOKEN_PATH_LOCKS`)
  serialising the re-seal's compare-and-save against every `save` on that path.
  That is the scenario the issue actually describes -- `/ready`'s thread and the
  refresh share one process -- and a `threading.Lock` has none of the drawbacks
  a file lock would: nothing platform-specific, nothing left behind on a crash,
  no NFS semantics. An earlier draft of this change rejected locking wholesale on
  those grounds, which conflated kernel advisory locks with lock *files*; only
  the latter go stale.

  Across processes it is best effort: the re-seal now compares the file
  byte-for-byte against what `load` read and skips if anything changed. Measured
  rather than assumed, the residual window is *not* small -- roughly two thirds
  of the span from read to rename sits after the compare, because `seal`,
  `mkstemp`, the write and the `fsync` are all on that side. What the compare
  buys cross-process is that the common sequential interleaving is caught, not
  that the race is gone. Cross-process locking is out of scope: multi-process
  refresh is already documented as unsound.

  Safe because a re-seal is never required for correctness -- the record was
  already decryptable, and a later `load` migrates it just as well, so skipping
  only extends how long the old key must stay present.

  Two things found along the way. The re-seal also *recreated a token file
  deleted during the load*, resurrecting a credential a logout had just removed;
  it now skips instead. And the compare's first draft read the file back as
  text, so a non-UTF-8 rewrite inside the window raised `UnicodeDecodeError` out
  of `load` -- neither `SealError` nor `OSError`, so uncaught, and not
  `AuthError` either. Reading bytes removes the failure mode structurally.

  One correction to the issue's own text: it attributes the failure mode to
  #103. Git history says the re-seal-on-load arrived with
  `EncryptedFileTokenStore` itself; #103 only widened the `except` around it.
  `load` could lose data before #103 exactly as after.

- Issue #121 (#37 audit, P2, latent): `verify_token` enforced audience and
  issuer but never expiry, and its docstring enumerated the rejection reasons
  while omitting it -- which is how the gap survived review. Nothing else
  covered it either: the SDK's `RequireAuthMiddleware` has zero `expires_at`
  references, so an integration calling `verify_token` directly inherited no
  expiry check at all and would honour an expired-but-otherwise-valid token.

  A token whose `expires_at` is `None` is now **rejected as unbounded**, not
  accepted. This was #121's one genuine decision and is recorded on the issue
  rather than made silently. Every other branch in `verify_token` already treats
  missing information as grounds for rejection, `AccessToken.expires_at`
  *defaults* to `None` so a resolver that forgets it produces exactly this case,
  and the asymmetry decides it: rejecting fails loudly the first time a real
  resolver is wired up, while accepting grants a permanent credential to a year
  of someone's physiological data, silently.

  The check is deliberately not a copy of the SDK's. `BearerAuthBackend` guards
  with `if auth_info.expires_at and ...`, so `expires_at = 0` -- the epoch,
  comprehensively expired -- is falsy and read as "no expiry set".
  `_is_unexpired` tests `is None` explicitly, and compares with `<=` because
  RFC 7519 requires the current time to be strictly before `exp`. Both are
  pinned by tests.

  Also: `_resolve`'s docstring now records what a real resolver inherits (the
  issuer, audience and expiry checks) and what it does not and cannot -- the
  cryptographic binding. By the time `verify_token` holds an `AccessToken`, both
  its checks read `resource` and `claims["iss"]` as data, so a resolver that
  decodes a JWT without verifying its signature lets an attacker forge both.
  That obligation is invisible from `verify_token`'s own code, which is exactly
  why it is written where the resolver will be. No scope check was added, with
  the reason stated and a test pinning it: `verify_token` takes no
  `required_scopes`, and `RequireAuthMiddleware` already enforces them.

  Every existing `AccessToken` in `test_mcpauth.py` gained an explicit expiry --
  21 of them, none had one. That matters beyond making them pass: a token built
  to be rejected for its *resource* or *issuer* must not start being rejected
  for a missing expiry instead, or the check it was written to exercise stops
  being exercised. The same trap the file's own #102 note describes for `iss`.

  `_is_unexpired` also verifies the value's `int` shape, for the reason
  `_issued_by_trusted_as` already states about `claims`: `model_construct`
  bypasses pydantic's validation and a future non-pydantic resolver need not
  honour the declared type. Without it a `str` or `datetime` expiry raised
  `TypeError` out of the verifier -- a 500 rather than a 401 -- and an object
  with a custom `__gt__` was *accepted*. Found in review; this check was the
  only one in the module not already meeting that standard.

  Still latent overall -- `_resolve` returns `None` unconditionally, so no token
  is accepted by any path today. The value is that whoever plugs in a real
  resolver inherits a boundary that is correct rather than one that looks it.
- Issue #155 (found reviewing #154, P3, latent): `_execute_scoped` documents
  that it calls `conn.rollback()` before raising, because a non-`SELECT`
  statement has already run by the time a tenancy violation can be detected.
  That rollback is a **no-op** for a statement whose leading token is outside
  `INSERT`/`UPDATE`/`DELETE`/`REPLACE`: Python's `sqlite3` auto-opens a
  transaction only for those, so anything else runs in autocommit. Measured on
  main: `WITH x AS (SELECT 1) DELETE FROM recoveries WHERE whoop_user_id != ?
  AND (SELECT 1 FROM x)` is correctly *rejected* by the member-predicate check
  and the other member's rows stay deleted anyway -- the guard detecting a
  cross-member delete and failing to reverse it.

  Fixed by enforcing the precondition the rollback depends on, in
  `_execute_with_tenancy_authorizer` *before* anything executes, so both entry
  points inherit it by construction rather than by convention. Chosen over
  flipping `isolation_level` globally or opening a transaction inside
  `_execute_scoped`: both change transaction semantics for every write in the
  module -- including #104's erasure batch and `enforce_retention`'s -- to close
  a hole no caller can currently reach. Every mutating statement here is static
  in-repo SQL, so after this check the documented guarantee is true across the
  whole reachable set, and the guard is what keeps it true.

  Review of the fix turned up a **second vector #155 never mentioned**: sqlite's
  tokeniser skips a UTF-8 BOM but the driver's DML detection does not, so
  `\ufeffDELETE FROM ...` also executes in autocommit and survives a rollback.
  The guard already refused it, because the leading-keyword scan stops at the
  first non-alphabetic byte -- now deliberate and pinned by a test, since
  "helpfully" skipping a BOM would reopen it.

  The guard over-rejects, deliberately: a read-only `WITH ... SELECT` mutates
  nothing yet is refused, as are `EXPLAIN` and a bare `VALUES`. Telling a
  read-only CTE from a writing one needs the SQL parser this module has declined
  four times, and sqlite's own `sqlite3_stmt_readonly` is not exposed by
  Python's driver. No caller writes those shapes; the cost is documented and
  pinned rather than left to be rediscovered.

- Issue #140 (#37 audit, P3, latent): `_upsert_if_not_older` compared the
  incoming and stored `updated_at` as *strings*. Lexicographic order equals
  chronological order only while every value is uniform RFC3339 UTC at identical
  precision, and `.` (0x2E) and `+` (0x2B) both sort below `Z` (0x5A), so two
  spellings of the same second already broke it in both directions:

  - stored `...:00Z` vs incoming `...:00.500Z` -- 0.5s **newer**, skipped as
    older, silently discarding an update.
  - stored `...:00.500Z` vs incoming `...:00Z` -- genuinely **older**, applied,
    overwriting the newer record. This is the state regression on someone's
    health record that the guard exists to prevent, and it is the direction the
    issue mentions only in passing.

  Both sides are now parsed to `datetime` before comparing. Latent rather than
  live: it needs WHOOP's serialisation to vary, and nothing an attacker
  controls reaches the comparison. Verified to be a no-op for the shape WHOOP
  sends today -- across all 2916 pairs of uniform `...Z` second-precision
  values the old and new verdicts agree exactly, and on the mixed-precision and
  mixed-offset pairs where they differ the new one matches chronology, including
  comparisons across a non-UTC offset.

  One input class where parsing is *worse* than the string comparison, accepted
  knowingly rather than glossed: `fromisoformat` truncates fractional seconds
  past six digits, so values differing only in a 7th digit parse equal and the
  incoming record is applied, where lexicographic order happened to get them
  right. WHOOP sends second and millisecond precision, "equal" is the honest
  reading of two values that cannot be distinguished, and reading the remaining
  digits would mean hand-parsing them for an input that does not occur. Pinned
  by a test so it stays a known cost.

  An unparseable value on either side is treated as *not comparable* and
  therefore upserted -- the same as an absent one, which is this function's
  documented behaviour -- but logged at warning, since that is the case where
  the guard quietly stops guarding and nothing else would say so. A value with
  no offset is read as UTC, which is the assumption the string comparison was
  already making.

- Issue #154 (found reviewing #129, P3, latent): `_execute_scoped` examined
  only the *first* parenthesis-depth-zero `WHERE`, so a compound statement's
  second arm could supply the member predicate while the first spanned every
  member. `SELECT raw_json FROM recoveries WHERE whoop_user_id != ? UNION
  SELECT raw_json FROM recoveries WHERE whoop_user_id = ?` was accepted and
  returned the other member's `raw_json` -- their health payload. #129's
  depth requirement cannot catch this: the fragment it finds genuinely is at
  depth zero, and the defect is in *which* `WHERE` anchors the search. The
  statement is now split into arms at depth-zero `UNION` / `UNION ALL` /
  `INTERSECT` / `EXCEPT`, and every arm must have a top-level `WHERE` whose
  every occurrence carries a depth-zero fragment. Requiring the arm to *have*
  one is the half that is easy to miss, and the first version of this fix
  missed it: an arm with no `WHERE` at all (`SELECT raw_json FROM recoveries
  UNION SELECT ... WHERE whoop_user_id = ?`) offers no anchor for a
  `WHERE`-walking check to trip over, yet spans its whole table -- so the
  invariant has to be a property of each arm, not of each `WHERE`. Also
  replaces #109's and #129's two incremental parenthesis counters with a
  single precomputed depth array, because a third hand-rolled counter for the
  per-arm check was the next bug waiting to happen. Still latent: no path
  routes caller-supplied SQL through `_execute_scoped`, and the universal
  authorizer check was never affected. Verified against main by evaluating
  every statement the suite routes through the check with both
  implementations: 147 unique statements, 21 divergences -- 20 of them the new
  tests' own compound shapes, all fail-closed -- and zero divergence on the
  119 statements that predate this change, which is what pins the counter
  restructure as behaviour-preserving. The 21st is discussed below.

  Two rounds of review were needed to get this right, and both findings were
  the same defect class as the issue itself -- a check whose invariant was one
  step off what it needed to be:

  * The first formulation required every top-level `WHERE` to carry a
    fragment. An arm with no `WHERE` has no anchor, so a `WHERE`-walking loop
    never visited it; `SELECT raw_json FROM recoveries UNION SELECT raw_json
    FROM recoveries WHERE whoop_user_id = ?` returned every member's payload.
  * The second required every arm, but the sanitiser *deleted* stripped
    regions instead of replacing them, and to sqlite a comment is a token
    separator. `UNION/**/ALL` collapsed to `UNIONALL` and
    `recoveries/**/UNION` to `recoveriesUNION`, so the arm split silently did
    not happen: `SELECT raw_json FROM recoveries EXCEPT/**/SELECT raw_json
    FROM recoveries WHERE whoop_user_id = ?` was accepted and returned exactly
    the *other* members' rows. Stripped regions now leave a space behind.

  That second change makes the sanitiser strictly more faithful in both
  directions. Deletion could *forge* a fragment the statement never wrote
  (`WHERE whoop_user/**/_id = ?` fused into a match), and it could *hide* a
  real anchor (`FROM recoveries/**/WHERE whoop_user_id = ?` fused into
  `recoveriesWHERE`, so a properly restricted statement was refused). The
  latter is the single `False -> True` divergence against main in the
  measurement above, and accepting it is correct: sqlite parses that comment
  as whitespace and applies the `WHERE`.

- Issue #131 (#37 audit, P3): the sanitiser inside
  `_statement_restricts_to_one_member` stripped `'`- and `"`-quoted regions but
  not SQLite's other two identifier forms, `` `backticks` `` and `[brackets]`,
  so their contents were searched as live SQL. The issue rated this
  robustness-only -- "I could not construct a weaponised false-accept from this
  alone" -- and #129 made that assessment obsolete without either issue
  noticing: once the member predicate had to sit at parenthesis depth zero, a
  stray `)` inside an unstripped identifier could desynchronise the depth
  counter. `... WHERE whoop_user_id != ? AND resource_id = (SELECT
  max(resource_id) FROM recoveries AS [q)]) AND EXISTS (SELECT 1 FROM
  recoveries r2 WHERE r2.whoop_user_id = ?)` was accepted, and mutated another
  member's row. Both forms are now stripped, each with SQLite's own escape
  rule, measured rather than assumed: backticks double (`` `a``b` `` is the one
  identifier ``a`b``), brackets have no escape at all (SQLite rejects
  `[a]]b]` as an unrecognised token), so they cannot share an implementation
  branch -- giving brackets the doubling rule would consume past the real
  terminator and swallow live SQL. Still latent: no caller routes
  caller-supplied SQL through `_execute_scoped`, and the universal authorizer
  check, which is the load-bearing control, was never affected. Verified
  non-breaking by running the whole suite with both sanitisers side by side and
  comparing the verdict on every statement that reached the check: five
  divergences, all of them the new tests' own exploit shapes, all in the
  fail-closed direction.

- Issue #129 (#37 audit, P3, latent): `_statement_restricts_to_one_member`
  matched the member predicate depth-blind. #109 required the
  `whoop_user_id = ?` fragment to sit after the statement's first
  parenthesis-depth-zero `WHERE`, but anchored only where the search
  *started* -- never the depth of what it found. A fragment nested in a
  subquery *after* a non-restrictive top-level predicate therefore satisfied
  the check: `WHERE whoop_user_id != ? AND EXISTS (SELECT 1 FROM recoveries
  r2 WHERE r2.whoop_user_id = ?)` reads the column (so the universal
  authorizer check passes), spans every member but the caller, and had the
  nested fragment accepted as its member restriction. Reproduced end to end
  as a cross-member `UPDATE`, and in `INSERT ... SELECT` form as another
  member's `raw_json` health payload copied into the caller's own partition,
  where ordinary scoped getters then return it. The match must now sit at
  depth zero as well. Latent, not exploitable: every caller of
  `_execute_scoped` passes static in-repo SQL and no path routes
  caller-supplied SQL through it -- and the universal authorizer check, which
  is the load-bearing control, was never affected. Fixing it anyway because
  #109's own documentation claimed this shape was caught, and a guard that
  overstates its reach is what a future maintainer will trust. The
  `CAUGHT`/`NOT CAUGHT` list above `_MEMBER_EQUALITY_PREDICATE` is corrected
  in the same commit, including the one deliberate false positive the fix
  introduces (`WHERE whoop_user_id IN (SELECT whoop_user_id FROM sleeps WHERE
  whoop_user_id = ?)` does confine itself to one member and is rejected
  anyway; no caller writes that shape). Verified non-breaking by running the
  whole suite with both the old and the depth-checked form and comparing the
  verdict on every statement that reached the check: zero divergences.

- Issue #130 (#37 audit, P3): the comment justifying `webhook_events`'
  exclusion from `_TENANT_SCOPED_TABLES` said its `whoop_user_id` "is nullable
  pre-identity-resolution data". #105 made that column `NOT NULL`, so the
  exclusion outlived its stated reason. The exclusion is still correct, but on
  different grounds -- reachability: the table is read only by `trace_id` from
  `webhook_processor`, or by a per-member reader that filters on
  `whoop_user_id` itself for #32's export, so the boundary is enforced by the
  callers rather than by that registry. It does hold member data, which is why
  `_ERASURE_TABLES` includes it. A test now pins those facts, so the rationale
  fails loudly if reality moves under it again.

- Issue #136 (#37 audit, P3): `atomic_write_text` now `fsync`s the data before
  the rename and the parent directory after it. Write-then-rename is atomic
  against a *process* crash on its own, but not against power loss: the rename
  could reach disk before the bytes, leaving an empty or partial file exactly
  where a good token had been -- the failure the dance exists to prevent,
  arriving by a route it did not cover. The directory sync is POSIX-only, since
  Windows cannot open a directory for `fsync`.

- Issue #134 (#37 audit, P3): `Authenticator.exchange_code` now installs the
  token on the session *before* persisting it. By the time `save` runs WHOOP
  has already minted the grant, so a failed write -- a full disk, a read-only
  state directory, a `SealError` from a half-configured key set -- used to
  leave the process holding nothing while a live, refreshable credential
  existed upstream: unusable from here and unrevokable, with the user retrying
  and minting a fresh grant each time. The exception still propagates, so the
  caller knows the token was not written and will not survive a restart.

- Issue #137 (#37 audit, P3): `KeyringTokenStore.load` now raises `AuthError`
  for a corrupt keychain entry instead of letting the raw
  `JSONDecodeError`/`KeyError`/`ValueError` escape. Both file-backed stores
  already wrapped the identical `Token.from_json` call; the keyring store
  called it bare, breaking `TokenStore.load`'s `Token | None` or `AuthError`
  contract and bypassing callers that catch `AuthError` to redact a failure,
  such as `doctor`'s store check. The message names the exception type but
  never the entry: unlike a file path, the keychain entry is itself the
  credential. An empty entry still returns `None` -- no stored token is not an
  error.

- Issue #135 (#37 audit, P3): the lazy re-seal in `EncryptedFileTokenStore.load`
  now tolerates a failed *write*, not just a missing key. #103 made a missing
  re-seal key serve the token unrotated rather than raise, but its guard caught
  only `SealError`, so an `OSError` -- a full disk, a read-only state
  directory, a permission change -- still escaped and turned a token that had
  decrypted perfectly into a hard `load()` failure. The same outage #103
  existed to prevent, arriving by a different exception, and contradicting
  `load()`'s own docstring promise that the re-seal "never raises out of
  `load`". Both causes are now caught and logged with the exception type named
  so they stay distinguishable. `save()` still raises for direct callers, and
  the stored record is left untouched by a failed re-seal.

- Issue #133 (#37 audit, P3): `repr(Token)` and `repr(Config)` no longer print
  the secrets they hold. `access_token` and `refresh_token` on `Token`, and
  `client_secret`, `token_encryption_keys`, `metrics_token`, and
  `metrics_member_salt` on `Config`, are now `field(repr=False)` -- the exact
  six fields the audit found exposed, no more. `token_backend` and
  `token_encryption_key_version` stay visible: they're a backend name and an
  integer version, not credentials, and a repr that hides everything is as
  unhelpful for diagnosis as one that hides nothing is unsafe. Nothing else
  changes: no custom `__repr__`, `__str__`, or serialisation touched, and the
  exposure was latent -- no current call site reprs either object -- so this
  closes a future footgun rather than a live leak.

- Issue #120 (#37 audit): the OAuth `state` is now single-use.
  `Authenticator.verify_state` used to leave `_pending_state` in place after
  a successful check, so the same value verified indefinitely instead of
  only for the one callback it was issued for, violating OAuth's security
  BCP. A successful verification now clears the pending state, so a second
  verification of the same value fails exactly like an unknown one; a
  *mismatched* state still does not clear it, since doing so would let
  anyone able to reach the callback kill a genuine in-progress login by
  sending one bad value, and the state's 32 random bytes leave nothing to
  brute-force in the meantime. State generation and the `compare_digest`
  comparison are unchanged.

- Issue #119 (#37 audit): `softprops/action-gh-release` in the release
  workflow's `contents: write` job is now pinned by commit SHA rather than the
  mutable `v3` tag. It was the one non-GitHub action still on a floating tag in
  a write-privileged job, so whoever controlled that tag could have written to
  this repository on every release -- while the sibling
  `pypa/gh-action-pypi-publish` in the same workflow was already SHA-pinned.
  `v3` and `v3.0.2` both resolve to commit `3d0d9888`, so the pin is
  behaviour-neutral. A test now asserts the property for every non-GitHub
  action in any write-privileged job across all workflows.

- Issue #122 (#37 audit): `invalid_grant` from a token refresh no longer
  conflates "WHOOP rejected this refresh token" with "the user's grant is
  gone." WHOOP rotates refresh tokens on use, so a stale token failing
  usually means it was superseded by a rotation another process already
  completed and saved -- treating that as "gone" both deleted the valid
  rotated credential the other process had just written and, via
  `GrantAlreadyGoneError` (which `__main__.py`'s `erase-member`/
  `delete-member` catch as "revoke succeeded", issue #65), made the CLI
  report a revoke that never happened while the grant was still live at
  WHOOP. `refresh()` now refreshes the store's token, not the caller's
  stale one, whenever `_supersedes` shows the store has moved on -- even
  if that store token has itself expired, previously the short-circuit's
  requirement that dropped it back to sending WHOOP the caller's already-
  rotated-past token. `_do_refresh` now re-reads the store on
  `invalid_grant` and only clears it and raises `GrantAlreadyGoneError`
  when the store still holds the very token that failed; when the store
  has already moved on it leaves the store untouched and raises a plain
  `AuthError` instead, so the CLI treats it as a real failure rather than
  revoke-step success.
- Issue #123 (#37 audit): `logout()`/`revoke_and_forget()` no longer race a
  refresh already in flight. A refresh that completes after credentials were
  forgotten used to run straight through to `self._store.save(new_token)` /
  `self._token = new_token` regardless, silently resurrecting a fully live
  grant on disk after the user asked to forget it. `logout()` is synchronous
  and so cannot await or cancel that task, which rules out a "cancel the
  refresh" fix; instead a monotonic credential epoch is captured at the top
  of `refresh()`, before it even acquires the refresh lock, and passed into
  `_do_refresh` to be re-checked immediately before the save/install, and
  both `logout()` and `revoke_and_forget` (which calls it) bump it.
  Capturing the epoch in `refresh()` rather than inside `_do_refresh` itself
  matters because `_do_refresh` runs as a task created via
  `asyncio.ensure_future` and doesn't start executing until the event loop
  gets to it, so a logout arriving first in that same tick (e.g. a sibling
  `whoop_logout` tool call) would otherwise still be captured as a "before
  the request" epoch and pass the check. The in-flight call's own caller
  still receives the token it obtained -- only persisting and installing it
  as the session credential are skipped -- so the interleaved logout does
  not raise out of an unrelated tool call. The coalescing machinery
  (`_inflight_refresh`, the lock, single-flighted `refresh()`) is unchanged;
  this adds a check, not a redesign.
- Issue #109: `_execute_scoped`'s member-equality check now sits behind a
  new `_statement_restricts_to_one_member` helper instead of a bare
  `_MEMBER_EQUALITY_PREDICATE.search(sql)`, closing three ways a
  `whoop_user_id = ?` fragment could satisfy the requirement without
  actually restricting the statement to one member: sitting in a `SET`
  assignment (`UPDATE recoveries SET whoop_user_id = ? WHERE whoop_user_id
  IS NOT NULL` reassigned every member's rows to one caller-chosen id), a
  `--`/`/* */` comment, or a string literal -- plus a subquery in `SET`
  supplying the fragment while the outer statement stays unfiltered. The
  helper searches a sanitised copy (comments and string literals stripped)
  and requires the match to fall after the first top-level `WHERE`; the SQL
  executed against sqlite is never altered. No statement kind gains or
  loses an exemption -- the `INSERT` exemption and the retention sweep's
  waiver are unchanged -- and the residual this does not close (a fragment
  `OR`-ed with a wider clause after the `WHERE`, and per-statement ambiguity
  when two tenant-scoped tables are named) stays documented, not papered
  over, on `_MEMBER_EQUALITY_PREDICATE`.
- Issue #102: `MCPTokenVerifier.verify_token` now rejects a token whose
  issuer is not one of `MCPAuthConfig.authorization_servers`, closing an
  audience-is-right-but-issuer-is-untrusted substitution -- previously the
  trust list was consumed only to publish RFC 9728 metadata, never to gate
  acceptance. A missing `claims` dict, a missing or non-`str` `iss`, and an
  empty `iss` are all rejected the same way a wrong `iss` is (mirroring
  `_names_this_resource`'s own precedent for a missing resource claim); the
  comparison tolerates exactly one trailing slash, nothing looser. New
  `_issued_by_trusted_as` runs alongside the existing audience check, and
  neither check can be satisfied by the other passing.
- Issue #105: `webhook_events.whoop_user_id` is now `NOT NULL` (migration 5),
  since a NULL there made a row invisible to both `export_member_data` and
  `erase_member_data` -- both select on `WHERE whoop_user_id = ?` -- the
  worst combination for a data-subject rights request. The migration
  rebuilds the table (sqlite has no `ALTER COLUMN`) inside its own
  transaction and refuses up front, leaving the database untouched, if any
  NULL-user rows already exist, naming the row count rather than letting a
  bare `IntegrityError` surface from partway through the rebuild.
  `insert_webhook_event`'s `whoop_user_id` parameter is now `int`, not
  `int | None`, to match.
- Issue #103: `EncryptedFileTokenStore.load`'s lazy re-seal no longer leaks a
  raw `crypto.SealError` when the current key version's key is missing --
  e.g. a half-completed key rotation, or a hand-built `Config` that skips
  `Config.from_env`'s guard. The record still decrypted fine under its own
  (older) key, so `load` now serves it unrotated and logs a warning naming
  the missing version, once per store instance, rather than turning a
  misconfigured key set into an outage; the repo owner chose availability
  here deliberately. The warning uses its own flag, distinct from `save`'s
  existing Windows-file-permissions warning, so neither can suppress the
  other. A direct `save()` call -- as `exchange_code` makes right after a
  token exchange -- still raises on the same failure, since silently
  failing to persist a freshly obtained token would lose it.
- Issue #100: after `erase-member` deletes a member's data, the database file is
  now compacted via `VACUUM` so the deleted rows' bytes are overwritten in freed
  pages, rather than remaining recoverable in the file. `PRIVACY.md` promises
  erasure is "a real removal" of the data subject's records; the promise is now
  kept for the bytes themselves, not just the SQL table rows. The cost lands on
  the rare operator command (`erase-member`) rather than on every `DELETE` in
  the store (retention and webhook cleanup), per the repo owner's design
  decision. A failed compaction (e.g., disk full, or corruption detected
  mid-`VACUUM`) does not abort or report erasure as failed; the deletes are
  already committed and irreversible at that point. A distinct stderr message
  and exit code 3 -- distinct from the pre-deletion abort's 1 -- signal the
  incomplete compaction so a caller does not mistake it for "nothing was
  deleted" or otherwise confuse it with erasure failure.
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
