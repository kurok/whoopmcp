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

### Changed

- **Support narrowed to the two newest stable Python releases, 3.13 and
  3.14.** `requires-python` was `>=3.10` while CI is the thing that decides
  what actually works, so the floor now matches the matrix instead of
  advertising four versions and vouching for them by inference. Python has no
  LTS track; these two are supported upstream until 2029 and 2030. Users on
  3.10–3.12 should stay on a release made before this change.

### Fixed

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
