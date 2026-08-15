# Contributing

Thanks for considering it. Bug reports, docs fixes and PRs are all welcome.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
Security issues go through [SECURITY.md](SECURITY.md), not a public issue.

## Setup

Python 3.13 or 3.14. The project tracks the two newest stable releases rather
than a long tail of old ones, so `requires-python`, the CI matrix, the ruff
target and the mypy target all move together — change one, change all four.

```bash
git clone https://github.com/kurok/whoopmcp
cd whoopmcp
uv venv --python 3.14 && uv pip install -e '.[dev,lint]'
pre-commit install     # optional, runs the checks below on commit
```

## The checks

CI runs six checks. The four to run before every push:

```bash
pytest
ruff check .
ruff format --check .
mypy
```

CI additionally runs `bandit -r src/` (static security scan) and
`pip-audit .` (dependency audit), plus a build/`twine check` of the
distributions — install the `security` extra if you want the first two
locally. `mypy` is strict on `src/`. Tests are not type-checked.

## Where things go

```
__init__.py            package marker; only __version__, no placement decisions
config.py              environment -> Config, validated once at startup
auth.py                OAuth 2.0 flow + token storage
mcpauth.py             inbound OAuth 2.1 resource server: bearer-token validation
                       for MCP clients; never touches WHOOP's own grant
crypto.py              envelope encryption primitive (AES-GCM, versioned keys); no auth/WHOOP knowledge
client.py              one method per documented WHOOP endpoint, nothing more
store.py               sqlite3 persistence: schema, migrations, per-user upserts and reads
analysis.py            pure functions over already-fetched records
context_budget.py      response-shaping/measurement shared by tools (token
                       estimation, null-stripping); not network, not statistics
webhooks.py            webhook receiver: HMAC verification, raw-body handling,
                       hands verified events to a queue
webhook_processor.py   webhook event consumer: idempotent processing keyed on trace_id
backfill.py            resumable, throttled full history import; CLI-only, never a tool
sync.py                incremental sync from an updated_at high-water mark
reconciliation.py      periodic full reconciliation: the webhook backstop for missed deletions
metrics.py             Prometheus exposition: sync lag, webhook health, rate budget, token failures
doctor.py              whoopmcp doctor: one-pass health check for a local-mode install
server.py              MCP tool definitions; the outward-facing MCP surface
__main__.py            CLI entry point; MCP clients launch this over stdio, --http for testing
```

Only `server.py`, `webhooks.py`, and `mcpauth.py` import `mcp`; no other
module does -- enforced by `tests/test_module_map.py`, not just stated here.

The split is the point. Keep network code out of `analysis.py` and statistics
out of `client.py`, so each stays testable without the other. Anything that
knows WHOOP's response *shapes* belongs in `analysis.extract_metric` or in
`client`, not scattered across tools.

**The user is an argument, never ambient.** A tool body gets its caller's
identity from the `Context` it was handed, resolved once at the edge by
`server.resolve_member_id` (via `_ensure_matches_live_grant`, which also
refuses a resolved member that isn't this process's live WHOOP grant) --
never by reaching into `Config.from_env()`, an environment variable, or any
other process-global state. `resolve_member_id` itself reads only the
`principal_members` table, written only by a completed WHOOP login
(`whoop_complete_login`), never a caller-supplied parameter, header, or
query string. #29 is exactly the resolver this paragraph used to promise:
adding a second, genuinely concurrent live WHOOP grant is still future
work, but the identity plumbing every tool goes through is already the one
join point, not a per-tool rewrite.

## Working on a stub

The scaffold's unimplemented functions raise `NotImplementedError` naming
their issue. To implement one:

1. Delete the corresponding `test_*_is_not_implemented` guard.
2. Write tests first. Mock HTTP with `respx`; do not hit the real API in
   tests, and never commit a fixture captured from a real account.
3. Implement it, and delete the `TODO(#n)` comment.

## Conventions

- **Comments explain why, not what.** If a line needs a comment to say what it
  does, rename something instead. Comments earn their place by recording a
  constraint that is not visible in the code — a WHOOP quirk, a rejected
  alternative, a reason an obvious simplification is wrong.
- **Tool docstrings are prompt surface.** They are what the model reads to
  decide which tool to call. State units. Say what the data is not.
- **Read-only stays read-only.** A new tool that writes to a WHOOP account
  will not be merged; see the design notes in [SECURITY.md](SECURITY.md).
- **No credentials, ever** — not in code, tests, fixtures, or examples.
  `.env` is gitignored; keep it that way.
- **No health data in issues or PRs.** They are public. Redact before pasting
  a response body.

## Pull requests

Small and focused beats large and sweeping. Include tests for behaviour
changes, update `CHANGELOG.md` under `[Unreleased]`, and update the README if
you change the tool surface or configuration.

Commit messages: imperative mood, why in the body if it is not obvious.

```
Clamp page size to the API maximum

WHOOP 400s on limit > 25 rather than truncating, so an optimistic
limit=1000 from a caller failed the whole request.
```

## Releases

Maintainers: bump the version in `pyproject.toml` and `src/whoopmcp/__init__.py`,
move `[Unreleased]` to a dated section in `CHANGELOG.md`, tag `vX.Y.Z`, and
push the tag — the release workflow publishes to PyPI via Trusted Publishing.
