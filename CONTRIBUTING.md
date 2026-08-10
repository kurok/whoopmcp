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

CI runs exactly these, so run them before pushing:

```bash
pytest
ruff check .
ruff format --check .
mypy
```

`mypy` is strict on `src/`. Tests are not type-checked.

## Where things go

```
config.py     environment -> Config, validated once at startup
auth.py       OAuth 2.0 flow + token storage
client.py     one method per documented WHOOP endpoint, nothing more
analysis.py   pure functions over already-fetched records
server.py     MCP tool definitions; the only file that imports mcp
```

The split is the point. Keep network code out of `analysis.py` and statistics
out of `client.py`, so each stays testable without the other. Anything that
knows WHOOP's response *shapes* belongs in `analysis.extract_metric` or in
`client`, not scattered across tools.

**The user is an argument, never ambient.** A tool body gets its caller's
identity from the `AppContext` it was handed (`_ensure_principal(app)`),
never by reaching into `Config.from_env()`, an environment variable, or any
other process-global state. Today there is exactly one user, resolved once
at startup and after login, so this looks like ceremony -- but it is what
lets a second user (#29) become a change to one resolver instead of a
rewrite of every tool.

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
