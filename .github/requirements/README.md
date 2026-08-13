# Hash-locked release tooling

`build`, `twine` and `pip-audit` run during CI and, for the first two, during
the job that produces the distributions `release.yml` publishes to PyPI. #125
pinned each tool to an exact version; that fixed *which release of the named
tool* executes and left its dependency closure to be resolved against PyPI at
run time. A compromised release of any transitive dependency — `packaging`,
`pyproject_hooks`, `requests`, `keyring`, `rich`, and 20-odd more — executes in
that same job with the same reach. #159 closed that.

Each `<tool>.txt` here pins the tool **and its whole closure** by version and
SHA-256, and the workflows install with `pip install --require-hashes`, which
refuses to install anything whose artifact does not match a listed hash and
refuses to run at all if any dependency is unpinned.

## Regenerating

Edit the one-line `<tool>.in` — that file is the source of truth for the version
— then recompile:

```sh
cd .github/requirements
for tool in build twine pip-audit; do
  uv pip compile --universal --generate-hashes --output-file "$tool.txt" "$tool.in"
done
```

`--universal` is not optional, though not for the reason it first appears.
Without it, uv resolves for *the machine that ran it* and omits packages only
other platforms need: compiled on macOS, `twine.txt` comes out with 22 packages
instead of 28. It does not omit Linux's wheel hashes — a non-universal lock built
here still installs on Linux today, because Linux happens to need a subset of
what macOS resolved. That is luck, not a guarantee: the moment a platform needs a
package the resolving machine excluded, `--require-hashes` refuses the install,
and it refuses on the runner rather than here. (Measured both ways before writing
this down; an earlier draft of this file claimed the missing piece was Linux wheel
hashes, and that was wrong.)

With `--universal`, every marker branch is included — `colorama ; os_name == 'nt'`
and the rest — so one file is correct on every platform.

Then verify before committing, because a broken lock in `release.yml` is
invisible until a tag is pushed:

```sh
for tool in build twine pip-audit; do
  python -m venv "/tmp/verify-$tool"
  "/tmp/verify-$tool/bin/pip" install --require-hashes -r "$tool.txt" || echo "FAILED: $tool"
done
```

## Why not dependabot

`dependabot.yml` configures the `pip` ecosystem with `directory: "/"`, so it
looks at the project's own dependency declarations — not at these files, which
live under `.github/requirements/`. Nothing here is on a bot's update path, by
configuration rather than by any claim about what dependabot can or cannot do
with hashes.

So these files are updated by hand, with the two commands above. Bumping a tool
is: edit the `.in`, recompile, verify, commit. Treat a pinned closure that has
gone stale as a task rather than an accident — the whole point is that no upgrade
reaches the release path without someone choosing it.

`ci.yml` installs from these same files on every push, so a stale or broken lock
fails there long before a release depends on it — which is the whole reason the
CI copies exist.
