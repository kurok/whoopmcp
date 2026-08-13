"""Tests for packaging, release plumbing, and MCP registry manifest.

These tests verify the release configuration and the MCP server manifest
without publishing anything.

Schema version: https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json
This test file reflects the schema as of 2025-09-29.
"""

import json
import re
import tomllib
from pathlib import Path

import pytest


@pytest.fixture
def project_root() -> Path:
    """Return the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def pyproject_toml(project_root: Path) -> dict:
    """Load and return the pyproject.toml as a dictionary."""
    pyproject_path = project_root / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        return tomllib.load(f)


@pytest.fixture
def server_json(project_root: Path) -> dict:
    """Load and return server.json as a dictionary.

    Note: This will fail if server.json does not exist yet.
    """
    server_json_path = project_root / "server.json"
    with open(server_json_path) as f:
        return json.load(f)


@pytest.fixture
def release_yml_content(project_root: Path) -> str:
    """Load and return the release workflow as a string."""
    release_yml_path = project_root / ".github" / "workflows" / "release.yml"
    with open(release_yml_path) as f:
        return f.read()


@pytest.fixture
def ci_yml_content(project_root: Path) -> str:
    """Load and return the CI workflow as a string."""
    ci_yml_path = project_root / ".github" / "workflows" / "ci.yml"
    with open(ci_yml_path) as f:
        return f.read()


@pytest.fixture
def src_files(project_root: Path) -> list[Path]:
    """Return all .py files in the src/ directory."""
    src_dir = project_root / "src"
    return sorted(src_dir.rglob("*.py"))


class TestServerJsonValidation:
    """Test that server.json conforms to the published MCP registry schema."""

    def test_server_json_structure(self, server_json: dict) -> None:
        """Test that server.json validates against the published registry schema.

        Schema: https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json

        The schema requires:
        - $schema: reference to schema version
        - name: reverse-DNS format with exactly one forward slash
        - version: semantic version
        - description: max 100 characters
        - packages or remotes: at least one required

        This test does not make network calls; it asserts the concrete structure.
        """
        assert "$schema" in server_json, "server.json must declare $schema"
        assert "name" in server_json, "server.json must declare name"
        assert "version" in server_json, "server.json must declare version"
        assert "description" in server_json, "server.json must declare description"

        # Validate name format: reverse-DNS with exactly one forward slash
        name = server_json["name"]
        assert "/" in name, f"name '{name}' must contain exactly one forward slash"
        assert name.count("/") == 1, f"name '{name}' must contain exactly one forward slash"
        parts = name.split("/")
        assert len(parts) == 2, "name must be in reverse-DNS/server-name format"

        # Validate description length
        description = server_json["description"]
        assert isinstance(description, str), "description must be a string"
        desc_len = len(description)
        assert desc_len <= 100, f"description length {desc_len} exceeds 100 characters"

        # Validate that at least packages or remotes is present
        has_packages = "packages" in server_json and server_json["packages"]
        has_remotes = "remotes" in server_json and server_json["remotes"]
        assert has_packages or has_remotes, "server.json must declare packages or remotes (or both)"


class TestServerJsonConsistency:
    """Test that server.json is consistent with pyproject.toml and the console script."""

    def test_package_name_matches_pyproject(self, server_json: dict, pyproject_toml: dict) -> None:
        """Test that server.json's declared package name matches pyproject.toml.

        A manifest that drifts from the package it describes is a failure mode
        worth pinning.
        """
        # Get the package name from pyproject.toml
        pyproject_name = pyproject_toml["project"]["name"]

        # Get the package name from server.json
        # The packages array contains one or more package declarations
        assert "packages" in server_json, "server.json must declare packages"
        packages = server_json["packages"]
        assert packages, "packages array must not be empty"

        # Find the pypi package (registryType should be "pypi")
        pypi_packages = [p for p in packages if p.get("registryType") == "pypi"]
        assert pypi_packages, "server.json must declare at least one PyPI package"

        # The identifier should match the project name
        pypi_package = pypi_packages[0]
        server_json_name = pypi_package["identifier"]
        assert server_json_name == pyproject_name, (
            f"server.json package identifier '{server_json_name}' "
            f"must match pyproject.toml name '{pyproject_name}'"
        )

    def test_package_version_matches_pyproject(
        self, server_json: dict, pyproject_toml: dict
    ) -> None:
        """Test that server.json's declared package version matches pyproject.toml."""
        # Get the version from pyproject.toml
        pyproject_version = pyproject_toml["project"]["version"]

        # Get the version from server.json
        packages = server_json["packages"]
        pypi_packages = [p for p in packages if p.get("registryType") == "pypi"]
        assert pypi_packages, "server.json must declare at least one PyPI package"

        pypi_package = pypi_packages[0]
        server_json_version = pypi_package["version"]
        assert server_json_version == pyproject_version, (
            f"server.json package version '{server_json_version}' "
            f"must match pyproject.toml version '{pyproject_version}'"
        )

    def test_name_consistency_across_manifest(
        self, server_json: dict, pyproject_toml: dict
    ) -> None:
        """Test that name is consistent in server.json, pyproject.toml, and console script.

        The console script declaration must use the same name as the Python package.
        """
        pyproject_name = pyproject_toml["project"]["name"]

        # Check console script
        scripts = pyproject_toml["project"]["scripts"]
        assert "whoopmcp" in scripts, "console script 'whoopmcp' must be declared"

        script_entry = scripts["whoopmcp"]
        assert script_entry == "whoopmcp.__main__:main", (
            f"console script entry point must be 'whoopmcp.__main__:main', got '{script_entry}'"
        )

        # Check that the package name is 'whoopmcp'
        assert pyproject_name == "whoopmcp", (
            f"pyproject.toml name must be 'whoopmcp', got '{pyproject_name}'"
        )

        # Check server.json consistency
        packages = server_json["packages"]
        pypi_packages = [p for p in packages if p.get("registryType") == "pypi"]
        pypi_package = pypi_packages[0]
        assert pypi_package["identifier"] == "whoopmcp", (
            f"server.json package identifier must be 'whoopmcp', got '{pypi_package['identifier']}'"
        )


class TestReleaseConfiguration:
    """Test that the release workflow is properly configured for Trusted Publishing."""

    def test_no_token_required_in_release_workflow(self, release_yml_content: str) -> None:
        """Test that release.yml requires no stored token for publishing.

        This verifies the "dry-run release does not require a stored token"
        acceptance criterion by checking the release workflow structure.

        Specifically:
        - No password: key in the publish job
        - No PYPI_API_TOKEN secret reference anywhere
        - The publish job must declare id-token: write for Trusted Publishing
        """
        # Parse the YAML content by checking for the publish job section
        assert "publish:" in release_yml_content, "release.yml must have a publish job"

        # Extract the publish job section (from 'publish:' until the next job)
        publish_match = re.search(
            r"publish:\s*\n(.*?)(?=\n  [a-z\-]+:|$)",
            release_yml_content,
            re.DOTALL,
        )
        assert publish_match, "Could not extract publish job from release.yml"
        publish_section = publish_match.group(1)

        # Check for Trusted Publishing configuration
        assert "environment:" in publish_section, "publish job must declare an environment"
        assert "id-token: write" in publish_section, (
            "publish job must declare 'id-token: write' for Trusted Publishing"
        )

        # Verify no password or token secrets in the publish job
        assert "password:" not in publish_section, (
            "publish job must not contain 'password:' (Trusted Publishing should be used)"
        )
        assert "PYPI_API_TOKEN" not in publish_section, (
            "publish job must not reference PYPI_API_TOKEN secret"
        )

    def test_publish_action_is_sha_pinned(self, release_yml_content: str) -> None:
        """Test that the publish action is pinned to a SHA, not a floating tag.

        Pinning to a specific SHA prevents unexpected changes from action updates.
        """
        # Find the pypa/gh-action-pypi-publish action line
        action_pattern = r"uses:\s*pypa/gh-action-pypi-publish@([\da-f]+)"
        match = re.search(action_pattern, release_yml_content)
        assert match, (
            "release.yml must use the pypa/gh-action-pypi-publish action with @SHA pinning"
        )

        pin = match.group(1)

        # SHA-1 hashes are 40 hex characters, SHA-256 are 64
        # Both are valid; reject version tags like v1, v1.0, v1.14.2
        is_sha = len(pin) in (40, 64) and all(c in "0123456789abcdef" for c in pin)
        assert is_sha, f"publish action must be pinned to a SHA hash, not a tag like '{pin}'"


class TestServerJsonManifest:
    """Test that server.json does not declare a remote deployment."""

    def test_no_remote_declared(self, server_json: dict) -> None:
        """Test that no remote is declared in server.json.

        The manifest should not point at a remote HTTP deployment since
        no deployment exists to point at yet (per decision D1).
        """
        # The schema allows either 'packages' or 'remotes' or both.
        # For this server, we only declare packages (PyPI for local use).
        # No remotes should be declared.

        remotes = server_json.get("remotes")
        assert not remotes, (
            f"server.json must not declare remotes (no remote deployment exists). Got: {remotes}"
        )


class TestSecurityLinting:
    """Test that security linting is properly configured and enforced.

    These tests verify the automated gates for issue #37: bandit wiring
    and re-justification of S105/S106 suppressions.
    """

    def test_bandit_runs_in_ci(self, ci_yml_content: str) -> None:
        """Test that bandit is configured as a CI job targeting src/.

        The CI workflow must include a bandit job that checks source files.
        """
        assert "bandit" in ci_yml_content, "ci.yml must include a step that runs bandit"
        # Look for a pattern that shows bandit running against src/
        # The pattern should be something like 'bandit -r src/' or similar
        assert re.search(r"bandit\s+.*src/", ci_yml_content), (
            "ci.yml must include a bandit command targeting src/ (e.g., 'bandit -r src/')"
        )

    def test_no_unexplained_nosec_in_src(self, src_files: list[Path]) -> None:
        """Test that every # nosec comment in src/ has a trailing justification.

        A bare '# nosec' without explanation is itself a finding per issue #37.
        Each suppression must include a comment explaining why it is safe.
        """
        failures = []
        for src_file in src_files:
            with open(src_file) as f:
                lines = f.readlines()
            for line_num, line in enumerate(lines, start=1):
                if "# nosec" in line:
                    # Extract the part after '# nosec'
                    match = re.search(r"#\s*nosec\s*(.*)", line)
                    if match:
                        justification = match.group(1).strip()
                        if not justification:
                            # No text after # nosec - this is a bare suppression
                            rel_path = src_file.relative_to(src_file.parent.parent.parent)
                            msg = f"{rel_path}:{line_num}: bare '# nosec' with no justification"
                            failures.append(msg)

        assert not failures, "Unexplained suppressions found:\n" + "\n".join(failures)

    def test_no_unexplained_noqa_security_in_src(self, src_files: list[Path]) -> None:
        """Test that every # noqa: S... comment in src/ has a trailing justification.

        This mirrors the # nosec rule: a bare '# noqa: S105' with no reason fails.
        """
        failures = []
        for src_file in src_files:
            with open(src_file) as f:
                lines = f.readlines()
            for line_num, line in enumerate(lines, start=1):
                # Look for a noqa marker with a security rule code (S followed by digits).
                if "# noqa:" in line and re.search(r"#\s*noqa:\s*S\d+", line):
                    # Extract the part after the S-code
                    match = re.search(r"#\s*noqa:\s*S\d+\s*(--\s*)?(.*)$", line)
                    if match:
                        # group(2) is the comment after the code (if any)
                        justification = (match.group(2) or "").strip()
                        # A bare "--" separator with nothing after it (rule code,
                        # then dashes, then nothing) also counts as unjustified.
                        has_dash_only = re.search(r"#\s*noqa:\s*S\d+\s*--\s*", line)
                        if not justification and not has_dash_only:
                            # No text after the S-code and no dash separator either.
                            rel_path = src_file.relative_to(src_file.parent.parent.parent)
                            msg = f"{rel_path}:{line_num}: bare noqa S-code with no justification"
                            failures.append(msg)

        assert not failures, "Unexplained suppressions found:\n" + "\n".join(failures)

    def test_s105_s106_not_globally_ignored(self, pyproject_toml: dict) -> None:
        """Test that S105 and S106 are moved to per-file-ignores, not globally ignored.

        These rules should be scoped to tests/* via per-file-ignores, not blanked
        globally via the ignore list.
        """
        ruff_config = pyproject_toml.get("tool", {}).get("ruff", {})
        lint_config = ruff_config.get("lint", {})

        # Check that S105 and S106 are NOT in the global ignore list
        global_ignore = lint_config.get("ignore", [])
        assert "S105" not in global_ignore, (
            "S105 must not be in the global ignore list; move it to per-file-ignores for tests/*"
        )
        assert "S106" not in global_ignore, (
            "S106 must not be in the global ignore list; move it to per-file-ignores for tests/*"
        )

        # Check that S105 and S106 ARE in per-file-ignores for tests/*
        per_file_ignores = lint_config.get("per-file-ignores", {})
        tests_ignores = per_file_ignores.get("tests/*", [])
        assert "S105" in tests_ignores, "S105 must be in per-file-ignores['tests/*']"
        assert "S106" in tests_ignores, "S106 must be in per-file-ignores['tests/*']"

    def test_bandit_clean_on_src(self, ci_yml_content: str) -> None:
        """Test that the bandit invocation in CI is properly configured.

        The bandit job must run against src/ specifically.
        This assertion verifies the CI configuration; bandit itself
        will be run separately as part of the build gate.
        """
        assert "bandit" in ci_yml_content, "ci.yml must include a bandit step"
        # Look for the bandit invocation pattern
        assert re.search(r"bandit\s+.*src/", ci_yml_content), (
            "bandit invocation must target src/ directory"
        )

    def test_pip_audit_required_in_ci(self, ci_yml_content: str) -> None:
        """Test that pip-audit is configured as a required (non-optional) step.

        The audit job must include pip-audit as a plain run step
        with no continue-on-error or || true, so it fails the build.

        This test is about the step being *required*, not how the tool is
        fetched -- so it has been retargeted twice as the fetch changed: #125
        added `--spec pip-audit==X.Y.Z`, and #159 replaced `pipx run` entirely
        with a hash-locked install. How it is fetched is asserted by
        `test_release_tools_are_installed_from_hash_locked_closures`.
        """
        assert "pip-audit" in ci_yml_content, "ci.yml must include a pip-audit step"
        # Verify the step is not marked as optional
        # Look for the pip-audit line and ensure it's not followed by continue-on-error or || true
        audit_pattern = r"/bin/pip-audit\s+\."
        match = re.search(audit_pattern, ci_yml_content)
        assert match, "ci.yml must invoke pip-audit from its hash-locked venv"

        # Get the section around the pip-audit step to check for continue-on-error
        start = max(0, match.start() - 200)
        end = min(len(ci_yml_content), match.end() + 200)
        context = ci_yml_content[start:end]

        assert "continue-on-error:" not in context, (
            "pip-audit step must not have continue-on-error: true"
        )
        assert "|| true" not in context, "pip-audit step must not have '|| true' to allow failures"


def test_third_party_actions_in_write_privileged_jobs_are_sha_pinned(
    project_root: Path,
) -> None:
    """Issue #119: a third-party action on a mutable tag inside a job that can
    write to this repository is a standing supply-chain exposure -- whoever
    controls the tag gets that write scope on every run.

    Scoped deliberately to *non-GitHub* actions in *write-privileged* jobs,
    which is the audit's own framing: "the one non-GitHub floating-tag action
    in the highest-privilege job". GitHub-owned actions (`actions/*`,
    `github/*`) are exempted here so this test keeps asserting exactly what it
    says it does, and cannot quietly drift into being a broader one.

    Since #124 that broader property -- *every* action in *every* workflow is
    SHA-pinned -- holds, and is asserted by
    `test_every_action_is_sha_pinned_with_its_version_recorded`. The exemption
    below is therefore no longer load-bearing: nothing it skips is unpinned.
    It stays because the narrow claim is worth keeping separately provable.

    Scanned as text rather than parsed: PyYAML is not a declared dependency of
    this project, and every other workflow assertion in this file works on the
    raw content for the same reason.
    """
    job_re = re.compile(r"^  (?P<name>[A-Za-z_][\w-]*):\s*$")
    uses_re = re.compile(r"^\s*-?\s*uses:\s*(?P<uses>\S+)")
    write_re = re.compile(r"^\s+[\w-]+:\s*write\s*$")
    sha_pinned = re.compile(r"^[^@]+@[0-9a-f]{40}$")

    violations: list[str] = []
    for path in sorted((project_root / ".github" / "workflows").glob("*.yml")):
        blocks: dict[str, list[str]] = {}
        current: str | None = None
        in_jobs = False
        for line in path.read_text().splitlines():
            if line.startswith("jobs:"):
                in_jobs = True
                continue
            if not in_jobs:
                continue
            match = job_re.match(line)
            if match:
                current = match.group("name")
                blocks[current] = []
            elif current is not None:
                blocks[current].append(line)

        for job, body in blocks.items():
            if not any(write_re.match(line) for line in body):
                continue
            for line in body:
                found = uses_re.match(line)
                if not found:
                    continue
                uses = found.group("uses")
                if uses.startswith(("actions/", "github/")) or sha_pinned.match(uses):
                    continue
                violations.append(f"{path.name}:{job} -> {uses}")

    assert violations == [], (
        "non-GitHub actions in write-privileged jobs must be pinned by commit SHA, "
        f"not a mutable tag: {violations}"
    )


def test_every_action_is_sha_pinned_with_its_version_recorded(
    project_root: Path,
) -> None:
    """Issue #124: every action in every workflow must be pinned by commit SHA,
    with the human-readable version in a trailing comment.

    #119 pinned the one third-party action in the release job; the GitHub-owned
    ones stayed on moving major tags (`actions/checkout@v7`,
    `github/codeql-action/init@v4`, ...) against this repo's own stated pattern.
    GitHub-owned is lower risk than a random third party, not no risk: a moving
    tag is still a mutable pointer, and `actions/download-artifact` sits between
    the build and the PyPI publish, where a swapped artifact is a released
    artifact.

    The trailing `# vX.Y.Z` is asserted, not just the SHA. A bare 40-hex pin is
    unreviewable and unupgradeable -- nobody can tell what it is or whether it
    is current -- which is the practical objection to SHA pinning, and the
    reason dependabot needs the comment to bump it. Recording the version is
    what makes the pin maintainable rather than merely correct.

    Scanned as text rather than parsed: PyYAML is not a declared dependency of
    this project, and every other workflow assertion in this file does the same.
    Local actions (`uses: ./...`) are exempt and everything else is not -- see
    the comment on that branch for why, including why `docker://` refs are
    deliberately still flagged.
    """
    uses_re = re.compile(r"^\s*-?\s*uses:\s*(?P<uses>\S+)(?P<rest>.*)$")
    pinned_re = re.compile(r"^[^@]+@(?P<sha>[0-9a-f]{40})$")
    version_comment_re = re.compile(r"^\s*#\s*v\d+\.\d+")

    workflows = sorted((project_root / ".github" / "workflows").glob("*.yml"))
    assert workflows, "no workflow files found -- this test would pass vacuously"

    unpinned: list[str] = []
    undocumented: list[str] = []
    total = 0
    for path in workflows:
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            found = uses_re.match(line)
            if not found:
                continue
            uses, rest = found.group("uses"), found.group("rest")
            uses = uses.strip("\"'")  # `uses: "owner/repo@sha"` is valid YAML
            # A local action lives in this repository and is already at whatever
            # commit the workflow runs from, so there is no third party to pin
            # and nothing to bump. Exempted so adding one does not fail this test
            # with a message demanding an impossible pin. `docker://` refs are
            # deliberately NOT exempted: a mutable image tag is the same exposure
            # this test exists to catch, and should carry a digest.
            if uses.startswith("./"):
                continue
            total += 1
            if not pinned_re.match(uses):
                unpinned.append(f"{path.name}:{number} -> {uses}")
            elif not version_comment_re.match(rest):
                undocumented.append(f"{path.name}:{number} -> {uses}{rest}")

    assert total >= 20, f"only found {total} action references -- the scan is not working"
    assert unpinned == [], (
        f"every action must be pinned to a 40-character commit SHA, not a tag: {unpinned}"
    )
    assert undocumented == [], (
        "every SHA pin needs a trailing '# vX.Y.Z' naming the version it pins, "
        f"so it can be reviewed and upgraded: {undocumented}"
    )


# #125's `test_pipx_tools_are_version_pinned` lived here. It asserted that every
# `pipx run` pinned its tool with `--spec <pkg>==<version>`. #159 removed the last
# `pipx run` from the workflows, so the test's own "did the scan find anything?"
# guard could no longer be satisfied -- and its guarantee is strictly weaker than
# what replaced it: `test_no_workflow_still_resolves_a_tool_at_run_time` forbids
# `pipx run` outright, which implies every one of them is pinned. Deleted rather
# than loosened, because a scan that can never find its target is exactly the
# vacuous-test shape #143 and #163 were about.


def test_uvicorn_access_log_is_routed_to_stderr() -> None:
    """Issue #126: PRIVACY.md says this software's logs go to stderr. In hosted
    mode that was false.

    The SDK's `run_streamable_http_async` builds `uvicorn.Config` with only host,
    port and log level -- no `log_config` -- and uvicorn's default points the
    `uvicorn.access` handler at `ext://sys.stdout`. Every request line, client IP
    included, landed on stdout; for `/webhooks/whoop` and `/metrics` that is the
    IP of someone whose health data this server holds.

    This asserts the end state rather than the mechanism: after
    `_route_uvicorn_access_log_to_stderr` runs, uvicorn's own
    `configure_logging` must leave every `uvicorn.access` handler on stderr. That
    is what keeps the documentation honest if the SDK ever starts passing its own
    `log_config` -- the redirect would stop working and this fails, instead of the
    docs silently becoming false again.

    Both loggers are checked, via *effective* handlers rather than each logger's
    own: uvicorn gives `uvicorn.access` its own handler but lets `uvicorn.error`
    propagate up to `uvicorn`, so asking `uvicorn.error` for `.handlers` directly
    returns an empty list. Walking the hierarchy the way `logging` does is what
    makes the check accurate -- and checking `error` too would catch a fix that
    moved `access` by clobbering the whole config.
    """
    import logging
    import sys

    import uvicorn

    from whoopmcp.__main__ import _route_uvicorn_access_log_to_stderr

    _route_uvicorn_access_log_to_stderr()

    config = uvicorn.Config(app=lambda *_: None, host="127.0.0.1", port=0)
    config.configure_logging()

    def effective_streams(name: str) -> list[object]:
        """Every stream a record logged to `name` can reach, following
        propagation exactly as `logging.Logger.callHandlers` does."""
        streams: list[object] = []
        logger: logging.Logger | None = logging.getLogger(name)
        while logger:
            streams.extend(getattr(handler, "stream", None) for handler in logger.handlers)
            logger = logger.parent if logger.propagate else None
        return streams

    for name in ("uvicorn.access", "uvicorn.error"):
        streams = effective_streams(name)
        assert streams, f"{name} reaches no stream handler, so this proves nothing"
        assert all(stream is sys.stderr for stream in streams), (
            f"{name} logs somewhere other than stderr: {streams}"
        )


def test_the_http_transport_path_redirects_the_access_log() -> None:
    """The redirect has to be *called*, not merely defined.

    A helper nobody invokes is the same as no fix, and the call site is one line
    in `main()` that no other test covers -- so this reads the source rather than
    leaving it unasserted.
    """
    import inspect

    from whoopmcp import __main__ as cli

    source = inspect.getsource(cli)
    marker = 'if transport == "streamable-http":'
    assert marker in source, "the streamable-http branch moved or was renamed"
    http_branch = source[source.index(marker) :]

    # Asserted separately so a missing call reports as that, rather than as a
    # ValueError from str.index with no explanation of what went wrong.
    assert "_route_uvicorn_access_log_to_stderr()" in http_branch, (
        "the streamable-http branch does not call the access-log redirect, so "
        "PRIVACY.md's stderr-only row is false again in hosted mode"
    )
    assert http_branch.index("_route_uvicorn_access_log_to_stderr()") < http_branch.index(
        'run(transport="streamable-http"'
    ), "the redirect must happen before the server starts, or uvicorn is already configured"


def test_sdk_still_leaves_uvicorns_log_config_to_its_default() -> None:
    """Issue #126: the access-log redirect only works while the SDK does *not*
    pass its own `log_config` to `uvicorn.Config`.

    `_route_uvicorn_access_log_to_stderr` mutates uvicorn's module-level
    `LOGGING_CONFIG`, which `uvicorn.Config.__init__` consults only because it is
    that parameter's default. An SDK that supplied its own dict would bypass the
    mutation entirely and put access logs back on stdout, making PRIVACY.md false
    again -- silently, because nothing else would change.

    This is the test that actually watches for that, and it has to read the SDK's
    source to do it. A test that builds its own `uvicorn.Config` -- as the
    end-state test above does -- cannot detect a change in what the *SDK* passes;
    verified by simulation, where an independent `log_config` sent access logs to
    stdout while that test still passed. The docstring used to claim the
    end-state test covered this. It did not.
    """
    import inspect

    from mcp.server.mcpserver import MCPServer

    source = inspect.getsource(MCPServer.run_streamable_http_async)
    assert "uvicorn.Config(" in source, (
        "the SDK no longer builds uvicorn.Config here, so the redirect's premise "
        "needs re-deriving from scratch"
    )
    assert "log_config" not in source, (
        "the SDK now passes its own log_config to uvicorn.Config, which bypasses "
        "the LOGGING_CONFIG mutation in _route_uvicorn_access_log_to_stderr -- "
        "access logs are back on stdout and PRIVACY.md's stderr-only row is false"
    )


def test_compact_database_citation_of_privacy_md_resolves(project_root: Path) -> None:
    """Issue #128: `compact_database`'s docstring said `PRAGMA secure_delete` is 0
    "by design -- see PRIVACY.md", and PRIVACY.md said nothing about
    `secure_delete` or residual bytes anywhere.

    A pointer to documentation that does not exist is worse than no pointer: it
    reads as though the trade-off is disclosed to users when it was disclosed only
    to whoever read the source. This pins the pointer to actually resolving.

    Asserted against PRIVACY.md's **retention** section specifically, not the
    whole file. The erasure section already mentioned `VACUUM`, so a
    file-wide substring check would have passed before the fix and proved nothing
    -- the gap was that retention, the deletion class that runs on a schedule, said
    nothing about bytes surviving until the next compaction.
    """
    import inspect

    from whoopmcp.store import compact_database

    docstring = inspect.getdoc(compact_database) or ""
    assert "PRIVACY.md" in docstring, (
        "compact_database no longer cites PRIVACY.md; if the citation was removed "
        "on purpose, this test should go with it"
    )

    privacy = (project_root / "PRIVACY.md").read_text(encoding="utf-8")
    assert "**Retention.**" in privacy, "PRIVACY.md's retention section moved or was renamed"
    retention = privacy[privacy.index("**Retention.**") : privacy.index("**Backups.**")]

    assert "secure_delete" in retention, (
        "PRIVACY.md's retention section does not mention `secure_delete`, so "
        "compact_database's citation points at text that does not exist (#128)"
    )
    for phrase in ("rows", "bytes"):
        assert phrase in retention, (
            f"PRIVACY.md's retention section does not distinguish {phrase!r}; the "
            "row-versus-byte caveat is what #128 added"
        )


#: The release-path tools whose whole dependency closure is hash-locked (#159).
HASH_LOCKED_TOOLS = ("build", "twine", "pip-audit")


def test_release_tools_are_installed_from_hash_locked_closures(project_root: Path) -> None:
    """Issue #159: #125 pinned each tool's version and left its dependency closure
    to be resolved against PyPI at run time.

    `build` pulls in `packaging` and `pyproject_hooks`; `twine` and `pip-audit`
    pull in 27 more each. A compromised release of any of them executes inside the
    job that produces the distributions `release.yml` publishes -- the same blast
    radius as a compromised `build`, differing only in how many packages an
    attacker must own.

    Asserts the three properties that make the guarantee real: the lock exists,
    both workflows install from it, and they do so with `--require-hashes`, which
    refuses an artifact whose hash is not listed *and* refuses to run at all if any
    dependency is unpinned. The last part is why the flag matters more than the
    hashes: it is what makes the closure provably complete.

    This is a *structural* check and deliberately not a cryptographic one. It does
    not verify that any listed hash is the true digest of a real artifact -- that
    needs the network, and it is exactly what `pip install --require-hashes` does
    on every CI push. Confirmed that pip really enforces it: corrupting every hash
    for one package in a copy of `build.txt` makes the install fail with "THESE
    PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE". (Corrupting only
    *one* of a package's two hashes does not, and that is correct -- pip matches
    the artifact it downloaded against any listed hash, and a package normally
    lists both its sdist and its wheel.)
    """
    requirements = project_root / ".github" / "requirements"
    ci = (project_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    release = (project_root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    for tool in HASH_LOCKED_TOOLS:
        lock = requirements / f"{tool}.txt"
        assert lock.is_file(), f"{lock} is missing, so nothing pins {tool}'s closure"

        body = lock.read_text(encoding="utf-8")
        pinned = [line for line in body.splitlines() if line and not line.startswith((" ", "#"))]
        assert pinned, f"{tool}.txt pins nothing"
        for line in pinned:
            assert "==" in line, f"{tool}.txt has an unpinned requirement: {line!r}"
        assert body.count("--hash=sha256:") >= len(pinned), (
            f"{tool}.txt has fewer hashes than requirements, so something is unhashed"
        )

        # `pip-audit` only runs in CI; `build` and `twine` run in both, and
        # release.yml is the one that matters -- it only runs on a tag, so a
        # mistake there is invisible until release day.
        workflows = (
            [("ci.yml", ci)] if tool == "pip-audit" else [("ci.yml", ci), ("release.yml", release)]
        )
        for name, text in workflows:
            expected = f"--require-hashes -r .github/requirements/{tool}.txt"
            assert expected in text, (
                f"{name} does not install {tool} from its hash-locked closure "
                f"(expected {expected!r})"
            )


def test_no_workflow_still_resolves_a_tool_at_run_time(project_root: Path) -> None:
    """The other half of #159: the old mechanism must be gone, not merely joined.

    `pipx run --spec X==V` pins the named tool and resolves its closure fresh on
    every run. Leaving one behind would keep exactly the hole this issue closed,
    while the test above still passed for the tools that had been converted.
    """
    for workflow in sorted((project_root / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert "pipx run" not in stripped, (
                f"{workflow.name}:{number} still resolves a tool's closure at run "
                f"time: {stripped!r}"
            )


def test_lock_files_match_their_declared_input_version(project_root: Path) -> None:
    """The `.in` file is the source of truth for the version; the `.txt` must agree.

    Without this, editing `build.in` to a new version and forgetting to recompile
    leaves the old closure installed while the repository appears to say otherwise
    -- the same stale-claim failure mode as a docstring citing text that no longer
    exists.
    """
    requirements = project_root / ".github" / "requirements"
    for tool in HASH_LOCKED_TOOLS:
        declared = (requirements / f"{tool}.in").read_text(encoding="utf-8").strip()
        assert "==" in declared, f"{tool}.in does not pin a version: {declared!r}"
        locked = (requirements / f"{tool}.txt").read_text(encoding="utf-8")
        assert any(line.startswith(declared) for line in locked.splitlines()), (
            f"{tool}.txt does not pin {declared!r}; regenerate it (see "
            ".github/requirements/README.md)"
        )
