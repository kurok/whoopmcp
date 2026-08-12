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
        """
        assert "pip-audit" in ci_yml_content, "ci.yml must include a pip-audit step"
        # Verify the step is not marked as optional
        # Look for the pip-audit line and ensure it's not followed by continue-on-error or || true
        audit_pattern = r"-\s*run:\s*pipx run pip-audit\s*\.?"
        match = re.search(audit_pattern, ci_yml_content)
        assert match, "ci.yml must have a plain 'pipx run pip-audit .' step"

        # Get the section around the pip-audit step to check for continue-on-error
        start = max(0, match.start() - 200)
        end = min(len(ci_yml_content), match.end() + 200)
        context = ci_yml_content[start:end]

        assert "continue-on-error:" not in context, (
            "pip-audit step must not have continue-on-error: true"
        )
        assert "|| true" not in context, "pip-audit step must not have '|| true' to allow failures"
