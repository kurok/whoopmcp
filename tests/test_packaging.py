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
