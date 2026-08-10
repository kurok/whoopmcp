from __future__ import annotations

from pathlib import Path

import pytest

from whoopmcp.config import DEFAULT_SCOPES, Config, ConfigError

VALID_ENV = {
    "WHOOP_CLIENT_ID": "cid",
    "WHOOP_CLIENT_SECRET": "csecret",
    "WHOOP_REDIRECT_URI": "https://localhost:8443/callback",
}


def test_from_env_reads_required_values() -> None:
    config = Config.from_env(VALID_ENV)

    assert config.client_id == "cid"
    assert config.redirect_uri == "https://localhost:8443/callback"
    assert config.scopes == DEFAULT_SCOPES


def test_offline_scope_is_requested_by_default() -> None:
    # Without `offline` WHOOP issues no refresh token, and the user has to
    # re-authorise through a browser every hour.
    assert "offline" in DEFAULT_SCOPES


@pytest.mark.parametrize(
    "missing", ["WHOOP_CLIENT_ID", "WHOOP_CLIENT_SECRET", "WHOOP_REDIRECT_URI"]
)
def test_missing_required_variable_is_reported_by_name(missing: str) -> None:
    env = {k: v for k, v in VALID_ENV.items() if k != missing}

    with pytest.raises(ConfigError, match=missing):
        Config.from_env(env)


def test_http_redirect_uri_is_rejected() -> None:
    # WHOOP's dashboard will not accept it, so failing here is kinder than
    # failing after the user has already clicked through a consent screen.
    env = VALID_ENV | {"WHOOP_REDIRECT_URI": "http://localhost:8080/callback"}

    with pytest.raises(ConfigError, match="http://"):
        Config.from_env(env)


def test_custom_scheme_redirect_uri_is_allowed() -> None:
    env = VALID_ENV | {"WHOOP_REDIRECT_URI": "whoopmcp://callback"}

    assert Config.from_env(env).redirect_uri == "whoopmcp://callback"


def test_unknown_token_backend_is_rejected() -> None:
    env = VALID_ENV | {"WHOOPMCP_TOKEN_BACKEND": "vault"}

    with pytest.raises(ConfigError, match="file' or 'keyring"):
        Config.from_env(env)


def test_state_dir_overrides_derive_token_and_cache_paths(tmp_path: Path) -> None:
    env = VALID_ENV | {"WHOOPMCP_STATE_DIR": str(tmp_path)}

    config = Config.from_env(env)

    assert config.token_path == tmp_path / "token.json"
    assert config.cache_path == tmp_path / "cache.sqlite3"


def test_cache_is_off_unless_explicitly_enabled() -> None:
    assert Config.from_env(VALID_ENV).cache_enabled is False
    assert Config.from_env(VALID_ENV | {"WHOOPMCP_CACHE": "yes"}).cache_enabled is True


def test_scopes_can_be_narrowed() -> None:
    env = VALID_ENV | {"WHOOPMCP_SCOPES": "read:recovery offline"}

    assert Config.from_env(env).scopes == ("read:recovery", "offline")


def test_rate_limit_config_from_env() -> None:
    config = Config.from_env(VALID_ENV)
    assert config.rate_limit_per_minute == 100
    assert config.rate_limit_per_day == 10_000

    env = VALID_ENV | {
        "WHOOPMCP_RATE_LIMIT_PER_MINUTE": "50",
        "WHOOPMCP_RATE_LIMIT_PER_DAY": "500",
    }
    overridden = Config.from_env(env)
    assert overridden.rate_limit_per_minute == 50
    assert overridden.rate_limit_per_day == 500


# -- transport config (issue #27) -------------------------------------------


def test_transport_defaults_to_stdio() -> None:
    config = Config.from_env(VALID_ENV)

    assert config.transport == "stdio"
    assert config.http_host == "127.0.0.1"
    assert config.http_port == 8000


def test_transport_parses_from_env() -> None:
    env = VALID_ENV | {
        "WHOOPMCP_TRANSPORT": "streamable-http",
        "WHOOPMCP_HTTP_HOST": "192.0.2.1",
        "WHOOPMCP_HTTP_PORT": "9001",
    }

    config = Config.from_env(env)

    assert config.transport == "streamable-http"
    assert config.http_host == "192.0.2.1"
    assert config.http_port == 9001


def test_unknown_transport_is_rejected() -> None:
    env = VALID_ENV | {"WHOOPMCP_TRANSPORT": "carrier-pigeon"}

    with pytest.raises(ConfigError, match="stdio' or 'streamable-http"):
        Config.from_env(env)
