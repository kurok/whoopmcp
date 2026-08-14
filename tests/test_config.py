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

    # 'encrypted-file' (#30) joined 'file'/'keyring' as a third valid value.
    with pytest.raises(ConfigError, match="'file', 'keyring', or 'encrypted-file'"):
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


# -- backfill floor date (issue #14) ------------------------------------------


def test_backfill_floor_date_defaults_to_no_floor() -> None:
    # Unset means "walk until history is exhausted".
    assert Config.from_env(VALID_ENV).backfill_floor_date is None


def test_backfill_floor_date_accepts_iso_and_stays_a_string() -> None:
    # Kept as the string build_collection_params/the API convention expects,
    # not parsed into a datetime.
    env = VALID_ENV | {"WHOOPMCP_BACKFILL_FLOOR_DATE": "2024-01-01T00:00:00+00:00"}

    assert Config.from_env(env).backfill_floor_date == "2024-01-01T00:00:00+00:00"


def test_backfill_floor_date_accepts_a_bare_date() -> None:
    env = VALID_ENV | {"WHOOPMCP_BACKFILL_FLOOR_DATE": "2024-01-01"}

    assert Config.from_env(env).backfill_floor_date == "2024-01-01"


def test_malformed_backfill_floor_date_is_rejected_at_startup() -> None:
    # Fail at startup with the variable's name, not mid-backfill.
    env = VALID_ENV | {"WHOOPMCP_BACKFILL_FLOOR_DATE": "not-a-date"}

    with pytest.raises(ConfigError, match="WHOOPMCP_BACKFILL_FLOOR_DATE"):
        Config.from_env(env)


# -- repr redaction (issue #133) -----------------------------------------------
#
# Issue #37's audit found that repr(Token) and repr(Config) expose every secret
# they hold. This test suite ensures that repr=False is applied to the exact
# fields that hold secrets, without redacting non-secret fields that aid
# diagnosis.


def test_no_secret_in_repr_config(tmp_path: Path) -> None:
    """Test 2: No secret in repr(Config).

    Client secret, key bytes (in all forms: raw bytes, .hex(), base64),
    metrics token, and metrics_member_salt must not appear in repr(Config).

    This test MUST FAIL against current main (before repr=False is added).
    """
    import base64
    import os

    client_secret = "CLIENT-SECRET-abc123"
    key_bytes = os.urandom(32)
    metrics_token = "METRICS-SECRET-xyz789"
    metrics_salt = "SALT-SECRET-def456"

    config = Config(
        client_id="cid",
        client_secret=client_secret,
        redirect_uri="https://localhost:8443/callback",
        state_dir=tmp_path,
        token_encryption_keys={1: key_bytes},
        token_encryption_key_version=1,
        metrics_token=metrics_token,
        metrics_member_salt=metrics_salt,
    )

    config_repr = repr(config)

    # Check the client secret itself
    assert client_secret not in config_repr, f"client_secret leaked in repr: {config_repr}"

    # Check the encryption key in all forms it could surface. `config_repr`
    # is a str, so the raw `bytes` object itself can never be a substring of
    # it (Python raises TypeError on `bytes in str`) -- what a default repr
    # would actually emit for a bytes field is its own repr/str form (e.g.
    # "b'\\x01...'"), which is what str(bytes) produces.
    assert str(key_bytes) not in config_repr, (
        f"encryption key (raw bytes) leaked in repr: {config_repr}"
    )
    assert key_bytes.hex() not in config_repr, (
        f"encryption key (hex form) leaked in repr: {config_repr}"
    )
    assert base64.b64encode(key_bytes).decode() not in config_repr, (
        f"encryption key (base64 form) leaked in repr: {config_repr}"
    )

    # Check metrics secrets
    assert metrics_token not in config_repr, f"metrics_token leaked in repr: {config_repr}"
    assert metrics_salt not in config_repr, f"metrics_member_salt leaked in repr: {config_repr}"


def test_non_secret_fields_shown_in_repr_config(tmp_path: Path) -> None:
    """Test 3: Non-secret fields ARE still shown (D2).

    The token_backend name and token_encryption_key_version integer are not
    secrets and must remain visible in repr(Config) so diagnostics work.
    Redacting everything is worse for debugging than redacting nothing.
    """
    config = Config(
        client_id="cid",
        client_secret="csecret",
        redirect_uri="https://localhost:8443/callback",
        state_dir=tmp_path,
        token_backend="keyring",
        token_encryption_key_version=3,
    )

    config_repr = repr(config)

    # The backend name (not a secret, just a choice between file/keyring/encrypted-file)
    # must appear
    assert "keyring" in config_repr, (
        f"token_backend value must be visible in repr for diagnostics: {config_repr}"
    )

    # The key version number (not a secret, just an integer) must appear
    assert "3" in config_repr, (
        f"token_encryption_key_version value must be visible in repr for diagnostics: {config_repr}"
    )


def test_every_secret_field_has_repr_false() -> None:
    """Test 5: Structural guard (no regression on secret field additions).

    Every field whose name contains 'secret', 'key', 'token', or 'salt'
    (and which is actually a secret) must have repr=False. This test derives
    the field list from dataclasses.fields at runtime, so adding a new
    secret-bearing field later will fail the test rather than silently leak.

    Fields that match the naming pattern but are NOT secrets (e.g. client_id,
    token_backend, token_encryption_key_version) are explicitly exempted.
    """
    import dataclasses

    # Fields that match secret-like names but are NOT secrets
    # (public identifiers, configuration names, version numbers, paths, etc.)
    allowed_exceptions = {
        # Token fields
        "scopes",  # List of OAuth scope names (e.g. "read:sleep"), not secret
        # Config fields
        "client_id",  # OAuth client id (public)
        "token_backend",  # Backend name (file/keyring/encrypted-file), not a secret
        "token_encryption_key_version",  # Integer version number, not a secret
        "token_path",  # Filesystem path, not a secret
        "redirect_uri",  # OAuth redirect URI (public)
        "backfill_floor_date",  # Date string, not a secret
    }

    from whoopmcp.auth import Token
    from whoopmcp.config import Config

    for klass in (Token, Config):
        for field in dataclasses.fields(klass):
            # Check if the field name matches a secret-like pattern
            lower_name = field.name.lower()
            is_secret_named = any(
                keyword in lower_name for keyword in ("secret", "key", "token", "salt")
            )

            if is_secret_named and field.name not in allowed_exceptions:
                # This field matches a secret pattern and is not in the allowed list
                # It MUST have repr=False
                assert field.repr is False, (
                    f"{klass.__name__}.{field.name}: field name matches a secret pattern "
                    f"('secret', 'key', 'token', or 'salt') but has repr=True. "
                    f"It should have repr=False. If this is not actually a secret, "
                    f"add it to allowed_exceptions in the test."
                )


# -- numeric variable validation (#200) ----------------------------------------


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("WHOOPMCP_TIMEOUT", "abc"),
        ("WHOOPMCP_RATE_LIMIT_PER_MINUTE", "1,00"),
        ("WHOOPMCP_RATE_LIMIT_PER_DAY", "many"),
        ("WHOOPMCP_HTTP_PORT", "8000x"),
        ("WHOOPMCP_WEBHOOK_TIMESTAMP_SKEW_SECONDS", "5m"),
        ("WHOOPMCP_WEBHOOK_RATE_LIMIT_PER_MINUTE", "x"),
    ],
)
def test_malformed_numeric_variable_is_a_configerror_naming_it(variable: str, value: str) -> None:
    """from_env's docstring has always promised ConfigError for a malformed
    variable, and the backfill-floor precedent is that it names WHICH one --
    these six escaped as raw ValueError tracebacks that name nothing (#200),
    past every caller that degrades ConfigError gracefully (doctor, the CLI).
    """
    with pytest.raises(ConfigError, match=variable):
        Config.from_env(VALID_ENV | {variable: value})


@pytest.mark.parametrize(
    "variable", ["WHOOPMCP_RATE_LIMIT_PER_MINUTE", "WHOOPMCP_RATE_LIMIT_PER_DAY"]
)
@pytest.mark.parametrize("value", ["0", "-5"])
def test_non_positive_outbound_rate_limit_is_rejected(variable: str, value: str) -> None:
    """A 0 outbound limit built a RateLimiter whose acquire() can never grant
    (its counters must be > 0), so every request hung forever with no error
    (#200). The trap was baited: the INBOUND webhook limiter documents "0 or
    negative disables", so an operator carrying that convention over got a
    silent deadlock instead of "no limit". Rejected at startup, by name.
    """
    with pytest.raises(ConfigError, match=variable):
        Config.from_env(VALID_ENV | {variable: value})


@pytest.mark.parametrize("value", ["0", "-1"])
def test_non_positive_timeout_is_rejected(value: str) -> None:
    """A 0 timeout is not "no timeout" to httpx -- it times out immediately."""
    with pytest.raises(ConfigError, match="WHOOPMCP_TIMEOUT"):
        Config.from_env(VALID_ENV | {"WHOOPMCP_TIMEOUT": value})


@pytest.mark.parametrize("value", ["0", "65536", "-1"])
def test_out_of_range_http_port_is_rejected(value: str) -> None:
    with pytest.raises(ConfigError, match="WHOOPMCP_HTTP_PORT"):
        Config.from_env(VALID_ENV | {"WHOOPMCP_HTTP_PORT": value})


def test_zero_webhook_rate_limit_still_means_disabled() -> None:
    """The inbound limiter's documented opt-out must keep working: 0 (and
    negative) mean "no inbound limit" there, so range validation must not
    reach this variable -- only the malformed-value check does."""
    config = Config.from_env(VALID_ENV | {"WHOOPMCP_WEBHOOK_RATE_LIMIT_PER_MINUTE": "0"})
    assert config.webhook_rate_limit_per_minute == 0


def test_numeric_defaults_survive_the_validation() -> None:
    """The defaults themselves must parse and pass every range check."""
    config = Config.from_env(VALID_ENV)
    assert config.request_timeout == 30.0
    assert config.rate_limit_per_minute == 100
    assert config.rate_limit_per_day == 10_000
    assert config.http_port == 8000
    assert config.webhook_timestamp_skew_seconds == 300.0
    assert config.webhook_rate_limit_per_minute == 120
