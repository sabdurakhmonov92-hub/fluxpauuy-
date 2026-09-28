"""Unit tests for the application configuration module and environment contract.

Validates fail-fast boot invariants, secret length requirements, immutability,
caching behavior, and 100% synchronization between Settings fields and .env.example.
"""

import base64
import os
import re
from collections.abc import Generator
from pathlib import Path

import pytest
from pydantic import ValidationError

from fluxpay.config import Settings, get_settings


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Generator[dict[str, str], None, None]:
    """Provide an isolated environment with valid baseline configuration."""
    # Strip any existing ambient FLX_ environment variables
    for key in list(os.environ.keys()):
        if key.startswith("FLX_"):
            monkeypatch.delenv(key, raising=False)

    valid_vault_key = base64.b64encode(b"0" * 32).decode("ascii")
    valid_webhook_key = "a" * 32
    baseline = {
        "FLX_PG_DSN": "postgresql://test:test@localhost:5432/test",
        "FLX_VAULT_MASTER_KEY": valid_vault_key,
        "FLX_WEBHOOK_SIGNING_KEY": valid_webhook_key,
    }

    for key, value in baseline.items():
        monkeypatch.setenv(key, value)

    get_settings.cache_clear()
    yield baseline
    get_settings.cache_clear()


@pytest.mark.unit
def test_valid_configuration_constructs_successfully(clean_env: dict[str, str]) -> None:
    """Validate that valid baseline environment variables successfully construct Settings."""
    settings = Settings()
    assert settings.pg_dsn == clean_env["FLX_PG_DSN"]
    assert settings.vault_master_key == clean_env["FLX_VAULT_MASTER_KEY"]
    assert settings.webhook_signing_key == clean_env["FLX_WEBHOOK_SIGNING_KEY"]
    assert settings.pg_pool_min == 2
    assert settings.pg_pool_max == 20
    assert settings.valkey_url == "redis://localhost:6379/0"
    assert settings.rabbitmq_url == "amqp://localhost:5672/"
    assert settings.replay_window_ms == 30_000
    assert settings.nonce_ttl_ms == 120_000
    assert settings.env == "development"
    assert settings.log_level == "INFO"
    assert settings.sentry_dsn is None


@pytest.mark.unit
def test_missing_vault_master_key_raises_validation_error(
    clean_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate that omitting FLX_VAULT_MASTER_KEY raises ValidationError naming the field."""
    monkeypatch.delenv("FLX_VAULT_MASTER_KEY")
    with pytest.raises(ValidationError) as exc_info:
        Settings()

    errors = exc_info.value.errors()
    assert any("vault_master_key" in err["loc"] for err in errors)


@pytest.mark.unit
@pytest.mark.parametrize("byte_length", [31, 33])
def test_vault_master_key_wrong_byte_length_fails(
    clean_env: dict[str, str], monkeypatch: pytest.MonkeyPatch, byte_length: int
) -> None:
    """Validate that vault master keys with != 32 decoded bytes raise actionable ValidationError."""
    raw_bytes = b"x" * byte_length
    invalid_key = base64.b64encode(raw_bytes).decode("ascii")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", invalid_key)

    with pytest.raises(ValidationError) as exc_info:
        Settings()

    error_msg = str(exc_info.value)
    assert "vault_master_key must decode to exactly 32 bytes" in error_msg
    assert "openssl rand -base64 32" in error_msg
    # Crucial security invariant: never leak the key value in the error message
    assert invalid_key not in error_msg


@pytest.mark.unit
def test_vault_master_key_invalid_base64_fails(
    clean_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate that non-base64 vault keys raise ValidationError without echoing input."""
    invalid_key = "not_valid_base64_!@#$"
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", invalid_key)

    with pytest.raises(ValidationError) as exc_info:
        Settings()

    error_msg = str(exc_info.value)
    assert "valid base64-encoded string" in error_msg
    assert invalid_key not in error_msg


@pytest.mark.unit
def test_webhook_signing_key_too_short_fails(
    clean_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate that webhook signing keys shorter than 32 characters fail validation."""
    short_key = "only_10_ch"
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", short_key)

    with pytest.raises(ValidationError) as exc_info:
        Settings()

    error_msg = str(exc_info.value)
    assert "webhook_signing_key must be at least 32 characters long" in error_msg
    assert short_key not in error_msg


@pytest.mark.unit
def test_pg_dsn_invalid_scheme_fails(
    clean_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate that non-Postgres DSNs fail fast."""
    monkeypatch.setenv("FLX_PG_DSN", "mysql://user:pass@localhost:3306/db")

    with pytest.raises(ValidationError) as exc_info:
        Settings()

    error_msg = str(exc_info.value)
    assert "pg_dsn must start with 'postgresql://' or 'postgres://'" in error_msg


@pytest.mark.unit
def test_nonce_ttl_less_than_twice_replay_window_fails(
    clean_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate that nonce_ttl_ms < 2 * replay_window_ms violates anti-replay invariants."""
    monkeypatch.setenv("FLX_REPLAY_WINDOW_MS", "30000")
    monkeypatch.setenv("FLX_NONCE_TTL_MS", "59999")

    with pytest.raises(ValidationError) as exc_info:
        Settings()

    error_msg = str(exc_info.value)
    assert "nonce_ttl_ms" in error_msg
    assert "2x replay_window_ms" in error_msg


@pytest.mark.unit
def test_pg_pool_min_greater_than_max_fails(
    clean_env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validate that pg_pool_min > pg_pool_max raises ValidationError."""
    monkeypatch.setenv("FLX_PG_POOL_MIN", "25")
    monkeypatch.setenv("FLX_PG_POOL_MAX", "20")

    with pytest.raises(ValidationError) as exc_info:
        Settings()

    error_msg = str(exc_info.value)
    assert "pg_pool_min" in error_msg
    assert "pg_pool_max" in error_msg


@pytest.mark.unit
def test_settings_are_immutable_frozen(clean_env: dict[str, str]) -> None:
    """Validate that settings instances are strictly frozen and disallow runtime mutation."""
    settings = Settings()
    with pytest.raises(ValidationError):
        settings.log_level = "DEBUG"  # type: ignore[misc]


@pytest.mark.unit
def test_get_settings_caches_singleton(clean_env: dict[str, str]) -> None:
    """Validate that get_settings() caches and returns the exact same object reference."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


@pytest.mark.unit
def test_env_example_contains_all_settings_fields() -> None:
    """Automated contract test: ensure 100% of Settings fields are declared in .env.example."""
    # Find .env.example relative to repository root
    env_example_path = Path(__file__).resolve().parents[2] / ".env.example"
    assert env_example_path.is_file(), f".env.example not found at {env_example_path}"

    content = env_example_path.read_text(encoding="utf-8")
    declared_vars = set(re.findall(r"^(?:#\s*)?(FLX_[A-Z0-9_]+)=", content, re.MULTILINE))

    for field_name in Settings.model_fields:
        expected_var = f"FLX_{field_name.upper()}"
        assert expected_var in declared_vars, (
            f"Configuration field '{field_name}' (expected '{expected_var}') is not declared "
            f"in .env.example. All configuration options must be documented in .env.example."
        )
