"""Application configuration module enforcing strict twelve-factor environment contracts.

This module defines the primary configuration boundary for FluxPay. Settings are loaded
from environment variables prefixed with 'FLX_', immutable once initialized, and validated
to fail fast at boot before any network sockets or services are engaged.
"""

import base64
from functools import lru_cache
from typing import Literal, Self

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["Settings", "get_settings"]


class Settings(BaseSettings):
    """Immutable application settings loaded from environment variables with FLX_ prefix."""

    model_config = SettingsConfigDict(
        env_prefix="FLX_",
        frozen=True,
        extra="ignore",
        hide_input_in_errors=True,
    )

    # --- Postgres ---
    # Required; must start with postgresql:// or postgres://
    pg_dsn: str
    # Minimum idle connections in pool to avoid connection ramp latency
    pg_pool_min: int = 2
    # PgBouncer sits in front later; keep modest to prevent backend socket starvation
    pg_pool_max: int = 20

    # --- Valkey / RabbitMQ ---
    # Valkey URL for caching, rate limiting, and distributed locks
    valkey_url: str = "redis://localhost:6379/0"
    # RabbitMQ URL for async ledger events and transaction queues
    rabbitmq_url: str = "amqp://localhost:5672/"

    # --- Secrets (REQUIRED — app refuses to boot without them) ---
    # Base64, decodes to EXACTLY 32 bytes (AES-256 requirement for customer data vault)
    vault_master_key: str
    # Min length 32 chars for HMAC-SHA256 signature verification on outbound webhooks
    webhook_signing_key: str

    # --- Gateway (anti-replay / rate / quota — blueprint §3) ---
    # ±30s strict window for timestamp anti-replay verification
    replay_window_ms: int = 30_000
    # 60s sliding window for agent API request rate limiting
    rate_limit_window_ms: int = 60_000
    # Maximum allowed requests per agent per rate limit window
    rate_limit_max: int = 100
    # Maximum cumulative daily API operations allowed per autonomous agent account
    daily_quota_max: int = 10_000
    # >= 2x replay window: covers clock skew both ways to prevent nonce reuse
    nonce_ttl_ms: int = 120_000

    # --- Ledger ---
    # Bounded optimistic concurrency control retries; beyond this = systemic conflict
    ledger_max_occ_retries: int = 5

    # --- Environment / ops ---
    # Deployment stage determining security constraints
    env: Literal["development", "staging", "production"] = "development"
    # Structured logging verbosity threshold
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # None = disabled locally; only set in deploy env for error tracking
    sentry_dsn: str | None = None

    # --- Task 22 append ---
    # 24h hot-path retention; DB tier retains longer (Task 11 purge policy = Phase 2 worker).
    # WHY 24h: matches industry convention (Stripe); long enough for retry storms,
    # short enough for memory bounds.
    idempotency_fast_ttl_s: int = 86400

    @field_validator("pg_dsn")
    @classmethod
    def validate_pg_dsn(cls, v: str) -> str:
        """Validate PostgreSQL DSN scheme."""
        if not (v.startswith("postgresql://") or v.startswith("postgres://")):
            raise ValueError(
                "pg_dsn must start with 'postgresql://' or 'postgres://'. "
                "Provide a valid PostgreSQL DSN (e.g., 'postgresql://user:pass@localhost:5432/dbname')."
            )
        return v

    @field_validator("vault_master_key")
    @classmethod
    def validate_vault_master_key(cls, v: str) -> str:
        """Validate vault master key decodes to exactly 32 bytes without leaking key content."""
        try:
            decoded = base64.b64decode(v, validate=True)
        except Exception as exc:
            raise ValueError(
                "vault_master_key must be a valid base64-encoded string representing exactly "
                "32 bytes (AES-256 requirement). Generate with 'openssl rand -base64 32'."
            ) from exc

        if len(decoded) != 32:
            raise ValueError(
                f"vault_master_key must decode to exactly 32 bytes (AES-256 requirement), but "
                f"decoded to {len(decoded)} bytes. Generate with 'openssl rand -base64 32'."
            )
        return v

    @field_validator("webhook_signing_key")
    @classmethod
    def validate_webhook_signing_key(cls, v: str) -> str:
        """Validate webhook signing key meets minimum entropy length without leaking key content."""
        if len(v) < 32:
            raise ValueError(
                f"webhook_signing_key must be at least 32 characters long for HMAC-SHA256 "
                f"security, got length {len(v)}. Generate with 'openssl rand -hex 32'."
            )
        return v

    @field_validator("sentry_dsn", mode="before")
    @classmethod
    def empty_str_to_none(cls, v: str | None) -> str | None:
        """Convert empty string Sentry DSN to None for seamless local fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @model_validator(mode="after")
    def validate_cross_field_invariants(self) -> Self:
        """Validate connection pool, anti-replay window, and notification invariants."""
        if self.pg_pool_min > self.pg_pool_max:
            raise ValueError(
                f"pg_pool_min ({self.pg_pool_min}) cannot be greater than "
                f"pg_pool_max ({self.pg_pool_max}). Ensure pg_pool_min <= pg_pool_max."
            )
        if self.nonce_ttl_ms < 2 * self.replay_window_ms:
            raise ValueError(
                f"nonce_ttl_ms ({self.nonce_ttl_ms}) must be at least 2x replay_window_ms "
                f"({2 * self.replay_window_ms}) to cover clock skew in both directions."
            )
        # Task 43: half-configured Telegram = misconfiguration.
        # Token set but no chat_id → silent non-delivery. Fail fast at boot.
        if self.telegram_bot_token is not None and self.telegram_admin_chat_id is None:
            raise ValueError(
                "telegram_bot_token is set but telegram_admin_chat_id is None. "
                "Both must be provided to enable Telegram notifications, or both must "
                "be absent/empty to disable. Half-configured Telegram leads to silent "
                "non-delivery."
            )
        return self

    # --- Task 29 append ---
    # Keycloak JWKS endpoint URL for token verification (must start with https://)
    keycloak_jwks_url: str = (
        "https://auth.fluxpay.local/realms/fluxpay/protocol/openid-connect/certs"
    )
    # Keycloak OIDC issuer URL (must start with https://)
    keycloak_issuer: str = "https://auth.fluxpay.local/realms/fluxpay"
    # Keycloak client audience (must start with https://)
    keycloak_audience: str = "https://api.fluxpay.local"

    @field_validator("keycloak_jwks_url", "keycloak_issuer", "keycloak_audience")
    @classmethod
    def validate_keycloak_urls(cls, v: str) -> str:
        """Validate Keycloak URLs start with https:// prefix."""
        if not v.startswith("https://"):
            raise ValueError(
                "Keycloak configuration URLs must start with 'https://'. "
                f"Got invalid scheme or prefix in URL: '{v}'"
            )
        return v

    # --- Task 43 append ---
    # Telegram Bot API token for admin hold notifications.
    # None = adapter disabled — local dev runs without a bot; None disables loudly in logs,
    # never crashes. WHY optional: not every environment has a Telegram bot. When None,
    # the composition root selects LoggingStubNotifier (all events logged, zero HTTP calls).
    telegram_bot_token: str | None = None

    # Telegram chat ID (group, channel, or user) to receive admin alerts.
    # MUST be set if telegram_bot_token is set — half-configured = misconfiguration.
    telegram_admin_chat_id: str | None = None

    # SendGrid v3 API key for transactional emails.
    # None = email adapter disabled (Phase 1 default — see Phase 1 merchant email honesty note).
    sendgrid_api_key: str | None = None

    # From-address for transactional emails (plaintext only per content law).
    email_from: str = "noreply@fluxpay.local"

    # Maximum notification delivery attempts before switching to failure ledger row.
    # WHY 5: 5 attempts with exponential backoff covers transient infra blips (Telegram
    # downtime, SendGrid rate limits) without blocking the caller for >60s.
    notification_retry_max: int = 5

    # Base backoff interval in seconds for notification retry ladder (2^n scaling).
    # WHY 2.0: attempt 0=2s, 1=4s, 2=8s, 3=16s, 4=32s — total max ~62s for 5 retries.
    notification_backoff_base_s: float = 2.0

    @field_validator("telegram_bot_token", "sendgrid_api_key", mode="before")
    @classmethod
    def empty_str_to_none_notification(cls, v: str | None) -> str | None:
        """Convert empty string notification tokens to None for seamless local fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @field_validator("telegram_admin_chat_id", mode="before")
    @classmethod
    def empty_str_to_none_chat_id(cls, v: str | None) -> str | None:
        """Convert empty string chat_id to None for seamless local fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    # --- Task 50 append ---
    # Base L2 JSON-RPC endpoint URL. None = reader disabled (NullReader wired at composition root).
    base_rpc_url: str | None = None

    # Base chain ID (8453 for Base mainnet, 84532 for Base Sepolia testnet).
    base_chain_id: int = 8453

    # Base USDC token contract address (default: Base mainnet native USDC).
    base_usdc_address: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

    # Base L2 RPC query timeout in seconds.
    base_reader_timeout_s: float = 10.0

    @field_validator("base_rpc_url", mode="before")
    @classmethod
    def empty_str_to_none_base_rpc(cls, v: str | None) -> str | None:
        """Convert empty string Base RPC URL to None for disabled mode fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @field_validator("base_usdc_address")
    @classmethod
    def validate_base_usdc_address(cls, v: str) -> str:
        """Validate Base USDC address matches 40-character hexadecimal EVM address."""
        import re

        if not re.match(r"^0x[0-9a-fA-F]{40}$", v):
            raise ValueError(
                f"Invalid Base USDC contract address: '{v}'. "
                "Must be a 40-hex-character EVM address prefixed with '0x'."
            )
        return v

    # --- Task 52 append ---
    # Stripe secret key for authenticated API requests. None = adapter disabled.
    stripe_secret_key: str | None = None

    # Stripe webhook endpoint secret for signature verification (whsec_...).
    # None = webhook verification disabled.
    stripe_webhook_secret: str | None = None

    # Stripe API base URL (default: https://api.stripe.com).
    stripe_api_base: str = "https://api.stripe.com"

    # Stripe webhook timestamp tolerance in seconds (replay attack defense).
    stripe_webhook_tolerance_s: int = 300

    @field_validator("stripe_secret_key", mode="before")
    @classmethod
    def empty_str_to_none_stripe_key(cls, v: str | None) -> str | None:
        """Convert empty string Stripe secret key to None for disabled mode fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @field_validator("stripe_webhook_secret", mode="before")
    @classmethod
    def empty_str_to_none_stripe_webhook_secret(cls, v: str | None) -> str | None:
        """Convert empty string Stripe webhook secret to None for disabled mode fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @field_validator("stripe_webhook_secret")
    @classmethod
    def validate_stripe_webhook_secret(cls, v: str | None) -> str | None:
        """Validate Stripe webhook secret length >= 16 when configured."""
        if v is not None and len(v) < 16:
            raise ValueError(
                f"Stripe webhook secret must be at least 16 characters (got {len(v)})."
            )
        return v

    # --- Task 53 append ---
    # Wise API key for authenticated API requests (read/write profile credential).
    # None = adapter disabled. WHY optional: disabled-mode law ensures local development
    # runs safely without live Wise account credentials.
    wise_api_key: str | None = None

    # Wise API base URL (default: sandbox environment).
    # WHY SANDBOX DEFAULT: A default-on-production base URL risks test credentials hitting
    # live settlement rails during local dev or CI. Production URL MUST be set explicitly.
    wise_api_base: str = "https://api.sandbox.transferwise.tech"

    # Wise webhook signing secret for HMAC-SHA256 signature verification.
    # None = webhook verification disabled.
    wise_webhook_secret: str | None = None

    # Wise webhook timestamp tolerance in seconds (applied if payload timestamp present).
    wise_webhook_tolerance_s: int = 300

    @field_validator("wise_api_key", "wise_webhook_secret", mode="before")
    @classmethod
    def empty_str_to_none_wise(cls, v: str | None) -> str | None:
        """Convert empty string Wise secrets to None for disabled mode fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @field_validator("wise_api_base")
    @classmethod
    def validate_wise_api_base(cls, v: str) -> str:
        """Validate Wise API base URL starts with https:// scheme."""
        if not v.startswith("https://"):
            raise ValueError(f"Wise API base URL must start with 'https://' (got '{v}').")
        return v

    # --- Task 55 append ---
    # Sumsub App Token / API key for HTTP API authentication.
    # None = Sumsub adapter disabled (manual KYC mode used instead).
    sumsub_api_key: str | None = None

    # Sumsub secret key for request HMAC-SHA256 signing and webhook verification.
    # None = adapter disabled.
    sumsub_secret_key: str | None = None

    # Sumsub API base URL (default: production).
    sumsub_base: str = "https://api.sumsub.com"

    # Sumsub verification level name configured in Sumsub dashboard.
    sumsub_level_name: str = "basic-kyc-level"

    # Trulioo API key for x-trulioo-api-key / Bearer authentication.
    # None = Trulioo adapter disabled.
    trulioo_api_key: str | None = None

    # Trulioo API base URL (default: production gateway).
    trulioo_base: str = "https://gateway.trulioo.com"

    # Default KYC provider: 'manual' | 'sumsub' | 'trulioo'.
    kyc_provider_default: str = "manual"

    @field_validator(
        "sumsub_api_key",
        "sumsub_secret_key",
        "trulioo_api_key",
        mode="before",
    )
    @classmethod
    def empty_str_to_none_kyc(cls, v: str | None) -> str | None:
        """Convert empty string KYC secrets to None for disabled mode fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @field_validator("kyc_provider_default")
    @classmethod
    def validate_kyc_provider_default(cls, v: str) -> str:
        """Validate default KYC provider is one of allowed providers."""
        allowed = ("manual", "sumsub", "trulioo")
        if v not in allowed:
            raise ValueError(f"Invalid kyc_provider_default: '{v}'. Must be one of {allowed}.")
        return v

    # --- Task 61 append ---
    # Dedicated secret key for signing dashboard session cookies and OAuth state.
    # None = dashboard disabled loudly (Task 49 disabled-mode law).
    dashboard_secret: str | None = None

    # Name of the dashboard session cookie stored in browser.
    dashboard_session_cookie_name: str = "flx_dash"

    # Lifetime of dashboard session cookie in seconds (default: 28800 = 8 hours / standard workday).
    dashboard_cookie_max_age_s: int = 28800

    # Allowed origin for CSRF mutation guard checks (e.g. 'http://localhost:8000').
    dashboard_origin: str = "http://localhost:8000"

    @field_validator("dashboard_secret", mode="before")
    @classmethod
    def empty_str_to_none_dashboard_secret(cls, v: str | None) -> str | None:
        """Convert empty string dashboard secret to None for disabled mode fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    # --- Task 69 append ---
    metrics_enabled: bool = True
    metrics_port_base: int = 9110
    alert_router_port: int = 9120
    alertrouter_secret: str | None = None

    @field_validator("alertrouter_secret", mode="before")
    @classmethod
    def empty_str_to_none_alertrouter_secret(cls, v: str | None) -> str | None:
        """Convert empty string alertrouter secret to None for disabled mode fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    # --- Task 51 append ---
    # Ethereum L1 JSON-RPC endpoint URL. None = rail disabled (disabled-mode law).
    eth_rpc_url: str | None = None

    # Ethereum chain ID (1 for Ethereum mainnet, 11155111 for Ethereum Sepolia testnet).
    eth_chain_id: int = 1

    # Ethereum USDC token contract address (default: Ethereum mainnet native USDC).
    eth_usdc_address: str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

    # Minimum confirmations required for Ethereum transaction finality (finality knob).
    # Default 1 block. RUNBOOK NOTE: While receipts are confirmed at 1 block for operational
    # monitoring, treasury-scale decisions and surplus sweeps should observe L1 Casper FFG
    # finality (~13 min / 2 epochs, 64-96 blocks).
    eth_confirmations_min: int = 1

    @field_validator("eth_rpc_url", mode="before")
    @classmethod
    def empty_str_to_none_eth_rpc(cls, v: str | None) -> str | None:
        """Convert empty string Ethereum RPC URL to None for disabled mode fallback."""
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @field_validator("eth_usdc_address")
    @classmethod
    def validate_eth_usdc_address(cls, v: str) -> str:
        """Validate Ethereum USDC address matches 40-character hexadecimal EVM address."""
        import re

        if not re.match(r"^0x[0-9a-fA-F]{40}$", v):
            raise ValueError(
                f"Invalid Ethereum USDC contract address: '{v}'. "
                "Must be a 40-hex-character EVM address prefixed with '0x'."
            )
        return v

    @field_validator("eth_confirmations_min")
    @classmethod
    def validate_eth_confirmations_min(cls, v: int) -> int:
        """Validate eth_confirmations_min is at least 1."""
        if v < 1:
            raise ValueError(f"eth_confirmations_min must be >= 1, got {v}")
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retrieve the cached singleton application settings.

    Settings are loaded from environment variables prefixed with 'FLX_' and immutable (frozen).
    To isolate tests mutating environment variables, invoke `get_settings.cache_clear()`
    before and after test execution.
    """
    return Settings()
