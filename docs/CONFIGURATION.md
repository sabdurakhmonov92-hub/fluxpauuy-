# FluxPay System Configuration Guide

This document defines the complete environment variable contract for the FluxPay autonomous AI agent payment operating system. FluxPay follows strict twelve-factor principles: all runtime parameters and secret credentials are provided via environment variables prefixed with `FLX_` and validated at boot time before network sockets are opened.

---

## Configuration Categories

1. [Application & Gateway](#1-application--gateway)
2. [Database (PostgreSQL)](#2-database-postgresql)
3. [Cache & Rate Limiting (Valkey / Redis)](#3-cache--rate-limiting-valkey--redis)
4. [Message Bus (RabbitMQ)](#4-message-bus-rabbitmq)
5. [Cryptographic Secrets & Vault](#5-cryptographic-secrets--vault)
6. [Blockchain (Base L2 & Ethereum L1)](#6-blockchain-base-l2--ethereum-l1)
7. [Identity Provider (Keycloak OIDC)](#7-identity-provider-keycloak-oidc)
8. [Notifications & Alerts](#8-notifications--alerts)
9. [External Fiat & KYC Rails](#9-external-fiat--kyc-rails)
10. [Observability & Telemetry](#10-observability--telemetry)

---

### 1. Application & Gateway

| Variable Name | Type | Default | Required | Security Level | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FLX_ENV` | String | `development` | Yes | Public | Runtime environment: `development`, `staging`, or `production`. Governs security enforcement and docs suppression. |
| `FLX_LOG_LEVEL` | String | `INFO` | No | Public | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `FLX_REPLAY_WINDOW_MS` | Integer | `30000` | No | Public | Maximum allowable client request timestamp skew in milliseconds (±30s). Rejects expired or futuristic signatures. |
| `FLX_RATE_LIMIT_WINDOW_MS` | Integer | `60000` | No | Public | Duration of the sliding rate-limiting window in milliseconds (default: 60 seconds). |
| `FLX_RATE_LIMIT_MAX` | Integer | `100` | No | Public | Maximum allowed operations per autonomous agent per rate limit window. |
| `FLX_DAILY_QUOTA_MAX` | Integer | `10000` | No | Public | Maximum daily cumulative API calls per agent before quota restriction kicks in. |
| `FLX_NONCE_TTL_MS` | Integer | `120000` | No | Public | Nonce deduplication TTL in milliseconds. Invariant: Must be >= `2 * FLX_REPLAY_WINDOW_MS`. |
| `FLX_LEDGER_MAX_OCC_RETRIES` | Integer | `5` | No | Public | Maximum optimistic concurrency control (OCC) transaction retry iterations upon version collision. |
| `FLX_IDEMPOTENCY_FAST_TTL_S` | Integer | `86400` | No | Public | Valkey hot-tier idempotency cache retention period in seconds (24 hours). |

---

### 2. Database (PostgreSQL)

| Variable Name | Type | Default | Required | Security Level | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FLX_PG_DSN` | String | None | **YES** | Confidential | PostgreSQL connection DSN (`postgresql://...`). Requires `synchronous_commit=on` and `TimeZone=UTC`. |
| `FLX_PG_POOL_MIN` | Integer | `2` | No | Public | Minimum idle database connections maintained in connection pool. |
| `FLX_PG_POOL_MAX` | Integer | `20` | No | Public | Maximum active connection limit. Keep bounded when connecting via PgBouncer. |

---

### 3. Cache & Rate Limiting (Valkey / Redis)

| Variable Name | Type | Default | Required | Security Level | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FLX_VALKEY_URL` | String | `redis://localhost:6379/0` | No | Confidential | Redis/Valkey URI for atomic rate-limiting, idempotency fast-path, and ephemeral caches. |

---

### 4. Message Bus (RabbitMQ)

| Variable Name | Type | Default | Required | Security Level | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FLX_RABBITMQ_URL` | String | `amqp://localhost:5672/` | No | Confidential | RabbitMQ AMQP broker URI for financial domain event publishing and webhook fanout. |

---

### 5. Cryptographic Secrets & Vault

| Variable Name | Type | Default | Required | Security Level | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FLX_VAULT_MASTER_KEY` | String | None | **YES** | **Secret / HSM** | Base64-encoded 32-byte key used for AES-256-GCM envelope encryption of sensitive agent vault data. |
| `FLX_WEBHOOK_SIGNING_KEY` | String | None | **YES** | **Secret** | Hex-encoded HMAC-SHA256 secret (min 32 chars) for signing outbound webhook payloads. |
| `FLX_DASHBOARD_SECRET` | String | None | No | Confidential | Secret key used for signing console and dashboard session authentication cookies. |
| `FLX_DASHBOARD_ORIGIN` | String | `http://localhost:8000` | No | Public | Trusted HTTP origin for CSRF validation on mutation endpoints. |

---

### 6. Blockchain (Base L2 & Ethereum L1)

| Variable Name | Type | Default | Required | Security Level | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FLX_BASE_RPC_URL` | String | None | Optional | Confidential | Base L2 JSON-RPC provider endpoint (e.g. Alchemy, Infura, QuickNode, or local geth node). |
| `FLX_BASE_CHAIN_ID` | Integer | `8453` | No | Public | Target EVM chain ID (8453 for Base Mainnet, 84532 for Base Sepolia Testnet). |
| `FLX_BASE_USDC_ADDRESS` | String | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` | No | Public | Checksummed EVM contract address of native USDC on Base. |
| `FLX_BASE_READER_TIMEOUT_S` | Float | `10.0` | No | Public | HTTP timeout in seconds for Base RPC queries. |
| `FLX_ETH_RPC_URL` | String | None | Optional | Confidential | Ethereum L1 JSON-RPC provider endpoint for high-value settlement and surplus sweep verification. |
| `FLX_ETH_CHAIN_ID` | Integer | `1` | No | Public | Ethereum L1 chain ID (1 for Mainnet, 11155111 for Sepolia). |
| `FLX_ETH_USDC_ADDRESS` | String | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | No | Public | Checksummed EVM contract address of native USDC on Ethereum L1. |
| `FLX_ETH_CONFIRMATIONS_MIN`| Integer | `1` | No | Public | Minimum required block confirmations for Ethereum finality before crediting deposits. |

---

### 7. Identity Provider (Keycloak OIDC)

| Variable Name | Type | Default | Required | Security Level | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FLX_KEYCLOAK_JWKS_URL` | String | `https://auth.fluxpay.local/...` | Yes | Confidential | HTTPS endpoint serving Keycloak JSON Web Key Set (JWKS) public keys. |
| `FLX_KEYCLOAK_ISSUER` | String | `https://auth.fluxpay.local/...` | Yes | Confidential | Expected OIDC token issuer URL matching the `iss` JWT claim. |
| `FLX_KEYCLOAK_AUDIENCE` | String | `https://api.fluxpay.local` | Yes | Confidential | Expected client audience matching the `aud` JWT claim. |

---

### 8. Notifications & Alerts

| Variable Name | Type | Default | Required | Security Level | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FLX_TELEGRAM_BOT_TOKEN` | String | None | Optional | Confidential | Telegram Bot API token for dispatching high-priority admin alert notifications. |
| `FLX_TELEGRAM_ADMIN_CHAT_ID` | String | None | Optional | Confidential | Telegram chat ID of admin group/channel. Required if `FLX_TELEGRAM_BOT_TOKEN` is set. |
| `FLX_SENDGRID_API_KEY` | String | None | Optional | Confidential | SendGrid v3 API key for transactional emails. |
| `FLX_EMAIL_FROM` | String | `noreply@fluxpay.local` | No | Public | Verified sender email address for transactional communications. |
| `FLX_NOTIFICATION_RETRY_MAX`| Integer | `5` | No | Public | Maximum dispatch retry attempts for failed notifications. |
| `FLX_NOTIFICATION_BACKOFF_BASE_S`| Float | `2.0` | No | Public | Exponential backoff base interval in seconds. |

---

### 9. External Fiat & KYC Rails

| Variable Name | Type | Default | Required | Security Level | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FLX_STRIPE_SECRET_KEY` | String | None | Optional | **Secret** | Stripe API Secret Key (`sk_live_...`). |
| `FLX_STRIPE_WEBHOOK_SECRET` | String | None | Optional | **Secret** | Stripe Webhook Secret (`whsec_...`) for inbound signature verification. |
| `FLX_WISE_API_KEY` | String | None | Optional | **Secret** | Wise API key for fiat payouts and treasury settlement. |
| `FLX_WISE_WEBHOOK_SECRET` | String | None | Optional | **Secret** | Wise webhook signature verification secret. |
| `FLX_SUMSUB_API_KEY` | String | None | Optional | **Secret** | Sumsub App Token for automated agent operator identity verification. |
| `FLX_SUMSUB_SECRET_KEY` | String | None | Optional | **Secret** | Sumsub Secret Key for request HMAC signing and webhook authentication. |
| `FLX_TRULIOO_API_KEY` | String | None | Optional | **Secret** | Trulioo GlobalGateway API key. |
| `FLX_KYC_PROVIDER_DEFAULT` | String | `manual` | No | Public | Default KYC verification engine (`manual`, `sumsub`, `trulioo`). |

---

### 10. Observability & Telemetry

| Variable Name | Type | Default | Required | Security Level | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `FLX_METRICS_ENABLED` | Boolean | `true` | No | Public | Whether Prometheus `/metrics` exposition is active. |
| `FLX_METRICS_PORT_BASE` | Integer | `9110` | No | Public | Dedicated port for Prometheus scraping endpoint. |
| `FLX_ALERT_ROUTER_PORT` | Integer | `9120` | No | Public | Port for inbound Prometheus Alertmanager webhook notifications. |
| `FLX_ALERTROUTER_SECRET` | String | None | Optional | Confidential | Secret key for authenticating Prometheus Alertmanager webhook payloads. |
| `FLX_SENTRY_DSN` | String | None | Optional | Confidential | Sentry DSN for unhandled exception capture and performance monitoring. |
