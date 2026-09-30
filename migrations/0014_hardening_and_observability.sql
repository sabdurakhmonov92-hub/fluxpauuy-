-- ==============================================================================
-- Migration: 0014_hardening_and_observability.sql
-- Subsystem: x402 Protocol, Nonce Vault, KMS Audit, Incident & Health Records
--
-- UP Migration:
-- 1. `x402_payments`: Cryptographic settlement record for x402 micropayments.
-- 2. `x402_nonces`: Ephemeral nonce deduplication table with TTL.
-- 3. `kms_audit_log`: Tamper-evident ledger of all KMS key signing operations.
-- 4. `health_checks`: Persistent operational probe history.
-- 5. `incident_log`: Incident tracking ledger for SEV1/SEV2/SEV3 events.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. x402 PAYMENTS (EIP-3009 / x402 PROTOCOL SETTLEMENTS)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS x402_payments (
    payment_id      UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    payer_address   TEXT           NOT NULL CHECK (payer_address ~ '^0x[0-9a-fA-F]{40}$'),
    payee_address   TEXT           NOT NULL CHECK (payee_address ~ '^0x[0-9a-fA-F]{40}$'),
    token_address   TEXT           NOT NULL CHECK (token_address ~ '^0x[0-9a-fA-F]{40}$'),
    amount_raw      NUMERIC(78, 0) NOT NULL CHECK (amount_raw > 0),
    nonce           TEXT           NOT NULL UNIQUE CHECK (nonce ~ '^0x[0-9a-fA-F]{64}$'),
    valid_after     BIGINT         NOT NULL DEFAULT 0,
    valid_before    BIGINT         NOT NULL,
    signature       TEXT           NOT NULL,
    tx_hash         TEXT           NULL CHECK (tx_hash IS NULL OR tx_hash ~ '^0x[0-9a-fA-F]{64}$'),
    status          TEXT           NOT NULL DEFAULT 'verified'
                                   CHECK (status IN ('verified', 'settled', 'reverted')),
    created_at      TIMESTAMPTZ    NOT NULL DEFAULT now(),
    settled_at      TIMESTAMPTZ    NULL
);

CREATE INDEX IF NOT EXISTS idx_x402_payments_payer
    ON x402_payments (payer_address, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_x402_payments_payee
    ON x402_payments (payee_address, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_x402_payments_status
    ON x402_payments (status) WHERE status = 'verified';

COMMENT ON TABLE  x402_payments                IS 'x402 payment protocol verifications and Base L2 settlements.';
COMMENT ON COLUMN x402_payments.payment_id     IS 'Unique UUID for this x402 payment record.';
COMMENT ON COLUMN x402_payments.payer_address  IS 'EVM address of the payer who signed the payment.';
COMMENT ON COLUMN x402_payments.payee_address  IS 'EVM address of the recipient receiving tokens.';
COMMENT ON COLUMN x402_payments.token_address  IS 'ERC-20 token address (USDC on Base).';
COMMENT ON COLUMN x402_payments.amount_raw     IS 'Amount in minor units (e.g. 10^6 for USDC).';
COMMENT ON COLUMN x402_payments.nonce          IS 'Unique 32-byte hex nonce preventing double-spends.';

-- ------------------------------------------------------------------------------
-- 2. x402 NONCES (REPLAY DEFENSE WITH TTL)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS x402_nonces (
    nonce           TEXT        PRIMARY KEY CHECK (nonce ~ '^0x[0-9a-fA-F]{64}$'),
    payer_address   TEXT        NOT NULL CHECK (payer_address ~ '^0x[0-9a-fA-F]{40}$'),
    consumed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_x402_nonces_expires
    ON x402_nonces (expires_at);

COMMENT ON TABLE x402_nonces IS 'Nonce tracking table for EIP-3009 and x402 replay defense.';

-- ------------------------------------------------------------------------------
-- 3. KMS AUDIT LOG (CRYPTOGRAPHIC SIGNING JOURNAL)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kms_audit_log (
    id            UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id        TEXT           NOT NULL,
    operation     TEXT           NOT NULL,
    caller        TEXT           NOT NULL,
    digest        TEXT           NOT NULL,
    status        TEXT           NOT NULL CHECK (status IN ('success', 'failure')),
    latency_ms    NUMERIC(10, 3) NOT NULL,
    error_message TEXT           NULL,
    created_at    TIMESTAMPTZ    NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_kms_audit_created
    ON kms_audit_log (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_kms_audit_key_id
    ON kms_audit_log (key_id, created_at DESC);

COMMENT ON TABLE kms_audit_log IS 'Immutable audit trail of all Cloud KMS / HSM cryptographic signing requests.';

-- ------------------------------------------------------------------------------
-- 4. HEALTH CHECKS (OPERATIONAL PROBE LOG)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS health_checks (
    id          BIGSERIAL   PRIMARY KEY,
    service     TEXT        NOT NULL,
    status      TEXT        NOT NULL CHECK (status IN ('healthy', 'degraded', 'down')),
    details     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    checked_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_health_checks_checked_at
    ON health_checks (checked_at DESC);

COMMENT ON TABLE health_checks IS 'Historical health probe logs for availability verification.';

-- ------------------------------------------------------------------------------
-- 5. INCIDENT LOG (SEV1/SEV2/SEV3 AUDIT LOG)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incident_log (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    severity         TEXT        NOT NULL CHECK (severity IN ('SEV1', 'SEV2', 'SEV3')),
    title            TEXT        NOT NULL,
    description      TEXT        NOT NULL,
    status           TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'mitigated', 'resolved')),
    mitigation_steps TEXT        NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at      TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_incident_log_status
    ON incident_log (status, severity, created_at DESC);

COMMENT ON TABLE incident_log IS 'Formal tracking ledger for production incidents and fail-closed events.';
