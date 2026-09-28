-- ==============================================================================
-- Migration: 0008_webhooks.sql
-- Subsystem: Resilient Webhook Notification Dispatcher & Deliveries (Block H, Part 1)
--
-- Architectural Role:
-- 1. `webhook_endpoints`: Per-merchant notification destinations with envelope-encrypted
--    signing secrets (AES-256-GCM, Task 7/23).
--    Enforces HTTPS-ONLY destinations via CHECK regex to prevent secret disclosure
--    and cleartext eavesdropping on the public wire.
-- 2. `webhook_deliveries`: The durable, queryable outbox and retry ladder.
--    Payload is frozen at fanout time as immutable JSONB to guarantee replay-after-retention
--    faithfulness against event-log or schema drift.
--    Postgres FOR UPDATE SKIP LOCKED provides lock-free, multi-instance concurrency
--    without duplicate dispatch.
--    Dead-lettering is stored natively in-table as status='dead' (DLQ-as-status),
--    preserving failed deliveries as an operational work queue for manual redrive.
--
-- Concurrency & Invariants:
-- - UNIQUE(merchant_id, url): A merchant cannot register duplicate endpoint URLs.
-- - UNIQUE(event_id, endpoint_id): The database-level deduplication law; exactly one
--   delivery record per domain event per destination endpoint.
-- - Partial index on (status, next_attempt_at) WHERE status='pending': Optimizes
--   worker batch claiming while keeping index bloat minimal as deliveries complete.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. WEBHOOK ENDPOINTS
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merchant_id UUID NOT NULL
        REFERENCES merchants(id) ON DELETE CASCADE,
    url TEXT NOT NULL
        CONSTRAINT webhook_endpoints_url_check
        CHECK (url ~ '^https://[A-Za-z0-9]'),
        -- WHY HTTPS-ONLY: Webhook secrets and payment metadata transmitted over HTTP
        -- constitute wire disclosure; the regex strictly pins the https:// scheme and host
        -- presence. Localhost HTTPS testing is permitted; plain HTTP is forbidden.
    secret_encrypted TEXT NOT NULL,
        -- AES-256-GCM vault envelope bound to context "webhook_secret:<endpoint_id>"
    active BOOLEAN NOT NULL DEFAULT true,
    version BIGINT NOT NULL DEFAULT 1
        CONSTRAINT webhook_endpoints_version_check
        CHECK (version >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_webhook_endpoints_merchant_url UNIQUE (merchant_id, url)
);

COMMENT ON TABLE webhook_endpoints IS 'Merchant HTTPS notification destinations with AES-256-GCM vault-encrypted signing secrets.';

CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_merchant_active
    ON webhook_endpoints (merchant_id)
    WHERE active = true;

-- ------------------------------------------------------------------------------
-- 2. WEBHOOK DELIVERIES (The Delivery Queue & Work Ledger)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL,
    endpoint_id UUID NOT NULL
        REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
        -- Immutable payload frozen at fanout time (schema vs event-log drift immune)
    status TEXT NOT NULL DEFAULT 'pending'
        CONSTRAINT webhook_deliveries_status_check
        CHECK (status IN ('pending', 'delivered', 'dead')),
    attempts INT NOT NULL DEFAULT 0
        CONSTRAINT webhook_deliveries_attempts_check
        CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_response_code INT,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_webhook_deliveries_event_endpoint UNIQUE (event_id, endpoint_id)
);

COMMENT ON TABLE webhook_deliveries IS 'Durable webhook delivery queue and attempt log; payload frozen at fanout time for deterministic replay.';

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending_claim
    ON webhook_deliveries (status, next_attempt_at)
    WHERE status = 'pending';

-- ==============================================================================
-- ROLLBACK SECTION (DEV-ONLY - NEVER EXECUTE ON ENVIRONMENTS HOLDING REAL MONEY)
--
-- DROP INDEX IF EXISTS idx_webhook_deliveries_pending_claim;
-- DROP INDEX IF EXISTS idx_webhook_endpoints_merchant_active;
-- DROP TABLE IF EXISTS webhook_deliveries CASCADE;
-- DROP TABLE IF EXISTS webhook_endpoints CASCADE;
-- ==============================================================================
