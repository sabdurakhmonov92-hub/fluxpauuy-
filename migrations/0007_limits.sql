-- ==============================================================================
-- Migration: 0007_limits.sql
-- Subsystem: Risk Engine, Effective Limits & Quarantine Queue (Blueprint §4 & §5)
--
-- Architectural Role:
-- 1. agent_limits: per-agent financial policy rules (spending ceilings, velocity,
--    daily outflow cap). Provisioned lazily; absence of a row implies default
--    platform policy (decoupled provisioning).
-- 2. payment_holds: Human-In-The-Loop (HITL) quarantine queue for payments breaching
--    financial ceilings or flagged for manual review. Linked to Task 11 reservation
--    via idem_key; re-quarantine of the same key updates the existing row (1:1).
--
-- Invariant Handoff for Task 31 & Task 42:
-- - Task 31's service consults the risk engine BEFORE any ledger write.
-- - If quarantined, Task 31 places a hold in payment_holds and returns a pending response.
-- - Task 42's approval worker drains payment_holds atomically (decide) and replays
--   the settlement path using the SAME idem_key (Task 11 reservation idempotency).
-- ==============================================================================

CREATE TABLE IF NOT EXISTS agent_limits (
    agent_id UUID PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    velocity_limit INT NOT NULL DEFAULT 5
        CHECK (velocity_limit BETWEEN 1 AND 100),
    velocity_window_s INT NOT NULL DEFAULT 60
        CHECK (velocity_window_s BETWEEN 10 AND 3600),
    max_single_tx_minor BIGINT NOT NULL DEFAULT 100000000
        CHECK (max_single_tx_minor > 0),
    daily_outflow_cap_minor BIGINT NOT NULL DEFAULT 500000000
        CHECK (daily_outflow_cap_minor > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE agent_limits IS 'per-agent financial policy; row created lazily by ensure_row — creation of an agent does not require limits provisioning (decoupled provisioning).';

CREATE TABLE IF NOT EXISTS payment_holds (
    hold_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id),
    idem_key TEXT NOT NULL,
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    currency VARCHAR(10) NOT NULL CHECK (currency ~ '^[A-Z0-9]{2,10}$'),
    reason TEXT NOT NULL CHECK (reason IN ('single_tx_ceiling', 'daily_cap', 'velocity', 'manual')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_payment_holds_agent_idem UNIQUE (agent_id, idem_key)
);

COMMENT ON TABLE payment_holds IS 'HITL quarantine hold queue; idempotent re-quarantine updates payload on conflict; money is NOT moved by hold creation or approval.';

CREATE INDEX IF NOT EXISTS idx_payment_holds_pending
    ON payment_holds (status)
    WHERE status = 'pending';

-- ==============================================================================
-- ROLLBACK SECTION (DEV-ONLY - NEVER EXECUTE ON ENVIRONMENTS HOLDING REAL MONEY)
--
-- DROP INDEX IF EXISTS idx_payment_holds_pending;
-- DROP TABLE IF EXISTS payment_holds CASCADE;
-- DROP TABLE IF EXISTS agent_limits CASCADE;
-- ==============================================================================
