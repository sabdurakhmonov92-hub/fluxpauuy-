-- ==============================================================================
-- Migration: 0011_treasury.sql
-- Subsystem: Treasury Foundation — Custody Schema & Cold Payout Queue (Block I)
--
-- Architectural Role:
-- 1. `wallet_state`:
--    Per-rail custody observation state and cache of on-chain balances.
--    Truth lives on-chain. Caches exist for operational dashboards and threshold
--    math between sync cycles; staleness is bounded by the 15-minute sync cadence.
--    Enforces the threshold ordering invariant: high_water_minor > low_water_minor > 0.
-- 2. `cold_payouts`:
--    Manual transfer queue for movements from cold vault (or surplus sweeps).
--    The server OBSERVES and PROPOSES; humans EXECUTE (behind a Gnosis Safe 2-of-3 multisig).
--    A database-level BEFORE UPDATE state transition guard guarantees valid transitions:
--    requested -> approved | rejected; approved -> executed; executed -> confirmed.
--    Terminal states (confirmed, rejected) are permanently immutable.
-- 3. `payout_approvals`:
--    Multi-party approval votes table enforcing the 2-man rule invariant:
--    exactly one vote per voter per payout via UNIQUE (payout_id, voter_sub).
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. WALLET STATE (PER-RAIL CUSTODY OBSERVATION)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wallet_state (
    -- Payment rail identifier. Additive CHECK: new rails added via future migrations.
    rail                TEXT        PRIMARY KEY CHECK (rail IN ('base_usdc')),

    -- Hot wallet address (0x + 40 hex chars). Observational only.
    hot_address         TEXT        NOT NULL CHECK (hot_address ~ '^0x[0-9a-fA-F]{40}$'),

    -- Cold vault address (Gnosis Safe 2-of-3 multisig).
    cold_address        TEXT        NOT NULL CHECK (cold_address ~ '^0x[0-9a-fA-F]{40}$'),

    -- Cached on-chain balances in rail minor units.
    hot_balance_minor   BIGINT      NOT NULL DEFAULT 0 CHECK (hot_balance_minor >= 0),
    cold_balance_minor  BIGINT      NOT NULL DEFAULT 0 CHECK (cold_balance_minor >= 0),

    -- Threshold invariants: low > 0, high > low.
    low_water_minor     BIGINT      NOT NULL CHECK (low_water_minor > 0),
    high_water_minor    BIGINT      NOT NULL CHECK (high_water_minor > low_water_minor),

    -- Observation sync health and timestamps.
    last_synced_at      TIMESTAMPTZ NULL,
    sync_status         TEXT        NOT NULL DEFAULT 'never'
                                    CHECK (sync_status IN ('never', 'ok', 'reader_error')),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  wallet_state                    IS 'Per-rail custody observation state. Balances are caches of on-chain truth; truth lives on-chain. Caches exist for dashboards and threshold math between syncs; staleness is bounded by the 15-minute sync cadence.';
COMMENT ON COLUMN wallet_state.rail               IS 'Payment rail identifier. Additive CHECK (Task 26 evolution pattern).';
COMMENT ON COLUMN wallet_state.hot_address        IS 'EVM hot wallet address (0x + 40 hex chars). Observational only.';
COMMENT ON COLUMN wallet_state.cold_address       IS 'Gnosis Safe 2-of-3 multisig address (0x + 40 hex chars). Backing vault.';
COMMENT ON COLUMN wallet_state.hot_balance_minor  IS 'Cached hot wallet balance in rail minor units. Refreshed by OnChainReader.';
COMMENT ON COLUMN wallet_state.cold_balance_minor IS 'Cached cold vault balance in rail minor units. Refreshed by OnChainReader.';
COMMENT ON COLUMN wallet_state.low_water_minor    IS 'Top-up trigger threshold in minor units. DB enforces low_water_minor > 0.';
COMMENT ON COLUMN wallet_state.high_water_minor   IS 'Surplus sweep trigger threshold in minor units. DB enforces high_water_minor > low_water_minor.';
COMMENT ON COLUMN wallet_state.last_synced_at     IS 'Timestamp of last successful or attempted sync. NULL = never synced.';
COMMENT ON COLUMN wallet_state.sync_status        IS 'Health of last observation: never, ok, reader_error.';
COMMENT ON COLUMN wallet_state.updated_at         IS 'Record modification timestamp.';

-- Seed: one 'base_usdc' row with placeholder addresses.
-- CRITICAL RUNBOOK WARNING: Ansible Task 68 sets real addresses via env —
-- placeholder 0x0000000000000000000000000000000000000000 must be replaced before production.
-- Default thresholds: low = 50_000_000000 ($50 USDC 6dp — Phase 1 test-scale),
-- high = 200_000_000000 ($200) — test-friendly defaults, runbook-documented.
INSERT INTO wallet_state (
    rail,
    hot_address,
    cold_address,
    hot_balance_minor,
    cold_balance_minor,
    low_water_minor,
    high_water_minor,
    last_synced_at,
    sync_status
) VALUES (
    'base_usdc',
    '0x0000000000000000000000000000000000000000',
    '0x0000000000000000000000000000000000000000',
    0,
    0,
    50000000000,
    200000000000,
    NULL,
    'never'
) ON CONFLICT (rail) DO NOTHING;

-- ------------------------------------------------------------------------------
-- 2. COLD PAYOUTS (MANUAL TRANSFER QUEUE)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cold_payouts (
    payout_id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    rail                TEXT         NOT NULL REFERENCES wallet_state(rail),
    to_address          TEXT         NOT NULL CHECK (to_address ~ '^0x[0-9a-fA-F]{40}$'),
    amount_minor        BIGINT       NOT NULL CHECK (amount_minor > 0),
    currency            VARCHAR(10)  NOT NULL DEFAULT 'USDC'
                                     CHECK (currency ~ '^[A-Z0-9]{2,10}$'),
    reason              TEXT         NOT NULL
                                     CHECK (reason IN ('surplus_sweep', 'operational', 'rebalance')),
    status              TEXT         NOT NULL DEFAULT 'requested'
                                     CHECK (status IN ('requested', 'approved', 'executed', 'confirmed', 'rejected')),
    requested_by_sub    TEXT         NOT NULL,
    tx_hash             TEXT         NULL CHECK (tx_hash IS NULL OR tx_hash ~ '^0x[0-9a-fA-F]{64}$'),
    executed_at         TIMESTAMPTZ  NULL,
    confirmed_at        TIMESTAMPTZ  NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);

COMMENT ON TABLE  cold_payouts                  IS 'Manual transfer queue from cold vault or hot surplus sweep. The server observes and proposes; humans execute via Gnosis Safe 2-of-3.';
COMMENT ON COLUMN cold_payouts.payout_id        IS 'Synthetic UUID primary key for payout record.';
COMMENT ON COLUMN cold_payouts.rail             IS 'Target rail identifier referencing wallet_state(rail).';
COMMENT ON COLUMN cold_payouts.to_address       IS 'Destination EVM address (0x + 40 hex chars).';
COMMENT ON COLUMN cold_payouts.amount_minor     IS 'Payout amount in minor units. Enforced > 0.';
COMMENT ON COLUMN cold_payouts.currency         IS 'Currency ticker matching Task 12 grammar (default USDC).';
COMMENT ON COLUMN cold_payouts.reason           IS 'Reason category: surplus_sweep, operational, rebalance.';
COMMENT ON COLUMN cold_payouts.status           IS 'State machine status: requested, approved, executed, confirmed, rejected.';
COMMENT ON COLUMN cold_payouts.requested_by_sub IS 'Keycloak subject identifier or system.';
COMMENT ON COLUMN cold_payouts.tx_hash          IS 'On-chain transaction hash (0x + 64 hex chars) once broadcast.';
COMMENT ON COLUMN cold_payouts.executed_at       IS 'Timestamp when tx was submitted/broadcast on-chain.';
COMMENT ON COLUMN cold_payouts.confirmed_at      IS 'Timestamp when tx was finalized with required confirmations on-chain.';
COMMENT ON COLUMN cold_payouts.created_at       IS 'Creation timestamp.';
COMMENT ON COLUMN cold_payouts.updated_at       IS 'Last update timestamp.';

-- ------------------------------------------------------------------------------
-- STATE-TRANSITION GUARD (DB-LEVEL — THE MACHINE IS LAW)
-- ------------------------------------------------------------------------------
-- Legal transitions:
-- requested -> approved | rejected
-- approved -> executed (DECISION: approved -> executed ONLY; a rejected-after-approve
-- needs a NEW request — cleaner audit trail)
-- executed -> confirmed
-- Terminal states immutable: rejected and confirmed are permanently final.
-- Illegal transitions raise check_violation (Task 14's guard philosophy cited).
CREATE OR REPLACE FUNCTION cold_payouts_state_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Terminal states are immutable
    IF OLD.status IN ('rejected', 'confirmed') THEN
        RAISE EXCEPTION 'cold_payouts record % is in terminal state % and cannot be modified',
            OLD.payout_id, OLD.status
            USING ERRCODE = 'check_violation';
    END IF;

    -- Enforce legal state transitions
    IF OLD.status <> NEW.status THEN
        IF OLD.status = 'requested' AND NEW.status IN ('approved', 'rejected') THEN
            NULL;
        ELSIF OLD.status = 'approved' AND NEW.status = 'executed' THEN
            IF NEW.executed_at IS NULL THEN
                NEW.executed_at = now();
            END IF;
        ELSIF OLD.status = 'executed' AND NEW.status = 'confirmed' THEN
            IF NEW.confirmed_at IS NULL THEN
                NEW.confirmed_at = now();
            END IF;
        ELSE
            RAISE EXCEPTION 'illegal cold_payouts transition from % to % (payout_id=%)',
                OLD.status, NEW.status, OLD.payout_id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_cold_payouts_state_guard ON cold_payouts;
CREATE TRIGGER trg_cold_payouts_state_guard
BEFORE UPDATE ON cold_payouts
FOR EACH ROW
EXECUTE FUNCTION cold_payouts_state_guard();

-- ------------------------------------------------------------------------------
-- 3. PAYOUT APPROVALS (MULTI-PARTY QUORUM)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS payout_approvals (
    payout_id   UUID         NOT NULL REFERENCES cold_payouts(payout_id) ON DELETE CASCADE,
    voter_sub   TEXT         NOT NULL,
    vote        TEXT         NOT NULL CHECK (vote IN ('approve', 'reject')),
    note        TEXT         NOT NULL DEFAULT '',
    voted_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_payout_approvals_payout_voter UNIQUE (payout_id, voter_sub)
);

COMMENT ON TABLE  payout_approvals           IS 'Multi-party approval votes for cold payouts. Enforces 2-man rule quorum: exactly one vote per voter per payout.';
COMMENT ON COLUMN payout_approvals.payout_id IS 'Foreign key reference to cold_payouts(payout_id).';
COMMENT ON COLUMN payout_approvals.voter_sub IS 'Keycloak subject identifier of human administrator.';
COMMENT ON COLUMN payout_approvals.vote      IS 'Approval decision: approve or reject.';
COMMENT ON COLUMN payout_approvals.note      IS 'Voter rationale context (200-char app-side truncation).';
COMMENT ON COLUMN payout_approvals.voted_at  IS 'Timestamp when vote was recorded.';

CREATE INDEX IF NOT EXISTS idx_payout_approvals_payout_id
    ON payout_approvals (payout_id);

CREATE INDEX IF NOT EXISTS idx_cold_payouts_rail_reason_status
    ON cold_payouts (rail, reason, status);

-- ==============================================================================
-- ROLLBACK SECTION (DEV-ONLY - NEVER EXECUTE ON ENVIRONMENTS HOLDING REAL MONEY)
--
-- DROP INDEX IF EXISTS idx_cold_payouts_rail_reason_status;
-- DROP INDEX IF EXISTS idx_payout_approvals_payout_id;
-- DROP TABLE IF EXISTS payout_approvals CASCADE;
-- DROP TRIGGER IF EXISTS trg_cold_payouts_state_guard ON cold_payouts;
-- DROP FUNCTION IF EXISTS cold_payouts_state_guard();
-- DROP TABLE IF EXISTS cold_payouts CASCADE;
-- DROP TABLE IF EXISTS wallet_state CASCADE;
-- ==============================================================================
