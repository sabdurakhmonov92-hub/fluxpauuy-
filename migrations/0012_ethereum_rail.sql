-- ==============================================================================
-- Migration: 0012_ethereum_rail.sql
-- Subsystem: Treasury Multi-Chain Rail Evolution (Block J, Task 51)
--
-- Architectural Role:
-- 1. Widen `wallet_state` rail CHECK constraint:
--    Allows 'base_usdc' and 'ethereum_usdc'.
--    Additive constraint widening pattern: dynamically discovers and drops
--    the existing check constraint on `rail` via pg_constraint query within a DO
--    block, then re-adds the widened CHECK (rail IN ('base_usdc', 'ethereum_usdc')).
-- 2. Seed `ethereum_usdc` row:
--    Inserts observation tracking row with zero-address placeholders.
--    Matches Task 44 test scale: low water = $50, high water = $200.
--    Idempotent via ON CONFLICT (rail) DO NOTHING.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. ADDITIVE CHECK WIDENING (RAIL IN ('base_usdc', 'ethereum_usdc'))
-- ------------------------------------------------------------------------------
DO $$
DECLARE
    r RECORD;
BEGIN
    -- Query pg_constraint to locate any existing check constraint on column 'rail'
    -- in table 'wallet_state' and drop it dynamically.
    FOR r IN (
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON c.conrelid = t.oid
        JOIN pg_namespace n ON t.relnamespace = n.oid
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(c.conkey)
        WHERE n.nspname = CURRENT_SCHEMA()
          AND t.relname = 'wallet_state'
          AND a.attname = 'rail'
          AND c.contype = 'c'
    ) LOOP
        EXECUTE format('ALTER TABLE wallet_state DROP CONSTRAINT %I;', r.conname);
    END LOOP;
END $$;

ALTER TABLE wallet_state
    ADD CONSTRAINT wallet_state_rail_check
    CHECK (rail IN ('base_usdc', 'ethereum_usdc'));

-- ------------------------------------------------------------------------------
-- 2. SEED ETHEREUM_USDC CUSTODY OBSERVATION ROW
-- ------------------------------------------------------------------------------
-- CRITICAL RUNBOOK WARNING: Ansible sets real addresses via env —
-- placeholder 0x0000000000000000000000000000000000000000 must be replaced before production.
-- Default thresholds: low = 50_000_000000 ($50 USDC 6dp — Phase 1 test-scale),
-- high = 200_000_000000 ($200) — test-friendly defaults matching Task 44's scale.
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
    'ethereum_usdc',
    '0x0000000000000000000000000000000000000000',
    '0x0000000000000000000000000000000000000000',
    0,
    0,
    50000000000,
    200000000000,
    NULL,
    'never'
) ON CONFLICT (rail) DO NOTHING;
