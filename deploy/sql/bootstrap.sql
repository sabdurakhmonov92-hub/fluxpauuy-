-- ==============================================================================
-- Seed: deploy/sql/bootstrap.sql
-- Subsystem: Platform Core Ledger Accounts Bootstrap
--
-- NOTE: If migrations already created these tables, bootstrap.sql must run AFTER migrate.sh.
--
-- Architectural Role:
-- Seeds the deterministic platform accounts (system, fees, treasury) required
-- for all financial flows in FluxPay.
--
-- Invariants & Decisions:
-- 1. WHY SEED NOT RUNTIME:
--    These platform accounts pre-exist any tenant or dynamic agent/merchant.
--    Runtime creation during request handling would introduce race conditions,
--    redundant checks, and bootstrap latency on hot paths.
--    An idempotent seed script runs safely during deployment and test initialization.
--
-- 2. DETERMINISTIC OWNER IDS (UUIDv5):
--    Owner IDs are computed deterministically via uuid5 using the fixed
--    FLXPAY_NAMESPACE constant:
--        FLXPAY_NAMESPACE = 'f1047a71-0000-5000-8000-000000000000'
--        system:   uuid5(FLXPAY_NAMESPACE, 'system')   = '97b333de-f2b6-5d2d-98c9-51de34590c17'
--        fees:     uuid5(FLXPAY_NAMESPACE, 'fees')     = '36723e80-972f-54bc-a5a1-76d83b2d1438'
--        treasury: uuid5(FLXPAY_NAMESPACE, 'treasury') = 'aa51a413-b2f4-5bba-9be1-96ed6c605853'
--    WHY DETERMINISM MATTERS:
--    Deterministic UUIDs make fees-account lookups and reconciliation
--    depend on stable ids across environments without dynamic id discovery.
--
-- 3. GENESIS TREASURY FUNDING (OUT-OF-LEDGER BALANCE):
--    Treasury genesis funding is an out-of-ledger balance update.
--    This file inserts treasury at balance=0. In production/staging, the genesis
--    balance is applied via the documented explicit UPDATE template below.
-- ==============================================================================

-- 1. System Account (owner_type='system', currency='USDC')
INSERT INTO ledger_accounts (
    owner_type,
    owner_id,
    currency,
    balance,
    version
)
VALUES (
    'system',
    '97b333de-f2b6-5d2d-98c9-51de34590c17',
    'USDC',
    0,
    0
)
ON CONFLICT (owner_type, owner_id, currency) DO NOTHING;

-- 2. Fees Account (owner_type='fees', currency='USDC')
INSERT INTO ledger_accounts (
    owner_type,
    owner_id,
    currency,
    balance,
    version
)
VALUES (
    'fees',
    '36723e80-972f-54bc-a5a1-76d83b2d1438',
    'USDC',
    0,
    0
)
ON CONFLICT (owner_type, owner_id, currency) DO NOTHING;

-- 3. Treasury Account (owner_type='treasury', currency='USDC')
INSERT INTO ledger_accounts (
    owner_type,
    owner_id,
    currency,
    balance,
    version
)
VALUES (
    'treasury',
    'aa51a413-b2f4-5bba-9be1-96ed6c605853',
    'USDC',
    0,
    0
)
ON CONFLICT (owner_type, owner_id, currency) DO NOTHING;

-- ==============================================================================
-- RUNBOOK: Genesis Treasury Balance Initialization
--
-- UPDATE ledger_accounts
-- SET balance = <AMOUNT_MINOR>, version = version + 1
-- WHERE owner_type = 'treasury'
--   AND owner_id = 'aa51a413-b2f4-5bba-9be1-96ed6c605853'
--   AND currency = 'USDC';
-- ==============================================================================
