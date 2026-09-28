-- ==============================================================================
-- Migration: 0003_ledger_invariants.sql
-- Subsystem: Database-Level Financial Ledger Invariants (Blueprint §5 & §7)
--
-- Architectural Role:
-- The database is the last line of defense. Application-level balancing
-- (Task 16) is the first line; this migration installs engine-level guards that
-- make unbalanced transactions and ledger history tampering IMPOSSIBLE to commit,
-- even if application validation is bypassed by scripts, manual fixes, or bugs.
--
-- Invariants Enforced:
-- 1. Double-Entry Zero-Sum: For every tx_id and currency, sum(DEBIT) == sum(CREDIT)
--    at transaction COMMIT (DEFERRABLE INITIALLY DEFERRED).
-- 2. Immutability Guard: BEFORE UPDATE OR DELETE on ledger_entries permanently
--    raises an exception (defense in depth; stops even the table owner).
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. APPEND-ONLY GUARD (Defense in depth - protects even the table owner)
-- ------------------------------------------------------------------------------
-- WHY this exists alongside deploy/sql/grants.sql:
-- grants.sql revokes UPDATE, DELETE, and TRUNCATE from the application role (fluxpay_app).
-- This trigger stops EVERYONE (including the table owner and postgres superuser).
-- In a regulated financial system, an erroneous row cannot be silently edited;
-- any correction must be an explicit, audible compensating transaction.
-- A hard data correction requires dropping this trigger first, creating an
-- unavoidable operational audit trail in PostgreSQL logs.

CREATE OR REPLACE FUNCTION ledger_entries_immutable_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        RAISE EXCEPTION 'ledger_entries is append-only: % forbidden (seq=%)',
            TG_OP, COALESCE(OLD.seq, 0)
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

COMMENT ON FUNCTION ledger_entries_immutable_guard() IS
'Defense-in-depth immutability guard. Permanently raises restrict_violation on UPDATE or DELETE. Applies to all roles including database owner. Immutability bypass requires an explicit DROP TRIGGER operational event.';

-- WHY BEFORE ... FOR EACH ROW on the PARTITIONED parent:
-- PostgreSQL 13+ automatically clones row triggers from partitioned parent tables
-- to all existing child partitions and dynamically attached future partitions.
-- Future monthly partitions inherit the guard with zero maintenance overhead.
DROP TRIGGER IF EXISTS trg_ledger_entries_immutable ON ledger_entries;
CREATE TRIGGER trg_ledger_entries_immutable
BEFORE UPDATE OR DELETE ON ledger_entries
FOR EACH ROW
EXECUTE FUNCTION ledger_entries_immutable_guard();

-- ------------------------------------------------------------------------------
-- 2. DOUBLE-ENTRY BALANCE INVARIANT (Deferred Constraint Trigger)
-- ------------------------------------------------------------------------------
-- WHY DEFERRABLE INITIALLY DEFERRED:
-- Double-entry transactions insert entries sequentially (e.g., DEBIT first, then
-- CREDITs). An IMMEDIATE trigger would fire mid-transaction when the ledger is
-- intentionally and temporarily unbalanced. DEFERRED semantics check the zero-sum
-- invariant at COMMIT time against the complete, finalized transaction.
--
-- WHY per-row (not statement) constraint trigger:
-- PostgreSQL CREATE CONSTRAINT TRIGGER only supports FOR EACH ROW.
-- Cost analysis: Each row firing runs one index scan on tx_id using idx_ledger_entries_tx_id
-- (created in Task 13). Typical transactions contain 2-3 rows, resulting in 2-3 small
-- indexed lookups at commit. At Phase 1 scale (8 tx/s), this overhead is negligible (<1ms);
-- micro-batching is the Phase 2 optimization path (Task 16 notes).
--
-- WHY per-currency scoping:
-- Summing amounts across disparate currency tickers (e.g. USDC minor units vs ETH wei)
-- is financially meaningless. Each transaction must balance to zero in EACH currency
-- independently.

CREATE OR REPLACE FUNCTION assert_tx_balanced()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    r RECORD;
BEGIN
    -- Verify zero-sum double-entry balance per currency for this tx_id
    FOR r IN
        SELECT
            currency,
            COALESCE(SUM(amount) FILTER (WHERE direction = 'DEBIT'), 0) AS debit_sum,
            COALESCE(SUM(amount) FILTER (WHERE direction = 'CREDIT'), 0) AS credit_sum
        FROM ledger_entries
        WHERE tx_id = NEW.tx_id
        GROUP BY currency
    LOOP
        IF r.debit_sum <> r.credit_sum THEN
            -- 3AM readability contract: Exception text explicitly names tx_id, currency, and sums
            RAISE EXCEPTION 'unbalanced transaction % currency % debit=% credit=%',
                NEW.tx_id, r.currency, r.debit_sum, r.credit_sum
                USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;

    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION assert_tx_balanced() IS
'Double-entry zero-sum invariant check per transaction and currency. Evaluated at COMMIT time via DEFERRABLE INITIALLY DEFERRED constraint trigger. Checks sum(DEBIT) == sum(CREDIT) for each currency touched by NEW.tx_id using idx_ledger_entries_tx_id.';

-- Constraint triggers on partitioned tables in PostgreSQL 13+ automatically propagate
-- to all child partitions.
DROP TRIGGER IF EXISTS trg_tx_balanced ON ledger_entries;
CREATE CONSTRAINT TRIGGER trg_tx_balanced
AFTER INSERT ON ledger_entries
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION assert_tx_balanced();

-- ------------------------------------------------------------------------------
-- 3. ARCHITECTURAL NOTE: SEQUENCE CONTINUITY (No Gap Trigger)
-- ------------------------------------------------------------------------------
-- WHY NO seq-continuity trigger:
-- Enforcing gapless seq continuity via database triggers causes severe serialization
-- lock contention across concurrent writers, destroying payment throughput.
-- seq allocation is serialized by application write locks on ledger_chain_tip (Task 16),
-- and continuous sequential integrity is audited post-hoc by the background chain
-- validator (Task 16 verify_chain and Task 40 worker) which walks the chain hourly.

-- ==============================================================================
-- ROLLBACK SECTION (DEV-ONLY - NEVER EXECUTE ON ENVIRONMENTS HOLDING REAL MONEY)
-- WARNING: Removing these triggers eliminates database-level financial guards.
--
-- DROP TRIGGER IF EXISTS trg_tx_balanced ON ledger_entries;
-- DROP FUNCTION IF EXISTS assert_tx_balanced();
-- DROP TRIGGER IF EXISTS trg_ledger_entries_immutable ON ledger_entries;
-- DROP FUNCTION IF EXISTS ledger_entries_immutable_guard();
-- ==============================================================================
