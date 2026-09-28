-- ==============================================================================
-- Migration: 0001_idempotency.sql
-- Subsystem: Distributed Idempotency Controller (Blueprint §3)
--
-- Handoff Note for Task 13:
-- The ledger migration previously slated for 0001 is renumbered to:
-- migrations/0002_ledger.sql (0001 is reserved for the idempotency keys table).
--
-- Architectural Role:
-- In a two-tier idempotency architecture (Redis fast-path in Task 22 + DB source
-- of truth here), Redis may experience failover, eviction, or split-brain.
-- PostgreSQL is the sole immutable authority preventing double-debit.
--
-- Grant Policy:
-- The application role requires INSERT, SELECT, UPDATE, DELETE permissions on
-- this table. Unlike financial ledger tables (Task 13), which are strictly
-- append-only by architectural contract, idempotency_keys is MUTABLE by design
-- to support atomic state transitions (PENDING -> COMPLETED / FAILED) and stale
-- reservation takeovers. This is the ONLY mutable shared database table in FluxPay.
--
-- Byte-Exact Replay Contract:
-- response_body is typed as TEXT, NOT JSONB.
-- WHY: PostgreSQL JSONB normalization eliminates insignicant whitespace, strips
-- duplicate keys, and re-sorts dictionary keys lexically. Autonomous AI agents
-- and payment clients verify cryptographic HMAC signatures and hash digests over
-- exact wire responses. Normalizing wire bytes would return a payload that
-- fails client-side signature verification on replay. TEXT preserves 100% byte fidelity.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS idempotency_keys (
    agent_id        UUID NOT NULL,
    idem_key        TEXT NOT NULL,
    body_hash       TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (state IN ('PENDING', 'COMPLETED', 'FAILED')),
    tx_id           UUID,
    response_status INTEGER,
    response_body   TEXT,
    attempts        INTEGER NOT NULL DEFAULT 1,
    reserved_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, idem_key)
);

-- Partial index for high-efficiency stale reservation sweep and reclamation.
-- Scans exclusively over in-flight PENDING reservations, ignoring high-volume COMPLETED records.
CREATE INDEX IF NOT EXISTS idx_idempotency_keys_stale_sweep
    ON idempotency_keys (state, reserved_at)
    WHERE state = 'PENDING';
