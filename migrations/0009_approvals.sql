-- ==============================================================================
-- Migration: 0009_approvals.sql
-- Subsystem: Dual-Authorization: 2-Man Rule for Held Payments (Block H, Part 4)
--
-- Architectural Role:
-- 1. `approval_votes`:
--    Immutable quorum voting ledger for quarantined payment holds (Task 28).
--    Enforces the 2-man rule invariant: exactly one vote per human administrator
--    (keycloak_sub) per hold via UNIQUE(hold_id, voter_sub).
-- 2. `payment_holds.notified_at`:
--    In-table notification deduplication marker. Tracks when a pending hold was
--    dispatched to operators via the Task 43 notifier seam.
--    WHY a column not a side-table: 1:1 relationship with payment_holds; avoiding joins
--    keeps worker batch queries lock-free with minimal query overhead.
--
-- Invariant Handoff & Security Posture:
-- - Vote integrity is ENFORCED HERE + app-side self-vote check (DB cannot know actor
--   identity mapping - defense in depth: UNIQUE(hold_id, voter_sub) + app-side voter != creator).
-- - Money is NEVER moved by voting or approval alone. Quorum approval signals
--   Task 31's settle_approved exactly-once door.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. APPROVAL VOTES TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS approval_votes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hold_id UUID NOT NULL REFERENCES payment_holds(hold_id),
    voter_sub TEXT NOT NULL,
    vote TEXT NOT NULL CHECK (vote IN ('approve', 'reject')),
    note TEXT NOT NULL DEFAULT '',
    voted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_approval_votes_hold_voter UNIQUE (hold_id, voter_sub)
);

COMMENT ON TABLE approval_votes IS 'Vote integrity is enforced here + app-side self-vote check (DB cannot know actor identity mapping - defense in depth: UNIQUE(hold_id, voter_sub) + app-side voter != creator).';
COMMENT ON COLUMN approval_votes.id IS 'Synthetic UUID primary key for vote record.';
COMMENT ON COLUMN approval_votes.hold_id IS 'Foreign key reference to payment_holds table.';
COMMENT ON COLUMN approval_votes.voter_sub IS 'Keycloak subject identifier (sub) of the human administrator.';
COMMENT ON COLUMN approval_votes.vote IS 'Vote decision: approve or reject.';
COMMENT ON COLUMN approval_votes.note IS 'Approver rationale context (truncated to 200 characters app-side).';
COMMENT ON COLUMN approval_votes.voted_at IS 'Timestamp when vote was recorded.';

CREATE INDEX IF NOT EXISTS idx_approval_votes_hold_id
    ON approval_votes (hold_id);

-- ------------------------------------------------------------------------------
-- 2. NOTIFICATION DEDUPLICATION MARKER
-- ------------------------------------------------------------------------------
ALTER TABLE payment_holds
    ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ NULL;

COMMENT ON COLUMN payment_holds.notified_at IS 'Notification deduplication marker for Task 43 seam (additive ALTER; owned by 2-man approval worker).';

-- ==============================================================================
-- ROLLBACK SECTION (DEV-ONLY - NEVER EXECUTE ON ENVIRONMENTS HOLDING REAL MONEY)
--
-- DROP INDEX IF EXISTS idx_approval_votes_hold_id;
-- DROP TABLE IF EXISTS approval_votes CASCADE;
-- ALTER TABLE payment_holds DROP COLUMN IF EXISTS notified_at;
-- ==============================================================================
