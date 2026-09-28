-- ==============================================================================
-- Migration: 0004_agents.sql
-- Subsystem: Agent Registry & Auth-Path Store (Blueprint §3 & §7)
--
-- Handoff Note for Task 26:
-- Registry merchants/users/kyc migration previously slated for 0004 is renumbered to:
-- migrations/0005_registry.sql (0004 is reserved for the agents auth-path table).
-- Task 26's card must be updated with this renumber handoff.
--
-- Architectural Role:
-- The agents table is the authoritative source of truth for agent authentication,
-- identity, and effective request rate/quota limits. It stores AES-256-GCM encrypted
-- secret envelopes (vault format) bound with AAD to prevent ciphertext swaps.
--
-- Invariant Handoff for Task 27:
-- A payment-capable agent without a ledger account is strictly forbidden.
-- The ledger_accounts row (owner_type='agent', owner_id=agents.id) is created
-- ATOMICALLY WITH the agent row inside a single Unit of Work by Task 27's
-- lifecycle service. That lifecycle invariant belongs to Task 27, not here.
--
-- OCC Versioning Split:
-- The `version` column provides optimistic concurrency control for administrative
-- updates (Task 27 / 28 admin lifecycle). It is completely independent of the
-- ledger OCC version on ledger_accounts (Task 16).
--
-- Grant Policy:
-- This table is MUTABLE (admin lifecycle). In production, the application role
-- receives full DML privileges (SELECT, INSERT, UPDATE, DELETE) per deploy/sql/grants.sql.
-- Applying grants in production environments is handled by Task 68 Ansible automation.
-- ==============================================================================

CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id TEXT NOT NULL UNIQUE
        CHECK (external_id ~ '^[a-z0-9_.-]{3,64}$'),
    name TEXT NOT NULL DEFAULT '',
    secret_encrypted TEXT NOT NULL
        CHECK (secret_encrypted ~ '^[A-Za-z0-9+/=]+$'),
        -- vault envelope b64; WHY CHECK: catches accidental plaintext
        -- with spaces/newlines at the door (cheap, not exhaustive —
        -- real protection is the AAD binding)
    active BOOLEAN NOT NULL DEFAULT true,
    rate_limit_max INT NOT NULL DEFAULT 100
        CHECK (rate_limit_max > 0),
    daily_quota_max INT NOT NULL DEFAULT 10000
        CHECK (daily_quota_max > 0),
    version BIGINT NOT NULL DEFAULT 1
        CHECK (version >= 1),
        -- registry OCC (Task 27 admin updates); NOT ledger version
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE agents IS 'auth-path source of truth; the ledger_accounts row (owner_type=''agent'') is created ATOMICALLY WITH the agent by Task 27''s lifecycle service — a payment-capable agent without a ledger account is a Task 27 invariant, not yours.';
