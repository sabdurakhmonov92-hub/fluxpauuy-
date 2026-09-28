-- ==============================================================================
-- Migration: 0005_registry.sql
-- Subsystem: Merchant Registry, Admin Users & KYC Requests (Block E, Part 1)
--
-- Architectural Role:
-- 1. `merchants`: The settlement identity authoritative store. A merchant's external_id
--    is what money settles TO. The financial ledger account (owner_type='merchant')
--    is provisioned ATOMICALLY WITH this row by Task 27's lifecycle service.
-- 2. `users`: Dashboard/admin identity and RBAC anchor. Keycloak is the IdP, but
--    roles and active status are anchored in this table for defense-in-depth (stale token
--    protection if IdP revocation is delayed).
-- 3. `kyc_requests`: Phase 1 admin-decided KYC records. Schema is designed for
--    automated provider integration (Task 55) via additive CHECK constraints.
--
-- Invariant Handoff for Task 27:
-- An active merchant without a ledger account is strictly forbidden.
-- The ledger_accounts row (owner_type='merchant', owner_id=merchants.id, currency)
-- is created ATOMICALLY WITH the merchant row inside a single Unit of Work by Task 27.
-- An active merchant without an account is a Task 27 invariant violation, never a
-- runtime lookup surprise.
--
-- Invariant Handoff for Task 29:
-- Admin plane endpoints authenticate via Keycloak JWT, but verify the subject against
-- the `users` table to enforce DB-anchored roles and immediate revocation.
--
-- OCC Versioning:
-- The `version` column provides optimistic concurrency control for administrative
-- updates (Task 27 / Task 29), completely independent of ledger OCC versioning (Task 16).
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. MERCHANTS TABLE (Settlement Identity)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS merchants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id TEXT NOT NULL UNIQUE
        CHECK (external_id ~ '^[a-z0-9_.-]{3,64}$'),  -- Task 24 grammar, cross-checked against MERCHANT_ID_PATTERN by test
    name TEXT NOT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT true,
    version BIGINT NOT NULL DEFAULT 1
        CHECK (version >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE merchants IS 'settlement identity; the merchant''s ledger account is created ATOMICALLY WITH this row by Task 27 — an active merchant without an account is a Task 27 invariant violation, never a runtime lookup surprise.';

-- ------------------------------------------------------------------------------
-- 2. USERS TABLE (Admin / Dashboard Identities)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keycloak_sub TEXT NOT NULL UNIQUE,
        -- TEXT not UUID: Keycloak subs are opaque strings, treating
        -- them as UUIDs couples us to their format (WHY comment)
    email TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL
        CHECK (role IN ('admin', 'support')),
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE users IS 'dashboard/admin humans — Keycloak is the IdP, this is the role/audit anchor; Phase 1 RBAC is role-in-DB; Keycloak roles are a mirror (Task 29 verifies IdP token roles AND this row — defense in depth; a deleted user''s stale token must fail here even if the IdP was slow to revoke).';

-- ------------------------------------------------------------------------------
-- 3. KYC_REQUESTS TABLE (Phase 1 Admin-Decided KYC)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS kyc_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_type TEXT NOT NULL
        CHECK (subject_type IN ('merchant')),
    subject_id UUID NOT NULL REFERENCES merchants(id),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
    provider TEXT NOT NULL DEFAULT 'manual',
        -- 'manual' | provider keys later (sumsub/trulioo), CHECK widened additively in a
        -- later migration, never edited in place (WHY comment)
    provider_ref TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    decided_by UUID NULL REFERENCES users(id),  -- NULL until decided
    decided_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE kyc_requests IS 'Phase 1 admin-decided KYC; provider-wired later. Partial index on status=pending optimizes admin approval queue.';

-- Partial index: (status) WHERE status = 'pending' — the admin approval queue is the only hot query.
CREATE INDEX IF NOT EXISTS idx_kyc_requests_pending
    ON kyc_requests (status)
    WHERE status = 'pending';

-- ==============================================================================
-- ROLLBACK SECTION (DEV-ONLY - NEVER EXECUTE ON ENVIRONMENTS HOLDING REAL MONEY)
-- WARNING: Dropping registry tables destroys merchant identities and admin accounts.
--
-- DROP INDEX IF EXISTS idx_kyc_requests_pending;
-- DROP TABLE IF EXISTS kyc_requests CASCADE;
-- DROP TABLE IF EXISTS users CASCADE;
-- DROP TABLE IF EXISTS merchants CASCADE;
-- ==============================================================================
