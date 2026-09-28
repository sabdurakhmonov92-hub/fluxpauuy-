-- ==============================================================================
-- Migration: 0006_audit.sql
-- Subsystem: System Audit Service & Admin Action Trail (Block E, Task 29)
--
-- Architectural Role:
-- Blueprint §5: System Audit Service — immutable logging of administrative actions.
-- Every administrative mutation (agent creation/suspension, merchant lifecycle,
-- KYC decisions) MUST land in this append-only audit table in the EXACT SAME
-- transaction (Unit of Work) as the mutation itself.
-- An admin action without an audit row is structurally impossible by design.
--
-- Downstream Consumers:
-- Task 70 consumes rows from this table for SEV reviews and automated escalation
-- into Sentry / Telegram alerting channels.
--
-- Database Identity vs Financial Ledger Sequence:
-- In `ledger_entries` (Task 13 / 16), `seq` is monotonically gapless and cryptographically
-- hash-chained; gaps indicate data loss or tampering.
-- Here, `audit_log.id` uses `BIGINT GENERATED ALWAYS AS IDENTITY`. Audit rows are not
-- hash-chained: transaction rollbacks may consume an identity sequence value without
-- violating audit log integrity. The identity sequence provides non-blocking,
-- high-throughput concurrent inserts without lock contention.
--
-- Heterogeneous Target ID as TEXT:
-- `target_id` stores targets of varying entities: agent UUIDs, merchant external_ids or
-- UUIDs, user Keycloak subs or UUIDs, and KYC request UUIDs. Storing `target_id` as TEXT
-- preserves a single, clean append-only schema without complex polymorphic foreign keys,
-- nullable columns, or entity-specific join tables.
--
-- Details Payload Divergence (JSONB vs Ledger Flat Scalars):
-- The financial ledger enforces strictly typed, flat scalar columns to maximize transaction
-- density and zero-allocation processing. In contrast, `audit_log.details` uses JSONB to
-- store rich, queryable contextual data (such as decision rationales, parameter changes,
-- and SIEM tags) designed for human inspection and forensic SIEM ingestion.
--
-- Partitioning Growth Plan:
-- Partitioning is omitted during Phase 1 volume (<100k admin actions/month).
-- In Task 41 (reconciliation and high-scale era), when the audit table approaches
-- 10M rows, monthly RANGE partitioning on `occurred_at` will be introduced.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. AUDIT_LOG TABLE (Immutable Admin Audit Trail)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_sub TEXT NOT NULL,           -- Keycloak subject identifier of the admin
    actor_role TEXT NOT NULL,          -- Role at time of action: 'admin' | 'support'
    action TEXT NOT NULL
        CHECK (action ~ '^[a-z_.]{3,64}$'),  -- Grammar: 'agent.create', 'agent.suspend', etc.
    target_type TEXT NOT NULL
        CHECK (target_type IN ('agent', 'merchant', 'user', 'kyc')),
    target_id TEXT NOT NULL,           -- Heterogeneous target identifier stored as TEXT
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

COMMENT ON TABLE audit_log IS 'Immutable administrative mutation log. Every admin mutation writes to this table atomically within the same Unit of Work transaction.';
COMMENT ON COLUMN audit_log.id IS 'Monotonically increasing identity primary key. Rollback gaps permitted; rows are not hash-chained unlike ledger_entries.';
COMMENT ON COLUMN audit_log.actor_sub IS 'Keycloak subject identifier of the admin principal who executed the action.';
COMMENT ON COLUMN audit_log.actor_role IS 'Role of the acting principal at the time the action was performed (admin or support).';
COMMENT ON COLUMN audit_log.action IS 'Domain action identifier in snake_case format matching ^[a-z_.]{3,64}$.';
COMMENT ON COLUMN audit_log.target_type IS 'Domain entity category affected: agent, merchant, user, or kyc.';
COMMENT ON COLUMN audit_log.target_id IS 'Target entity identifier represented as text to accommodate heterogeneous UUIDs and handles.';
COMMENT ON COLUMN audit_log.details IS 'Structured JSONB metadata and contextual SIEM parameters. Leaf values must be scalars.';

-- ------------------------------------------------------------------------------
-- 2. INDEXES (Optimized for Forensic Queries and Admin UI)
-- ------------------------------------------------------------------------------
-- Primary timeline query: recent admin actions ordered newest first
CREATE INDEX IF NOT EXISTS idx_audit_log_occurred_at
    ON audit_log (occurred_at DESC);

-- Entity forensic lookup: all historical admin operations on a specific target
CREATE INDEX IF NOT EXISTS idx_audit_log_target
    ON audit_log (target_type, target_id);

-- Operator accountability lookup: all operations performed by a specific Keycloak admin
CREATE INDEX IF NOT EXISTS idx_audit_log_actor_sub
    ON audit_log (actor_sub);

-- ------------------------------------------------------------------------------
-- 3. APPEND-ONLY GUARD (Task 14 Pattern Clone)
-- ------------------------------------------------------------------------------
-- Clones the defense-in-depth philosophy established in Task 14 (ledger immutability):
-- In addition to database privilege revokes, an engine-level BEFORE UPDATE OR DELETE
-- trigger raises `restrict_violation` permanently. Even the table owner or superuser
-- cannot silently mutate or delete audit records without an auditable DROP TRIGGER event.

CREATE OR REPLACE FUNCTION audit_log_immutable_guard()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        RAISE EXCEPTION 'audit_log is append-only: % forbidden (id=%)',
            TG_OP, COALESCE(OLD.id, 0)
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$;

COMMENT ON FUNCTION audit_log_immutable_guard() IS
'Defense-in-depth immutability trigger function. Permanently raises restrict_violation on UPDATE or DELETE. Modifying audit history requires an explicit DROP TRIGGER operational intervention.';

DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
CREATE TRIGGER trg_audit_log_immutable
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW
EXECUTE FUNCTION audit_log_immutable_guard();

-- ------------------------------------------------------------------------------
-- 4. PERMISSIONS & ROLE GRANTS (Grants.sql Mirror Pattern)
-- ------------------------------------------------------------------------------
-- The application role (fluxpay_app) is granted append-only privileges (SELECT, INSERT).
-- Mutation and deletion operations (UPDATE, DELETE, TRUNCATE) are explicitly revoked.
-- Production deployment applies this via Ansible (Task 68) using deploy/sql/grants.sql:
--
-- REVOKE ALL ON audit_log FROM PUBLIC;
-- GRANT SELECT, INSERT ON audit_log TO fluxpay_app;
-- REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM fluxpay_app;

-- ==============================================================================
-- ROLLBACK SECTION (DEV-ONLY - NEVER EXECUTE ON ENVIRONMENTS HOLDING REAL MONEY)
-- WARNING: Dropping audit tables destroys privileged operational trails.
--
-- DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log;
-- DROP FUNCTION IF EXISTS audit_log_immutable_guard();
-- DROP INDEX IF EXISTS idx_audit_log_actor_sub;
-- DROP INDEX IF EXISTS idx_audit_log_target;
-- DROP INDEX IF EXISTS idx_audit_log_occurred_at;
-- DROP TABLE IF EXISTS audit_log CASCADE;
-- ==============================================================================
