-- ==============================================================================
-- Deploy Grants: Append-Only Production Role Contract
-- Environment-agnostic artifact applied by Ansible (Task 68).
--
-- Architectural Role:
-- Enforces database-level immutability. The application role (fluxpay_app)
-- is granted append-only privileges (SELECT, INSERT) on ledger_entries, with
-- UPDATE, DELETE, and TRUNCATE explicitly revoked.
-- ==============================================================================

-- Deny-by-default to public
REVOKE ALL ON ledger_entries FROM PUBLIC;
REVOKE ALL ON ledger_accounts FROM PUBLIC;
REVOKE ALL ON ledger_chain_tip FROM PUBLIC;

-- THE core blueprint grant: app role can append, never rewrite.
GRANT SELECT, INSERT ON ledger_entries TO fluxpay_app;

-- TRUNCATE is the forgotten one - it bypasses row DELETE thinking.
REVOKE UPDATE, DELETE, TRUNCATE ON ledger_entries FROM fluxpay_app;

-- Mutable cache by design (balance/version OCC updates).
GRANT SELECT, INSERT, UPDATE, DELETE ON ledger_accounts TO fluxpay_app;

-- The pointer is mutable; deleting it would orphan the chain.
GRANT SELECT, INSERT, UPDATE ON ledger_chain_tip TO fluxpay_app;
REVOKE DELETE, TRUNCATE ON ledger_chain_tip FROM fluxpay_app;

-- FUTURE partitions (created monthly by create_month_partition) must inherit
-- grants automatically. Without this, next month's partition is invisible to the
-- app role and payments break at month boundary. This is the classic production trap.
-- Note: FOR ROLE <owner> placeholder is configured by Ansible in deployment.
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT ON TABLES TO fluxpay_app;
