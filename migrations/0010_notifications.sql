-- ==============================================================================
-- Migration: 0010_notifications.sql
-- Subsystem: Notification Adapters — Failure Ledger (Task 43)
--
-- Purpose:
--   Persist every notification delivery failure as an auditable row so that
--   a missed Telegram or email alert is NEVER silent — it becomes a database
--   record that the notification sweep can re-dispatch and operations can query.
--
-- Design decisions:
--   1. FAIL-CLOSED-TO-RECORD DOCTRINE: Any channel failure (transport error,
--      5xx, 429 ladder exhausted) records a row here. The sweep worker
--      re-dispatches every 15 minutes. Abandon threshold = 11 attempts, after
--      which resolved_at is set with error='abandoned'. These rows are visible
--      to ops via direct SQL query (not the Task 41 reconciliation report — kept
--      scoped deliberately; notification health is an ops concern, not a
--      financial-ledger concern).
--   2. SUBJECT stores the channel recipient identity (chat_id or email address),
--      NEVER secrets (bot token, API key).
--   3. PAYLOAD stores the full structured context needed to rebuild and re-send
--      the message on sweep, without re-querying the originating tables.
--   4. PURPOSE constrains to known operational notification categories
--      (hold lifecycle, KYC decisions, SEV escalations). This prevents the
--      table from accumulating unmapped entries from future code paths without
--      a corresponding migration to expand the CHECK constraint.
--   5. The partial index on (resolved_at) WHERE resolved_at IS NULL keeps the
--      sweep SELECT fast: only unresolved rows are scanned.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. NOTIFICATION FAILURES TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notification_failures (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Channel identifier: 'telegram' or 'email'
    channel       TEXT         NOT NULL
                               CHECK (channel IN ('telegram', 'email')),

    -- Recipient identity: chat_id string or email address.
    -- NEVER a secret (bot token, API key). Used for display and re-send targeting.
    subject       TEXT         NOT NULL,

    -- Operational purpose of the notification.
    -- CHECK ensures only known categories are stored; expand by migration.
    -- Deliberately lowercase_dotted to match structured log event naming.
    purpose       TEXT         NOT NULL
                               CHECK (purpose ~ '^[a-z_.]{3,64}$'),

    -- Full structured context for rebuilding the message on sweep retry.
    -- Includes all fields the formatter needs (hold_id, agent_id, amount, currency,
    -- reason, etc.) so no secondary DB lookup is required during sweep.
    payload       JSONB        NOT NULL,

    -- Defect class only — never raw exception strings, never stack traces,
    -- never credentials. E.g.: 'transport_error', 'http_5xx', 'http_429_exhausted'.
    error         TEXT         NOT NULL,

    -- Number of dispatch attempts so far (1 on first INSERT; incremented on sweep failure).
    attempts      INT          NOT NULL DEFAULT 1,

    -- Record creation timestamp (UTC).
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Set when delivery succeeds (sweep resolves) or when abandoned (attempts > 10).
    -- NULL = unresolved / pending sweep.
    resolved_at   TIMESTAMPTZ  NULL
);

COMMENT ON TABLE  notification_failures IS
    'Fail-closed-to-record ledger: every missed notification becomes a row the sweep worker re-dispatches. Never silent.';
COMMENT ON COLUMN notification_failures.subject   IS 'Recipient identity (chat_id or email) — NOT secrets.';
COMMENT ON COLUMN notification_failures.purpose   IS 'Operational notification category (hold.pending, hold.settled, hold.rejected, kyc.decided, sev.escalation).';
COMMENT ON COLUMN notification_failures.payload   IS 'Full message context for re-send — no secondary DB lookup required on sweep.';
COMMENT ON COLUMN notification_failures.error     IS 'Defect class only (transport_error, http_5xx, etc.) — no credentials or raw stack traces.';
COMMENT ON COLUMN notification_failures.attempts  IS 'Delivery attempt count; abandon threshold = 11.';
COMMENT ON COLUMN notification_failures.resolved_at IS 'NULL = pending sweep; set on success or abandoned.';

-- ------------------------------------------------------------------------------
-- 2. PARTIAL INDEX FOR SWEEP EFFICIENCY
-- Covers only unresolved rows — typically a tiny fraction of the table.
-- The sweep SELECT (SKIP LOCKED) hits this index exclusively.
-- ------------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_notification_failures_unresolved
    ON notification_failures (created_at ASC)
    WHERE resolved_at IS NULL;

-- ==============================================================================
-- ROLLBACK SECTION (DEV-ONLY - NEVER EXECUTE ON ENVIRONMENTS HOLDING REAL MONEY)
--
-- DROP INDEX IF EXISTS idx_notification_failures_unresolved;
-- DROP TABLE IF EXISTS notification_failures;
-- ==============================================================================
