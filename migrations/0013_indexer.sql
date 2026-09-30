-- ==============================================================================
-- Migration: 0013_indexer.sql
-- Subsystem: Base L2 Inbound USDC Deposit Indexer (Block J, Part 4)
--
-- Architectural Role:
-- 1. `indexer_cursor`:
--    Tracks the last processed block number and block hash for each indexed chain.
--    Guarantees deterministic, gap-free resume across worker restarts and crashes.
-- 2. `indexer_events`:
--    Stores observed ERC-20 Transfer deposit logs filtered for registered agent wallets.
--    Enforces (chain_id, tx_hash, log_index) uniqueness for at-least-once ingestion.
--    Tracks confirmation progression: 'provisional' (1 block) -> 'confirmed' (N blocks)
--    or 'reorged' upon chain re-organization.
-- 3. `indexer_reorgs`:
--    Forensic audit trail of all detected blockchain reorganizations, recording the
--    rolled-back block range, detection timestamp, and diagnostic cause.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. INDEXER CURSOR (PER-CHAIN RECOVERY WATERMARK)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS indexer_cursor (
    chain_id             BIGINT      PRIMARY KEY,
    last_processed_block BIGINT      NOT NULL CHECK (last_processed_block >= 0),
    last_block_hash      TEXT        NOT NULL CHECK (last_block_hash ~ '^0x[0-9a-fA-F]{64}$'),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE  indexer_cursor                      IS 'Per-chain watermark tracking block number and hash for gapless restart.';
COMMENT ON COLUMN indexer_cursor.chain_id             IS 'EVM chain ID (e.g. 8453 for Base Mainnet, 84532 for Base Sepolia).';
COMMENT ON COLUMN indexer_cursor.last_processed_block IS 'Latest sequentially processed block height.';
COMMENT ON COLUMN indexer_cursor.last_block_hash      IS '32-byte block hash of last_processed_block.';
COMMENT ON COLUMN indexer_cursor.updated_at           IS 'Timestamp of last watermark commit.';

-- ------------------------------------------------------------------------------
-- 2. INDEXER EVENTS (INGESTED DEPOSIT TRANSFERS)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS indexer_events (
    id             UUID           PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id       BIGINT         NOT NULL,
    tx_hash        TEXT           NOT NULL CHECK (tx_hash ~ '^0x[0-9a-fA-F]{64}$'),
    log_index      INTEGER        NOT NULL CHECK (log_index >= 0),
    block_number   BIGINT         NOT NULL CHECK (block_number >= 0),
    block_hash     TEXT           NOT NULL CHECK (block_hash ~ '^0x[0-9a-fA-F]{64}$'),
    from_addr      TEXT           NOT NULL CHECK (from_addr ~ '^0x[0-9a-fA-F]{40}$'),
    to_addr        TEXT           NOT NULL CHECK (to_addr ~ '^0x[0-9a-fA-F]{40}$'),
    amount_raw     NUMERIC(78, 0) NOT NULL CHECK (amount_raw > 0),
    confirmations  INTEGER        NOT NULL DEFAULT 1 CHECK (confirmations >= 0),
    status         TEXT           NOT NULL DEFAULT 'provisional'
                                  CHECK (status IN ('provisional', 'confirmed', 'reorged')),
    created_at     TIMESTAMPTZ    NOT NULL DEFAULT now(),
    confirmed_at   TIMESTAMPTZ    NULL,

    CONSTRAINT uq_indexer_events_chain_tx_log UNIQUE (chain_id, tx_hash, log_index)
);

CREATE INDEX IF NOT EXISTS idx_indexer_events_to_addr
    ON indexer_events (to_addr);

CREATE INDEX IF NOT EXISTS idx_indexer_events_block_number
    ON indexer_events (chain_id, block_number);

CREATE INDEX IF NOT EXISTS idx_indexer_events_status
    ON indexer_events (status)
    WHERE status = 'provisional';

COMMENT ON TABLE  indexer_events                IS 'Observed ERC-20 deposit logs for agent wallets with confirmation lifecycle.';
COMMENT ON COLUMN indexer_events.chain_id       IS 'EVM chain ID.';
COMMENT ON COLUMN indexer_events.tx_hash        IS 'Transaction hash of the Transfer event.';
COMMENT ON COLUMN indexer_events.log_index      IS 'Log index within the transaction receipt.';
COMMENT ON COLUMN indexer_events.block_number   IS 'Block number where the event was mined.';
COMMENT ON COLUMN indexer_events.block_hash     IS 'Block hash where the event was mined.';
COMMENT ON COLUMN indexer_events.from_addr      IS 'Checksummed sender address.';
COMMENT ON COLUMN indexer_events.to_addr        IS 'Checksummed agent deposit address.';
COMMENT ON COLUMN indexer_events.amount_raw     IS 'Raw token value in minor units (e.g. 10^6 for USDC).';
COMMENT ON COLUMN indexer_events.confirmations  IS 'Current confirmation depth observed.';
COMMENT ON COLUMN indexer_events.status         IS 'provisional (1 block), confirmed (N blocks), or reorged.';
COMMENT ON COLUMN indexer_events.created_at     IS 'Timestamp when deposit was first ingested.';
COMMENT ON COLUMN indexer_events.confirmed_at   IS 'Timestamp when deposit achieved final confirmation and credited ledger.';

-- ------------------------------------------------------------------------------
-- 3. INDEXER REORGS (CHAIN REORGANIZATION AUDIT TRAIL)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS indexer_reorgs (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    chain_id       BIGINT      NOT NULL DEFAULT 8453,
    from_block     BIGINT      NOT NULL CHECK (from_block >= 0),
    to_block       BIGINT      NOT NULL CHECK (to_block >= from_block),
    detected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason         TEXT        NOT NULL
);

COMMENT ON TABLE  indexer_reorgs             IS 'Audit trail recording blockchain reorganizations and depth rolled back.';
COMMENT ON COLUMN indexer_reorgs.chain_id    IS 'EVM chain ID where reorg occurred.';
COMMENT ON COLUMN indexer_reorgs.from_block  IS 'Lowest affected block height (LCA + 1).';
COMMENT ON COLUMN indexer_reorgs.to_block    IS 'Highest orphaned block height rolled back.';
COMMENT ON COLUMN indexer_reorgs.detected_at IS 'Timestamp of reorg detection.';
COMMENT ON COLUMN indexer_reorgs.reason      IS 'Diagnostic reason for the rollback.';
