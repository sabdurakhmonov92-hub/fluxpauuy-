-- ==============================================================================
-- Migration: 0002_ledger.sql
-- Subsystem: Partitioned Append-Only Financial Ledger Storage (Blueprint §5 & §7)
--
-- Architectural Role:
-- Immutable financial core of FluxPay. Stores cryptographic hash-chained audit
-- entries, balance cache accounts, and the singleton tip write-serializer.
--
-- Laws Inherited from Task 12 (Frozen Protocol Spec):
-- L1. currency: VARCHAR(10) with regex ^[A-Z0-9]{2,10}$ (NOT CHAR(3); allows crypto tickers like USDC).
-- L2. ledger_chain_tip.last_hash DEFAULT must be the literal 'GENESIS'.
-- L3. CHECK constraints strictly mirror hashchain.py guards:
--     amount > 0, balance_after >= 0, version >= 1, direction IN ('DEBIT','CREDIT'),
--     entry_hash/prev_hash lowercase 64-hex (prev_hash may alternatively be 'GENESIS').
-- L4. Genesis bidirectional guard as a cross-field CHECK:
--     CHECK ((seq = 1) = (prev_hash = 'GENESIS'))
-- L5. created_at: TIMESTAMPTZ. The app hashes format_timestamp(dt) canonical UTC string
--     "%Y-%m-%dT%H:%M:%S.%fZ" and inserts the same dt. Postgres microsecond precision preserves it.
--     Partition bounds are UTC dates.
-- L6. NO identity/sequence on seq. seq is allocated by the application under the
--     ledger_chain_tip FOR UPDATE lock (Task 16).
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. ledger_accounts (MUTABLE by design - balance cache + OCC version counter)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ledger_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_type TEXT NOT NULL
        CONSTRAINT ledger_accounts_owner_type_check
        CHECK (owner_type IN ('agent', 'merchant', 'treasury', 'fees', 'system')),
    owner_id UUID NOT NULL,
    currency VARCHAR(10) NOT NULL
        CONSTRAINT ledger_accounts_currency_check
        CHECK (currency ~ '^[A-Z0-9]{2,10}$'),
    balance BIGINT NOT NULL DEFAULT 0
        CONSTRAINT ledger_accounts_balance_check
        CHECK (balance >= 0),
    version BIGINT NOT NULL DEFAULT 0
        CONSTRAINT ledger_accounts_version_check
        CHECK (version >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_ledger_accounts_owner_currency UNIQUE (owner_type, owner_id, currency)
);

-- WHY CHECK (balance >= 0): DB-level backstop behind application InsufficientFunds;
-- accounts can never hold negative money, even under an application bug.
-- WHY default version 0: first mutation records version=1 (Task 12 L3
-- "recorded version is the post-mutation value, >= 1").

COMMENT ON TABLE ledger_accounts IS
'Mutable balance cache and OCC version counter. The ledger_entries table is the immutable financial source of truth (reconciliation = Task 41).';

-- ------------------------------------------------------------------------------
-- 2. ledger_entries (APPEND-ONLY, PARTITIONED BY RANGE (created_at))
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ledger_entries (
    seq BIGINT NOT NULL
        CONSTRAINT ledger_entries_seq_positive_check
        CHECK (seq >= 1),
    tx_id UUID NOT NULL,
    account_id UUID NOT NULL
        CONSTRAINT fk_ledger_entries_account
        REFERENCES ledger_accounts(id),
    direction TEXT NOT NULL
        CONSTRAINT ledger_entries_direction_check
        CHECK (direction IN ('DEBIT', 'CREDIT')),
    amount BIGINT NOT NULL
        CONSTRAINT ledger_entries_amount_positive
        CHECK (amount > 0),
    currency VARCHAR(10) NOT NULL
        CONSTRAINT ledger_entries_currency_check
        CHECK (currency ~ '^[A-Z0-9]{2,10}$'),
    balance_after BIGINT NOT NULL
        CONSTRAINT ledger_entries_balance_after_nonnegative
        CHECK (balance_after >= 0),
    version BIGINT NOT NULL
        CONSTRAINT ledger_entries_version_positive
        CHECK (version >= 1),
    prev_hash TEXT NOT NULL
        CONSTRAINT ledger_entries_prev_hash_format
        CHECK (prev_hash = 'GENESIS' OR prev_hash ~ '^[0-9a-f]{64}$'),
    entry_hash TEXT NOT NULL
        CONSTRAINT ledger_entries_entry_hash_format
        CHECK (entry_hash ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_ledger_entries PRIMARY KEY (seq, created_at),
    CONSTRAINT ledger_entries_genesis_bidirectional_check
        CHECK ((seq = 1) = (prev_hash = 'GENESIS'))
) PARTITION BY RANGE (created_at);

-- WHY created_at in PK: Postgres requires the partition key in every unique/PK constraint.
-- seq global uniqueness across partitions cannot be enforced by a local index alone;
-- it is guaranteed by the ledger_chain_tip serialization lock (L6) and audited by
-- the hourly chain validator (Task 18/40 checks seq continuity).
-- WHY NO identity/sequence on seq: seq allocation is coupled to tip locking in Task 16.

CREATE INDEX IF NOT EXISTS idx_ledger_entries_created_at_brin
    ON ledger_entries USING brin (created_at);

CREATE INDEX IF NOT EXISTS idx_ledger_entries_account_seq_desc
    ON ledger_entries (account_id, seq DESC);

CREATE INDEX IF NOT EXISTS idx_ledger_entries_tx_id
    ON ledger_entries (tx_id);

COMMENT ON TABLE ledger_entries IS
'Immutable append-only audit ledger. Immutability enforced by SQL grants (deploy/sql/grants.sql) + BEFORE UPDATE/DELETE guard (Task 14).';

-- ------------------------------------------------------------------------------
-- 3. ledger_chain_tip (SINGLETON - chain write serializer)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ledger_chain_tip (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE
        CONSTRAINT ledger_chain_tip_singleton_check
        CHECK (singleton),
    last_seq BIGINT NOT NULL DEFAULT 0,
    last_hash TEXT NOT NULL DEFAULT 'GENESIS'
);

INSERT INTO ledger_chain_tip (singleton, last_seq, last_hash)
VALUES (TRUE, 0, 'GENESIS')
ON CONFLICT (singleton) DO NOTHING;

COMMENT ON TABLE ledger_chain_tip IS
'Singleton write serializer. Every post_transaction takes SELECT ... FOR UPDATE on this row first to serialize hash-chain appends. Phase 1 load (8 tx/s) makes this a non-bottleneck; micro-batching is the Phase 2 path (Task 16 notes).';

-- ------------------------------------------------------------------------------
-- 4. PARTITION AUTOMATION (Native PostgreSQL function, NO extensions)
-- ------------------------------------------------------------------------------
-- WHY native function: a 20-line idempotent function beats an external extension
-- dependency (e.g., pg_partman) on the mission-critical money path.
CREATE OR REPLACE FUNCTION create_month_partition(month_start DATE)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    partition_name TEXT;
    start_date TEXT;
    end_date TEXT;
    m_start DATE;
BEGIN
    m_start := date_trunc('month', month_start)::DATE;
    partition_name := 'ledger_entries_' || to_char(m_start, 'YYYY_MM');
    start_date := to_char(m_start, 'YYYY-MM-DD');
    end_date := to_char((m_start + INTERVAL '1 month')::DATE, 'YYYY-MM-DD');

    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF ledger_entries FOR VALUES FROM (%L) TO (%L);',
        partition_name,
        start_date,
        end_date
    );
END;
$$;

-- Create partition runway: current month + next 2 months (covers 1 quarter of runway).
-- WHY NO DEFAULT partition: a default partition silently swallows stray timestamps and
-- defeats partition pruning guarantees; missing partition must FAIL LOUD ("no partition found"), not absorb.
SELECT create_month_partition((date_trunc('month', now()) + (i * INTERVAL '1 month'))::DATE)
FROM generate_series(0, 2) AS i;

-- ==============================================================================
-- ROLLBACK SECTION (DEV-ONLY - NEVER EXECUTE ON ENVIRONMENTS HOLDING REAL MONEY)
-- WARNING: Executing this rollback destroys all historical audit records,
-- cryptographic hash chains, and account balance caches.
--
-- DROP FUNCTION IF EXISTS create_month_partition(DATE);
-- DROP TABLE IF EXISTS ledger_chain_tip CASCADE;
-- DROP TABLE IF EXISTS ledger_entries CASCADE;
-- DROP TABLE IF EXISTS ledger_accounts CASCADE;
-- ==============================================================================
