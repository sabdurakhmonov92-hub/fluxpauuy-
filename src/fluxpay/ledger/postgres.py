"""PostgreSQL 17 Implementation of FluxPay LedgerStore (Blueprint §5 & §7).

This module implements the frozen LedgerStore protocol against PostgreSQL 17
using asyncpg. It handles double-entry balance validation, monotonic sequence
allocation under the singleton chain tip row lock, SHA-256 hash chaining,
and optimistic concurrency control (OCC) with jittered backoff retries.

ARCHITECTURAL INVARIANTS:
1. Self-Owned Transaction Boundary (Task 8 Separation):
   The store acquires its own connection and manages its own internal database
   transaction from the pool. It must NEVER be wrapped in an ambient UnitOfWork.
2. Global Chain Serialization (Phase 1 Concurrency Model):
   The singleton ledger_chain_tip row lock (SELECT ... FOR UPDATE) serializes all
   ledger writes globally, guaranteeing strictly gapless consecutive sequences.
3. Layered Invariant Defense:
   Fast, typed in-application checks (Step 0) fail before acquiring any database
   locks. The deferred constraint trigger (Task 14) serves as the engine-level
   last line of defense at transaction COMMIT.
4. Canonical Serialization Discipline (Task 12 Law):
   Entry timestamps are captured once as tz-aware UTC datetimes, formatted once
   via format_timestamp, hashed, and inserted. The canonical string is the audit contract.
"""

import random
import uuid
from collections import defaultdict
from collections.abc import Callable, Coroutine, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg  # type: ignore[import-untyped]

from fluxpay.ledger.hashchain import (
    GENESIS,
    Direction,
    EntryFingerprint,
    compute_entry_hash,
    format_timestamp,
    verify_link,
)
from fluxpay.ledger.store import (
    Balance,
    ChainVerification,
    EntryDraft,
    LedgerEntry,
    LedgerTransaction,
    validate_chain_range,
    validate_history_params,
)
from fluxpay.shared.errors import (
    InsufficientFunds,
    InternalError,
    LedgerNotFoundError,
    OCCConflict,
    UnbalancedTransaction,
)

__all__ = ["AccountBalanceVersion", "PostgresLedgerStore"]


@dataclass(frozen=True, slots=True)
class AccountBalanceVersion:
    """Internal representation of account balance and OCC version.

    Supports tuple unpacking, attribute access, and dictionary-style indexing
    to provide seamless white-box monkeypatching in test fixtures.
    """

    balance: int
    version: int

    def __iter__(self) -> Iterator[int]:
        yield self.balance
        yield self.version

    def __getitem__(self, item: str | int) -> int:
        if item == "balance" or item == 0:
            return self.balance
        if item == "version" or item == 1:
            return self.version
        raise KeyError(item)


def _row_to_entry(row: asyncpg.Record) -> LedgerEntry:
    """Convert an asyncpg database record into an immutable LedgerEntry domain object."""
    dt: datetime = row["created_at"]
    # Enforce UTC timezone discipline: naive or non-UTC datetimes represent pool defects.
    if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
        raise ValueError(
            f"Database returned non-UTC or naive timestamp: {dt!r}. "
            "Connection pool must enforce UTC timezone discipline."
        )
    created_at_str = format_timestamp(dt)

    raw_tx_id = row["tx_id"]
    tx_id = raw_tx_id if isinstance(raw_tx_id, UUID) else UUID(str(raw_tx_id))
    raw_acc_id = row["account_id"]
    account_id = raw_acc_id if isinstance(raw_acc_id, UUID) else UUID(str(raw_acc_id))

    return LedgerEntry(
        seq=int(row["seq"]),
        tx_id=tx_id,
        account_id=account_id,
        direction=Direction(row["direction"]),
        amount=int(row["amount"]),
        currency=str(row["currency"]),
        balance_after=int(row["balance_after"]),
        version=int(row["version"]),
        prev_hash=str(row["prev_hash"]),
        entry_hash=str(row["entry_hash"]),
        created_at=created_at_str,
    )


class PostgresLedgerStore:
    """PostgreSQL 17 implementation of the FluxPay LedgerStore protocol."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        max_occ_retries: int = 5,
        sleep_fn: Callable[[float], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        """Initialize the PostgreSQL ledger store.

        WHY config is NOT imported here:
        Settings (e.g. settings.ledger_max_occ_retries) are injected at the composition
        root (Task 33) to maintain pure decoupling, maximum testability, and symmetry
        with Phase 2 TigerBeetle adapters.

        WHY injectable sleep callable:
        Allows integration tests to verify exponential backoff and jitter calculations
        deterministically without sleeping real clock time or causing flaky test delays.
        """
        self._pool = pool
        self._max_occ_retries = max_occ_retries
        if sleep_fn is not None:
            self._sleep_fn = sleep_fn
        else:
            import asyncio

            self._sleep_fn = asyncio.sleep

    async def _read_account(
        self,
        conn: asyncpg.Connection,
        account_id: UUID,
    ) -> AccountBalanceVersion:
        """Internal account-read coroutine reading balance and OCC version.

        WHY isolated coroutine:
        Enables deterministic white-box monkeypatching of stale versions in tests
        to prove the OCC retry machinery without simulating live race conditions.
        """
        row = await conn.fetchrow(
            "SELECT balance, version FROM ledger_accounts WHERE id = $1;",
            account_id,
        )
        if row is None:
            # Missing row rolls back the active transaction and halts the pipeline immediately.
            raise LedgerNotFoundError(
                details={
                    "account": str(account_id),
                    "account_id": str(account_id),
                },
                message=f"Ledger account not found: {account_id}",
            )
        return AccountBalanceVersion(
            balance=int(row["balance"]),
            version=int(row["version"]),
        )

    async def post_transaction(self, entries: Sequence[EntryDraft]) -> LedgerTransaction:
        """Atomically commit a balanced double-entry transaction.

        Execution Pipeline (Order is law):
        Step 0: Pre-lock in-application zero-sum balance check.
        Step 1: Bounded OCC retry loop with jittered backoff.
        Step 2: Database transaction under singleton chain tip row lock:
            2.a. Lock ledger_chain_tip singleton (serializes all writers globally).
            2.b. For each entry in given order:
                 i.   Allocate consecutive sequence number (seq = tip.last_seq + 1).
                 ii.  Capture and format timestamp once (canonical representation).
                 iii. Read account balance/version and verify solvency (balance >= 0).
                 iv.  Conditional OCC update on ledger_accounts (defense-in-depth).
                 v.   Compute entry SHA-256 fingerprint chained to prev_hash.
                 vi.  Insert ledger_entries partition row.
                 vii. Advance local chain tip tracking.
            2.c. Update ledger_chain_tip singleton pointer.
            2.d. Commit transaction (Task 14 deferred balance trigger backstop fires).
        Step 3: Assemble and return immutable LedgerTransaction tuple.
        """
        # =========================================================================
        # STEP 0: In-Application Pre-Lock Balance Validation
        # =========================================================================
        # Protocol contract: Empty entries sequence is rejected immediately.
        if not entries:
            raise UnbalancedTransaction(
                details={"reason": "entries sequence cannot be empty"},
                message="Transaction must contain at least two entries.",
            )

        # Per-currency double-entry check: sum(DEBIT) == sum(CREDIT) for each currency.
        # WHY in-app check before DB lock:
        # Failing before acquiring database locks eliminates wasted connection pool
        # acquisitions and table lock contention for malformed requests. The database
        # deferred trigger (Task 14) serves as the engine-level backstop at COMMIT.
        debits: dict[str, int] = defaultdict(int)
        credits: dict[str, int] = defaultdict(int)
        for e in entries:
            if e.direction == Direction.DEBIT:
                debits[e.currency] += e.amount
            else:
                credits[e.currency] += e.amount

        all_currencies = set(debits.keys()) | set(credits.keys())
        for curr in sorted(all_currencies):
            deb_sum = debits[curr]
            cred_sum = credits[curr]
            if deb_sum != cred_sum:
                raise UnbalancedTransaction(
                    details={
                        "currency": curr,
                        "debit_sum": str(deb_sum),
                        "credit_sum": str(cred_sum),
                    },
                    message=(
                        f"Transaction unbalanced for currency {curr}: "
                        f"debit={deb_sum}, credit={cred_sum}"
                    ),
                )

        # --- Task 31 evolution (sanctioned)
        first_tx_id = entries[0].tx_id
        if any(e.tx_id is not None for e in entries):
            if first_tx_id is None or not all(e.tx_id == first_tx_id for e in entries):
                raise ValueError("All drafts in transaction must share the same tx_id")
            tx_id: uuid.UUID = first_tx_id
        else:
            tx_id = uuid.uuid4()

        # =========================================================================
        # STEP 1: OCC Retry Loop with Jittered Exponential Backoff
        # =========================================================================
        for attempt in range(self._max_occ_retries + 1):
            try:
                # =====================================================================
                # STEP 2: Single Pool Connection + Transaction
                # =====================================================================
                async with self._pool.acquire() as conn:
                    async with conn.transaction():
                        # -------------------------------------------------------------
                        # 2.a. Lock ledger_chain_tip singleton
                        # -------------------------------------------------------------
                        # WHY SELECT ... FOR UPDATE here:
                        # Serializes all write transactions globally across all nodes in Phase 1.
                        # Guarantees gapless sequence numbers and deterministic hash chaining.
                        tip_row = await conn.fetchrow(
                            """
                            SELECT last_seq, last_hash
                            FROM ledger_chain_tip
                            WHERE singleton = TRUE
                            FOR UPDATE;
                            """
                        )
                        if tip_row is None:
                            raise InternalError(
                                details={"table": "ledger_chain_tip"},
                                message="ledger_chain_tip singleton row is uninitialized.",
                            )

                        curr_seq: int = int(tip_row["last_seq"])
                        curr_hash: str = str(tip_row["last_hash"])

                        committed_entries: list[LedgerEntry] = []

                        # -------------------------------------------------------------
                        # 2.b. Process each entry in given order
                        # -------------------------------------------------------------
                        # WHY caller ordering is preserved:
                        # Callers may group debits or credits first, but ledger correctness
                        # and cryptographic verification depend on the exact execution sequence.
                        for e in entries:
                            # i. Consecutive sequence allocation under tip lock (no gaps on abort)
                            seq = curr_seq + 1

                            # ii. Timestamp discipline: capture once, format once, hash and store
                            created_at_dt = datetime.now(UTC)
                            created_at_str = format_timestamp(created_at_dt)

                            # iii. Read account balance and OCC version
                            acc_balance, read_version = await self._read_account(conn, e.account_id)

                            # Calculate signed delta: CREDIT increases balance, DEBIT decreases
                            delta = e.amount if e.direction == Direction.CREDIT else -e.amount
                            new_balance = acc_balance + delta

                            # Solvency invariant: accounts cannot drop below zero
                            if new_balance < 0:
                                raise InsufficientFunds(
                                    details={
                                        "account": str(e.account_id),
                                        "account_id": str(e.account_id),
                                        "currency": e.currency,
                                        "balance": str(acc_balance),
                                        "requested": str(e.amount),
                                    },
                                    message=(
                                        f"Insufficient funds for account {e.account_id}: "
                                        f"available {acc_balance}, requested {e.amount}"
                                    ),
                                )

                            # iv. OCC write: conditional update on account balance and version
                            # WHY conditional write inside tip lock:
                            # Defense-in-depth against out-of-band writers (manual SQL)
                            # bypassing the tip protocol. If another writer modified this account,
                            # 0 rows are returned and OCCConflict is raised, triggering retry.
                            update_res = await conn.fetchrow(
                                """
                                UPDATE ledger_accounts
                                SET balance = $1, version = version + 1
                                WHERE id = $2 AND version = $3
                                RETURNING version;
                                """,
                                new_balance,
                                e.account_id,
                                read_version,
                            )
                            if update_res is None:
                                raise OCCConflict(
                                    details={
                                        "account": str(e.account_id),
                                        "account_id": str(e.account_id),
                                        "expected_version": str(read_version),
                                    },
                                    message=(
                                        f"OCC conflict on account {e.account_id}: "
                                        f"expected version {read_version}"
                                    ),
                                )
                            new_version: int = int(update_res["version"])

                            # v. Compute SHA-256 cryptographic audit hash chained to prev_hash
                            fp = EntryFingerprint(
                                seq=seq,
                                tx_id=str(tx_id),
                                account_id=str(e.account_id),
                                direction=e.direction,
                                amount=e.amount,
                                currency=e.currency,
                                balance_after=new_balance,
                                version=new_version,
                                created_at=created_at_str,
                            )
                            entry_hash = compute_entry_hash(curr_hash, fp)

                            # vi. Persist entry row to partitioned ledger_entries table
                            await conn.execute(
                                """
                                INSERT INTO ledger_entries (
                                    seq, tx_id, account_id, direction, amount, currency,
                                    balance_after, version, prev_hash, entry_hash, created_at
                                )
                                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
                                """,
                                seq,
                                tx_id,
                                e.account_id,
                                e.direction.value,
                                e.amount,
                                e.currency,
                                new_balance,
                                new_version,
                                curr_hash,
                                entry_hash,
                                created_at_dt,
                            )

                            committed_entries.append(
                                LedgerEntry(
                                    seq=seq,
                                    tx_id=tx_id,
                                    account_id=e.account_id,
                                    direction=e.direction,
                                    amount=e.amount,
                                    currency=e.currency,
                                    balance_after=new_balance,
                                    version=new_version,
                                    prev_hash=curr_hash,
                                    entry_hash=entry_hash,
                                    created_at=created_at_str,
                                )
                            )

                            # vii. Advance local chain linkage state for next leg
                            curr_hash = entry_hash
                            curr_seq = seq

                        # -------------------------------------------------------------
                        # 2.c. Advance singleton tip state
                        # -------------------------------------------------------------
                        await conn.execute(
                            """
                            UPDATE ledger_chain_tip
                            SET last_seq = $1, last_hash = $2
                            WHERE singleton = TRUE;
                            """,
                            curr_seq,
                            curr_hash,
                        )

                        # -------------------------------------------------------------
                        # 2.d. Commit transaction
                        # -------------------------------------------------------------
                        # The database deferred constraint trigger (Task 14) validates
                        # double-entry balance across all touched currencies at commit.
                        # It must never fire given Step 0; if it does, it catches an app bug.
                        return LedgerTransaction(tx_id=tx_id, entries=tuple(committed_entries))

            except OCCConflict:
                # Bounded retry with jittered exponential backoff:
                # Base 25ms * 2^attempt + random 0-10ms, capped at 400ms.
                # Aborted connection is dropped; retry acquires a fresh connection from pool.
                if attempt < self._max_occ_retries:
                    base_delay = 0.025 * (2**attempt)
                    jitter = random.uniform(0.0, 0.010)  # noqa: S311
                    delay = min(base_delay + jitter, 0.400)
                    await self._sleep_fn(delay)
                    continue
                raise
            except Exception:
                # Non-concurrency errors (InsufficientFunds, LedgerNotFoundError,
                # UnbalancedTransaction) are deterministic failures. Retrying would be a
                # design defect. Propagate immediately.
                raise

        # Fallthrough safety (loop exhausted)
        raise OCCConflict(  # pragma: no cover
            details={"max_retries": str(self._max_occ_retries)},
            message="Exhausted maximum OCC retries.",
        )

    async def get_balance(self, account_id: UUID) -> Balance:
        """Retrieve current balance and OCC version for an account.

        Raises LedgerNotFoundError if the account does not exist.
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT balance, version, currency FROM ledger_accounts WHERE id = $1;",
                account_id,
            )
            if row is None:
                raise LedgerNotFoundError(
                    details={
                        "account": str(account_id),
                        "account_id": str(account_id),
                    },
                    message=f"Ledger account not found: {account_id}",
                )
            return Balance(
                account_id=account_id,
                currency=str(row["currency"]),
                balance=int(row["balance"]),
                version=int(row["version"]),
            )

    async def get_transaction(self, tx_id: UUID) -> LedgerTransaction | None:
        """Retrieve committed transaction entries by transaction ID.

        Returns None if transaction ID is not found.
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT seq, tx_id, account_id, direction, amount, currency,
                       balance_after, version, prev_hash, entry_hash, created_at
                FROM ledger_entries
                WHERE tx_id = $1
                ORDER BY seq ASC;
                """,
                tx_id,
            )
            if not rows:
                return None
            entries = tuple(_row_to_entry(row) for row in rows)
            return LedgerTransaction(tx_id=tx_id, entries=entries)

    async def get_history(
        self,
        account_id: UUID,
        *,
        limit: int = 50,
        before_seq: int | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """Query historical entries for an account using keyset pagination.

        Ordered newest-first (seq DESC). Validates limit and cursor via validate_history_params.
        """
        validate_history_params(limit, before_seq)

        async with self._pool.acquire() as conn:
            if before_seq is None:
                rows = await conn.fetch(
                    """
                    SELECT seq, tx_id, account_id, direction, amount, currency,
                           balance_after, version, prev_hash, entry_hash, created_at
                    FROM ledger_entries
                    WHERE account_id = $1
                    ORDER BY seq DESC
                    LIMIT $2;
                    """,
                    account_id,
                    limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT seq, tx_id, account_id, direction, amount, currency,
                           balance_after, version, prev_hash, entry_hash, created_at
                    FROM ledger_entries
                    WHERE account_id = $1 AND seq < $2
                    ORDER BY seq DESC
                    LIMIT $3;
                    """,
                    account_id,
                    before_seq,
                    limit,
                )
            return tuple(_row_to_entry(row) for row in rows)

    async def verify_chain(
        self,
        *,
        from_seq: int = 1,
        to_seq: int | None = None,
    ) -> ChainVerification:
        """Walk and cryptographically verify a range of the SHA-256 entry hash chain.

        Verifies:
        1. Sequence continuity (seq == prev_seq + 1).
        2. Genesis root invariant (seq == 1 iff prev_hash == 'GENESIS').
        3. Cryptographic prev_hash linkage.
        4. Byte-exact recomputation of entry_hash via EntryFingerprint and verify_link.
        5. Tip cross-check against mutable ledger_chain_tip singleton in full-scan mode.
        """
        validate_chain_range(from_seq, to_seq)

        async with self._pool.acquire() as conn:
            # Cursor streaming requires a transaction context in asyncpg
            async with conn.transaction(readonly=True):
                tip_row = await conn.fetchrow(
                    "SELECT last_seq, last_hash FROM ledger_chain_tip WHERE singleton = TRUE;"
                )
                if tip_row is None:
                    tip_last_seq = 0
                    tip_last_hash = GENESIS
                else:
                    tip_last_seq = int(tip_row["last_seq"])
                    tip_last_hash = str(tip_row["last_hash"])

                # Empty chain handling
                if tip_last_seq == 0:
                    if from_seq == 1 and to_seq is None:
                        return ChainVerification(ok=True, last_verified_seq=0)
                    return ChainVerification(
                        ok=False,
                        last_verified_seq=0,
                        broken_seq=from_seq,
                        reason=f"Empty ledger: sequence {from_seq} does not exist",
                    )

                # Anchor retrieval: when from_seq > 1, read prior entry to establish prev_hash
                if from_seq > 1:
                    anchor_seq = from_seq - 1
                    anchor_row = await conn.fetchrow(
                        "SELECT entry_hash FROM ledger_entries WHERE seq = $1;",
                        anchor_seq,
                    )
                    if anchor_row is None:
                        return ChainVerification(
                            ok=False,
                            last_verified_seq=max(0, from_seq - 2),
                            broken_seq=anchor_seq,
                            reason=f"Anchor entry at seq={anchor_seq} not found",
                        )
                    expected_prev_hash: str = str(anchor_row["entry_hash"])
                    last_verified_seq: int = anchor_seq
                else:
                    expected_prev_hash = GENESIS
                    last_verified_seq = 0

                expected_next_seq = from_seq

                # Streaming query construction
                query = """
                    SELECT seq, tx_id, account_id, direction, amount, currency,
                           balance_after, version, prev_hash, entry_hash, created_at
                    FROM ledger_entries
                    WHERE seq >= $1
                """
                params: list[Any] = [from_seq]
                if to_seq is not None:
                    query += " AND seq <= $2"
                    params.append(to_seq)
                query += " ORDER BY seq ASC;"

                # Stream cursor in chunks of 1000 to keep memory flat
                cur = await conn.cursor(query, *params)
                while True:
                    rows = await cur.fetch(1000)
                    if not rows:
                        break

                    for row in rows:
                        row_seq = int(row["seq"])
                        row_prev_hash = str(row["prev_hash"])
                        row_entry_hash = str(row["entry_hash"])

                        # 1. Sequence continuity verification
                        if row_seq != expected_next_seq:
                            return ChainVerification(
                                ok=False,
                                last_verified_seq=last_verified_seq,
                                broken_seq=expected_next_seq,
                                reason=(
                                    f"Sequence discontinuity: expected {expected_next_seq}, "
                                    f"got {row_seq}"
                                ),
                            )

                        # 2. Genesis rule: seq=1 iff prev_hash='GENESIS'
                        if row_seq == 1:
                            if row_prev_hash != GENESIS:
                                return ChainVerification(
                                    ok=False,
                                    last_verified_seq=last_verified_seq,
                                    broken_seq=1,
                                    reason="Genesis entry seq=1 must have prev_hash == 'GENESIS'",
                                )
                        else:
                            if row_prev_hash == GENESIS:
                                return ChainVerification(
                                    ok=False,
                                    last_verified_seq=last_verified_seq,
                                    broken_seq=row_seq,
                                    reason=(
                                        f"Entry at seq={row_seq} cannot have prev_hash == 'GENESIS'"
                                    ),
                                )

                        # 3. Cryptographic chain linkage verification
                        if row_prev_hash != expected_prev_hash:
                            return ChainVerification(
                                ok=False,
                                last_verified_seq=last_verified_seq,
                                broken_seq=row_seq,
                                reason=(
                                    f"Hash chain linkage broken at seq={row_seq}: "
                                    f"expected prev_hash {expected_prev_hash}, got {row_prev_hash}"
                                ),
                            )

                        # 4. Canonical cryptographic recomputation
                        dt: datetime = row["created_at"]
                        if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
                            return ChainVerification(
                                ok=False,
                                last_verified_seq=last_verified_seq,
                                broken_seq=row_seq,
                                reason=f"Non-UTC timestamp drift at seq={row_seq}: {dt!r}",
                            )
                        created_at_str = format_timestamp(dt)

                        try:
                            fp = EntryFingerprint(
                                seq=row_seq,
                                tx_id=str(row["tx_id"]),
                                account_id=str(row["account_id"]),
                                direction=Direction(row["direction"]),
                                amount=int(row["amount"]),
                                currency=str(row["currency"]),
                                balance_after=int(row["balance_after"]),
                                version=int(row["version"]),
                                created_at=created_at_str,
                            )
                        except ValueError as exc:
                            return ChainVerification(
                                ok=False,
                                last_verified_seq=last_verified_seq,
                                broken_seq=row_seq,
                                reason=f"Invalid fingerprint at seq={row_seq}: {exc}",
                            )

                        if not verify_link(row_prev_hash, fp, row_entry_hash):
                            return ChainVerification(
                                ok=False,
                                last_verified_seq=last_verified_seq,
                                broken_seq=row_seq,
                                reason=(
                                    f"Cryptographic hash recomputation mismatch at seq={row_seq}"
                                ),
                            )

                        last_verified_seq = row_seq
                        expected_prev_hash = row_entry_hash
                        expected_next_seq = row_seq + 1

                # Range completeness verification if explicit to_seq was bounded
                if to_seq is not None and last_verified_seq < to_seq:
                    return ChainVerification(
                        ok=False,
                        last_verified_seq=last_verified_seq,
                        broken_seq=last_verified_seq + 1,
                        reason=(
                            f"Chain ended prematurely at seq={last_verified_seq}, "
                            f"expected up to to_seq={to_seq}"
                        ),
                    )

                # 5. Full-scan tip cross-check
                # In full-scan mode, verify mutable tip matches terminal chain state
                if from_seq == 1 and to_seq is None:
                    if last_verified_seq != tip_last_seq or expected_prev_hash != tip_last_hash:
                        # WHY broken_seq=last_verified_seq+1:
                        # The chain from 1..last_verified_seq is cryptographically verified.
                        # The mutable tip pointing elsewhere represents corruption at the boundary.
                        return ChainVerification(
                            ok=False,
                            last_verified_seq=last_verified_seq,
                            broken_seq=last_verified_seq + 1,
                            reason=(
                                "tip_mismatch: ledger_chain_tip does not match "
                                "terminal chain hash or sequence"
                            ),
                        )

                return ChainVerification(ok=True, last_verified_seq=last_verified_seq)
