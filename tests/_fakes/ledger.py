"""In-Memory Fake Implementation of FluxPay LedgerStore Protocol.

WHY this file lives in tests/, not src/:
It is a test oracle designed for fast, deterministic, non-durable unit and service testing.
Shipping fakes in src/ invites accidental production dependency on an in-memory
store that lacks durability, ACID cross-service guarantees, and crash safety.

HONEST FAKE DISCIPLINE:
- Uses the real hashchain formulas (compute_entry_hash, GENESIS, canonical_bytes).
- Produces byte-equal SHA-256 fingerprints to PostgreSQL production storage.
- Reuses the frozen validation routines (validate_history_params, validate_chain_range)
  directly from store.py. A permissive fake is a false-green factory.
- Enforces double-entry balance, per-currency zero-sum balancing, and solvency.
- Provides test-only tampering hooks for forensic and resilience test cases.
"""

import asyncio
import uuid
from collections import defaultdict
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

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
    LedgerNotFoundError,
    UnbalancedTransaction,
)

__all__ = ["FakeLedgerStore"]


class FakeLedgerStore:
    """In-memory, fully protocol-compliant fake implementation of LedgerStore."""

    def __init__(
        self,
        *,
        initial_seq: int = 0,
        initial_hash: str = GENESIS,
        time_fn: Callable[[], datetime] | None = None,
        uuid_fn: Callable[[], UUID] | None = None,
    ) -> None:
        self._lock = asyncio.Lock()
        # Internal state: {account_id: [balance: int, version: int, currency: str]}
        self._accounts: dict[UUID, list[Any]] = {}
        # Entries list: seq-allocated 1..n consecutively
        self._entries: list[LedgerEntry] = []
        # Transaction index: {tx_id: tuple[LedgerEntry, ...]}
        self._tx_index: dict[UUID, tuple[LedgerEntry, ...]] = {}
        # Chain tip pointer
        self._last_seq: int = initial_seq
        self._last_hash: str = initial_hash
        self._time_fn = time_fn if time_fn is not None else lambda: datetime.now(UTC)
        self._uuid_fn = uuid_fn if uuid_fn is not None else uuid.uuid4

    def init_account(
        self,
        account_id: UUID,
        *,
        currency: str = "USDC",
        initial_balance: int = 0,
        version: int = 1,
    ) -> None:
        """Helper to register and seed an account in the fake store."""
        self._accounts[account_id] = [initial_balance, version, currency]

    async def post_transaction(self, entries: Sequence[EntryDraft]) -> LedgerTransaction:
        """Atomically commit a balanced double-entry transaction in-memory."""
        # 0. Fast door validation: empty entries rejected immediately
        if not entries:
            raise UnbalancedTransaction(
                details={"reason": "entries sequence cannot be empty"},
                message="Transaction must contain at least two entries.",
            )

        # Per-currency double-entry zero-sum check: sum(DEBIT) == sum(CREDIT)
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

        async with self._lock:
            # 1. Verify existence of all touched accounts
            for e in entries:
                if e.account_id not in self._accounts:
                    raise LedgerNotFoundError(
                        details={
                            "account": str(e.account_id),
                            "account_id": str(e.account_id),
                        },
                        message=f"Ledger account not found: {e.account_id}",
                    )

            # 2. Solvency simulation before modifying any account state
            temp_balances: dict[UUID, int] = {
                acc_id: self._accounts[acc_id][0] for acc_id in {e.account_id for e in entries}
            }
            for e in entries:
                delta = e.amount if e.direction == Direction.CREDIT else -e.amount
                if temp_balances[e.account_id] + delta < 0:
                    raise InsufficientFunds(
                        details={
                            "account": str(e.account_id),
                            "account_id": str(e.account_id),
                            "currency": e.currency,
                            "balance": str(temp_balances[e.account_id]),
                            "requested": str(e.amount),
                        },
                        message=(
                            f"Insufficient funds for account {e.account_id}: "
                            f"available {temp_balances[e.account_id]}, requested {e.amount}"
                        ),
                    )
                temp_balances[e.account_id] += delta

            # 3. Apply atomic transaction legs
            # --- Task 31 evolution (sanctioned)
            first_tx_id = entries[0].tx_id
            if any(e.tx_id is not None for e in entries):
                if first_tx_id is None or not all(e.tx_id == first_tx_id for e in entries):
                    raise ValueError("All drafts in transaction must share the same tx_id")
                tx_id: UUID = first_tx_id
            else:
                tx_id = self._uuid_fn()
            committed_entries: list[LedgerEntry] = []

            for e in entries:
                seq = self._last_seq + 1
                created_at_dt = self._time_fn()
                if created_at_dt.tzinfo is None or created_at_dt.utcoffset() != timedelta(0):
                    raise ValueError(f"Timestamp must be tz-aware UTC, got {created_at_dt!r}")
                created_at_str = format_timestamp(created_at_dt)

                acc_state = self._accounts[e.account_id]
                cur_balance: int = acc_state[0]
                cur_version: int = acc_state[1]

                delta = e.amount if e.direction == Direction.CREDIT else -e.amount
                new_balance = cur_balance + delta
                new_version = cur_version + 1

                acc_state[0] = new_balance
                acc_state[1] = new_version

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
                entry_hash = compute_entry_hash(self._last_hash, fp)

                entry = LedgerEntry(
                    seq=seq,
                    tx_id=tx_id,
                    account_id=e.account_id,
                    direction=e.direction,
                    amount=e.amount,
                    currency=e.currency,
                    balance_after=new_balance,
                    version=new_version,
                    prev_hash=self._last_hash,
                    entry_hash=entry_hash,
                    created_at=created_at_str,
                )

                self._entries.append(entry)
                committed_entries.append(entry)

                self._last_seq = seq
                self._last_hash = entry_hash

            tx = LedgerTransaction(tx_id=tx_id, entries=tuple(committed_entries))
            self._tx_index[tx_id] = tx.entries
            return tx

    async def get_balance(self, account_id: UUID) -> Balance:
        """Retrieve current balance snapshot for an account."""
        async with self._lock:
            if account_id not in self._accounts:
                raise LedgerNotFoundError(
                    details={
                        "account": str(account_id),
                        "account_id": str(account_id),
                    },
                    message=f"Ledger account not found: {account_id}",
                )
            acc = self._accounts[account_id]
            return Balance(
                account_id=account_id,
                balance=int(acc[0]),
                version=int(acc[1]),
                currency=str(acc[2]),
            )

    async def get_transaction(self, tx_id: UUID) -> LedgerTransaction | None:
        """Retrieve transaction entries by transaction ID, or None if unknown."""
        async with self._lock:
            if tx_id not in self._tx_index:
                return None
            return LedgerTransaction(tx_id=tx_id, entries=self._tx_index[tx_id])

    async def get_history(
        self,
        account_id: UUID,
        *,
        limit: int = 50,
        before_seq: int | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """Query historical entries for an account using keyset pagination (seq DESC)."""
        validate_history_params(limit, before_seq)

        async with self._lock:
            matching = [
                e
                for e in self._entries
                if e.account_id == account_id and (before_seq is None or e.seq < before_seq)
            ]
            matching.sort(key=lambda e: e.seq, reverse=True)
            return tuple(matching[:limit])

    async def verify_chain(
        self,
        *,
        from_seq: int = 1,
        to_seq: int | None = None,
    ) -> ChainVerification:
        """Walk and cryptographically verify a range of the entry hash chain."""
        validate_chain_range(from_seq, to_seq)

        async with self._lock:
            if not self._entries:
                if from_seq == 1 and to_seq is None:
                    return ChainVerification(ok=True, last_verified_seq=0)
                return ChainVerification(
                    ok=False,
                    last_verified_seq=0,
                    broken_seq=from_seq,
                    reason=f"Empty ledger: sequence {from_seq} does not exist",
                )

            # Establish anchor when from_seq > 1
            if from_seq > 1:
                anchor_seq = from_seq - 1
                anchor_entry = next((e for e in self._entries if e.seq == anchor_seq), None)
                if anchor_entry is None:
                    return ChainVerification(
                        ok=False,
                        last_verified_seq=max(0, from_seq - 2),
                        broken_seq=anchor_seq,
                        reason=f"Anchor entry at seq={anchor_seq} not found",
                    )
                expected_prev_hash = anchor_entry.entry_hash
                last_verified_seq = anchor_seq
            else:
                expected_prev_hash = GENESIS
                last_verified_seq = 0

            expected_next_seq = from_seq

            scan_entries = [
                e
                for e in self._entries
                if e.seq >= from_seq and (to_seq is None or e.seq <= to_seq)
            ]
            scan_entries.sort(key=lambda e: e.seq)

            for entry in scan_entries:
                row_seq = entry.seq
                row_prev_hash = entry.prev_hash
                row_entry_hash = entry.entry_hash

                # 1. Continuity check
                if row_seq != expected_next_seq:
                    return ChainVerification(
                        ok=False,
                        last_verified_seq=last_verified_seq,
                        broken_seq=expected_next_seq,
                        reason=(
                            f"Sequence discontinuity: expected {expected_next_seq}, got {row_seq}"
                        ),
                    )

                # 2. Genesis rule
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
                            reason=f"Entry at seq={row_seq} cannot have prev_hash == 'GENESIS'",
                        )

                # 3. Cryptographic chain linkage
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

                # 4. Cryptographic recomputation
                try:
                    fp = EntryFingerprint(
                        seq=entry.seq,
                        tx_id=str(entry.tx_id),
                        account_id=str(entry.account_id),
                        direction=entry.direction,
                        amount=entry.amount,
                        currency=entry.currency,
                        balance_after=entry.balance_after,
                        version=entry.version,
                        created_at=entry.created_at,
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
                        reason=f"Cryptographic hash recomputation mismatch at seq={row_seq}",
                    )

                last_verified_seq = row_seq
                expected_prev_hash = row_entry_hash
                expected_next_seq = row_seq + 1

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
            if from_seq == 1 and to_seq is None:
                if last_verified_seq != self._last_seq or expected_prev_hash != self._last_hash:
                    return ChainVerification(
                        ok=False,
                        last_verified_seq=last_verified_seq,
                        broken_seq=last_verified_seq + 1,
                        reason=(
                            "tip_mismatch: fake ledger tip does not match "
                            "terminal chain hash or sequence"
                        ),
                    )

            return ChainVerification(ok=True, last_verified_seq=last_verified_seq)

    # =========================================================================
    # TEST-ONLY HOOKS (DO NOT USE IN PRODUCTION)
    # =========================================================================

    def corrupt_entry(self, seq: int) -> None:
        """Test hook: corrupt entry_hash by recomputing over amount + 1.

        Realistic tamper shape: simulates payload tampering where the hash
        was recomputed over an altered amount without properly forging the chain.
        """
        for idx, e in enumerate(self._entries):
            if e.seq == seq:
                tampered_fp = EntryFingerprint(
                    seq=e.seq,
                    tx_id=str(e.tx_id),
                    account_id=str(e.account_id),
                    direction=e.direction,
                    amount=e.amount + 1,
                    currency=e.currency,
                    balance_after=e.balance_after,
                    version=e.version,
                    created_at=e.created_at,
                )
                tampered_hash = compute_entry_hash(e.prev_hash, tampered_fp)
                corrupted = LedgerEntry(
                    seq=e.seq,
                    tx_id=e.tx_id,
                    account_id=e.account_id,
                    direction=e.direction,
                    amount=e.amount,
                    currency=e.currency,
                    balance_after=e.balance_after,
                    version=e.version,
                    prev_hash=e.prev_hash,
                    entry_hash=tampered_hash,
                    created_at=e.created_at,
                )
                self._entries[idx] = corrupted
                if e.tx_id in self._tx_index:
                    self._tx_index[e.tx_id] = tuple(
                        corrupted if item.seq == seq else item for item in self._tx_index[e.tx_id]
                    )
                return
        raise ValueError(f"Entry with seq={seq} not found")

    def drop_entry(self, seq: int) -> None:
        """Test hook: drop an entry to simulate a sequence continuity gap."""
        target = None
        for e in self._entries:
            if e.seq == seq:
                target = e
                break
        if target is None:
            raise ValueError(f"Entry with seq={seq} not found")
        self._entries.remove(target)
        if target.tx_id in self._tx_index:
            self._tx_index[target.tx_id] = tuple(
                e for e in self._tx_index[target.tx_id] if e.seq != seq
            )
