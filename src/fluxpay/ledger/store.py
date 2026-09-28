"""=============================================================================
FluxPay LedgerStore: The Frozen Domain Contract (Blueprint §5 & §7)
=============================================================================
This module defines the abstract interface (Protocol) and domain data models
for FluxPay's double-entry, cryptographically hash-chained financial ledger.

ARCHITECTURAL ROLE & BLUEPRINT INVARIANT 🔒:
"LedgerStore abstrakt protokoli — Postgres implementatsiya; TigerBeetle adapter
keyin qo'shiladi; biznes logika O'ZGARMAYDI."

This Protocol serves as the inviolable seam between upper business layers
(payment execution, agent limits, webhooks, idempotency) and ledger storage.
Phase 1 implements LedgerStore via PostgreSQL 17 (Task 16).
Phase 2 implements LedgerStore via TigerBeetle.
Business logic MUST NOT know which underlying storage engine executes the entries.

TRANSACTION & BOUNDARY RULE (Task 8):
LedgerStore manages its OWN internal database transaction. The hash-chain tip
lock (SELECT ... FOR UPDATE on ledger_chain_tip) must span entry sequence allocation,
hash calculation, and balance cache updates.
LedgerStore does NOT run inside UnitOfWork, nor should it ever be wrapped in an
external UnitOfWork context.

ZERO I/O IN THIS MODULE:
This is a pure domain interface and typing contract module.
No database drivers (asyncpg), network sockets, or external configuration
may be imported here.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from uuid import UUID

from fluxpay.ledger.hashchain import Direction

__all__ = [
    "Balance",
    "ChainVerification",
    "Direction",
    "EntryDraft",
    "LedgerEntry",
    "LedgerStore",
    "LedgerTransaction",
    "validate_chain_range",
    "validate_history_params",
]

_CURRENCY_REGEX: re.Pattern[str] = re.compile(r"^[A-Z0-9]{2,10}$")


# -----------------------------------------------------------------------------
# 1. DRAFT TYPE (Caller's input - validated at construction)
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EntryDraft:
    """Caller-provided draft specification for an atomic ledger transaction leg.

    WHY guards live here:
    The Protocol is the domain boundary. Malformed parameters, invalid currency
    tickers, negative amounts, or incorrect types must be rejected at the door
    (via ValueError) before entering any database transaction or storage pipeline.
    """

    account_id: UUID
    direction: Direction
    amount: int
    currency: str
    tx_id: UUID | None = None  # --- Task 31 evolution (sanctioned)

    def __post_init__(self) -> None:
        raw_acc_id: object = self.account_id
        if not isinstance(raw_acc_id, UUID):
            raise ValueError("account_id: must be a uuid.UUID instance")
        raw_direction: object = self.direction
        if not isinstance(raw_direction, Direction):
            dir_type = type(raw_direction).__name__
            raise ValueError(f"direction: must be an instance of Direction enum, got {dir_type}")
        # In Python, bool is a subclass of int (isinstance(True, int) is True).
        # We explicitly disallow boolean values for monetary amounts.
        if type(self.amount) is bool or not isinstance(self.amount, int) or self.amount <= 0:
            raise ValueError("amount: must be a positive integer > 0 in minor units")
        if not isinstance(self.currency, str) or not _CURRENCY_REGEX.fullmatch(self.currency):
            raise ValueError("currency: must match regex ^[A-Z0-9]{2,10}$ (e.g. 'USDC', 'USD')")
        if self.tx_id is not None and not isinstance(
            self.tx_id, UUID
        ):  # --- Task 31 evolution (sanctioned)
            raise ValueError("tx_id: must be a uuid.UUID instance or None")


# -----------------------------------------------------------------------------
# 2. RESULT TYPES (Immutable audit-ready domain records)
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """Committed, hash-chained ledger entry.

    DISTINCTION FROM EntryFingerprint (Task 12):
    - EntryFingerprint: Serialization shape used strictly for computing SHA-256
      hashes where UUIDs and integers are normalized to raw strings/bytes.
    - LedgerEntry: Rich domain result object with typed UUIDs, exposed to callers
      and auditors.

    WHY created_at is str not datetime:
    The canonical string ("%Y-%m-%dT%H:%M:%S.%fZ") IS the exact representation
    that entered the cryptographic SHA-256 hash. Converting to datetime and back
    risks microsecond precision loss, timezone offset drift, or library reformatting
    differences. The raw canonical string guarantees deterministic verification.
    """

    seq: int
    tx_id: UUID
    account_id: UUID
    direction: Direction
    amount: int
    currency: str
    balance_after: int
    version: int
    prev_hash: str
    entry_hash: str
    created_at: str


@dataclass(frozen=True, slots=True)
class LedgerTransaction:
    """Immutable snapshot of an atomic multi-entry transaction.

    WHY entries is tuple not list:
    Results escape the store to external callers, event dispatchers, and logs.
    A tuple guarantees that the transaction's entries cannot be modified or reordered
    after commit.
    """

    tx_id: UUID
    entries: tuple[LedgerEntry, ...]


@dataclass(frozen=True, slots=True)
class Balance:
    """Point-in-time balance and OCC version snapshot for an account."""

    account_id: UUID
    currency: str
    balance: int
    version: int


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """Result of walking and cryptographically verifying the ledger hash chain.

    WHY a named result object rather than a (bool, int) tuple:
    When ok=False, the background audit worker (Task 40) needs to emit SEV1
    telemetry containing the broken sequence number and forensic reason.
    Positional tuples make code brittle and fail to provide structured error diagnostics.
    """

    ok: bool
    last_verified_seq: int
    broken_seq: int | None = None
    reason: str | None = None


# -----------------------------------------------------------------------------
# 3. PURE VALIDATION FUNCTIONS (Contracts as executable code)
# -----------------------------------------------------------------------------


def validate_history_params(limit: int, before_seq: int | None = None) -> None:
    """Validate query parameters for get_history.

    WHY explicit bounds check:
    Unbounded queries risk memory exhaustion. Silent clamping (e.g. limit = min(limit, 100))
    hides caller pagination bugs. Raising ValueError forces callers to adhere
    to API contracts.
    """
    if limit < 1 or limit > 100:
        raise ValueError("limit: must be between 1 and 100")
    if before_seq is not None and before_seq < 1:
        raise ValueError("before_seq: must be >= 1")


def validate_chain_range(from_seq: int, to_seq: int | None = None) -> None:
    """Validate sequence range for verify_chain.

    from_seq must be >= 1 (genesis is seq=1).
    to_seq, if provided, must be >= from_seq.
    """
    if from_seq < 1:
        raise ValueError("from_seq: must be >= 1")
    if to_seq is not None:
        if to_seq < 1:
            raise ValueError("to_seq: must be >= 1")
        if to_seq < from_seq:
            raise ValueError("to_seq: must be >= from_seq")


# -----------------------------------------------------------------------------
# 4. THE PROTOCOL
# -----------------------------------------------------------------------------


@runtime_checkable
class LedgerStore(Protocol):
    """Abstract storage interface for the FluxPay financial ledger.

    Implementations:
    - Task 16: PostgresLedgerStore (PostgreSQL 17, asyncpg, partitioned tables)
    - Phase 2: TigerBeetleLedgerStore (TigerBeetle native client)

    All methods are coroutines. Implementations manage their own transactions.
    """

    async def post_transaction(self, entries: Sequence[EntryDraft]) -> LedgerTransaction:
        """Atomically commit a balanced double-entry transaction.

        CONTRACT & INVARIANTS:
        - Atomicity: All draft entries commit together, or none do.
        - Self-Owned Transaction: The store acquires its own transaction and tip lock.
          NEVER wrap this call inside an ambient UnitOfWork transaction (Task 8 boundary).
        - Zero-Sum Balancing: For every currency present in entries,
          sum(DEBIT) == sum(CREDIT). Mismatches raise UnbalancedTransaction.
          Empty entries sequence raises UnbalancedTransaction.
        - Solvency: Debit legs must not cause the account balance to drop below zero.
          Overdraft attempts raise InsufficientFunds.
        - OCC Versioning: Each affected account row in ledger_accounts is updated
          with version = version + 1 and balance = balance_after. If an OCC version
          conflict occurs, the store retries up to max_occ_retries (default 5).
          Exhaustion raises OCCConflict.
        - Hash Chaining: Under the singleton ledger_chain_tip row lock, the store allocates
          strictly contiguous seq numbers (seq = last_seq + 1), computes entry_hash
          chained to prev_hash via canonical_bytes, formats canonical created_at,
          and updates ledger_chain_tip.

        Args:
            entries: Ordered sequence of EntryDraft legs making up the transaction.

        Returns:
            LedgerTransaction containing the committed, immutable LedgerEntry records.

        Raises:
            UnbalancedTransaction: If entries is empty or debits != credits per currency.
            InsufficientFunds: If any account balance would drop below zero.
            OCCConflict: If concurrent account modifications exceed retry limit.
            LedgerNotFoundError: If any referenced account does not exist.
        """
        ...

    async def get_balance(self, account_id: UUID) -> Balance:
        """Retrieve the current balance and OCC version for an account.

        CONTRACT & INVARIANTS:
        - Unknown account raises LedgerNotFoundError.
        - WHY ASYMMETRY VS get_transaction:
          Querying the balance of a non-existent account indicates a programmer or routing
          error (e.g. attempting to operate on an account that was never initialized).
          In contrast, querying an unknown transaction ID is a legitimate client lookup.

        Args:
            account_id: Account identifier to inspect.

        Returns:
            Balance snapshot containing current balance and OCC version.

        Raises:
            LedgerNotFoundError: If the account does not exist.
        """
        ...

    async def get_transaction(self, tx_id: UUID) -> LedgerTransaction | None:
        """Retrieve a committed transaction and all its entries by transaction ID.

        CONTRACT & INVARIANTS:
        - Returns None if tx_id does not exist (NOT an error).
        - Returned entries are ordered by seq ascending.

        Args:
            tx_id: Transaction identifier to query.

        Returns:
            LedgerTransaction if found, otherwise None.
        """
        ...

    async def get_history(
        self,
        account_id: UUID,
        *,
        limit: int = 50,
        before_seq: int | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """Query historical entries for an account using keyset pagination.

        CONTRACT & INVARIANTS:
        - Ordering: Newest first (seq DESC).
        - Keyset Cursor: When before_seq is provided, returns entries with seq < before_seq.
        - Bound: 1 <= limit <= 100. Violations raise ValueError immediately.
        - Missing/Empty: Returns an empty tuple () if no matching entries exist.

        Args:
            account_id: Target account identifier.
            limit: Maximum number of entries to return (1..100, default 50).
            before_seq: Keyset pagination cursor (strictly older than this sequence).

        Returns:
            Tuple of LedgerEntry records ordered newest-first (seq DESC).

        Raises:
            ValueError: If limit is < 1 or > 100, or before_seq < 1.
        """
        ...

    async def verify_chain(
        self,
        *,
        from_seq: int = 1,
        to_seq: int | None = None,
    ) -> ChainVerification:
        """Walk and cryptographically verify a range of the SHA-256 entry hash chain.

        CONTRACT & INVARIANTS:
        - Sequence Continuity: Checks that every seq is contiguous (seq == prev_seq + 1),
          closing the cross-partition gap auditably.
        - Genesis Invariant: seq == 1 iff prev_hash == 'GENESIS'.
        - Cryptographic Integrity: For every entry, recomputes the SHA-256 hash using
          canonical_bytes and verifies that entry_hash matches. Asserts that entry N's
          prev_hash equals entry N-1's entry_hash.
        - Anchor Requirement: If from_seq > 1, the store reads entry (from_seq - 1)
          to anchor the prev_hash of from_seq.
        - Fail-Fast: Verification stops at the first broken link or sequence gap,
          returning ChainVerification(ok=False, broken_seq=..., reason=...).
        - Range: Validates from_seq >= 1 and to_seq >= from_seq (if to_seq is provided).

        Args:
            from_seq: Starting sequence number (default 1, genesis).
            to_seq: Ending sequence number inclusive (default None: verify to current tip).

        Returns:
            ChainVerification summary indicating status and error details if broken.

        Raises:
            ValueError: If from_seq < 1 or to_seq < from_seq.
        """
        ...
