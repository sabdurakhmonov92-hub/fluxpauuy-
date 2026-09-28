"""FluxPay Ledger Read Model: Account Statement & Point-in-Time Balances.

This module provides read models that compose the frozen LedgerStore Protocol.
Zero raw SQL, zero database drivers, and zero protocol modifications are permitted.
Caching is explicitly owned by upstream services (e.g. wallet/cache.py).

ARCHITECTURAL PRINCIPLES:
1. Mathematical Anchoring:
   Read models in fintech must provide evidentiary proof: an opening balance,
   a slice of committed ledger entries, a closing balance, and cryptographic
   chain validation proof (first/last entry hashes + link continuity).
2. Domain-to-Fingerprint Bridge:
   Translates rich domain LedgerEntry records to audit EntryFingerprint shapes
   for SHA-256 verification without duplicating hashing formulas.
3. Bounded Statement Extraction:
   Statements are bounded audit artifacts (MAX_STATEMENT_ENTRIES = 10_000).
   Unbounded extraction is a DoS vector and a product mistake.
"""

from dataclasses import dataclass
from uuid import UUID

from fluxpay.ledger.hashchain import (
    GENESIS,
    EntryFingerprint,
    verify_link,
)
from fluxpay.ledger.store import (
    LedgerEntry,
    LedgerStore,
)
from fluxpay.shared.logging import get_logger

logger = get_logger(__name__)

__all__ = [
    "MAX_STATEMENT_ENTRIES",
    "AccountStatement",
    "account_statement",
    "balance_at",
    "to_fingerprint",
    "validate_statement_range",
]

# Maximum entries returned in a single statement extraction.
# WHY: Statements are bounded artifacts; unbounded extraction is a DoS vector
# and a product mistake — paginate instead.
# (Phase 2 note: streaming statement design will support chunked downloads
# via async iterator for large historical archives).
MAX_STATEMENT_ENTRIES: int = 10_000


# -----------------------------------------------------------------------------
# 1. DOMAIN -> FINGERPRINT BRIDGE
# -----------------------------------------------------------------------------


def to_fingerprint(entry: LedgerEntry) -> EntryFingerprint:
    """Bridge a domain LedgerEntry to an audit EntryFingerprint for hash verification.

    Exported and reused by Task 18 CLI and Task 40 audit worker.

    WHY here and not hashchain:
    hashchain knows fingerprint shapes, not domain types; queries is the
    domain<->fingerprint translator. Single definition — duplicating it forks verification.
    """
    return EntryFingerprint(
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


# -----------------------------------------------------------------------------
# 2. STATEMENT TYPES
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AccountStatement:
    """Cryptographically anchored point-in-time account statement.

    WHY first/last hashes:
    A statement is EVIDENCE — the recipient can anchor it against the global
    chain (hourly validator, audits) without trusting our rendering.

    WHY opening_balance can be None:
    None = pre-genesis window (from_seq == 1): not computable from entries alone
    because system accounts carry an out-of-ledger genesis balance (Task 16 note).
    """

    account_id: UUID
    currency: str
    from_seq: int
    to_seq: int  # resolved inclusive window
    opening_balance: int | None
    entries: tuple[LedgerEntry, ...]  # seq-ascending
    closing_balance: int | None
    first_entry_hash: str | None
    last_entry_hash: str | None
    chain_verified: bool  # range linkage recomputed


# -----------------------------------------------------------------------------
# 3. PURE VALIDATOR
# -----------------------------------------------------------------------------


def validate_statement_range(from_seq: int, to_seq: int | None = None) -> None:
    """Validate sequence window boundaries for an account statement.

    from_seq must be >= 1.
    to_seq, if provided, must be >= from_seq.
    Window size (to_seq - from_seq + 1) must not exceed MAX_STATEMENT_ENTRIES.

    WHY bounds check:
    Statements are bounded artifacts; unbounded extraction is a DoS and a
    product mistake — paginate instead.
    """
    if from_seq < 1:
        raise ValueError("from_seq: must be >= 1")
    if to_seq is not None:
        if to_seq < 1:
            raise ValueError("to_seq: must be >= 1")
        if to_seq < from_seq:
            raise ValueError("to_seq: must be >= from_seq")
        window_size = to_seq - from_seq + 1
        if window_size > MAX_STATEMENT_ENTRIES:
            raise ValueError(
                f"Requested window ({window_size}) exceeds maximum statement entries "
                f"({MAX_STATEMENT_ENTRIES}). Paginate instead."
            )


# -----------------------------------------------------------------------------
# 4. READ FUNCTIONS
# -----------------------------------------------------------------------------


async def balance_at(store: LedgerStore, account_id: UUID, *, seq: int) -> int | None:
    """Retrieve historical balance of an account at or immediately prior to a sequence.

    Uses get_history(account_id, limit=1, before_seq=seq + 1) to find the newest entry
    with entry.seq <= seq, and returns its balance_after. If no such entry exists (e.g.
    before the account's first transaction or seq < 1), returns None.
    """
    if seq < 1:
        return None
    history = await store.get_history(account_id, limit=1, before_seq=seq + 1)
    if not history:
        return None
    return history[0].balance_after


async def account_statement(
    store: LedgerStore,
    account_id: UUID,
    *,
    from_seq: int = 1,
    to_seq: int | None = None,
) -> AccountStatement:
    """Generate a mathematically anchored, cryptographically verified account statement.

    Composes the frozen LedgerStore protocol ONLY. Zero raw SQL.

    Paging & Collection Strategy:
    1. Validate range bounds upfront before any store calls.
    2. Page get_history DESC with before_seq=(to_seq + 1 if to_seq else None), limit=100,
       collecting until entry.seq < from_seq.
    3. If collected entries exceed MAX_STATEMENT_ENTRIES, raise ValueError.
    4. Reverse collected entries to obtain ascending sequence ordering.
    5. Calculate opening/closing balances and verify cryptographic range linkage.
    """
    # 1. Door validation runs BEFORE any store operations or paging
    validate_statement_range(from_seq, to_seq)

    # 2. Keyset pagination via get_history (DESC)
    collected_entries: list[LedgerEntry] = []
    current_before_seq = to_seq + 1 if to_seq is not None else None
    page_limit = 100

    while True:
        page = await store.get_history(
            account_id,
            limit=page_limit,
            before_seq=current_before_seq,
        )
        if not page:
            break

        stop = False
        for entry in page:
            if entry.seq < from_seq:
                stop = True
                break
            collected_entries.append(entry)
            if len(collected_entries) > MAX_STATEMENT_ENTRIES:
                raise ValueError(
                    f"Statement exceeded maximum limit of {MAX_STATEMENT_ENTRIES} entries"
                )

        if stop:
            break

        current_before_seq = page[-1].seq

    # 3. Reverse to seq-ascending window
    entries = tuple(reversed(collected_entries))

    # 4. Handle empty statement window
    if not entries:
        # Resolve currency from account state snapshot
        bal = await store.get_balance(account_id)
        resolved_to_seq = to_seq if to_seq is not None else from_seq
        return AccountStatement(
            account_id=account_id,
            currency=bal.currency,
            from_seq=from_seq,
            to_seq=resolved_to_seq,
            opening_balance=None,
            entries=(),
            closing_balance=None,
            first_entry_hash=None,
            last_entry_hash=None,
            chain_verified=True,  # empty range is trivially consistent
        )

    # 5. Non-empty statement window
    resolved_to_seq = to_seq if to_seq is not None else entries[-1].seq
    currency = entries[0].currency
    first_entry_hash = entries[0].entry_hash
    last_entry_hash = entries[-1].entry_hash

    # Opening balance: None if from_seq == 1 (pre-genesis window);
    # else balance_after of latest entry prior to from_seq
    if from_seq == 1:
        opening_balance = None
    else:
        opening_balance = await balance_at(store, account_id, seq=from_seq - 1)

    closing_balance = entries[-1].balance_after

    # 6. Cryptographic chain verification (range proof)
    # Range-proof vs full-chain forensics distinction:
    # Full-chain forensics (verify_chain / Task 18 CLI) walks the global contiguous ledger
    # from genesis to tip to detect server-side tampering. An account statement is a localized
    # range proof: it verifies that all retrieved entries are individually valid fingerprints
    # and contiguous within the account's window, anchoring the statement's first/last hashes.
    chain_verified = True

    # Genesis rule when from_seq == 1: first entry must link to GENESIS
    if from_seq == 1 and entries[0].prev_hash != GENESIS:
        chain_verified = False

    # Verify cryptographic fingerprint of every entry
    if chain_verified:
        for entry in entries:
            fp = to_fingerprint(entry)
            if not verify_link(entry.prev_hash, fp, entry.entry_hash):
                chain_verified = False
                break

    # Verify pairwise hash chain linkage across ascending entries
    if chain_verified:
        for i in range(len(entries) - 1):
            if entries[i + 1].prev_hash != entries[i].entry_hash:
                chain_verified = False
                break

    # Logging: account_id + window on chain_verified False ONLY (alarm path)
    if not chain_verified:
        logger.error(
            "statement_chain_verification_failed",
            account_id=str(account_id),
            from_seq=from_seq,
            to_seq=resolved_to_seq,
            window=f"{from_seq}..{resolved_to_seq}",
        )

    return AccountStatement(
        account_id=account_id,
        currency=currency,
        from_seq=from_seq,
        to_seq=resolved_to_seq,
        opening_balance=opening_balance,
        entries=entries,
        closing_balance=closing_balance,
        first_entry_hash=first_entry_hash,
        last_entry_hash=last_entry_hash,
        chain_verified=chain_verified,
    )
