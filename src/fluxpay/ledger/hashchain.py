"""=============================================================================
FREEZE WARNING: PROTOCOL SPECIFICATION - DO NOT MODIFY
=============================================================================
This module defines the canonical audit fingerprint and hash-chaining protocol
for the FluxPay ledger core.

THE ENCODING IS THE CONTRACT.
Changing ANY input field, field order, separator, integer formatting, or
timestamp representation invalidates the ENTIRE ledger history — every stored
entry_hash becomes permanently unverifiable. Therefore, this file's encoding
is FROZEN from its first commit.

Future encoding evolution requires a chain-epoch design (chain_id field,
Phase 2) — NOT an in-place modification of this specification.

AUDIT RIGHT & NON-PROPRIETARY DESIGN:
The canonical encoding is published, deterministic, and non-proprietary.
External auditors, regulators, and forensic tools must be able to reconstruct
the exact hashed bytes directly from a database row without access to
proprietary code. Canonical reconstruction is an inviolable audit right.

CANONICAL ENCODING SPECIFICATION (Byte-exact):
    canonical = (
        prev_hash      || 0x1F ||
        seq            || 0x1F ||
        tx_id          || 0x1F ||
        account_id     || 0x1F ||
        direction      || 0x1F ||
        amount         || 0x1F ||
        currency       || 0x1F ||
        balance_after  || 0x1F ||
        version        || 0x1F ||
        created_at
    )
    entry_hash = lowercase_hex( SHA-256( canonical ) )

SEPARATOR RATIONALE:
    0x1F is the ASCII Unit Separator. It is structurally reserved to guarantee
    unambiguous field boundaries and eliminate concatenation collisions
    (e.g., amount=1, balance_after=23 vs amount=12, balance_after=3).
    All fields are validated to never contain 0x1F.

GENESIS SEMANTICS:
    prev_hash for seq=1 is the string literal "GENESIS". This provides a
    human-auditable root anchor and matches the database schema default
    (ledger_chain_tip.last_hash DEFAULT 'GENESIS'). A bidirectional guard
    enforces: prev_hash == "GENESIS" IFF seq == 1.
============================================================================="""

import hashlib
import hmac
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

__all__ = [
    "GENESIS",
    "SEPARATOR",
    "Direction",
    "EntryFingerprint",
    "canonical_bytes",
    "compute_entry_hash",
    "format_timestamp",
    "verify_link",
]

# Structural ASCII unit separator (0x1F).
# WHY: Eliminates concatenation collisions without payload escaping overhead.
SEPARATOR: bytes = b"\x1f"

# Canonical genesis root anchor string.
# WHY: Human-auditable literal matching ledger_chain_tip.last_hash database default.
GENESIS: str = "GENESIS"

_HEX_64_REGEX: re.Pattern[str] = re.compile(r"^[0-9a-f]{64}$")
_CURRENCY_REGEX: re.Pattern[str] = re.compile(r"^[A-Z0-9]{2,10}$")


class Direction(StrEnum):
    """Ledger entry transaction direction.

    LIVES HERE (Single source of truth):
    Direction is an immutable part of the frozen fingerprint specification.
    Downstream modules (e.g., store.py) MUST import this enum directly and
    MUST NOT redefine it.
    """

    DEBIT = "DEBIT"
    CREDIT = "CREDIT"


def format_timestamp(dt: datetime) -> str:
    """Format a datetime instance into canonical UTC ISO-8601 string.

    Format: "%Y-%m-%dT%H:%M:%S.%fZ"

    WHY:
    Enforces a single byte-exact timestamp format for hash computation and DB storage.
    Callers own UTC discipline: naive or non-UTC datetimes are strictly rejected with
    ValueError rather than silently converted, preventing upstream timezone bugs.
    """
    if not isinstance(dt, datetime):
        raise ValueError("created_at: must be a datetime.datetime instance")
    if dt.tzinfo is None:
        raise ValueError("created_at: naive datetime rejected; must be tz-aware UTC")
    if dt.utcoffset() != timedelta(0):
        raise ValueError("created_at: non-UTC timezone rejected; must have UTC offset 0")

    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True, slots=True)
class EntryFingerprint:
    """Immutable audit record fingerprint payload.

    All guards execute at construction time (__post_init__). Invalid or
    adversarial fingerprints are rejected immediately with ValueError before
    reaching hashing algorithms or database persistence.
    """

    seq: int
    tx_id: str
    account_id: str
    direction: Direction
    amount: int
    currency: str
    balance_after: int
    version: int
    created_at: str

    def __post_init__(self) -> None:
        # Guard: seq must be integer >= 1
        if type(self.seq) is bool or not isinstance(self.seq, int) or self.seq < 1:
            raise ValueError(f"seq: must be an integer >= 1, got {self.seq!r}")

        # Guard: tx_id must be canonical lowercase hyphenated UUID
        # WHY: "ABC..." vs "abc..." or raw hex vs hyphenated would silently fork encoding.
        if not isinstance(self.tx_id, str):
            raise ValueError("tx_id: must be a string")
        if "\x1f" in self.tx_id:
            raise ValueError("tx_id: must not contain reserved separator 0x1f")
        try:
            parsed_tx = uuid.UUID(self.tx_id)
            if str(parsed_tx) != self.tx_id:
                raise ValueError(
                    f"tx_id: must be canonical lowercase hyphenated UUID, got {self.tx_id!r}"
                )
        except ValueError as exc:
            raise ValueError(f"tx_id: invalid UUID format: {exc}") from exc

        # Guard: account_id must be canonical lowercase hyphenated UUID
        if not isinstance(self.account_id, str):
            raise ValueError("account_id: must be a string")
        if "\x1f" in self.account_id:
            raise ValueError("account_id: must not contain reserved separator 0x1f")
        try:
            parsed_acc = uuid.UUID(self.account_id)
            if str(parsed_acc) != self.account_id:
                raise ValueError(
                    f"account_id: must be canonical lowercase hyphenated UUID, "
                    f"got {self.account_id!r}"
                )
        except ValueError as exc:
            raise ValueError(f"account_id: invalid UUID format: {exc}") from exc

        # Guard: direction must be Direction StrEnum instance
        # WHY: Raw strings are rejected to maintain strict typing discipline.
        raw_direction: object = self.direction
        if not isinstance(raw_direction, Direction):
            dir_type = type(raw_direction).__name__
            raise ValueError(f"direction: must be an instance of Direction StrEnum, got {dir_type}")

        # Guard: amount > 0 (minor units, strictly positive)
        # WHY: Zero/negative movements violate double-entry accounting integrity.
        if type(self.amount) is bool or not isinstance(self.amount, int) or self.amount <= 0:
            raise ValueError(f"amount: must be integer > 0 (minor units), got {self.amount!r}")

        # Guard: balance_after >= 0 (accounts cannot go negative)
        if (
            type(self.balance_after) is bool
            or not isinstance(self.balance_after, int)
            or self.balance_after < 0
        ):
            raise ValueError(
                f"balance_after: must be non-negative integer >= 0, got {self.balance_after!r}"
            )

        # Guard: version >= 1 (post-mutation record version)
        if type(self.version) is bool or not isinstance(self.version, int) or self.version < 1:
            raise ValueError(f"version: must be integer >= 1, got {self.version!r}")

        # Guard: currency regex ^[A-Z0-9]{2,10}$
        # WHY: VARCHAR(10) allows crypto tickers (e.g., USDC, WBTC) exceeding CHAR(3).
        if not isinstance(self.currency, str):
            raise ValueError("currency: must be a string")
        if "\x1f" in self.currency:
            raise ValueError("currency: must not contain reserved separator 0x1f")
        if not _CURRENCY_REGEX.match(self.currency):
            raise ValueError(
                f"currency: must match regex '^[A-Z0-9]{{2,10}}$', got {self.currency!r}"
            )

        # Guard: created_at canonical representation verification
        # WHY: Re-formatting and requiring exact string equality guarantees single representation.
        if not isinstance(self.created_at, str):
            raise ValueError("created_at: must be a string")
        if "\x1f" in self.created_at:
            raise ValueError("created_at: must not contain reserved separator 0x1f")
        if not self.created_at.endswith("Z"):
            raise ValueError("created_at: canonical format must end with 'Z'")

        try:
            # Python 3.11+ fromisoformat handles trailing 'Z' as UTC
            dt = datetime.fromisoformat(self.created_at)
        except Exception as exc:
            raise ValueError(f"created_at: malformed ISO-8601 timestamp: {exc}") from exc

        if dt.tzinfo is None or dt.utcoffset() != timedelta(0):
            raise ValueError("created_at: timestamp must be tz-aware UTC")

        reformatted = format_timestamp(dt)
        if reformatted != self.created_at:
            raise ValueError(
                f"created_at: non-canonical representation "
                f"(expected '{reformatted}', got '{self.created_at}')"
            )


def canonical_bytes(prev_hash: str, f: EntryFingerprint) -> bytes:
    """Serialize ledger entry fields into canonical byte representation.

    PUBLIC AUDIT INTERFACE:
    Auditors reconstruct this exact byte sequence from DB columns to independently
    verify ledger integrity.
    """
    if not isinstance(prev_hash, str):
        raise ValueError("prev_hash: must be a string")
    if not isinstance(f, EntryFingerprint):
        raise ValueError("f: must be an instance of EntryFingerprint")

    # Bidirectional genesis guard
    # WHY: prev_hash == GENESIS IFF seq == 1. seq=7 with GENESIS is chain corruption.
    if f.seq == 1:
        if prev_hash != GENESIS:
            raise ValueError(
                f"prev_hash: entry with seq=1 must have prev_hash == '{GENESIS}', got {prev_hash!r}"
            )
    else:
        if prev_hash == GENESIS:
            raise ValueError(f"prev_hash: '{GENESIS}' is only permitted for seq=1, got seq={f.seq}")
        if not _HEX_64_REGEX.match(prev_hash):
            raise ValueError("prev_hash: must be a 64-character lowercase hexadecimal string")

    # Decimal integer formatting: str(int) guarantees canonical ASCII without leading zeros
    fields: list[bytes] = [
        prev_hash.encode("utf-8"),
        str(f.seq).encode("utf-8"),
        f.tx_id.encode("utf-8"),
        f.account_id.encode("utf-8"),
        f.direction.value.encode("utf-8"),
        str(f.amount).encode("utf-8"),
        f.currency.encode("utf-8"),
        str(f.balance_after).encode("utf-8"),
        str(f.version).encode("utf-8"),
        f.created_at.encode("utf-8"),
    ]

    return SEPARATOR.join(fields)


def compute_entry_hash(prev_hash: str, f: EntryFingerprint) -> str:
    """Compute the 64-character lowercase hexadecimal SHA-256 hash of canonical_bytes."""
    raw = canonical_bytes(prev_hash, f)
    return hashlib.sha256(raw).hexdigest().lower()


def verify_link(prev_entry_hash: str, f: EntryFingerprint, claimed_hash: str) -> bool:
    """Verify that claimed_hash equals the computed hash linked to prev_entry_hash.

    ADVERSARIAL VERIFICATION PATH:
    Verification is total: it NEVER raises exceptions for malformed hashes, broken
    links, or corrupted inputs. Returns False on any verification or integrity failure.
    Uses hmac.compare_digest for constant-time comparison to prevent timing side channels.
    """
    if not isinstance(claimed_hash, str) or not _HEX_64_REGEX.match(claimed_hash):
        return False

    try:
        expected_hash = compute_entry_hash(prev_entry_hash, f)
    except Exception:
        # Any failure in canonical byte construction or guard validation fails verification
        return False

    return hmac.compare_digest(expected_hash, claimed_hash)
