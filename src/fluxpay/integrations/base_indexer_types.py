"""Data types, protocols, enums, and error taxonomy for Base L2 Deposit Indexer.

Design Invariants:
1. MINOR-UNITS IDENTITY & DECIMAL DISCIPLINE:
   On-chain ERC-20 values are received as integer minor units (uint256).
   Human/financial amounts are converted strictly via Decimal, never float,
   preventing IEEE 754 precision loss.
2. IMMUTABLE FROZEN DATA MODELS:
   All event structures and cursor representations are frozen dataclasses with slots,
   guaranteeing thread-safety and zero in-place mutation.
3. STRICT ERROR TAXONOMY:
   Indexer-specific failures map deterministically to typed subclasses of IntegrationError,
   carrying standard error codes, retryable status, and client-safe messages.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Protocol, runtime_checkable

import asyncpg  # type: ignore[import-untyped]

from fluxpay.shared.errors import IntegrationError

__all__ = [
    "BaseIndexerError",
    "BlockGapError",
    "BlockHeaderInfo",
    "BlockOutcome",
    "DepositAddressRegistry",
    "DepositEvent",
    "DepositLedgerProtocol",
    "DepositOutcome",
    "EventStatus",
    "IndexerCursor",
    "IndexerMode",
    "LedgerFailureError",
    "ReorgDetectedError",
    "ReorgReport",
    "RpcErrorType",
    "RpcRateLimitError",
    "RpcUnavailableError",
    "WebSocketDisconnectError",
]


# -----------------------------------------------------------------------------
# 1. ENUMS
# -----------------------------------------------------------------------------


class EventStatus(StrEnum):
    """Lifecycle status of an ingested on-chain deposit event."""

    PROVISIONAL = "provisional"
    CONFIRMED = "confirmed"
    REORGED = "reorged"


class IndexerMode(StrEnum):
    """Operational mode of the indexer ingestion engine."""

    BACKFILL = "backfill"
    LIVE_WSS = "live_wss"
    LIVE_POLLING = "live_polling"


class RpcErrorType(StrEnum):
    """Categorized RPC provider failure taxonomy."""

    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    OTHER = "other"


class BlockOutcome(StrEnum):
    """Telemetry label for block processing result."""

    OK = "ok"
    GAP = "gap"
    REORG = "reorg"


class DepositOutcome(StrEnum):
    """Telemetry label for deposit event processing outcome."""

    DETECTED = "detected"
    CONFIRMED = "confirmed"
    REORGED = "reorged"


# -----------------------------------------------------------------------------
# 2. FROZEN DOMAIN MODELS
# -----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BlockHeaderInfo:
    """Essential block header metadata for chain continuity and reorg tracking."""

    block_number: int
    block_hash: str
    parent_hash: str
    timestamp: int


@dataclass(frozen=True, slots=True)
class DepositEvent:
    """Ingested on-chain ERC-20 transfer event bound to an autonomous agent."""

    chain_id: int
    tx_hash: str
    log_index: int
    block_number: int
    block_hash: str
    from_addr: str
    to_addr: str
    amount_raw: int
    amount: Decimal
    confirmations: int
    status: EventStatus
    agent_id: str
    created_at: datetime | None = None
    confirmed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class IndexerCursor:
    """Persistent watermark representing the latest sequentially indexed block."""

    chain_id: int
    last_processed_block: int
    last_block_hash: str
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ReorgReport:
    """Diagnostic report generated upon detecting and resolving a chain reorg."""

    chain_id: int
    lca_block: int
    from_block: int
    to_block: int
    orphaned_events_count: int
    reversed_deposits_count: int
    reason: str
    detected_at: datetime


# -----------------------------------------------------------------------------
# 3. PROTOCOLS (DEPENDENCY INJECTION CONTRACTS)
# -----------------------------------------------------------------------------


@runtime_checkable
class DepositAddressRegistry(Protocol):
    """Protocol for dynamic lookup and resolution of registered agent deposit addresses."""

    async def get_all_addresses(self) -> dict[str, str]:
        """Fetch all actively watched deposit addresses mapped to agent external or UUID handles.

        Returns:
            Dictionary mapping checksummed EVM address (0x...) to agent_id string.
        """
        ...

    async def resolve_agent_id(self, address: str) -> str | None:
        """Resolve the agent_id for a single deposit address.

        Args:
            address: Checksummed or lowercase EVM address string.

        Returns:
            The associated agent_id string if registered, or None if unknown.
        """
        ...


@runtime_checkable
class DepositLedgerProtocol(Protocol):
    """Protocol for double-entry ledger integration upon deposit confirmation and reorg reversal."""

    async def credit_deposit(
        self,
        conn: asyncpg.Connection,
        *,
        debit_account: str,
        credit_account: str,
        amount_raw: int,
        idempotency_key: str,
        tx_hash: str,
        log_index: int,
    ) -> None:
        """Atomically credit agent ledger account and debit hot wallet within a database tx.

        Args:
            conn: Active database connection possessing the transaction context.
            debit_account: Source account handle (e.g. 'blockchain:base:usdc:hot_wallet').
            credit_account: Recipient agent account handle (e.g. 'agent:{agent_id}:usdc').
            amount_raw: Raw minor units of the deposit (e.g. 6 decimals for USDC).
            idempotency_key: Unique deterministic key f"base:deposit:{tx_hash}:{log_index}".
            tx_hash: EVM transaction hash.
            log_index: Transfer event log index.
        """
        ...

    async def reverse_deposit(
        self,
        conn: asyncpg.Connection,
        *,
        debit_account: str,
        credit_account: str,
        amount_raw: int,
        idempotency_key: str,
        tx_hash: str,
        log_index: int,
        reason: str = "reorg",
    ) -> None:
        """Atomically post a compensating ledger entry reversing an orphaned deposit.

        Args:
            conn: Active database connection possessing the transaction context.
            debit_account: Original debit account (now credited or reversed).
            credit_account: Original credit account (now debited to revoke credit).
            amount_raw: Raw minor units of the reversed deposit.
            idempotency_key: Unique deterministic key f"base:deposit:reorg:{tx_hash}:{log_index}".
            tx_hash: EVM transaction hash.
            log_index: Transfer event log index.
            reason: Diagnostic explanation for the compensating reversal.
        """
        ...


# -----------------------------------------------------------------------------
# 4. ERROR TAXONOMY (MAPPED TO IntegrationError)
# -----------------------------------------------------------------------------


class BaseIndexerError(IntegrationError):
    """Base exception for all Base L2 indexer domain errors."""

    code: str = "base_indexer_error"
    status: int = 502
    retryable: bool = False
    client_message: str = "Base L2 deposit indexer encountered an error"


class RpcUnavailableError(BaseIndexerError):
    """RPC provider node is unreachable or returned transport-level failure."""

    code: str = "rpc_unavailable"
    status: int = 502
    retryable: bool = True
    client_message: str = "RPC provider node is temporarily unavailable"


class RpcRateLimitError(BaseIndexerError):
    """Upstream RPC returned HTTP 429 or rate limit code."""

    code: str = "rpc_rate_limit"
    status: int = 429
    retryable: bool = True
    client_message: str = "RPC provider rate limit exceeded"


class WebSocketDisconnectError(BaseIndexerError):
    """WebSocket log subscription connection dropped."""

    code: str = "websocket_disconnect"
    status: int = 502
    retryable: bool = True
    client_message: str = "Indexer WebSocket connection disconnected"


class BlockGapError(BaseIndexerError):
    """Non-sequential block discontinuity detected during polling or streaming."""

    code: str = "block_gap"
    status: int = 500
    retryable: bool = True
    client_message: str = "Block height gap detected in ingestion pipeline"


class ReorgDetectedError(BaseIndexerError):
    """Blockchain reorganizing deeper than allowable threshold or unresolvable."""

    code: str = "reorg_detected"
    status: int = 500
    retryable: bool = True
    client_message: str = "Blockchain reorganization detected"


class LedgerFailureError(BaseIndexerError):
    """Double-entry ledger credit or compensation call failed."""

    code: str = "ledger_failure"
    status: int = 500
    retryable: bool = False
    client_message: str = "Ledger transaction failure during deposit credit"
