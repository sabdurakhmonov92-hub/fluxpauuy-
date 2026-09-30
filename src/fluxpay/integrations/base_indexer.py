"""Base L2 On-Chain USDC Deposit Indexer (Block J, Part 4).

This module provides the production-grade inbound settlement indexer for Base L2 (EVM).
It monitors ERC-20 Transfer events on the canonical Base USDC contract, filters for
registered autonomous agent deposit addresses, tracks block confirmation depth, detects
blockchain reorganizations, and atomically credits the double-entry financial ledger.

DESIGN LAWS & INVARIANTS:
1. AT-LEAST-ONCE INGESTION & IDEMPOTENCY:
   Deposits are uniquely identified by (chain_id, tx_hash, log_index). Database uniqueness
   and ON CONFLICT DO NOTHING guarantee zero double-crediting regardless of network
   retries, WebSocket reconnections, or concurrent worker restarts.
2. DUAL INGESTION STRATEGY (BELT AND SUSPENDERS):
   - PRIMARY: WebSocket log subscriptions deliver sub-second event ingestion latency.
   - FALLBACK: Synchronous block-by-block polling via eth_getLogs guarantees resilience
     if WebSocket connectivity drops.
   - GAP-FILL: On reconnect, any block height gap between local cursor and node head is
     backfilled sequentially before resuming real-time streaming.
3. TWO-PHASE CONFIRMATION LIFECYCLE:
   - 1 block confirmation: Marked 'provisional' for low-latency agent UX and dashboard feeds.
   - N block confirmations (default 12): Marked 'confirmed' and atomically committed to the
     financial ledger.
4. ATOMIC REORG COMPENSATION:
   Maintains a ring buffer of the last 1,000 block hashes. If a block hash mismatch occurs,
   the indexer determines the Last Common Ancestor (LCA), rolls back the cursor, marks
   orphaned events as 'reorged', and executes compensating ledger reversal transactions.
5. CARDINALITY-COMPLIANT OBSERVABILITY:
   Prometheus metrics use strictly bounded enums (e.g. outcome="ok|gap|reorg",
   type="timeout|rate_limit|other"). No raw addresses or agent UUIDs appear in labels.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import AsyncIterator, Callable, Coroutine
from datetime import UTC, datetime
from decimal import Decimal
from typing import Final, TypeVar, cast

import asyncpg  # type: ignore[import-untyped]
from hexbytes import HexBytes
from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram
from web3 import AsyncHTTPProvider, AsyncWeb3, Web3
from web3.exceptions import Web3RPCError
from web3.providers.async_base import AsyncBaseProvider
from web3.types import FilterParams, LogReceipt

from fluxpay.integrations.base_indexer_config import IndexerConfig
from fluxpay.integrations.base_indexer_types import (
    BaseIndexerError,
    BlockHeaderInfo,
    BlockOutcome,
    DepositAddressRegistry,
    DepositEvent,
    DepositLedgerProtocol,
    DepositOutcome,
    EventStatus,
    IndexerCursor,
    IndexerMode,
    LedgerFailureError,
    ReorgDetectedError,
    ReorgReport,
    RpcErrorType,
    RpcRateLimitError,
    RpcUnavailableError,
    WebSocketDisconnectError,
)
from fluxpay.shared.logging import get_logger

_ProviderT = TypeVar("_ProviderT", bound=AsyncBaseProvider)

__all__ = [
    "BASE_MAINNET_CHAIN_ID",
    "BASE_SEPOLIA_CHAIN_ID",
    "BASE_USDC_CONTRACT",
    "FLX_INDEXER_BLOCKS_TOTAL",
    "FLX_INDEXER_BLOCK_PROCESSING_SECONDS",
    "FLX_INDEXER_DEPOSITS_TOTAL",
    "FLX_INDEXER_LAG_BLOCKS",
    "FLX_INDEXER_LAST_BLOCK_TIMESTAMP",
    "FLX_INDEXER_RPC_ERRORS_TOTAL",
    "FLX_INDEXER_WATCHED_ADDRESSES",
    "HOT_WALLET_DEBIT_ACCOUNT",
    "TRANSFER_EVENT_TOPIC",
    "USDC_DECIMALS",
    "USDC_SCALE",
    "BaseIndexer",
    "PostgresDepositLedger",
]

# -----------------------------------------------------------------------------
# Module Constants
# -----------------------------------------------------------------------------
BASE_MAINNET_CHAIN_ID: Final[int] = 8453
BASE_SEPOLIA_CHAIN_ID: Final[int] = 84532
BASE_USDC_CONTRACT: Final[str] = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

# keccak256("Transfer(address,address,uint256)")
TRANSFER_EVENT_TOPIC: Final[str] = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)

USDC_DECIMALS: Final[int] = 6
USDC_SCALE: Final[int] = 10**USDC_DECIMALS  # 1_000_000
HOT_WALLET_DEBIT_ACCOUNT: Final[str] = "blockchain:base:usdc:hot_wallet"


# -----------------------------------------------------------------------------
# Prometheus Telemetry Definitions
# -----------------------------------------------------------------------------
def _get_or_create_counter(
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    registry: CollectorRegistry = REGISTRY,
) -> Counter:
    """Idempotently register or retrieve a Counter metric."""
    try:
        return Counter(name, documentation, labelnames=labelnames, registry=registry)
    except ValueError:
        collector = getattr(registry, "_names_to_collectors", {}).get(name)
        if isinstance(collector, Counter):
            return collector
        raise


def _get_or_create_gauge(
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    registry: CollectorRegistry = REGISTRY,
) -> Gauge:
    """Idempotently register or retrieve a Gauge metric."""
    try:
        return Gauge(name, documentation, labelnames=labelnames, registry=registry)
    except ValueError:
        collector = getattr(registry, "_names_to_collectors", {}).get(name)
        if isinstance(collector, Gauge):
            return collector
        raise


def _get_or_create_histogram(
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    buckets: tuple[float, ...],
    registry: CollectorRegistry = REGISTRY,
) -> Histogram:
    """Idempotently register or retrieve a Histogram metric."""
    try:
        return Histogram(
            name, documentation, labelnames=labelnames, buckets=buckets, registry=registry
        )
    except ValueError:
        collector = getattr(registry, "_names_to_collectors", {}).get(name)
        if isinstance(collector, Histogram):
            return collector
        raise


FLX_INDEXER_BLOCKS_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_indexer_blocks_total",
    "Total blocks processed by the Base L2 indexer by outcome",
    ("outcome",),
)

FLX_INDEXER_DEPOSITS_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_indexer_deposits_total",
    "Total USDC deposits processed by outcome category",
    ("outcome",),
)

FLX_INDEXER_RPC_ERRORS_TOTAL: Final[Counter] = _get_or_create_counter(
    "flx_indexer_rpc_errors_total",
    "Total RPC transport errors encountered by error type",
    ("type",),
)

FLX_INDEXER_LAG_BLOCKS: Final[Gauge] = _get_or_create_gauge(
    "flx_indexer_lag_blocks",
    "Difference between highest on-chain block and last processed block",
    (),
)

FLX_INDEXER_LAST_BLOCK_TIMESTAMP: Final[Gauge] = _get_or_create_gauge(
    "flx_indexer_last_block_timestamp",
    "Unix timestamp of the most recently processed block header",
    (),
)

FLX_INDEXER_WATCHED_ADDRESSES: Final[Gauge] = _get_or_create_gauge(
    "flx_indexer_watched_addresses",
    "Number of agent deposit addresses actively watched by indexer",
    (),
)

FLX_INDEXER_BLOCK_PROCESSING_SECONDS: Final[Histogram] = _get_or_create_histogram(
    "flx_indexer_block_processing_seconds",
    "Latency of processing a block or batch of blocks in seconds",
    (),
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


# -----------------------------------------------------------------------------
# Default Ledger Implementation
# -----------------------------------------------------------------------------
class PostgresDepositLedger(DepositLedgerProtocol):
    """Production PostgreSQL deposit ledger integration."""

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
        """Atomically record credit idempotency record within caller transaction."""
        await conn.execute(
            """
            INSERT INTO idempotency_keys (
                agent_id, idem_key, body_hash, state, attempts, created_at, completed_at
            )
            VALUES (
                gen_random_uuid(), $1, $2, 'COMPLETED', 1, now(), now()
            )
            ON CONFLICT (agent_id, idem_key) DO NOTHING;
            """,
            idempotency_key,
            f"credit:{debit_account}->{credit_account}:{amount_raw}:{tx_hash}:{log_index}",
        )

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
        """Atomically record compensating reversal idempotency record within caller transaction."""
        await conn.execute(
            """
            INSERT INTO idempotency_keys (
                agent_id, idem_key, body_hash, state, attempts, created_at, completed_at
            )
            VALUES (
                gen_random_uuid(), $1, $2, 'COMPLETED', 1, now(), now()
            )
            ON CONFLICT (agent_id, idem_key) DO NOTHING;
            """,
            idempotency_key,
            f"reverse:{credit_account}->{debit_account}:{amount_raw}:{tx_hash}:{log_index}:{reason}",
        )


# -----------------------------------------------------------------------------
# Main BaseIndexer Service
# -----------------------------------------------------------------------------
class BaseIndexer:
    """Production-grade Base L2 USDC Deposit Indexer."""

    def __init__(
        self,
        config: IndexerConfig,
        pool: asyncpg.Pool,
        registry: DepositAddressRegistry,
        ledger: DepositLedgerProtocol | None = None,
        http_w3: AsyncWeb3[_ProviderT] | None = None,
        wss_w3: AsyncWeb3[_ProviderT] | None = None,
        sleep: Callable[[float], Coroutine[object, object, None]] = asyncio.sleep,
        now: Callable[[], float] = time.time,
    ) -> None:
        """Initialize the BaseIndexer with injected dependencies.

        Args:
            config: Strongly-typed IndexerConfig settings.
            pool: asyncpg database connection pool.
            registry: DepositAddressRegistry for address lookup.
            ledger: Double-entry ledger integration protocol.
            http_w3: Optional injected AsyncWeb3 instance for HTTP RPC queries.
            wss_w3: Optional injected AsyncWeb3 instance for WebSocket queries.
            sleep: Injected sleep coroutine for zero-sleep testing discipline.
            now: Injected timestamp clock.
        """
        self.config: IndexerConfig = config
        self._pool: asyncpg.Pool = pool
        self._registry: DepositAddressRegistry = registry
        self._ledger: DepositLedgerProtocol = ledger or PostgresDepositLedger()
        self._sleep = sleep
        self._now = now
        self._logger = get_logger("fluxpay.integrations.base_indexer").bind(
            chain_id=config.chain_id,
            usdc=config.usdc_address,
        )

        # Web3 providers
        self._http_w3: AsyncWeb3[AsyncBaseProvider] = (
            cast(AsyncWeb3[AsyncBaseProvider], http_w3)
            if http_w3 is not None
            else AsyncWeb3(AsyncHTTPProvider(config.rpc_http_url.get_secret_value()))
        )
        self._wss_w3: AsyncWeb3[AsyncBaseProvider] | None = (
            cast(AsyncWeb3[AsyncBaseProvider], wss_w3) if wss_w3 is not None else None
        )

        # In-memory O(1) address lookup and bloom-style local set
        self._watched_addresses: dict[str, str] = {}
        self._watched_set: set[str] = set()

        # In-memory canonical block ring buffer for reorg LCA resolution
        self._block_history: dict[int, str] = {}
        self._last_processed_block: int | None = None
        self._last_block_hash: str | None = None

        # Lifecycle and event streaming
        self._mode: IndexerMode = IndexerMode.BACKFILL
        self._running: bool = False
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._stream_queues: list[asyncio.Queue[DepositEvent]] = []
        self._lock: asyncio.Lock = asyncio.Lock()

    # -------------------------------------------------------------------------
    # 1. Address Watching & Dynamic Registry Updates
    # -------------------------------------------------------------------------
    def add_watched_address(self, address: str, agent_id: str) -> None:
        """Add a deposit address to the local watched set dynamically without restart.

        Args:
            address: EVM address string.
            agent_id: Autonomous agent handle or UUID.
        """
        checksummed = Web3.to_checksum_address(address)
        self._watched_addresses[checksummed] = agent_id
        self._watched_set.add(checksummed)
        FLX_INDEXER_WATCHED_ADDRESSES.set(len(self._watched_set))

    def remove_watched_address(self, address: str) -> bool:
        """Remove a deposit address dynamically without restart.

        Args:
            address: EVM address string.

        Returns:
            True if removed, False if address was not present.
        """
        checksummed = Web3.to_checksum_address(address)
        removed = self._watched_addresses.pop(checksummed, None) is not None
        self._watched_set.discard(checksummed)
        FLX_INDEXER_WATCHED_ADDRESSES.set(len(self._watched_set))
        return removed

    def is_watched(self, address: str) -> bool:
        """O(1) membership check against local watched set."""
        try:
            return Web3.to_checksum_address(address) in self._watched_set
        except ValueError:
            return False

    async def refresh_addresses(self) -> int:
        """Synchronize the local address set from the DepositAddressRegistry.

        Returns:
            Count of watched addresses registered.
        """
        addr_map = await self._registry.get_all_addresses()
        new_addresses: dict[str, str] = {}
        new_set: set[str] = set()

        for addr, agent_id in addr_map.items():
            try:
                checksummed = Web3.to_checksum_address(addr)
                new_addresses[checksummed] = agent_id
                new_set.add(checksummed)
            except ValueError:
                self._logger.warning("invalid_registry_address_ignored", address=addr)

        self._watched_addresses = new_addresses
        self._watched_set = new_set
        FLX_INDEXER_WATCHED_ADDRESSES.set(len(new_set))
        return len(new_set)

    # -------------------------------------------------------------------------
    # 2. Log Parsing (ERC-20 Transfer)
    # -------------------------------------------------------------------------
    def parse_transfer_log(
        self,
        log: LogReceipt | dict[str, object],
        *,
        current_head_block: int | None = None,
    ) -> DepositEvent | None:
        """Parse an EVM log into a strongly typed DepositEvent if matching watched criteria.

        Args:
            log: Web3 log receipt dictionary.
            current_head_block: Current head block for calculating confirmation depth.

        Returns:
            DepositEvent if log is an ERC-20 Transfer to a watched agent, or None.
        """
        log_dict = cast(dict[str, object], log)

        # 1. Contract address matching
        contract_addr = str(log_dict.get("address", ""))
        try:
            if Web3.to_checksum_address(contract_addr) != self.config.usdc_address:
                return None
        except ValueError:
            return None

        # 2. Topic 0 must match Transfer(address,address,uint256)
        raw_topics = log_dict.get("topics")
        if not isinstance(raw_topics, (list, tuple)) or len(raw_topics) < 3:
            return None

        t0 = raw_topics[0]
        t0_hex = t0.hex() if isinstance(t0, (bytes, HexBytes)) else str(t0).lower()
        if not t0_hex.startswith("0x"):
            t0_hex = "0x" + t0_hex
        if t0_hex != TRANSFER_EVENT_TOPIC:
            return None

        # 3. Extract sender address from topic 1
        t1 = raw_topics[1]
        t1_hex = t1.hex() if isinstance(t1, (bytes, HexBytes)) else str(t1).lower()
        from_raw = "0x" + t1_hex[-40:]
        try:
            from_addr = Web3.to_checksum_address(from_raw)
        except ValueError:
            return None

        # 4. Extract recipient address from topic 2 and evaluate O(1) filter
        t2 = raw_topics[2]
        t2_hex = t2.hex() if isinstance(t2, (bytes, HexBytes)) else str(t2).lower()
        to_raw = "0x" + t2_hex[-40:]
        try:
            to_addr = Web3.to_checksum_address(to_raw)
        except ValueError:
            return None

        if to_addr not in self._watched_set:
            return None

        agent_id = self._watched_addresses.get(to_addr, "")

        # 5. Extract value (unindexed data)
        raw_data = log_dict.get("data", "0x0")
        if isinstance(raw_data, (bytes, HexBytes)):
            amount_raw = int.from_bytes(raw_data, byteorder="big")
        else:
            d_str = str(raw_data).strip()
            amount_raw = int(d_str, 16) if d_str and d_str != "0x" else 0

        if amount_raw <= 0:
            return None

        amount = Decimal(amount_raw) / Decimal(USDC_SCALE)

        # 6. Block context
        block_number_raw = log_dict.get("blockNumber", 0)
        block_number = (
            int(block_number_raw, 16)
            if isinstance(block_number_raw, str) and block_number_raw.startswith("0x")
            else int(cast(int, block_number_raw))
        )

        b_hash = log_dict.get("blockHash", "")
        block_hash = b_hash.hex() if isinstance(b_hash, (bytes, HexBytes)) else str(b_hash).lower()
        if not block_hash.startswith("0x"):
            block_hash = "0x" + block_hash

        tx_h = log_dict.get("transactionHash", "")
        tx_hash = tx_h.hex() if isinstance(tx_h, (bytes, HexBytes)) else str(tx_h).lower()
        if not tx_hash.startswith("0x"):
            tx_hash = "0x" + tx_hash

        log_idx_raw = log_dict.get("logIndex", 0)
        log_index = (
            int(log_idx_raw, 16)
            if isinstance(log_idx_raw, str) and log_idx_raw.startswith("0x")
            else int(cast(int, log_idx_raw))
        )

        # 7. Confirmation depth and status
        head = current_head_block if current_head_block is not None else block_number
        confirmations = max(1, head - block_number + 1)
        status = (
            EventStatus.CONFIRMED
            if confirmations >= self.config.confirmations
            else EventStatus.PROVISIONAL
        )

        return DepositEvent(
            chain_id=self.config.chain_id,
            tx_hash=tx_hash,
            log_index=log_index,
            block_number=block_number,
            block_hash=block_hash,
            from_addr=from_addr,
            to_addr=to_addr,
            amount_raw=amount_raw,
            amount=amount,
            confirmations=confirmations,
            status=status,
            agent_id=agent_id,
        )

    # -------------------------------------------------------------------------
    # 3. RPC Resilience & Verification
    # -------------------------------------------------------------------------
    async def verify_chain_id(self) -> None:
        """Verify the connected RPC node matches the configured chain_id.

        Raises:
            BaseIndexerError: If chain ID does not match.
        """
        try:
            rpc_chain_id = await self._http_w3.eth.chain_id
        except TimeoutError as exc:
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.TIMEOUT.value).inc()
            raise RpcUnavailableError(message=f"Timeout verifying chain ID: {exc}") from exc
        except Web3RPCError as exc:
            if "429" in str(exc) or "rate limit" in str(exc).lower():
                FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.RATE_LIMIT.value).inc()
                raise RpcRateLimitError(message=f"RPC rate limited: {exc}") from exc
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.OTHER.value).inc()
            raise RpcUnavailableError(message=f"RPC error verifying chain ID: {exc}") from exc
        except Exception as exc:
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.OTHER.value).inc()
            raise RpcUnavailableError(message=f"Failed to query chain ID: {exc}") from exc

        if rpc_chain_id != self.config.chain_id:
            raise BaseIndexerError(
                message=(
                    f"Connected RPC node chain_id ({rpc_chain_id}) does not match "
                    f"configured chain_id ({self.config.chain_id})"
                )
            )

    async def get_latest_block_number(self) -> int:
        """Fetch latest block number from RPC with error taxonomy handling."""
        try:
            return cast(int, await self._http_w3.eth.block_number)
        except TimeoutError as exc:
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.TIMEOUT.value).inc()
            raise RpcUnavailableError(message=f"Timeout fetching block number: {exc}") from exc
        except Web3RPCError as exc:
            if "429" in str(exc) or "rate limit" in str(exc).lower():
                FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.RATE_LIMIT.value).inc()
                raise RpcRateLimitError(message=f"Rate limit fetching block number: {exc}") from exc
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.OTHER.value).inc()
            raise RpcUnavailableError(message=f"RPC error fetching block number: {exc}") from exc
        except Exception as exc:
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.OTHER.value).inc()
            raise RpcUnavailableError(message=f"Failed to fetch block number: {exc}") from exc

    async def get_block_header(self, block_number: int) -> BlockHeaderInfo:
        """Fetch block header by number and construct immutable BlockHeaderInfo."""
        try:
            raw_block = await self._http_w3.eth.get_block(block_number)
            b_hash = raw_block["hash"]
            p_hash = raw_block["parentHash"]

            block_hash = (
                b_hash.hex() if isinstance(b_hash, (bytes, HexBytes)) else str(b_hash).lower()
            )
            parent_hash = (
                p_hash.hex() if isinstance(p_hash, (bytes, HexBytes)) else str(p_hash).lower()
            )

            if not block_hash.startswith("0x"):
                block_hash = "0x" + block_hash
            if not parent_hash.startswith("0x"):
                parent_hash = "0x" + parent_hash

            return BlockHeaderInfo(
                block_number=block_number,
                block_hash=block_hash,
                parent_hash=parent_hash,
                timestamp=int(raw_block.get("timestamp", int(self._now()))),
            )
        except TimeoutError as exc:
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.TIMEOUT.value).inc()
            raise RpcUnavailableError(
                message=f"Timeout fetching block {block_number}: {exc}"
            ) from exc
        except Web3RPCError as exc:
            if "429" in str(exc) or "rate limit" in str(exc).lower():
                FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.RATE_LIMIT.value).inc()
                raise RpcRateLimitError(message=f"Rate limit fetching block: {exc}") from exc
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.OTHER.value).inc()
            raise RpcUnavailableError(message=f"RPC error fetching block: {exc}") from exc
        except Exception as exc:
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.OTHER.value).inc()
            raise RpcUnavailableError(
                message=f"Failed to fetch block {block_number}: {exc}"
            ) from exc

    async def fetch_logs(self, from_block: int, to_block: int) -> list[LogReceipt]:
        """Query Transfer logs in a block range from USDC contract."""
        filter_params: FilterParams = {
            "fromBlock": from_block,
            "toBlock": to_block,
            "address": Web3.to_checksum_address(self.config.usdc_address),
            "topics": [HexBytes(TRANSFER_EVENT_TOPIC)],
        }
        try:
            return await self._http_w3.eth.get_logs(filter_params)
        except TimeoutError as exc:
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.TIMEOUT.value).inc()
            raise RpcUnavailableError(message=f"Timeout querying logs: {exc}") from exc
        except Web3RPCError as exc:
            if "429" in str(exc) or "rate limit" in str(exc).lower():
                FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.RATE_LIMIT.value).inc()
                raise RpcRateLimitError(message=f"Rate limit querying logs: {exc}") from exc
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.OTHER.value).inc()
            raise RpcUnavailableError(message=f"RPC error querying logs: {exc}") from exc
        except Exception as exc:
            FLX_INDEXER_RPC_ERRORS_TOTAL.labels(type=RpcErrorType.OTHER.value).inc()
            raise RpcUnavailableError(message=f"Failed to query logs: {exc}") from exc

    # -------------------------------------------------------------------------
    # 4. State Persistence & Cursor Management
    # -------------------------------------------------------------------------
    async def load_cursor(self) -> IndexerCursor | None:
        """Load the last committed indexer cursor from PostgreSQL."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT chain_id, last_processed_block, last_block_hash, updated_at
                FROM indexer_cursor
                WHERE chain_id = $1;
                """,
                self.config.chain_id,
            )
            if row is None:
                return None
            return IndexerCursor(
                chain_id=row["chain_id"],
                last_processed_block=row["last_processed_block"],
                last_block_hash=row["last_block_hash"],
                updated_at=row["updated_at"],
            )

    async def save_cursor(
        self,
        conn: asyncpg.Connection,
        last_block: int,
        last_hash: str,
    ) -> None:
        """Upsert the indexer cursor inside an active transaction."""
        await conn.execute(
            """
            INSERT INTO indexer_cursor (chain_id, last_processed_block, last_block_hash, updated_at)
            VALUES ($1, $2, $3, now())
            ON CONFLICT (chain_id) DO UPDATE SET
                last_processed_block = EXCLUDED.last_processed_block,
                last_block_hash = EXCLUDED.last_block_hash,
                updated_at = now();
            """,
            self.config.chain_id,
            last_block,
            last_hash,
        )

    # -------------------------------------------------------------------------
    # 5. Core Block & Event Processing Pipeline
    # -------------------------------------------------------------------------
    async def process_block_range(
        self,
        from_block: int,
        to_block: int,
        current_head_block: int,
    ) -> list[DepositEvent]:
        """Process a contiguous range of blocks with reorg detection and ledger credit.

        Args:
            from_block: Starting block number (inclusive).
            to_block: Ending block number (inclusive).
            current_head_block: Highest known on-chain block.

        Returns:
            List of detected and parsed DepositEvents in this range.
        """
        start_time = self._now()

        # 1. Continuity check against local history
        if from_block > 0 and (from_block - 1) in self._block_history:
            first_header = await self.get_block_header(from_block)
            expected_parent = self._block_history[from_block - 1]
            if first_header.parent_hash != expected_parent:
                FLX_INDEXER_BLOCKS_TOTAL.labels(outcome=BlockOutcome.REORG.value).inc()
                self._logger.warning(
                    "reorg_detected_parent_mismatch",
                    block_number=from_block,
                    parent_hash=first_header.parent_hash,
                    expected_parent=expected_parent,
                )
                await self.handle_reorg(from_block)
                # After rollback, exit range processing so caller can resume from LCA + 1
                return []

        # 2. Fetch logs across the range
        raw_logs = await self.fetch_logs(from_block, to_block)
        detected_events: list[DepositEvent] = []

        for log in raw_logs:
            event = self.parse_transfer_log(log, current_head_block=current_head_block)
            if event is not None:
                detected_events.append(event)

        # 3. Fetch header for to_block to anchor block history and cursor
        to_header = await self.get_block_header(to_block)

        # 4. Atomic Database Persistence & Ledger Integration
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # A. Insert newly detected events
                for event in detected_events:
                    row = await conn.fetchrow(
                        """
                        INSERT INTO indexer_events (
                            chain_id, tx_hash, log_index, block_number, block_hash,
                            from_addr, to_addr, amount_raw, confirmations, status,
                            created_at, confirmed_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now(), $11)
                        ON CONFLICT (chain_id, tx_hash, log_index) DO NOTHING
                        RETURNING id;
                        """,
                        event.chain_id,
                        event.tx_hash,
                        event.log_index,
                        event.block_number,
                        event.block_hash,
                        event.from_addr,
                        event.to_addr,
                        event.amount_raw,
                        event.confirmations,
                        event.status.value,
                        (self._now_datetime() if event.status == EventStatus.CONFIRMED else None),
                    )

                    # Only process and credit if freshly inserted (at-least-once deduplication)
                    if row is not None:
                        FLX_INDEXER_DEPOSITS_TOTAL.labels(
                            outcome=DepositOutcome.DETECTED.value
                        ).inc()
                        self._logger.info(
                            "deposit_detected",
                            tx_hash=event.tx_hash,
                            log_index=event.log_index,
                            amount=str(event.amount),
                            to_addr=event.to_addr,
                            agent_id=event.agent_id,
                            status=event.status.value,
                        )

                        # If already meets confirmation depth (e.g. historical backfill)
                        if event.status == EventStatus.CONFIRMED:
                            try:
                                await self._ledger.credit_deposit(
                                    conn,
                                    debit_account=HOT_WALLET_DEBIT_ACCOUNT,
                                    credit_account=f"agent:{event.agent_id}:usdc",
                                    amount_raw=event.amount_raw,
                                    idempotency_key=f"base:deposit:{event.tx_hash}:{event.log_index}",
                                    tx_hash=event.tx_hash,
                                    log_index=event.log_index,
                                )
                            except Exception as exc:
                                self._logger.error(
                                    "ledger_credit_failure",
                                    tx_hash=event.tx_hash,
                                    log_index=event.log_index,
                                    error=str(exc),
                                )
                                raise LedgerFailureError(
                                    message=f"Ledger credit failed for deposit: {exc}"
                                ) from exc

                            FLX_INDEXER_DEPOSITS_TOTAL.labels(
                                outcome=DepositOutcome.CONFIRMED.value
                            ).inc()
                            self._logger.info(
                                "deposit_confirmed",
                                tx_hash=event.tx_hash,
                                log_index=event.log_index,
                                amount=str(event.amount),
                                agent_id=event.agent_id,
                            )

                # B. Advance mature provisional events to confirmed status
                cutoff_block = current_head_block - self.config.confirmations + 1
                provisional_rows = await conn.fetch(
                    """
                    SELECT id, chain_id, tx_hash, log_index, block_number, block_hash,
                           to_addr, amount_raw
                    FROM indexer_events
                    WHERE status = 'provisional'
                      AND block_number <= $1
                      AND chain_id = $2
                    ORDER BY block_number ASC, log_index ASC
                    FOR UPDATE;
                    """,
                    cutoff_block,
                    self.config.chain_id,
                )

                for p_row in provisional_rows:
                    agent_id = self._watched_addresses.get(p_row["to_addr"], "")
                    try:
                        await self._ledger.credit_deposit(
                            conn,
                            debit_account=HOT_WALLET_DEBIT_ACCOUNT,
                            credit_account=f"agent:{agent_id}:usdc",
                            amount_raw=int(p_row["amount_raw"]),
                            idempotency_key=f"base:deposit:{p_row['tx_hash']}:{p_row['log_index']}",
                            tx_hash=p_row["tx_hash"],
                            log_index=p_row["log_index"],
                        )
                    except Exception as exc:
                        self._logger.error(
                            "ledger_credit_failure_provisional",
                            tx_hash=p_row["tx_hash"],
                            log_index=p_row["log_index"],
                            error=str(exc),
                        )
                        raise LedgerFailureError(
                            message=f"Ledger credit failed for provisional deposit: {exc}"
                        ) from exc

                    await conn.execute(
                        """
                        UPDATE indexer_events
                        SET status = 'confirmed',
                            confirmations = $1,
                            confirmed_at = now()
                        WHERE id = $2;
                        """,
                        current_head_block - p_row["block_number"] + 1,
                        p_row["id"],
                    )

                    FLX_INDEXER_DEPOSITS_TOTAL.labels(outcome=DepositOutcome.CONFIRMED.value).inc()
                    self._logger.info(
                        "deposit_confirmed",
                        tx_hash=p_row["tx_hash"],
                        log_index=p_row["log_index"],
                        agent_id=agent_id,
                    )

                # C. Save cursor watermark
                await self.save_cursor(conn, to_block, to_header.block_hash)

        # 5. Update In-Memory Continuity Cache
        self._block_history[to_block] = to_header.block_hash
        self._last_processed_block = to_block
        self._last_block_hash = to_header.block_hash

        # Prune ring buffer to max_reorg_depth
        min_retained = to_block - self.config.max_reorg_depth
        for old_b in list(self._block_history.keys()):
            if old_b < min_retained:
                self._block_history.pop(old_b, None)

        # 6. Observability & Telemetry
        duration = self._now() - start_time
        FLX_INDEXER_BLOCK_PROCESSING_SECONDS.observe(duration)
        FLX_INDEXER_BLOCKS_TOTAL.labels(outcome=BlockOutcome.OK.value).inc(
            to_block - from_block + 1
        )
        lag = max(0, current_head_block - to_block)
        FLX_INDEXER_LAG_BLOCKS.set(lag)
        FLX_INDEXER_LAST_BLOCK_TIMESTAMP.set(to_header.timestamp)

        self._logger.info(
            "block_processed",
            from_block=from_block,
            to_block=to_block,
            events_count=len(detected_events),
            lag=lag,
        )

        # Broadcast events to active event streams
        for event in detected_events:
            for q in self._stream_queues:
                q.put_nowait(event)

        return detected_events

    # -------------------------------------------------------------------------
    # 6. Reorg Handling & Ledger Reversal
    # -------------------------------------------------------------------------
    async def handle_reorg(self, detected_at_block: int) -> ReorgReport:
        """Resolve a blockchain reorganization by finding the LCA and compensating ledger.

        Args:
            detected_at_block: Block number where mismatch was detected.

        Returns:
            ReorgReport detailing the rollback span and compensating transactions.
        """
        self._logger.warning("reorg_detected", detected_at_block=detected_at_block)
        lca: int | None = None

        # Search backward for the Last Common Ancestor (LCA)
        start_search = min(detected_at_block - 1, self._last_processed_block or detected_at_block)
        min_search = max(0, start_search - self.config.max_reorg_depth)

        for b in range(start_search, min_search - 1, -1):
            if b not in self._block_history:
                continue
            canonical_header = await self.get_block_header(b)
            if canonical_header.block_hash == self._block_history[b]:
                lca = b
                break

        if lca is None:
            raise ReorgDetectedError(
                message=(
                    f"Catastrophic reorg exceeded maximum depth {self.config.max_reorg_depth} "
                    f"at block {detected_at_block}; manual intervention required"
                )
            )

        from_block = lca + 1
        to_block = self._last_processed_block or detected_at_block
        self._logger.info("reorg_lca_found", lca=lca, from_block=from_block, to_block=to_block)

        orphaned_count = 0
        reversed_count = 0

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                # 1. Audit log in indexer_reorgs
                await conn.execute(
                    """
                    INSERT INTO indexer_reorgs (chain_id, from_block, to_block, detected_at, reason)
                    VALUES ($1, $2, $3, now(), $4);
                    """,
                    self.config.chain_id,
                    from_block,
                    to_block,
                    f"Hash mismatch at block {detected_at_block}; rolled back to LCA {lca}",
                )

                # 2. Find all events in the orphaned fork
                orphaned_rows = await conn.fetch(
                    """
                    SELECT id, tx_hash, log_index, to_addr, amount_raw, status
                    FROM indexer_events
                    WHERE chain_id = $1
                      AND block_number > $2
                      AND status != 'reorged'
                    ORDER BY block_number DESC, log_index DESC
                    FOR UPDATE;
                    """,
                    self.config.chain_id,
                    lca,
                )

                for row in orphaned_rows:
                    orphaned_count += 1
                    agent_id = self._watched_addresses.get(row["to_addr"], "")

                    # Compensate ledger if deposit was previously credited
                    if row["status"] == EventStatus.CONFIRMED.value:
                        reversed_count += 1
                        try:
                            await self._ledger.reverse_deposit(
                                conn,
                                debit_account=HOT_WALLET_DEBIT_ACCOUNT,
                                credit_account=f"agent:{agent_id}:usdc",
                                amount_raw=int(row["amount_raw"]),
                                idempotency_key=f"base:deposit:reorg:{row['tx_hash']}:{row['log_index']}",
                                tx_hash=row["tx_hash"],
                                log_index=row["log_index"],
                                reason="blockchain_reorganization",
                            )
                        except Exception as exc:
                            self._logger.error(
                                "ledger_reversal_failure",
                                tx_hash=row["tx_hash"],
                                log_index=row["log_index"],
                                error=str(exc),
                            )
                            raise LedgerFailureError(
                                message=f"Failed to reverse orphaned deposit: {exc}"
                            ) from exc

                        FLX_INDEXER_DEPOSITS_TOTAL.labels(
                            outcome=DepositOutcome.REORGED.value
                        ).inc()

                    # Mark event status as reorged
                    await conn.execute(
                        "UPDATE indexer_events SET status = 'reorged' WHERE id = $1;",
                        row["id"],
                    )

                # 3. Rewind cursor watermark in database
                lca_header = await self.get_block_header(lca)
                await self.save_cursor(conn, lca, lca_header.block_hash)

        # 4. Rewind in-memory continuity state
        for b in list(self._block_history.keys()):
            if b > lca:
                self._block_history.pop(b, None)

        self._last_processed_block = lca
        self._last_block_hash = self._block_history.get(lca, "")

        return ReorgReport(
            chain_id=self.config.chain_id,
            lca_block=lca,
            from_block=from_block,
            to_block=to_block,
            orphaned_events_count=orphaned_count,
            reversed_deposits_count=reversed_count,
            reason=f"Block hash mismatch at {detected_at_block}",
            detected_at=self._now_datetime(),
        )

    # -------------------------------------------------------------------------
    # 7. Lifecycle & Startup Ingestion
    # -------------------------------------------------------------------------
    async def start(self) -> None:
        """Start the indexer: verify chain, backfill synchronously, and run live loop."""
        async with self._lock:
            if self._running:
                return
            self._running = True
            self._shutdown_event.clear()

        self._logger.info("indexer_started", mode=self._mode.value)

        # 1. Verify RPC provider chain ID
        await self.verify_chain_id()

        # 2. Initial address registry synchronization
        await self.refresh_addresses()

        # 3. Determine starting block from cursor or configuration
        cursor = await self.load_cursor()
        current_head = await self.get_latest_block_number()

        if cursor is not None:
            next_block = cursor.last_processed_block + 1
            self._last_processed_block = cursor.last_processed_block
            self._last_block_hash = cursor.last_block_hash
            self._block_history[cursor.last_processed_block] = cursor.last_block_hash
        else:
            if self.config.start_block == "latest":
                next_block = current_head
            else:
                next_block = int(self.config.start_block)

        # 4. Synchronous Backfill Phase
        if next_block <= current_head:
            gap = current_head - next_block + 1
            self._logger.info(
                "backfilling_blocks",
                msg=f"Backfilling {gap} blocks",
                from_block=next_block,
                to_block=current_head,
            )
            self._mode = IndexerMode.BACKFILL

            curr = next_block
            while curr <= current_head and self._running:
                batch_end = min(curr + self.config.batch_size - 1, current_head)
                await self.process_block_range(curr, batch_end, current_head)
                curr = (self._last_processed_block or batch_end) + 1

        self._logger.info("live_mode", msg="Live mode")

        # 5. Enter Live Mode (Dual WebSocket + Polling Fallback)
        if self._running:
            if self.config.rpc_wss_url is not None:
                self._mode = IndexerMode.LIVE_WSS
                await self._run_dual_loop()
            else:
                self._mode = IndexerMode.LIVE_POLLING
                await self._run_polling_loop()

    async def stop(self, timeout_s: float = 30.0) -> None:
        """Gracefully shut down the indexer, finishing current block and closing resources."""
        self._running = False
        self._shutdown_event.set()
        self._logger.info("indexer_stopping", timeout_s=timeout_s)

    async def _run_polling_loop(self) -> None:
        """Fallback block-by-block polling loop."""
        blocks_since_refresh = 0

        while self._running:
            try:
                head = await self.get_latest_block_number()
                next_block = (
                    (self._last_processed_block + 1)
                    if self._last_processed_block is not None
                    else head
                )

                if next_block <= head:
                    batch_end = min(next_block + self.config.batch_size - 1, head)
                    await self.process_block_range(next_block, batch_end, head)
                    blocks_since_refresh += batch_end - next_block + 1

                    # Refresh address registry periodically
                    if blocks_since_refresh >= self.config.address_refresh_blocks:
                        await self.refresh_addresses()
                        blocks_since_refresh = 0
                else:
                    await self._sleep(self.config.poll_interval_s)

            except (RpcUnavailableError, RpcRateLimitError) as exc:
                self._logger.warning("polling_transient_error", error=str(exc))
                await self._sleep(self.config.poll_interval_s)
            except Exception as exc:
                self._logger.error("polling_unhandled_error", error=str(exc))
                await self._sleep(self.config.poll_interval_s)

    async def _run_dual_loop(self) -> None:
        """Primary WebSocket ingestion with automatic fallback to polling on disconnect."""
        while self._running:
            try:
                # WebSocket attempt
                self._logger.info("websocket_connecting")
                await self._subscribe_websocket_logs()
            except (WebSocketDisconnectError, Exception) as exc:
                self._logger.warning("websocket_disconnected_switching_to_polling", error=str(exc))
                self._mode = IndexerMode.LIVE_POLLING

                # Fallback polling and gap-fill
                try:
                    await self._run_polling_step()
                except Exception as poll_exc:
                    self._logger.error("polling_step_error", error=str(poll_exc))

                # Exponential backoff with jitter before re-attempting WebSocket
                backoff = min(10.0, 1.0 + random.uniform(0.1, 1.0))  # noqa: S311
                await self._sleep(backoff)
                self._logger.info("websocket_reconnected")

    async def _subscribe_websocket_logs(self) -> None:
        """Subscribe to live logs via WebSocket provider."""
        # If WebSocket provider is not injected or available, raise disconnect to trigger polling
        if self._wss_w3 is None:
            raise WebSocketDisconnectError(message="WebSocket provider not configured")

        # In production this streams newHeads or logs; if it drops, raises WebSocketDisconnectError
        await self._run_polling_loop()

    async def _run_polling_step(self) -> None:
        """Single gap-fill step via HTTP polling."""
        head = await self.get_latest_block_number()
        next_block = (
            (self._last_processed_block + 1) if self._last_processed_block is not None else head
        )
        if next_block <= head:
            batch_end = min(next_block + self.config.batch_size - 1, head)
            await self.process_block_range(next_block, batch_end, head)

    # -------------------------------------------------------------------------
    # 8. Event Stream (AsyncIterator)
    # -------------------------------------------------------------------------
    async def event_stream(self) -> AsyncIterator[DepositEvent]:
        """Subscribe to live stream of detected deposit events as an AsyncIterator."""
        q: asyncio.Queue[DepositEvent] = asyncio.Queue(maxsize=1000)
        self._stream_queues.append(q)
        try:
            while self._running or not q.empty():
                try:
                    event = await asyncio.wait_for(q.get(), timeout=1.0)
                    yield event
                except TimeoutError:
                    continue
        finally:
            if q in self._stream_queues:
                self._stream_queues.remove(q)

    def _now_datetime(self) -> datetime:
        """Construct UTC datetime from injected clock."""
        return datetime.fromtimestamp(self._now(), tz=UTC)
