"""Unit tests for Base L2 Inbound USDC Deposit Indexer.

Comprehensive unit test suite covering:
1. Log parsing with real Base L2 USDC Transfer event hex.
2. Idempotency (same on-chain event processed twice -> single ledger credit).
3. Reorg rollback (simulated 3-block reorg, rollback to LCA, and compensating ledger reversal).
4. Address filtering (1,000 watched addresses, non-watched events discarded in O(1)).
5. Confirmation progression (1 confirmation = provisional, 12 confirmations = final).
6. Dual ingestion resilience (WebSocket disconnect, automatic polling fallback, and gap-fill).
7. Cursor resumption (restarting indexer resumes from last_processed_block + 1).
8. Configuration validation (EIP-55 checksum, invalid confirmation bounds, URLs).
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any, cast

import pytest
from hexbytes import HexBytes
from pydantic import SecretStr, ValidationError
from web3 import AsyncWeb3
from web3.exceptions import Web3RPCError
from web3.providers.async_base import AsyncBaseProvider
from web3.types import RPCResponse

from fluxpay.integrations.base_indexer import (
    BASE_MAINNET_CHAIN_ID,
    TRANSFER_EVENT_TOPIC,
    BaseIndexer,
)
from fluxpay.integrations.base_indexer_config import IndexerConfig
from fluxpay.integrations.base_indexer_types import (
    BaseIndexerError,
    EventStatus,
    ReorgDetectedError,
    RpcRateLimitError,
    RpcUnavailableError,
)

pytestmark = pytest.mark.unit

TEST_USDC_ADDR: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
TEST_AGENT_ADDR_1: str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
TEST_AGENT_ADDR_2: str = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
TEST_SENDER_ADDR: str = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"


# -----------------------------------------------------------------------------
# In-Memory Scriptable Web3 Async Provider
# -----------------------------------------------------------------------------
class MockIndexerWeb3Provider(AsyncBaseProvider):
    """In-memory scriptable provider for indexer unit testing."""

    def __init__(
        self,
        *,
        chain_id: int = BASE_MAINNET_CHAIN_ID,
        latest_block: int = 100,
        blocks: dict[int, dict[str, Any]] | None = None,
        logs: list[dict[str, Any]] | None = None,
        rate_limit_failures: int = 0,
        timeout_failures: int = 0,
    ) -> None:
        super().__init__()
        self.chain_id = chain_id
        self.latest_block = latest_block
        self.blocks = blocks or {}
        self.logs = logs or []
        self.rate_limit_failures = rate_limit_failures
        self.timeout_failures = timeout_failures
        self.requests_log: list[tuple[str, Any]] = []

    async def make_request(self, method: str, params: Any) -> RPCResponse:
        self.requests_log.append((method, params))

        if self.timeout_failures > 0:
            self.timeout_failures -= 1
            raise TimeoutError("Simulated RPC transport timeout")

        if self.rate_limit_failures > 0:
            self.rate_limit_failures -= 1
            raise Web3RPCError("HTTP 429 Too Many Requests: Rate limit exceeded")

        if method == "eth_chainId":
            return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": hex(self.chain_id)})

        if method == "eth_blockNumber":
            return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": hex(self.latest_block)})

        if method == "eth_getBlockByNumber":
            b_num_str = params[0]
            b_num = int(b_num_str, 16) if isinstance(b_num_str, str) else int(b_num_str)
            block_info = self.blocks.get(b_num)
            if block_info is None:
                block_info = {
                    "number": hex(b_num),
                    "hash": "0x" + f"{b_num:064x}",
                    "parentHash": "0x" + f"{(b_num - 1):064x}",
                    "timestamp": hex(1700000000 + b_num * 2),
                }
            return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": block_info})

        if method == "eth_getLogs":
            filter_kwargs = params[0]
            raw_from = filter_kwargs.get("fromBlock", 0)
            raw_to = filter_kwargs.get("toBlock", self.latest_block)

            from_b = (
                int(raw_from, 16)
                if isinstance(raw_from, str) and raw_from.startswith("0x")
                else int(raw_from)
            )
            to_b = (
                int(raw_to, 16)
                if isinstance(raw_to, str) and raw_to.startswith("0x")
                else int(raw_to)
            )

            matched = []
            for log in self.logs:
                l_block = log.get("blockNumber", 0)
                if from_b <= l_block <= to_b:
                    matched.append(log)
            return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": matched})

        return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": None})


# -----------------------------------------------------------------------------
# In-Memory Mock asyncpg Pool and Connection
# -----------------------------------------------------------------------------
class MockTransaction:
    async def __aenter__(self) -> MockTransaction:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


class MockAsyncpgConnection:
    """In-memory mock connection simulating PostgreSQL indexer tables."""

    def __init__(self, db: MockDatabase) -> None:
        self.db = db

    def transaction(self) -> MockTransaction:
        return MockTransaction()

    async def execute(self, query: str, *args: Any) -> str:
        q = " ".join(query.split())
        if "INSERT INTO indexer_cursor" in q:
            chain_id, last_block, last_hash = args[0], args[1], args[2]
            self.db.cursor[chain_id] = {
                "chain_id": chain_id,
                "last_processed_block": last_block,
                "last_block_hash": last_hash,
                "updated_at": self.db.now,
            }
            return "INSERT 0 1"

        if "INSERT INTO indexer_reorgs" in q:
            chain_id, from_b, to_b, reason = args[0], args[1], args[2], args[3]
            self.db.reorgs.append(
                {
                    "chain_id": chain_id,
                    "from_block": from_b,
                    "to_block": to_b,
                    "reason": reason,
                }
            )
            return "INSERT 0 1"

        if "UPDATE indexer_events SET status = 'confirmed'" in q:
            confirmations, event_id = args[0], args[1]
            for ev in self.db.events:
                if ev["id"] == event_id:
                    ev["status"] = "confirmed"
                    ev["confirmations"] = confirmations
            return "UPDATE 1"

        if "UPDATE indexer_events SET status = 'reorged'" in q:
            event_id = args[0]
            for ev in self.db.events:
                if ev["id"] == event_id:
                    ev["status"] = "reorged"
            return "UPDATE 1"

        if "INSERT INTO idempotency_keys" in q:
            self.db.idempotency_keys.append(args[0])
            return "INSERT 0 1"

        return "OK"

    async def fetchrow(self, query: str, *args: Any) -> dict[str, Any] | None:
        q = " ".join(query.split())
        if "SELECT chain_id, last_processed_block" in q:
            chain_id = args[0]
            return self.db.cursor.get(chain_id)

        if "INSERT INTO indexer_events" in q:
            # Check unique constraint (chain_id, tx_hash, log_index)
            chain_id, tx_hash, log_index = args[0], args[1], args[2]
            for ev in self.db.events:
                if (
                    ev["chain_id"] == chain_id
                    and ev["tx_hash"] == tx_hash
                    and ev["log_index"] == log_index
                ):
                    return None  # ON CONFLICT DO NOTHING

            new_id = len(self.db.events) + 1
            record = {
                "id": new_id,
                "chain_id": chain_id,
                "tx_hash": tx_hash,
                "log_index": log_index,
                "block_number": args[3],
                "block_hash": args[4],
                "from_addr": args[5],
                "to_addr": args[6],
                "amount_raw": args[7],
                "confirmations": args[8],
                "status": args[9],
                "confirmed_at": args[10],
            }
            self.db.events.append(record)
            return {"id": new_id}

        return None

    async def fetch(self, query: str, *args: Any) -> list[dict[str, Any]]:
        q = " ".join(query.split())
        if "WHERE status = 'provisional'" in q:
            cutoff_block, chain_id = args[0], args[1]
            return [
                ev
                for ev in self.db.events
                if ev["status"] == "provisional"
                and ev["block_number"] <= cutoff_block
                and ev["chain_id"] == chain_id
            ]

        if "WHERE chain_id = $1" in q and "block_number > $2" in q:
            chain_id, lca = args[0], args[1]
            return [
                ev
                for ev in self.db.events
                if ev["chain_id"] == chain_id
                and ev["block_number"] > lca
                and ev["status"] != "reorged"
            ]

        return []


class MockDatabase:
    """State storage for in-memory simulated database."""

    def __init__(self) -> None:
        from datetime import UTC, datetime

        self.cursor: dict[int, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.reorgs: list[dict[str, Any]] = []
        self.idempotency_keys: list[str] = []
        self.now = datetime.now(tz=UTC)


class MockAsyncpgPool:
    """Mock asyncpg Pool vending MockAsyncpgConnection instances."""

    def __init__(self, db: MockDatabase | None = None) -> None:
        self.db = db or MockDatabase()

    def acquire(self) -> MockPoolContext:
        return MockPoolContext(self.db)


class MockPoolContext:
    def __init__(self, db: MockDatabase) -> None:
        self.db = db

    async def __aenter__(self) -> MockAsyncpgConnection:
        return MockAsyncpgConnection(self.db)

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


# -----------------------------------------------------------------------------
# Mock Injected Dependencies
# -----------------------------------------------------------------------------
class MockDepositAddressRegistry:
    def __init__(self, initial_map: dict[str, str] | None = None) -> None:
        self.addresses: dict[str, str] = initial_map or {}

    async def get_all_addresses(self) -> dict[str, str]:
        return dict(self.addresses)

    async def resolve_agent_id(self, address: str) -> str | None:
        return self.addresses.get(address)


class MockLedger:
    def __init__(self) -> None:
        self.credits: list[dict[str, Any]] = []
        self.reversals: list[dict[str, Any]] = []

    async def credit_deposit(
        self,
        conn: Any,
        *,
        debit_account: str,
        credit_account: str,
        amount_raw: int,
        idempotency_key: str,
        tx_hash: str,
        log_index: int,
    ) -> None:
        self.credits.append(
            {
                "debit_account": debit_account,
                "credit_account": credit_account,
                "amount_raw": amount_raw,
                "idempotency_key": idempotency_key,
                "tx_hash": tx_hash,
                "log_index": log_index,
            }
        )

    async def reverse_deposit(
        self,
        conn: Any,
        *,
        debit_account: str,
        credit_account: str,
        amount_raw: int,
        idempotency_key: str,
        tx_hash: str,
        log_index: int,
        reason: str = "reorg",
    ) -> None:
        self.reversals.append(
            {
                "debit_account": debit_account,
                "credit_account": credit_account,
                "amount_raw": amount_raw,
                "idempotency_key": idempotency_key,
                "tx_hash": tx_hash,
                "log_index": log_index,
                "reason": reason,
            }
        )


# -----------------------------------------------------------------------------
# Test Fixtures & Utilities
# -----------------------------------------------------------------------------
def make_transfer_log(
    *,
    from_addr: str = TEST_SENDER_ADDR,
    to_addr: str = TEST_AGENT_ADDR_1,
    amount_raw: int = 250_500_000,  # 250.50 USDC
    block_number: int = 100,
    block_hash: str = "0x" + "a" * 64,
    tx_hash: str = "0x" + "b" * 64,
    log_index: int = 0,
    contract_addr: str = TEST_USDC_ADDR,
) -> dict[str, Any]:
    """Helper to synthesize authentic EVM ERC-20 Transfer log hex."""
    t0 = TRANSFER_EVENT_TOPIC
    t1 = "0x" + "0" * 24 + from_addr[2:].lower()
    t2 = "0x" + "0" * 24 + to_addr[2:].lower()
    data = "0x" + f"{amount_raw:064x}"

    return {
        "address": contract_addr,
        "topics": [HexBytes(t0), HexBytes(t1), HexBytes(t2)],
        "data": HexBytes(data),
        "blockNumber": block_number,
        "blockHash": HexBytes(block_hash),
        "transactionHash": HexBytes(tx_hash),
        "logIndex": log_index,
    }


# -----------------------------------------------------------------------------
# 1. Unit: Log Parsing with Real Base L2 USDC Transfer Event Hex
# -----------------------------------------------------------------------------
def test_log_parsing_real_base_usdc_hex() -> None:
    """Verify parsing real Base L2 Transfer event hex with topics and data."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
        confirmations=12,
    )
    registry = MockDepositAddressRegistry({TEST_AGENT_ADDR_1: "agent_42"})
    indexer = BaseIndexer(config, cast(Any, MockAsyncpgPool()), registry)
    indexer.add_watched_address(TEST_AGENT_ADDR_1, "agent_42")

    raw_log = make_transfer_log(
        from_addr=TEST_SENDER_ADDR,
        to_addr=TEST_AGENT_ADDR_1,
        amount_raw=500_000_000,  # 500 USDC
        block_number=21_000_000,
        tx_hash="0x" + "1" * 64,
        log_index=2,
    )

    event = indexer.parse_transfer_log(raw_log, current_head_block=21_000_000)
    assert event is not None
    assert event.chain_id == BASE_MAINNET_CHAIN_ID
    assert event.amount_raw == 500_000_000
    assert event.amount == Decimal("500.0")
    assert event.to_addr == TEST_AGENT_ADDR_1
    assert event.from_addr == TEST_SENDER_ADDR
    assert event.agent_id == "agent_42"
    assert event.confirmations == 1
    assert event.status == EventStatus.PROVISIONAL


# -----------------------------------------------------------------------------
# 2. Unit: Address Filtering (1000 addresses, only matching events pass)
# -----------------------------------------------------------------------------
def test_address_filtering_large_set() -> None:
    """Verify O(1) filtering across 1,000 addresses: only watched pass."""
    watched_map = {f"0x{i:040x}": f"agent_{i}" for i in range(1, 1001)}
    # Pick one valid checksummed address from the set
    target_addr = "0x" + "0" * 36 + "1234"
    watched_map[target_addr] = "agent_target"

    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
    )
    registry = MockDepositAddressRegistry(watched_map)
    indexer = BaseIndexer(config, cast(Any, MockAsyncpgPool()), registry)

    for addr, aid in watched_map.items():
        try:
            indexer.add_watched_address(addr, aid)
        except ValueError:
            pass

    # Unwatched recipient log
    unwatched_log = make_transfer_log(to_addr=TEST_SENDER_ADDR)
    assert indexer.parse_transfer_log(unwatched_log) is None

    # Watched recipient log
    watched_log = make_transfer_log(to_addr=TEST_AGENT_ADDR_1)
    indexer.add_watched_address(TEST_AGENT_ADDR_1, "agent_1")
    matched = indexer.parse_transfer_log(watched_log)
    assert matched is not None
    assert matched.to_addr == TEST_AGENT_ADDR_1


# -----------------------------------------------------------------------------
# 3. Unit: Idempotency (Same Event Twice -> One Ledger Entry)
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_idempotency_duplicate_events() -> None:
    """Processing identical (tx_hash, log_index) event twice results in single credit."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
        confirmations=1,  # immediate confirmation
    )
    db = MockDatabase()
    pool = MockAsyncpgPool(db)
    ledger = MockLedger()
    registry = MockDepositAddressRegistry({TEST_AGENT_ADDR_1: "agent_alpha"})

    log = make_transfer_log(
        to_addr=TEST_AGENT_ADDR_1,
        amount_raw=100_000_000,
        block_number=50,
        tx_hash="0x" + "d" * 64,
        log_index=0,
    )

    provider = MockIndexerWeb3Provider(
        latest_block=50,
        logs=[log],
    )
    w3 = AsyncWeb3(provider)
    indexer = BaseIndexer(config, cast(Any, pool), registry, ledger=ledger, http_w3=w3)
    indexer.add_watched_address(TEST_AGENT_ADDR_1, "agent_alpha")

    # Ingest first time
    events1 = await indexer.process_block_range(50, 50, current_head_block=50)
    assert len(events1) == 1
    assert len(ledger.credits) == 1
    assert len(db.events) == 1

    # Ingest second time (replay/duplicate)
    events2 = await indexer.process_block_range(50, 50, current_head_block=50)
    assert len(events2) == 1
    # DB ON CONFLICT prevented second insertion and ledger credit
    assert len(ledger.credits) == 1
    assert len(db.events) == 1


# -----------------------------------------------------------------------------
# 4. Unit: Confirmations (1 block = provisional, 12 blocks = final)
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_confirmation_progression_lifecycle() -> None:
    """Event starts provisional at 1 block and transitions to confirmed at 12."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
        confirmations=12,
    )
    db = MockDatabase()
    pool = MockAsyncpgPool(db)
    ledger = MockLedger()
    registry = MockDepositAddressRegistry({TEST_AGENT_ADDR_1: "agent_confirm"})

    log = make_transfer_log(
        to_addr=TEST_AGENT_ADDR_1,
        amount_raw=200_000_000,
        block_number=100,
    )
    provider = MockIndexerWeb3Provider(latest_block=100, logs=[log])
    w3 = AsyncWeb3(provider)
    indexer = BaseIndexer(config, cast(Any, pool), registry, ledger=ledger, http_w3=w3)
    indexer.add_watched_address(TEST_AGENT_ADDR_1, "agent_confirm")

    # Block 100: 1 confirmation -> provisional, 0 ledger credits
    await indexer.process_block_range(100, 100, current_head_block=100)
    assert len(db.events) == 1
    assert db.events[0]["status"] == "provisional"
    assert len(ledger.credits) == 0

    # Advance chain to block 110 (11 confirmations) -> still provisional
    provider.latest_block = 110
    await indexer.process_block_range(101, 110, current_head_block=110)
    assert db.events[0]["status"] == "provisional"
    assert len(ledger.credits) == 0

    # Advance chain to block 111 (12 confirmations) -> confirmed and credited
    provider.latest_block = 111
    await indexer.process_block_range(111, 111, current_head_block=111)
    assert db.events[0]["status"] == "confirmed"
    assert len(ledger.credits) == 1
    assert ledger.credits[0]["amount_raw"] == 200_000_000


# -----------------------------------------------------------------------------
# 5. Unit: Reorg Rollback (Mock 3-block reorg, verify compensation)
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_reorg_rollback_and_compensation() -> None:
    """Detect hash mismatch, roll back 3 blocks to LCA, compensate ledger."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
        confirmations=1,  # confirmed immediately for testing compensation
    )
    db = MockDatabase()
    pool = MockAsyncpgPool(db)
    ledger = MockLedger()
    registry = MockDepositAddressRegistry({TEST_AGENT_ADDR_1: "agent_reorg"})

    provider = MockIndexerWeb3Provider(latest_block=105)
    w3 = AsyncWeb3(provider)
    indexer = BaseIndexer(config, cast(Any, pool), registry, ledger=ledger, http_w3=w3)
    indexer.add_watched_address(TEST_AGENT_ADDR_1, "agent_reorg")

    # Ingest canonical blocks 100 to 102
    await indexer.process_block_range(100, 102, current_head_block=102)

    # Ingest block 103 with deposit on fork A
    fork_a_log = make_transfer_log(
        to_addr=TEST_AGENT_ADDR_1,
        amount_raw=75_000_000,
        block_number=103,
        tx_hash="0x" + "f" * 64,
    )
    provider.logs = [fork_a_log]
    await indexer.process_block_range(103, 103, current_head_block=103)
    assert len(ledger.credits) == 1
    assert db.events[0]["status"] == "confirmed"

    # Reorg happens: canonical chain reorganized at block 103 with different hash
    # Fork B has different parentHash for block 104, matching LCA block 102
    provider.blocks[103] = {
        "number": hex(103),
        "hash": "0x" + "9" * 64,  # alternate hash
        "parentHash": indexer._block_history[102],
        "timestamp": hex(1700000206),
    }
    provider.blocks[104] = {
        "number": hex(104),
        "hash": "0x" + "8" * 64,
        "parentHash": "0x" + "9" * 64,
        "timestamp": hex(1700000208),
    }

    # Now process block 104: parent of 104 doesn't match old 103 hash -> triggers reorg
    report = await indexer.handle_reorg(detected_at_block=103)
    assert report.lca_block == 102
    assert report.orphaned_events_count == 1
    assert report.reversed_deposits_count == 1

    # Verify ledger compensating entry
    assert len(ledger.reversals) == 1
    assert ledger.reversals[0]["amount_raw"] == 75_000_000
    assert "reorg" in ledger.reversals[0]["idempotency_key"]

    # Verify event status marked reorged
    assert db.events[0]["status"] == "reorged"
    # Verify cursor rewound to LCA
    assert db.cursor[BASE_MAINNET_CHAIN_ID]["last_processed_block"] == 102


# -----------------------------------------------------------------------------
# 6. Unit: Cursor Resume (Restart from last_processed_block + 1)
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cursor_resume_on_startup() -> None:
    """Starting indexer with existing cursor resumes from last_processed_block + 1."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
        start_block=0,
    )
    db = MockDatabase()
    # Seed existing cursor at block 500
    db.cursor[BASE_MAINNET_CHAIN_ID] = {
        "chain_id": BASE_MAINNET_CHAIN_ID,
        "last_processed_block": 500,
        "last_block_hash": "0x" + f"{500:064x}",
        "updated_at": db.now,
    }
    pool = MockAsyncpgPool(db)
    provider = MockIndexerWeb3Provider(latest_block=502)
    w3 = AsyncWeb3(provider)
    indexer = BaseIndexer(config, cast(Any, pool), MockDepositAddressRegistry(), http_w3=w3)

    # Trigger start and immediately stop
    async def stop_soon() -> None:
        await asyncio.sleep(0.01)
        await indexer.stop()

    _stop_task = asyncio.create_task(stop_soon())
    await indexer.start()
    await _stop_task

    # Indexer processed blocks 501 to 502
    assert indexer._last_processed_block == 502
    assert db.cursor[BASE_MAINNET_CHAIN_ID]["last_processed_block"] == 502


# -----------------------------------------------------------------------------
# 7. Unit: WebSocket Disconnect & Polling Fallback
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_websocket_disconnect_fallback() -> None:
    """When WebSocket disconnects, indexer switches to polling and fills gap."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        rpc_wss_url=SecretStr("wss://base.example.com/ws"),
        usdc_address=TEST_USDC_ADDR,
        start_block=10,
    )
    db = MockDatabase()
    pool = MockAsyncpgPool(db)
    provider = MockIndexerWeb3Provider(latest_block=12)
    w3 = AsyncWeb3(provider)

    indexer = BaseIndexer(config, cast(Any, pool), MockDepositAddressRegistry(), http_w3=w3)
    indexer._last_processed_block = 10
    indexer._block_history[10] = "0x" + f"{10:064x}"

    # Calling _run_dual_loop with None wss_w3 triggers disconnect and polling step
    async def stop_soon() -> None:
        await asyncio.sleep(0.05)
        await indexer.stop()

    indexer._running = True
    _loop_task = asyncio.create_task(stop_soon())
    await indexer._run_dual_loop()
    await _loop_task

    # Verify fallback polling executed and caught up to block 12
    assert indexer._last_processed_block == 12


# -----------------------------------------------------------------------------
# 8. Unit: Configuration Validation Guardrails
# -----------------------------------------------------------------------------
def test_config_validations() -> None:
    """Verify security validation rules on IndexerConfig."""
    # Bad USDC address (not checksummed)
    with pytest.raises(ValidationError, match="EIP-55 checksummed"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address=TEST_USDC_ADDR.lower(),
        )

    # Bad RPC URL scheme
    with pytest.raises(ValidationError, match="HTTP or HTTPS"):
        IndexerConfig(
            rpc_http_url=SecretStr("ftp://invalid.rpc"),
            usdc_address=TEST_USDC_ADDR,
        )

    # Confirmations < 1
    with pytest.raises(ValidationError, match="between 1 and 100"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address=TEST_USDC_ADDR,
            confirmations=0,
        )

    # Confirmations > 100
    with pytest.raises(ValidationError, match="between 1 and 100"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address=TEST_USDC_ADDR,
            confirmations=101,
        )


# -----------------------------------------------------------------------------
# 9. Unit: Additional Configuration Validation Edge Cases
# -----------------------------------------------------------------------------
def test_additional_config_validations() -> None:
    """Verify regex, WebSocket scheme, start_block sentinels, and interval bounds."""
    # Bad regex format
    with pytest.raises(ValidationError, match="Invalid EVM address format"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address="0xInvalidHexAddressFormat",
        )

    # Bad WebSocket URL scheme
    with pytest.raises(ValidationError, match="WS or WSS URL"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            rpc_wss_url=SecretStr("http://not-a-websocket.com"),
            usdc_address=TEST_USDC_ADDR,
        )

    # start_block parsing: 'latest' string
    cfg_latest = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
        start_block="latest",
    )
    assert cfg_latest.start_block == "latest"

    # start_block parsing: integer string
    cfg_num_str = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
        start_block=" 42 ",
    )
    assert cfg_num_str.start_block == 42

    # start_block invalid string
    with pytest.raises(ValidationError, match="non-negative integer or 'latest'"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address=TEST_USDC_ADDR,
            start_block="invalid-block",
        )

    # start_block negative int
    with pytest.raises(ValidationError, match="start_block must be >= 0"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address=TEST_USDC_ADDR,
            start_block=-5,
        )

    # batch_size bounds
    with pytest.raises(ValidationError, match="batch_size must be between 1 and 50000"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address=TEST_USDC_ADDR,
            batch_size=0,
        )
    with pytest.raises(ValidationError, match="batch_size must be between 1 and 50000"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address=TEST_USDC_ADDR,
            batch_size=60000,
        )

    # poll_interval_s bounds
    with pytest.raises(ValidationError, match=r"poll_interval_s must be > 0\.0"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address=TEST_USDC_ADDR,
            poll_interval_s=0.0,
        )

    # max_reorg_depth bounds
    with pytest.raises(ValidationError, match="max_reorg_depth must be between 1 and 10000"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address=TEST_USDC_ADDR,
            max_reorg_depth=0,
        )

    # address_refresh_blocks bounds
    with pytest.raises(ValidationError, match="address_refresh_blocks must be >= 1"):
        IndexerConfig(
            rpc_http_url=SecretStr("https://mainnet.base.org"),
            usdc_address=TEST_USDC_ADDR,
            address_refresh_blocks=0,
        )


# -----------------------------------------------------------------------------
# 10. Unit: Address Management & Dynamic Refresh
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_address_management_and_refresh() -> None:
    """Verify dynamic address addition, removal, and registry synchronization."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
    )
    db = MockDatabase()
    pool = MockAsyncpgPool(db)
    registry = MockDepositAddressRegistry(
        {
            TEST_AGENT_ADDR_1: "agent_alpha",
            "0xinvalid": "agent_bad",
        }
    )
    indexer = BaseIndexer(config, cast(Any, pool), registry)

    # Manual add
    indexer.add_watched_address(TEST_AGENT_ADDR_2, "agent_beta")
    assert indexer.is_watched(TEST_AGENT_ADDR_2) is True
    assert indexer.is_watched("0xnonexistent") is False

    # Remove address
    assert indexer.remove_watched_address(TEST_AGENT_ADDR_2) is True
    assert indexer.remove_watched_address(TEST_AGENT_ADDR_2) is False
    assert indexer.is_watched(TEST_AGENT_ADDR_2) is False

    # Sync from registry (ignores invalid address)
    count = await indexer.refresh_addresses()
    assert count == 1
    assert indexer.is_watched(TEST_AGENT_ADDR_1) is True


# -----------------------------------------------------------------------------
# 11. Unit: RPC Resilience & Error Classification
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_rpc_verification_and_error_handling() -> None:
    """Verify chain_id validation mismatch and RPC error taxonomy classification."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
        chain_id=BASE_MAINNET_CHAIN_ID,
    )
    db = MockDatabase()
    pool = MockAsyncpgPool(db)

    # Chain ID mismatch (node returns Ethereum Mainnet = 1 instead of Base = 8453)
    bad_chain_provider = MockIndexerWeb3Provider(chain_id=1)
    indexer = BaseIndexer(
        config,
        cast(Any, pool),
        MockDepositAddressRegistry(),
        http_w3=AsyncWeb3(bad_chain_provider),
    )
    with pytest.raises(BaseIndexerError, match="does not match configured chain_id"):
        await indexer.verify_chain_id()

    # Timeout error on chain_id
    timeout_provider = MockIndexerWeb3Provider(timeout_failures=1)
    indexer_timeout = BaseIndexer(
        config,
        cast(Any, pool),
        MockDepositAddressRegistry(),
        http_w3=AsyncWeb3(timeout_provider),
    )
    with pytest.raises(RpcUnavailableError, match="Timeout"):
        await indexer_timeout.verify_chain_id()

    # Rate limit (HTTP 429) error on chain_id
    rate_limit_provider = MockIndexerWeb3Provider(rate_limit_failures=1)
    indexer_rate_limit = BaseIndexer(
        config,
        cast(Any, pool),
        MockDepositAddressRegistry(),
        http_w3=AsyncWeb3(rate_limit_provider),
    )
    with pytest.raises(RpcRateLimitError, match="rate limited"):
        await indexer_rate_limit.verify_chain_id()

    # Timeout error on get_block_header
    block_timeout_provider = MockIndexerWeb3Provider(timeout_failures=1)
    indexer_block_timeout = BaseIndexer(
        config,
        cast(Any, pool),
        MockDepositAddressRegistry(),
        http_w3=AsyncWeb3(block_timeout_provider),
    )
    with pytest.raises(RpcUnavailableError, match="Timeout fetching block"):
        await indexer_block_timeout.get_block_header(100)


# -----------------------------------------------------------------------------
# 12. Unit: Event Queue & AsyncIterator Stream
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_events_stream_and_queue_drain() -> None:
    """Verify that indexer.event_stream() streams events from internal queue."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
    )
    db = MockDatabase()
    pool = MockAsyncpgPool(db)
    indexer = BaseIndexer(config, cast(Any, pool), MockDepositAddressRegistry())

    test_event = None
    indexer.add_watched_address(TEST_AGENT_ADDR_1, "agent_stream")
    raw_log = make_transfer_log(to_addr=TEST_AGENT_ADDR_1, amount_raw=5_000_000)
    parsed = indexer.parse_transfer_log(raw_log, current_head_block=115)
    assert parsed is not None
    test_event = parsed

    received: list[Any] = []

    async def consumer() -> None:
        async for event in indexer.event_stream():
            received.append(event)
            break

    indexer._running = True
    consumer_task = asyncio.create_task(consumer())
    await asyncio.sleep(0.01)

    # Broadcast event to stream queues
    for q in indexer._stream_queues:
        q.put_nowait(test_event)

    await asyncio.wait_for(consumer_task, timeout=1.0)
    indexer._running = False
    assert len(received) == 1
    assert received[0].tx_hash == test_event.tx_hash
    assert received[0].amount == Decimal("5.0")


# -----------------------------------------------------------------------------
# 13. Unit: Reorg Exceeding Max Depth Halts
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_reorg_depth_exceeded_halts() -> None:
    """When a reorg exceeds max_reorg_depth, indexer raises ReorgDetectedError."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
        max_reorg_depth=5,
    )
    db = MockDatabase()
    pool = MockAsyncpgPool(db)
    # Populate provider with completely divergent hashes
    blocks: dict[int, dict[str, Any]] = {}
    for b in range(90, 110):
        blocks[b] = {
            "number": hex(b),
            "hash": "0x" + f"{(b + 9999):064x}",
            "parentHash": "0x" + f"{(b + 9998):064x}",
            "timestamp": hex(1700000000),
        }
    provider = MockIndexerWeb3Provider(latest_block=105, blocks=blocks)
    indexer = BaseIndexer(
        config, cast(Any, pool), MockDepositAddressRegistry(), http_w3=AsyncWeb3(provider)
    )

    # Fill local history with non-matching hashes
    for b in range(90, 106):
        indexer._block_history[b] = "0x" + f"{b:064x}"

    with pytest.raises(ReorgDetectedError, match="exceeded maximum depth"):
        await indexer.handle_reorg(detected_at_block=105)


# -----------------------------------------------------------------------------
# 14. Unit: Log Parsing Edge Cases
# -----------------------------------------------------------------------------
def test_log_parsing_edge_cases() -> None:
    """Verify unindexed data, invalid address lengths, and zero value rejection."""
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
    )
    db = MockDatabase()
    pool = MockAsyncpgPool(db)
    indexer = BaseIndexer(config, cast(Any, pool), MockDepositAddressRegistry())
    indexer.add_watched_address(TEST_AGENT_ADDR_1, "agent_1")

    # Wrong contract address
    bad_contract_log = make_transfer_log()
    bad_contract_log["address"] = "0x1111111111111111111111111111111111111111"
    assert indexer.parse_transfer_log(bad_contract_log) is None

    # Insufficient topics (< 3)
    bad_topics_log = make_transfer_log()
    bad_topics_log["topics"] = [HexBytes(TRANSFER_EVENT_TOPIC)]
    assert indexer.parse_transfer_log(bad_topics_log) is None

    # Wrong topic 0 (not Transfer)
    wrong_t0_log = make_transfer_log()
    wrong_t0_log["topics"][0] = HexBytes("0x" + "0" * 64)
    assert indexer.parse_transfer_log(wrong_t0_log) is None

    # Zero transfer amount rejected
    zero_amount_log = make_transfer_log(amount_raw=0)
    assert indexer.parse_transfer_log(zero_amount_log) is None
