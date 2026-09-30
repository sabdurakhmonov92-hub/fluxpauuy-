"""Property-based testing for Base L2 indexer reorg handling using Hypothesis.

Verifies the fundamental ledger consistency invariant:
Across arbitrary random block sequences with arbitrary random reorgs:
- Every finalized deposit on the canonical chain is credited exactly once (net balance = 1).
- Every orphaned deposit on a discarded fork is completely compensated (net balance = 0).
- No deposit is ever duplicated (net balance > 1 is impossible).
- No canonical finalized event is ever lost (net balance < 1 for canonical is impossible).
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest
from hexbytes import HexBytes
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import SecretStr
from web3 import AsyncWeb3
from web3.providers.async_base import AsyncBaseProvider
from web3.types import RPCResponse

from fluxpay.integrations.base_indexer import (
    BASE_MAINNET_CHAIN_ID,
    TRANSFER_EVENT_TOPIC,
    BaseIndexer,
)
from fluxpay.integrations.base_indexer_config import IndexerConfig

pytestmark = [
    pytest.mark.unit,
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
]

TEST_USDC_ADDR: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
TEST_AGENT_ADDR_1: str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
TEST_SENDER_ADDR: str = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"


# -----------------------------------------------------------------------------
# In-Memory Scriptable Web3 Async Provider
# -----------------------------------------------------------------------------
class MockIndexerWeb3Provider(AsyncBaseProvider):
    def __init__(
        self,
        *,
        chain_id: int = BASE_MAINNET_CHAIN_ID,
        latest_block: int = 100,
        blocks: dict[int, dict[str, Any]] | None = None,
        logs: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__()
        self.chain_id = chain_id
        self.latest_block = latest_block
        self.blocks = blocks or {}
        self.logs = logs or []

    async def make_request(self, method: str, params: Any) -> RPCResponse:
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
# In-Memory Mock asyncpg Database
# -----------------------------------------------------------------------------
class MockTransaction:
    async def __aenter__(self) -> MockTransaction:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


class MockAsyncpgConnection:
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
            }
            return "INSERT 0 1"

        if "INSERT INTO indexer_reorgs" in q:
            self.db.reorgs.append(
                {
                    "chain_id": args[0],
                    "from_block": args[1],
                    "to_block": args[2],
                    "reason": args[3],
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
            return self.db.cursor.get(args[0])

        if "INSERT INTO indexer_events" in q:
            chain_id, tx_hash, log_index = args[0], args[1], args[2]
            for ev in self.db.events:
                if (
                    ev["chain_id"] == chain_id
                    and ev["tx_hash"] == tx_hash
                    and ev["log_index"] == log_index
                ):
                    return None

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
    def __init__(self) -> None:
        self.cursor: dict[int, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.reorgs: list[dict[str, Any]] = []
        self.idempotency_keys: list[str] = []


class MockAsyncpgPool:
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


def make_transfer_log(
    *,
    to_addr: str = TEST_AGENT_ADDR_1,
    amount_raw: int = 100_000_000,
    block_number: int = 100,
    tx_hash: str = "0x" + "a" * 64,
    log_index: int = 0,
) -> dict[str, Any]:
    t0 = TRANSFER_EVENT_TOPIC
    t1 = "0x" + "0" * 24 + TEST_SENDER_ADDR[2:].lower()
    t2 = "0x" + "0" * 24 + to_addr[2:].lower()
    data = "0x" + f"{amount_raw:064x}"

    return {
        "address": TEST_USDC_ADDR,
        "topics": [HexBytes(t0), HexBytes(t1), HexBytes(t2)],
        "data": HexBytes(data),
        "blockNumber": block_number,
        "blockHash": HexBytes("0x" + f"{block_number:064x}"),
        "transactionHash": HexBytes(tx_hash),
        "logIndex": log_index,
    }


# -----------------------------------------------------------------------------
# Hypothesis Test Strategies
# -----------------------------------------------------------------------------
@st.composite
def chain_action_sequence(draw: st.DrawFn) -> list[tuple[str, int]]:
    actions: list[tuple[str, int]] = []
    n_steps = draw(st.integers(min_value=3, max_value=8))

    for _ in range(n_steps):
        action_type = draw(st.sampled_from(["advance", "deposit", "reorg"]))
        if action_type == "advance":
            blocks = draw(st.integers(min_value=1, max_value=3))
            actions.append(("advance", blocks))
        elif action_type == "deposit":
            val = draw(st.integers(min_value=10, max_value=500))
            actions.append(("deposit", val))
        else:
            depth = draw(st.integers(min_value=1, max_value=2))
            actions.append(("reorg", depth))

    return actions


@settings(max_examples=10, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(actions=chain_action_sequence())
def test_hypothesis_reorg_consistency_invariants(actions: list[tuple[str, int]]) -> None:
    """Hypothesis property test: random reorgs never lose or duplicate final events."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    loop.run_until_complete(_run_reorg_simulation(actions))


async def _run_reorg_simulation(actions: list[tuple[str, int]]) -> None:
    config = IndexerConfig(
        rpc_http_url=SecretStr("https://mainnet.base.org"),
        usdc_address=TEST_USDC_ADDR,
        confirmations=12,
    )
    db = MockDatabase()
    pool = MockAsyncpgPool(db)
    ledger = MockLedger()
    registry = MockDepositAddressRegistry({TEST_AGENT_ADDR_1: "agent_hypothesis"})

    provider = MockIndexerWeb3Provider(latest_block=100)
    w3 = AsyncWeb3(provider)
    indexer = BaseIndexer(config, cast(Any, pool), registry, ledger=ledger, http_w3=w3)
    indexer.add_watched_address(TEST_AGENT_ADDR_1, "agent_hypothesis")

    current_height = 100
    indexer._block_history[current_height] = "0x" + f"{current_height:064x}"
    indexer._last_processed_block = current_height

    deposit_counter = 0
    deposits: dict[str, dict[str, Any]] = {}

    for action_type, arg in actions:
        if action_type == "advance":
            new_height = current_height + arg
            provider.latest_block = new_height
            for b in range(current_height + 1, new_height + 1):
                await indexer.process_block_range(b, b, new_height)
            current_height = new_height

        elif action_type == "deposit":
            deposit_counter += 1
            tx_h = "0x" + f"{deposit_counter:064x}"
            amt = arg * 1_000_000
            deposits[tx_h] = {"canonical": True, "amount": amt, "block": current_height}

            log = make_transfer_log(
                to_addr=TEST_AGENT_ADDR_1,
                amount_raw=amt,
                block_number=current_height,
                tx_hash=tx_h,
            )
            provider.logs.append(log)
            await indexer.process_block_range(current_height, current_height, current_height)

        elif action_type == "reorg":
            depth = min(arg, max(1, current_height - 100))
            if depth >= 1 and current_height - depth >= 100:
                report = await indexer.handle_reorg(detected_at_block=current_height)
                current_height = report.lca_block
                provider.latest_block = current_height
                for _tx_h, meta in deposits.items():
                    if meta["block"] > report.lca_block:
                        meta["canonical"] = False

    # Advance chain by 15 blocks to settle all canonical deposits
    final_head = current_height + 15
    provider.latest_block = final_head
    for b in range(current_height + 1, final_head + 1):
        await indexer.process_block_range(b, b, final_head)

    # Net ledger verification
    net_credits: dict[str, int] = {}
    for credit in ledger.credits:
        idem = credit["idempotency_key"]
        net_credits[idem] = net_credits.get(idem, 0) + 1

    for reversal in ledger.reversals:
        parts = reversal["idempotency_key"].split(":")
        orig_key = f"base:deposit:{parts[3]}:{parts[4]}"
        net_credits[orig_key] = net_credits.get(orig_key, 0) - 1

    for tx_h, meta in deposits.items():
        key = f"base:deposit:{tx_h}:0"
        net = net_credits.get(key, 0)

        if meta["canonical"]:
            assert net == 1, (
                f"Canonical deposit {tx_h} lost or duplicated: net balance {net} (expected 1)"
            )
        else:
            assert net == 0, (
                f"Orphaned deposit {tx_h} not compensated: net balance {net} (expected 0)"
            )
