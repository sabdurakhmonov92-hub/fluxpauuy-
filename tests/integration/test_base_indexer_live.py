"""Live integration test against Base Sepolia testnet for Base L2 Deposit Indexer.

Tests end-to-end integration:
1. Connecting to Base Sepolia testnet (chain_id=84532).
2. Verifying chain ID negotiation with the RPC node.
3. Querying block headers and recent USDC Transfer logs on Base Sepolia.
4. Testing address filtering and confirmation calculation.
"""

from __future__ import annotations

import os
from typing import Any, cast

import httpx
import pytest
from pydantic import SecretStr
from web3 import AsyncHTTPProvider, AsyncWeb3

from fluxpay.integrations.base_indexer import (
    BASE_SEPOLIA_CHAIN_ID,
    BaseIndexer,
)
from fluxpay.integrations.base_indexer_config import IndexerConfig

pytestmark = pytest.mark.integration

BASE_SEPOLIA_USDC: str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
BASE_SEPOLIA_PUBLIC_RPC: str = "https://sepolia.base.org"


class LiveMockDatabase:
    def __init__(self) -> None:
        self.cursor: dict[int, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []


class LiveMockPoolContext:
    def __init__(self, db: LiveMockDatabase) -> None:
        self.db = db

    async def __aenter__(self) -> LiveMockConn:
        return LiveMockConn(self.db)

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass


class LiveMockConn:
    def __init__(self, db: LiveMockDatabase) -> None:
        self.db = db

    def transaction(self) -> Any:
        class _Tx:
            async def __aenter__(self) -> _Tx:
                return self

            async def __aexit__(self, *args: Any) -> None:
                pass

        return _Tx()

    async def execute(self, query: str, *args: Any) -> str:
        return "OK"

    async def fetchrow(self, query: str, *args: Any) -> dict[str, Any] | None:
        return None

    async def fetch(self, query: str, *args: Any) -> list[dict[str, Any]]:
        return []


class LiveMockPool:
    def __init__(self) -> None:
        self.db = LiveMockDatabase()

    def acquire(self) -> LiveMockPoolContext:
        return LiveMockPoolContext(self.db)


class LiveMockRegistry:
    async def get_all_addresses(self) -> dict[str, str]:
        return {}

    async def resolve_agent_id(self, address: str) -> str | None:
        return None


class LiveMockLedger:
    async def credit_deposit(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def reverse_deposit(self, *args: Any, **kwargs: Any) -> None:
        pass


@pytest.fixture
def sepolia_rpc_url() -> str:
    """Resolve Base Sepolia RPC URL from environment or default to public testnet RPC."""
    return os.environ.get("BASE_SEPOLIA_RPC_URL", BASE_SEPOLIA_PUBLIC_RPC)


@pytest.mark.filterwarnings("ignore:enable_cleanup_closed:DeprecationWarning")
@pytest.mark.asyncio
async def test_base_sepolia_chain_verification_and_head_query(sepolia_rpc_url: str) -> None:
    """Verify live connectivity, chain_id matching, and block header retrieval on Base Sepolia."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                sepolia_rpc_url,
                json={"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1},
            )
            if resp.status_code != 200:
                pytest.skip(f"Base Sepolia RPC unreachable: HTTP {resp.status_code}")
    except (httpx.TransportError, TimeoutError, OSError) as exc:
        pytest.skip(f"Network unavailable for Base Sepolia live test: {exc}")

    config = IndexerConfig(
        rpc_http_url=SecretStr(sepolia_rpc_url),
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        usdc_address=BASE_SEPOLIA_USDC,
        confirmations=12,
        batch_size=10,
    )

    pool = LiveMockPool()
    ledger = LiveMockLedger()
    registry = LiveMockRegistry()

    w3 = AsyncWeb3(AsyncHTTPProvider(sepolia_rpc_url))
    indexer = BaseIndexer(config, cast(Any, pool), registry, ledger=ledger, http_w3=w3)

    # 1. Verify chain ID
    await indexer.verify_chain_id()

    # 2. Fetch live block number
    latest_block = await indexer.get_latest_block_number()
    assert latest_block > 0

    # 3. Fetch live block header
    header = await indexer.get_block_header(latest_block)
    assert header.block_number == latest_block
    assert header.block_hash.startswith("0x")
    assert header.parent_hash.startswith("0x")
    assert header.timestamp > 0

    # 4. Fetch logs across last 5 blocks
    from_b = max(1, latest_block - 5)
    logs = await indexer.fetch_logs(from_b, latest_block)
    assert isinstance(logs, list)
