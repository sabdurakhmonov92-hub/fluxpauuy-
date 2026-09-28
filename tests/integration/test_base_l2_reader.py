"""Integration tests for Base L2 On-Chain Observation Reader.

TASK 50: BASE L2 READER: ON-CHAIN OBSERVATION (BLOCK J, PART 2)
Proves full-stack composition across Blocks I & J (Tasks 44, 45, 49, 50):
1. Resolver wiring & ABI calldata proof: addresses from wallet_state flow into
   balanceOf calls; Web3 generates exact 32-byte left-padded calldata.
2. HotWalletMonitor composition: Task 44's monitor + BaseL2Reader + seeded wallet_state
   -> run_once -> caches updated from on-chain truth.
3. Cold payout confirmation composition: Task 45's confirm_if_ready advances executed
   payout to confirmed on status=1; status=0 (reverted) stays executed for stuck triage.
4. BaseClient retry ladder through RPC: transient httpx.TransportError drops retry
   with backoff up to max_attempts and succeed.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import asyncpg  # type: ignore[import-untyped]
import httpx
import pytest
import pytest_asyncio
from web3 import AsyncWeb3
from web3.providers.async_base import AsyncBaseProvider

from fluxpay.integrations.base_l2 import (
    BALANCE_OF_SELECTOR,
    DECIMALS_SELECTOR,
    BaseL2Reader,
)
from fluxpay.treasury.monitor import HotWalletMonitor
from fluxpay.treasury.payouts import PayoutService

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
MIGRATION_0006_PATH = REPO_ROOT / "migrations" / "0006_audit.sql"
MIGRATION_0011_PATH = REPO_ROOT / "migrations" / "0011_treasury.sql"

SCALE = 1_000_000_000
LOW_WATER = 50 * SCALE
HIGH_WATER = 200 * SCALE

HOT_SEED_ADDR = "0x1111111111111111111111111111111111111111"
COLD_SEED_ADDR = "0x2222222222222222222222222222222222222222"
USDC_CONTRACT_ADDR = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"


# -----------------------------------------------------------------------------
# Recording & Scriptable Web3 Async Provider
# -----------------------------------------------------------------------------


class RecordingRpcProvider(AsyncBaseProvider):
    """Real Web3 AsyncBaseProvider that records calldata and returns scripted responses.

    Exercises the true Web3 ABI encoding pipeline while keeping network I/O in-process.
    """

    def __init__(
        self,
        *,
        chain_id: int = 8453,
        balances: dict[str, int] | None = None,
        receipts: dict[str, dict[str, Any]] | None = None,
        block_number: int = 100,
        transport_failures_remaining: int = 0,
    ) -> None:
        super().__init__()
        self.chain_id = chain_id
        self.balances = balances or {}
        self.receipts = receipts or {}
        self.block_number = block_number
        self.transport_failures_remaining = transport_failures_remaining
        self.recorded_calls: list[dict[str, Any]] = []

    async def make_request(self, method: str, params: Any) -> Any:
        """Process JSON-RPC requests via in-memory handler or simulate transport drops."""
        if self.transport_failures_remaining > 0:
            self.transport_failures_remaining -= 1
            raise httpx.TransportError("Simulated RPC transport connection drop")

        if method == "eth_chainId":
            return {"jsonrpc": "2.0", "id": 1, "result": hex(self.chain_id)}

        if method == "eth_blockNumber":
            return {"jsonrpc": "2.0", "id": 1, "result": hex(self.block_number)}

        if method == "eth_getTransactionReceipt":
            tx_hash = params[0].lower() if params else ""
            receipt = self.receipts.get(tx_hash)
            return {"jsonrpc": "2.0", "id": 1, "result": receipt}

        if method == "eth_call":
            call_obj = params[0]
            to_addr = call_obj.get("to")
            data = call_obj.get("data", "")
            self.recorded_calls.append({"to": to_addr, "data": data})

            # Selector: decimals()
            if data.startswith(DECIMALS_SELECTOR):
                # 6 decimals encoded as uint8
                return {"jsonrpc": "2.0", "id": 1, "result": "0x" + (6).to_bytes(32, "big").hex()}

            # Selector: balanceOf(address)
            if data.startswith(BALANCE_OF_SELECTOR):
                # Target address is the 20 bytes following 12 bytes of padding
                padded_target = data[10:]  # strip 0x + 8 hex selector chars
                target_hex = "0x" + padded_target[24:]
                balance_val = self.balances.get(target_hex.lower(), 0)
                encoded_bal = "0x" + balance_val.to_bytes(32, "big").hex()
                return {"jsonrpc": "2.0", "id": 1, "result": encoded_bal}

            return {"jsonrpc": "2.0", "id": 1, "result": "0x0"}

        return {"jsonrpc": "2.0", "id": 1, "result": None}


# -----------------------------------------------------------------------------
# Database Fixtures
# -----------------------------------------------------------------------------


@pytest_asyncio.fixture
async def apply_treasury_schema(db_pool: asyncpg.Pool) -> None:
    """Execute migrations/0006_audit.sql and 0011_treasury.sql idempotently."""
    async with db_pool.acquire() as conn:
        if MIGRATION_0006_PATH.exists():
            await conn.execute(MIGRATION_0006_PATH.read_text(encoding="utf-8"))
        await conn.execute(MIGRATION_0011_PATH.read_text(encoding="utf-8"))


@pytest_asyncio.fixture(autouse=True)
async def clean_treasury_tables(
    db_pool: asyncpg.Pool,
    apply_treasury_schema: None,
) -> AsyncGenerator[None, None]:
    """Isolate tests by purging cold_payouts and restoring wallet_state seed."""
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM payout_approvals;")
        await conn.execute("DELETE FROM cold_payouts;")
        await conn.execute(
            """
            UPDATE wallet_state
            SET hot_address = $1,
                cold_address = $2,
                hot_balance_minor = 0,
                cold_balance_minor = 0,
                low_water_minor = $3,
                high_water_minor = $4,
                last_synced_at = NULL,
                sync_status = 'never'
            WHERE rail = 'base_usdc';
            """,
            HOT_SEED_ADDR,
            COLD_SEED_ADDR,
            LOW_WATER,
            HIGH_WATER,
        )
    yield
    async with db_pool.acquire() as conn:
        await conn.execute("DELETE FROM payout_approvals;")
        await conn.execute("DELETE FROM cold_payouts;")


# -----------------------------------------------------------------------------
# DB Address Resolver Factory
# -----------------------------------------------------------------------------


def make_db_address_resolver(pool: asyncpg.Pool) -> Any:
    """Create an AddressResolver reading directly from the authoritative wallet_state table."""

    async def _resolve(rail: str) -> tuple[str, str]:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT hot_address, cold_address FROM wallet_state WHERE rail = $1;",
                rail,
            )
            if row is None:
                raise ValueError(f"No wallet_state entry for rail: {rail}")
            return (
                AsyncWeb3.to_checksum_address(row["hot_address"]),
                AsyncWeb3.to_checksum_address(row["cold_address"]),
            )

    return _resolve


# -----------------------------------------------------------------------------
# 1. RESOLVER WIRING & ABI CALLDATA PROOF
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolver_wiring_and_abi_calldata_proof(db_pool: asyncpg.Pool) -> None:
    """Prove addresses from wallet_state row flow into Web3 and generate correctly
    padded calldata.
    """
    provider = RecordingRpcProvider(
        balances={
            HOT_SEED_ADDR.lower(): 150 * SCALE,
            COLD_SEED_ADDR.lower(): 1000 * SCALE,
        }
    )
    w3 = AsyncWeb3(provider)
    resolver = make_db_address_resolver(db_pool)

    async with httpx.AsyncClient() as http:
        reader = BaseL2Reader(resolver=resolver, w3=w3, http=http)

        hot_bal = await reader.read_hot_balance("base_usdc")
        cold_bal = await reader.read_cold_balance("base_usdc")

    assert hot_bal == 150 * SCALE
    assert cold_bal == 1000 * SCALE

    # Verify Web3 ABI encoding generated exact calldata with 12 bytes of zero padding
    balance_calls = [
        c for c in provider.recorded_calls if c["data"].startswith(BALANCE_OF_SELECTOR)
    ]
    assert len(balance_calls) == 2

    # Check hot address call
    hot_call = balance_calls[0]
    assert hot_call["to"].lower() == USDC_CONTRACT_ADDR.lower()
    hot_calldata = hot_call["data"]
    # 0x70a08231 + 24 zeros + 40 hex chars of hot address
    expected_hot_padded = "000000000000000000000000" + HOT_SEED_ADDR[2:].lower()
    assert hot_calldata[10:].lower() == expected_hot_padded

    # Check cold address call
    cold_call = balance_calls[1]
    cold_calldata = cold_call["data"]
    expected_cold_padded = "000000000000000000000000" + COLD_SEED_ADDR[2:].lower()
    assert cold_calldata[10:].lower() == expected_cold_padded


# -----------------------------------------------------------------------------
# 2. MONITOR COMPOSITION (TASK 44 + TASK 50 CLICK)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hot_wallet_monitor_composition(db_pool: asyncpg.Pool) -> None:
    """Prove Task 44 HotWalletMonitor + BaseL2Reader + seeded wallet_state syncs full-stack."""
    hot_units = 150 * SCALE
    cold_units = 1000 * SCALE
    provider = RecordingRpcProvider(
        balances={
            HOT_SEED_ADDR.lower(): hot_units,
            COLD_SEED_ADDR.lower(): cold_units,
        }
    )
    w3 = AsyncWeb3(provider)
    resolver = make_db_address_resolver(db_pool)
    alerts: list[str] = []

    async def _capture_alert(msg: str) -> None:
        alerts.append(msg)

    async with httpx.AsyncClient() as http:
        reader = BaseL2Reader(resolver=resolver, w3=w3, http=http)
        fixed_now = datetime(2026, 9, 27, 15, 0, 0, tzinfo=UTC).timestamp()

        monitor = HotWalletMonitor(
            pool=db_pool,
            reader=reader,
            alert=_capture_alert,
            now=lambda: fixed_now,
            rail="base_usdc",
        )

        report = await monitor.run_once()

    assert report.synced is True
    assert report.hot_balance == hot_units
    assert report.cold_balance == cold_units
    assert report.verdict.action == "ok"
    assert len(alerts) == 0

    # Verify wallet_state row updated from on-chain truth
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM wallet_state WHERE rail = 'base_usdc';")
        assert row is not None
        assert row["hot_balance_minor"] == hot_units
        assert row["cold_balance_minor"] == cold_units
        assert row["sync_status"] == "ok"
        assert row["last_synced_at"] is not None


# -----------------------------------------------------------------------------
# 3. TASK 45 COLD PAYOUT CONFIRMATION COMPOSITION
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cold_payout_confirmation_composition(db_pool: asyncpg.Pool) -> None:
    """Prove Task 45 PayoutService + BaseL2Reader: status=1 confirms; status=0 stays executed."""
    tx_hash_success = "0x" + "1" * 64
    tx_hash_reverted = "0x" + "2" * 64

    provider = RecordingRpcProvider(
        receipts={
            tx_hash_success.lower(): {"status": 1, "blockNumber": 95},
            tx_hash_reverted.lower(): {"status": 0, "blockNumber": 96},
        },
        block_number=100,
    )
    w3 = AsyncWeb3(provider)
    resolver = make_db_address_resolver(db_pool)
    alerts: list[str] = []

    async def _capture_alert(msg: str) -> None:
        alerts.append(msg)

    async with httpx.AsyncClient() as http:
        reader = BaseL2Reader(resolver=resolver, w3=w3, http=http)
        service = PayoutService(pool=db_pool, reader=reader, alert=_capture_alert)

        # --- Case A: Successful On-Chain Transaction (status=1 -> confirmed) ---
        p1 = await service.request(
            rail="base_usdc",
            to_address=COLD_SEED_ADDR,
            amount_minor=25 * SCALE,
            currency="USDC",
            reason="surplus_sweep",
            requested_by_sub="system",
        )
        await service.vote(
            payout_id=p1.payout_id, voter_sub="admin_a", voter_role="admin", vote="approve"
        )
        await service.vote(
            payout_id=p1.payout_id, voter_sub="admin_b", voter_role="admin", vote="approve"
        )
        await service.record_execution(
            payout_id=p1.payout_id,
            tx_hash=tx_hash_success,
            recorded_by_sub="admin_b",
        )

        # Confirm if ready: reader observes status=1 -> advances to 'confirmed'
        confirmed_payout = await service.confirm_if_ready(payout_id=p1.payout_id)
        assert confirmed_payout is not None
        assert confirmed_payout.status == "confirmed"

        # --- Case B: Reverted On-Chain Transaction (status=0 -> stays executed) ---
        p2 = await service.request(
            rail="base_usdc",
            to_address=COLD_SEED_ADDR,
            amount_minor=15 * SCALE,
            currency="USDC",
            reason="surplus_sweep",
            requested_by_sub="system",
        )
        await service.vote(
            payout_id=p2.payout_id, voter_sub="admin_a", voter_role="admin", vote="approve"
        )
        await service.vote(
            payout_id=p2.payout_id, voter_sub="admin_b", voter_role="admin", vote="approve"
        )
        await service.record_execution(
            payout_id=p2.payout_id,
            tx_hash=tx_hash_reverted,
            recorded_by_sub="admin_b",
        )

        # Confirm if ready: reader observes status=0 -> returns None, stays executed
        reverted_result = await service.confirm_if_ready(payout_id=p2.payout_id)
        assert reverted_result is None

        # Verify DB state: p2 remains executed awaiting operator triage via classify_stuck
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT status FROM cold_payouts WHERE payout_id = $1;", p2.payout_id
            )
            assert row is not None
            assert row["status"] == "executed"


# -----------------------------------------------------------------------------
# 4. BASE CLIENT LADDER THROUGH RPC
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_base_client_ladder_composes_through_rpc(db_pool: asyncpg.Pool) -> None:
    """Prove BaseClient retry ladder handles 2 transient RPC drops and succeeds on attempt 3."""
    provider = RecordingRpcProvider(
        balances={HOT_SEED_ADDR.lower(): 777 * SCALE},
        transport_failures_remaining=2,  # Fail attempt 1 and 2, succeed attempt 3
    )
    w3 = AsyncWeb3(provider)
    resolver = make_db_address_resolver(db_pool)

    sleep_calls: list[float] = []

    async def _mock_sleep(s: float) -> None:
        sleep_calls.append(s)

    async with httpx.AsyncClient() as http:
        reader = BaseL2Reader(
            resolver=resolver,
            w3=w3,
            http=http,
            max_attempts=3,
            backoff_base_s=0.5,
            backoff_cap_s=4.0,
            sleep=_mock_sleep,
        )

        # Read hot balance should succeed on 3rd attempt via ladder
        balance = await reader.read_hot_balance("base_usdc")

    assert balance == 777 * SCALE
    assert len(sleep_calls) == 2, "Expected exactly 2 backoff sleeps for 2 dropped attempts"
    assert sleep_calls[0] >= 0.5
    assert sleep_calls[1] >= 1.0
