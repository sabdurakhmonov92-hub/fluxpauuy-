"""Pure unit tests for multi-chain RailConfig registry and generalized BaseL2Reader.

TASK 51: ETHEREUM RAIL: THE SECOND CHAIN VIA GENERALIZATION (BLOCK J)
Tests:
1. build_registry pure factory:
   - Both rails present when configured.
   - Base-only when Ethereum RPC is None.
   - Empty-safe when both are None.
   - Address and chain_id validation per rail (bad hex / invalid chain ID -> ValueError).
   - confirmations_min >= 1 validation.
2. Compat shim & deprecation path:
   - BaseL2Reader legacy base_* kwargs construct single-entry registry equal to base_usdc config.
   - Unknown rail dies at registry boundary before any network I/O.
3. Per-rail probe cache isolation:
   - Rail A probed, rail B independently probed.
   - Scripted chain mismatch on rail B raises IntegrationError and NEVER poisons rail A.
4. Finality knob unit validation:
   - Receipt with status=1 and confirmations < confirmations_min returns TxStatus(confirmed=False).
   - Receipt with status=1 and confirmations >= confirmations_min returns TxStatus(confirmed=True).
   - Reverted receipt (status=0) maps to TxStatus(confirmed=False, confirmations=0) permanently.
5. No-keys meta-test:
   - Verifies rails.py contains zero signing or private key tokens.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, is_dataclass
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from fluxpay.config import Settings
from fluxpay.integrations.base_l2 import BaseL2Reader, TxStatus
from fluxpay.integrations.rails import (
    RAIL_REGISTRY,
    RailConfig,
    build_registry,
)
from fluxpay.shared.errors import IntegrationError

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]


# -----------------------------------------------------------------------------
# Fake Web3 & Provider Infrastructure for Pure Unit Tests
# -----------------------------------------------------------------------------


class FakeEth:
    """Duck-typed Web3 eth namespace with per-rail scriptability."""

    def __init__(
        self,
        chain_id: int = 8453,
        block_number: int = 100,
        receipts: dict[str, Any] | None = None,
        decimals: int = 6,
        balances: dict[str, int] | None = None,
    ) -> None:
        self._chain_id = chain_id
        self._block_number = block_number
        self.receipts: dict[str, Any] = receipts or {}
        self._decimals = decimals
        self._balances = balances or {}
        self.chain_id_calls: int = 0

    @property
    async def chain_id(self) -> int:
        self.chain_id_calls += 1
        return self._chain_id

    def set_chain_id(self, new_id: int) -> None:
        self._chain_id = new_id

    @property
    async def block_number(self) -> int:
        return self._block_number

    def contract(self, address: str, abi: Any) -> FakeContract:
        return FakeContract(address, abi, self)

    async def get_transaction_receipt(self, tx_hash: str) -> Any:
        return self.receipts.get(tx_hash.lower())


class FakeContract:
    def __init__(self, address: str, abi: Any, eth: FakeEth) -> None:
        self.address = address
        self.abi = abi
        self.functions = FakeContractFunctions(eth)


class FakeContractFunctions:
    def __init__(self, eth: FakeEth) -> None:
        self._eth = eth

    def decimals(self) -> Any:
        class _Call:
            def __init__(self, val: int) -> None:
                self.val = val

            async def call(self) -> int:
                return self.val

        return _Call(self._eth._decimals)

    def balanceOf(self, address: str) -> Any:  # noqa: N802
        class _Call:
            def __init__(self, val: int) -> None:
                self.val = val

            async def call(self) -> int:
                return self.val

        bal = self._eth._balances.get(address.lower(), 0)
        return _Call(bal)


class FakeW3:
    def __init__(self, eth: FakeEth) -> None:
        self.eth = eth


@dataclass
class DummySettings:
    """Lightweight test configuration object for build_registry testing."""

    base_rpc_url: str | None = None
    base_chain_id: int = 8453
    base_usdc_address: str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    eth_rpc_url: str | None = None
    eth_chain_id: int = 1
    eth_usdc_address: str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    eth_confirmations_min: int = 1


# -----------------------------------------------------------------------------
# 1. BUILD_REGISTRY PURE FACTORY
# -----------------------------------------------------------------------------


def test_build_registry_both_rails_present() -> None:
    """Verify build_registry configures both rails when both RPC URLs are set."""
    settings = DummySettings(
        base_rpc_url="https://mainnet.base.org",
        base_chain_id=8453,
        base_usdc_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        eth_rpc_url="https://eth-mainnet.g.alchemy.com/v2/test",
        eth_chain_id=1,
        eth_usdc_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        eth_confirmations_min=3,
    )
    reg = build_registry(settings)

    assert "base_usdc" in reg
    assert "ethereum_usdc" in reg

    base_cfg = reg["base_usdc"]
    assert base_cfg.rail == "base_usdc"
    assert base_cfg.chain_id == 8453
    assert base_cfg.usdc_address == "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    assert base_cfg.rpc_url == "https://mainnet.base.org"
    assert base_cfg.confirmations_min == 1

    eth_cfg = reg["ethereum_usdc"]
    assert eth_cfg.rail == "ethereum_usdc"
    assert eth_cfg.chain_id == 1
    assert eth_cfg.usdc_address == "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    assert eth_cfg.rpc_url == "https://eth-mainnet.g.alchemy.com/v2/test"
    assert eth_cfg.confirmations_min == 3


def test_build_registry_base_only_when_eth_none() -> None:
    """Verify ethereum_usdc is omitted from registry when eth_rpc_url is None."""
    settings = DummySettings(
        base_rpc_url="https://mainnet.base.org",
        eth_rpc_url=None,
    )
    reg = build_registry(settings)

    assert "base_usdc" in reg
    assert "ethereum_usdc" not in reg


def test_build_registry_empty_safe() -> None:
    """Verify registry is empty dict when no RPC URLs are configured (disabled-mode law)."""
    settings = DummySettings(
        base_rpc_url=None,
        eth_rpc_url=None,
    )
    reg = build_registry(settings)
    assert reg == {}


def test_build_registry_with_real_pydantic_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify build_registry works directly with real Pydantic Settings instance."""
    monkeypatch.setenv("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)
    monkeypatch.setenv("FLX_BASE_RPC_URL", "https://mainnet.base.org")
    monkeypatch.setenv("FLX_ETH_RPC_URL", "https://eth-mainnet.alchemy.com")
    monkeypatch.setenv("FLX_ETH_CONFIRMATIONS_MIN", "5")

    settings = Settings()
    reg = build_registry(settings)
    assert "base_usdc" in reg
    assert "ethereum_usdc" in reg
    assert reg["ethereum_usdc"].confirmations_min == 5


def test_rail_config_validation_rules() -> None:
    """Verify RailConfig validations: bad hex address, invalid chain_id, confirmations_min < 1."""
    # 1. Invalid address (not 40 hex chars)
    with pytest.raises(ValueError, match="Invalid USDC contract address"):
        RailConfig(
            rail="base_usdc",
            chain_id=8453,
            usdc_address="0x123",  # Too short
            rpc_url="https://rpc",
            confirmations_min=1,
        )

    # 2. Invalid address (non-hex chars)
    with pytest.raises(ValueError, match="Invalid USDC contract address"):
        RailConfig(
            rail="ethereum_usdc",
            chain_id=1,
            usdc_address="0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            rpc_url="https://rpc",
            confirmations_min=1,
        )

    # 3. Invalid chain_id (<= 0)
    with pytest.raises(ValueError, match="Invalid chain_id"):
        RailConfig(
            rail="base_usdc",
            chain_id=0,
            usdc_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            rpc_url="https://rpc",
            confirmations_min=1,
        )

    # 4. Invalid confirmations_min (< 1)
    with pytest.raises(ValueError, match="Invalid confirmations_min"):
        RailConfig(
            rail="ethereum_usdc",
            chain_id=1,
            usdc_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            rpc_url="https://rpc",
            confirmations_min=0,
        )


def test_rail_config_slotted_dataclass() -> None:
    """Verify RailConfig is a frozen slotted dataclass."""
    assert is_dataclass(RailConfig)
    assert isinstance(RAIL_REGISTRY, dict)
    cfg = RailConfig(
        rail="base_usdc",
        chain_id=8453,
        usdc_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        rpc_url="https://mainnet.base.org",
        confirmations_min=1,
    )
    with pytest.raises(AttributeError):
        cfg.rail = "other"  # type: ignore[misc]


# -----------------------------------------------------------------------------
# 2. COMPAT SHIM & DEPRECATION PATH
# -----------------------------------------------------------------------------


def test_compat_shim_base_kwargs_to_registry() -> None:
    """Verify legacy base_* constructor kwargs build single-entry registry equal to base_usdc."""
    dummy_w3 = FakeW3(FakeEth())

    async def _dummy_resolver(rail: str) -> tuple[str, str]:
        return ("0x" + "1" * 40, "0x" + "2" * 40)

    reader = BaseL2Reader(
        resolver=_dummy_resolver,
        w3=dummy_w3,
        expected_chain_id=8453,
        usdc_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )

    # Internal registry was generated automatically
    reg = reader.registry
    assert "base_usdc" in reg
    assert len(reg) == 1
    assert reg["base_usdc"] == RailConfig(
        rail="base_usdc",
        chain_id=8453,
        usdc_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        rpc_url=None,
        confirmations_min=1,
    )


@pytest.mark.asyncio
async def test_unknown_rail_dies_at_registry_boundary() -> None:
    """Verify any query to a rail not in the registry immediately raises IntegrationError."""
    dummy_w3 = FakeW3(FakeEth())
    called = False

    async def _resolver(rail: str) -> tuple[str, str]:
        nonlocal called
        called = True
        return ("0x" + "1" * 40, "0x" + "2" * 40)

    reader = BaseL2Reader(resolver=_resolver, w3=dummy_w3)

    # 1. read_hot_balance on unregistered rail
    with pytest.raises(IntegrationError) as exc_hot:
        await reader.read_hot_balance("solana_usdc")
    assert exc_hot.value.details.get("phase") == "rail_check"
    assert exc_hot.value.details.get("rail") == "solana_usdc"
    assert not called

    # 2. read_cold_balance on unregistered rail
    with pytest.raises(IntegrationError) as exc_cold:
        await reader.read_cold_balance("polygon_usdc")
    assert exc_cold.value.details.get("phase") == "rail_check"
    assert exc_cold.value.details.get("rail") == "polygon_usdc"
    assert not called

    # 3. get_tx_status on unregistered rail
    with pytest.raises(IntegrationError) as exc_tx:
        await reader.get_tx_status("arbitrum_usdc", "0x" + "a" * 64)
    assert exc_tx.value.details.get("phase") == "rail_check"
    assert exc_tx.value.details.get("rail") == "arbitrum_usdc"

    # 4. probe on unregistered rail
    with pytest.raises(IntegrationError) as exc_probe:
        await reader.probe("tron_usdt")
    assert exc_probe.value.details.get("phase") == "rail_check"
    assert exc_probe.value.details.get("rail") == "tron_usdt"


# -----------------------------------------------------------------------------
# 3. PER-RAIL PROBE CACHE ISOLATION
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_per_rail_probe_cache_isolation() -> None:
    """Verify probe on rail A succeeds and caches, while scripted mismatch on rail B
    fails without poisoning rail A.
    """
    eth_base = FakeEth(chain_id=8453)
    eth_mainnet = FakeEth(chain_id=999)  # Scripted mismatch: expected 1, node returns 999

    w3_map = {
        "base_usdc": FakeW3(eth_base),
        "ethereum_usdc": FakeW3(eth_mainnet),
    }

    registry = {
        "base_usdc": RailConfig(
            rail="base_usdc",
            chain_id=8453,
            usdc_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            rpc_url="https://base-rpc",
            confirmations_min=1,
        ),
        "ethereum_usdc": RailConfig(
            rail="ethereum_usdc",
            chain_id=1,
            usdc_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            rpc_url="https://eth-rpc",
            confirmations_min=1,
        ),
    }

    async def _dummy_resolver(rail: str) -> tuple[str, str]:
        return ("0x" + "1" * 40, "0x" + "2" * 40)

    reader = BaseL2Reader(
        resolver=_dummy_resolver,
        w3=w3_map,
        registry=registry,
    )

    # 1. Probe rail A (base_usdc) -> succeeds
    base_id = await reader.probe("base_usdc")
    assert base_id == 8453
    assert reader._probed_rails["base_usdc"] is True

    # 2. Probe rail B (ethereum_usdc) -> fails with chain_id_mismatch
    with pytest.raises(IntegrationError) as exc_b:
        await reader.probe("ethereum_usdc")
    details_b = exc_b.value.details
    assert details_b.get("phase") == "chain_id_mismatch"
    assert details_b.get("expected") == "1"
    assert details_b.get("got") == "999"
    assert reader._probed_rails["ethereum_usdc"] is False

    # 3. Rail A is NOT poisoned: still True, does not trigger re-probe
    assert reader._probed_rails["base_usdc"] is True
    assert eth_base.chain_id_calls == 1

    # 4. Correct rail B node configuration and probe again
    eth_mainnet.set_chain_id(1)
    eth_id = await reader.probe("ethereum_usdc")
    assert eth_id == 1
    assert reader._probed_rails["ethereum_usdc"] is True


# -----------------------------------------------------------------------------
# 4. FINALITY KNOB UNIT TESTS
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_finality_knob_confirmations_threshold() -> None:
    """Verify that get_tx_status requires confirmations >= cfg.confirmations_min."""
    tx_hash = "0x" + "c" * 64
    eth = FakeEth(chain_id=1, block_number=100)
    w3 = FakeW3(eth)

    registry = {
        "ethereum_usdc": RailConfig(
            rail="ethereum_usdc",
            chain_id=1,
            usdc_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            rpc_url="https://eth-rpc",
            confirmations_min=3,  # Requires at least 3 blocks
        )
    }

    async def _dummy_resolver(rail: str) -> tuple[str, str]:
        return ("0x" + "1" * 40, "0x" + "2" * 40)

    reader = BaseL2Reader(
        resolver=_dummy_resolver,
        w3=w3,
        registry=registry,
    )

    # 1. Receipt with status=1, mined at block 100 (100 - 100 + 1 = 1 confirmation)
    # 1 < 3 -> confirmed=False
    eth.receipts[tx_hash.lower()] = {"status": 1, "blockNumber": 100}
    st1 = await reader.get_tx_status("ethereum_usdc", tx_hash)
    assert st1 == TxStatus(confirmed=False, confirmations=1)

    # 2. Receipt with status=1, mined at block 99 (100 - 99 + 1 = 2 confirmations)
    # 2 < 3 -> confirmed=False
    eth.receipts[tx_hash.lower()] = {"status": 1, "blockNumber": 99}
    st2 = await reader.get_tx_status("ethereum_usdc", tx_hash)
    assert st2 == TxStatus(confirmed=False, confirmations=2)

    # 3. Receipt with status=1, mined at block 98 (100 - 98 + 1 = 3 confirmations)
    # 3 >= 3 -> confirmed=True
    eth.receipts[tx_hash.lower()] = {"status": 1, "blockNumber": 98}
    st3 = await reader.get_tx_status("ethereum_usdc", tx_hash)
    assert st3 == TxStatus(confirmed=True, confirmations=3)

    # 4. Explicit confirmations attribute (e.g. 0 -> confirmed=False)
    eth.receipts[tx_hash.lower()] = {"status": 1, "confirmations": 0}
    st4 = await reader.get_tx_status("ethereum_usdc", tx_hash)
    assert st4 == TxStatus(confirmed=False, confirmations=0)

    # 5. Explicit confirmations attribute (e.g. 5 >= 3 -> confirmed=True)
    eth.receipts[tx_hash.lower()] = {"status": 1, "confirmations": 5}
    st5 = await reader.get_tx_status("ethereum_usdc", tx_hash)
    assert st5 == TxStatus(confirmed=True, confirmations=5)

    # 6. Reverted receipt (status=0) is permanently terminal (confirmed=False, 0)
    eth.receipts[tx_hash.lower()] = {"status": 0, "blockNumber": 90}
    st_revert = await reader.get_tx_status("ethereum_usdc", tx_hash)
    assert st_revert == TxStatus(confirmed=False, confirmations=0)


# -----------------------------------------------------------------------------
# 5. NO-KEYS META-TEST (RAILS.PY)
# -----------------------------------------------------------------------------


def test_no_keys_meta_test_rails() -> None:
    """Security invariant: rails.py must NEVER contain signing or private key tokens.

    Asserts absolute absence of:
    - "private_key"
    - "signing_key"
    - "mnemonic"
    - "Signer"
    - "Account.from_key"
    - "send_transaction"
    """
    rails_path = REPO_ROOT / "src" / "fluxpay" / "integrations" / "rails.py"
    assert rails_path.is_file(), f"rails.py not found at {rails_path}"

    forbidden_tokens = [
        "private_key",
        "signing_key",
        "mnemonic",
        "Signer",
        "Account.from_key",
        "send_transaction",
    ]

    content = rails_path.read_text(encoding="utf-8")
    for token in forbidden_tokens:
        assert token not in content, (
            f"SECURITY VIOLATION: Forbidden token '{token}' discovered in rails.py"
        )


# -----------------------------------------------------------------------------
# 6. SETTINGS & ENV SYNC VALIDATION
# -----------------------------------------------------------------------------


def test_settings_validators_eth_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate eth_usdc_address and eth_confirmations_min field validators in Settings."""
    monkeypatch.setenv("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)

    # Valid eth settings pass
    s = Settings(
        eth_usdc_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        eth_confirmations_min=2,
    )
    assert s.eth_usdc_address == "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    assert s.eth_confirmations_min == 2

    # Invalid address fails
    with pytest.raises(ValidationError):
        Settings(eth_usdc_address="0x123")

    # Invalid confirmations_min fails
    with pytest.raises(ValidationError):
        Settings(eth_confirmations_min=0)


def test_env_example_contains_task_51_settings() -> None:
    """Verify all Task 51 Settings fields are declared in .env.example."""
    env_example_path = REPO_ROOT / ".env.example"
    content = env_example_path.read_text(encoding="utf-8")

    declared_vars = set(re.findall(r"^(?:#\s*)?(FLX_[A-Z0-9_]+)=", content, re.MULTILINE))

    required_vars = [
        "FLX_ETH_RPC_URL",
        "FLX_ETH_CHAIN_ID",
        "FLX_ETH_USDC_ADDRESS",
        "FLX_ETH_CONFIRMATIONS_MIN",
    ]
    for var in required_vars:
        assert var in declared_vars, f"Missing {var} in .env.example"
