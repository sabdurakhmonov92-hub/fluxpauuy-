"""Pure unit tests for Base L2 On-Chain Observation Reader.

TASK 50: BASE L2 READER: ON-CHAIN OBSERVATION (BLOCK J, PART 2)
Verifies:
1. Protocol conformance: BaseL2Reader and NullReader satisfy OnChainReader protocol.
2. Rail gate: unknown rail raises IntegrationError before any I/O.
3. Tx hash validation matrix: 64-hex requirement, case-insensitivity,
   non-hex/wrong-length rejections.
4. Runtime decimals guard (10^12 defense): decimals != 6 raises typed
   IntegrationError (phase="decimals").
5. Chain ID probe & caching: mismatch raises typed IntegrationError (phase="chain_id_mismatch");
   failed probe is not cached; success caches self._probed.
6. Receipt mapping matrix: None -> (False, 0); status=0 (reverted) -> (False, 0);
   status=1 -> (True, latest - block + 1).
7. NullReader disabled mode: raises IntegrationError("reader not configured") on all methods.
8. Config validators & .env.example sync: validates base_usdc_address regex and .env sync.
9. No-keys meta-test: confirms absence of signing tokens in base_l2.py.
10. Error registry untouched: validates no unapproved error classes added.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from fluxpay.config import Settings
from fluxpay.integrations.base_l2 import (
    BALANCE_OF_SELECTOR,
    DECIMALS_SELECTOR,
    ERC20_MIN_ABI,
    BaseL2Reader,
    NullReader,
    TxStatus,
)
from fluxpay.shared.errors import ERROR_REGISTRY, IntegrationError
from fluxpay.treasury.reader import OnChainReader

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]


# -----------------------------------------------------------------------------
# Fake W3 Duck-Type for Pure Unit Tests
# -----------------------------------------------------------------------------


class FakeFunctionCall:
    """Wraps a callable returning an awaitable value."""

    def __init__(self, value: Any) -> None:
        self._value = value

    async def call(self) -> Any:
        if isinstance(self._value, Exception):
            raise self._value
        return self._value


class FakeContractFunctions:
    """Simulates minimal ERC-20 contract functions: balanceOf and decimals."""

    def __init__(self, balances: dict[str, int] | None = None, decimals_val: int = 6) -> None:
        self.balances: dict[str, int] = balances or {}
        self.decimals_val: int = decimals_val
        self.balance_calls: list[str] = []

    def balanceOf(self, owner: str) -> FakeFunctionCall:  # noqa: N802
        self.balance_calls.append(owner)
        return FakeFunctionCall(self.balances.get(owner.lower(), 0))

    def decimals(self) -> FakeFunctionCall:
        return FakeFunctionCall(self.decimals_val)


class FakeContract:
    """Minimal contract object matching Web3 contract API."""

    def __init__(self, address: str, abi: Any, functions: FakeContractFunctions) -> None:
        self.address = address
        self.abi = abi
        self.functions = functions


class FakeEth:
    """Duck-type for Web3 eth namespace."""

    def __init__(
        self,
        chain_id: int = 8453,
        block_number: int = 100,
        receipts: dict[str, Any] | None = None,
        contract_functions: FakeContractFunctions | None = None,
    ) -> None:
        self._chain_id = chain_id
        self._block_number = block_number
        self.receipts: dict[str, Any] = receipts or {}
        self.contract_functions = contract_functions or FakeContractFunctions()
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
        return FakeContract(address, abi, self.contract_functions)

    async def get_transaction_receipt(self, tx_hash: str) -> Any:
        return self.receipts.get(tx_hash.lower())


class FakeW3:
    """Duck-type for Web3 top-level object."""

    def __init__(self, eth: FakeEth) -> None:
        self.eth = eth


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture
def fake_addresses() -> tuple[str, str]:
    return (
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
    )


@pytest.fixture
def fake_resolver(fake_addresses: tuple[str, str]) -> Any:
    async def _resolve(rail: str) -> tuple[str, str]:
        if rail != "base_usdc":
            raise ValueError(f"Unknown rail: {rail}")
        return fake_addresses

    return _resolve


# -----------------------------------------------------------------------------
# 1. PROTOCOL CONFORMANCE & NULL READER
# -----------------------------------------------------------------------------


def test_protocol_conformance_isinstance(fake_resolver: Any) -> None:
    """Verify BaseL2Reader and NullReader both satisfy OnChainReader protocol."""
    eth = FakeEth()
    w3 = FakeW3(eth)
    reader = BaseL2Reader(resolver=fake_resolver, w3=w3)

    assert isinstance(reader, OnChainReader)
    assert isinstance(NullReader(), OnChainReader)


@pytest.mark.asyncio
async def test_null_reader_raises_integration_error() -> None:
    """Verify NullReader raises IntegrationError on all methods."""
    reader = NullReader()

    with pytest.raises(IntegrationError) as exc_hot:
        await reader.read_hot_balance("base_usdc")
    assert "reader not configured" in str(exc_hot.value)
    assert exc_hot.value.details.get("phase") == "unconfigured"

    with pytest.raises(IntegrationError) as exc_cold:
        await reader.read_cold_balance("base_usdc")
    assert "reader not configured" in str(exc_cold.value)
    assert exc_cold.value.details.get("phase") == "unconfigured"

    with pytest.raises(IntegrationError) as exc_tx:
        await reader.get_tx_status("base_usdc", "0x" + "a" * 64)
    assert "reader not configured" in str(exc_tx.value)
    assert exc_tx.value.details.get("phase") == "unconfigured"


# -----------------------------------------------------------------------------
# 2. RAIL GATE
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rail_gate_unknown_rail_raises_before_io(fake_resolver: Any) -> None:
    """Verify unknown rail raises IntegrationError before invoking resolver or w3."""
    called = False

    async def _poison_resolver(rail: str) -> tuple[str, str]:
        nonlocal called
        called = True
        return ("0x1", "0x2")

    eth = FakeEth()
    w3 = FakeW3(eth)
    reader = BaseL2Reader(resolver=_poison_resolver, w3=w3)

    with pytest.raises(IntegrationError) as exc_info:
        await reader.read_hot_balance("ethereum_usdc")
    assert exc_info.value.details.get("phase") == "rail_check"
    assert exc_info.value.details.get("rail") == "ethereum_usdc"
    assert not called, "AddressResolver should NOT be called on invalid rail"

    with pytest.raises(IntegrationError) as exc_cold:
        await reader.read_cold_balance("arbitrum")
    assert exc_cold.value.details.get("phase") == "rail_check"
    assert not called

    with pytest.raises(IntegrationError) as exc_tx:
        await reader.get_tx_status("polygon", "0x" + "a" * 64)
    assert exc_tx.value.details.get("phase") == "rail_check"


# -----------------------------------------------------------------------------
# 3. TRANSACTION HASH VALIDATION MATRIX
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "valid_hash",
    [
        "0x" + "a" * 64,  # standard lowercase
        "0x" + "A" * 64,  # standard uppercase (VALID hex — accepted case-insensitively)
        "0x" + ("1234567890abcdefABCDEF" * 3)[:64],  # mixed case 64-hex
    ],
)
async def test_tx_hash_valid_formats(fake_resolver: Any, valid_hash: str) -> None:
    """Verify valid 64-hex transaction hashes are accepted case-insensitively."""
    eth = FakeEth(receipts={valid_hash.lower(): {"status": 1, "blockNumber": 100}})
    w3 = FakeW3(eth)
    reader = BaseL2Reader(resolver=fake_resolver, w3=w3)

    status = await reader.get_tx_status("base_usdc", valid_hash)
    assert status.confirmed is True
    assert status.confirmations == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid_hash",
    [
        "0x" + "a" * 63,  # length 63 hex chars (too short)
        "0x" + "a" * 65,  # length 65 hex chars (too long)
        "a" * 64,  # missing 0x prefix
        "0x" + "a" * 63 + "g",  # non-hex character 'g'
        "0x" + "z" * 64,  # non-hex characters
        "",  # empty string
        "0x",  # only prefix
    ],
)
async def test_tx_hash_invalid_formats_raise_value_error(
    fake_resolver: Any, invalid_hash: str
) -> None:
    """Verify malformed transaction hashes raise ValueError immediately."""
    eth = FakeEth()
    w3 = FakeW3(eth)
    reader = BaseL2Reader(resolver=fake_resolver, w3=w3)

    with pytest.raises(ValueError) as exc_info:
        await reader.get_tx_status("base_usdc", invalid_hash)
    assert "Invalid transaction hash format" in str(exc_info.value)


# -----------------------------------------------------------------------------
# 4. RUNTIME DECIMALS GUARD (THE 10^12 DEFENSE)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_decimals", [18, 8, 0, 12])
async def test_decimals_not_six_raises_integration_error(
    fake_resolver: Any, bad_decimals: int
) -> None:
    """Verify decimals != 6 raises IntegrationError with phase='decimals'."""
    funcs = FakeContractFunctions(decimals_val=bad_decimals)
    eth = FakeEth(contract_functions=funcs)
    w3 = FakeW3(eth)
    reader = BaseL2Reader(resolver=fake_resolver, w3=w3)

    with pytest.raises(IntegrationError) as exc_info:
        await reader.read_hot_balance("base_usdc")

    details = exc_info.value.details
    assert details.get("phase") == "decimals"
    assert details.get("expected") == "6"
    assert details.get("got") == str(bad_decimals)


# -----------------------------------------------------------------------------
# 5. CHAIN ID PROBE & CACHING
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chain_id_mismatch_and_probe_caching(fake_resolver: Any) -> None:
    """Verify chain ID mismatch raises IntegrationError, does not cache on failure,
    and caches on success.
    """
    eth = FakeEth(chain_id=1)  # Ethereum mainnet (mismatch for Base 8453)
    w3 = FakeW3(eth)
    reader = BaseL2Reader(resolver=fake_resolver, w3=w3, expected_chain_id=8453)

    # 1. First attempt fails
    with pytest.raises(IntegrationError) as exc_info:
        await reader.probe()

    details = exc_info.value.details
    assert details.get("phase") == "chain_id_mismatch"
    assert details.get("expected") == "8453"
    assert details.get("got") == "1"
    assert not reader._probed

    # 2. Re-probing after failure still attempts probe (not cached)
    with pytest.raises(IntegrationError):
        await reader.probe()
    assert eth.chain_id_calls == 2

    # 3. Simulate human fixing config/RPC node to correct chain ID 8453
    eth.set_chain_id(8453)
    got_id = await reader.probe()
    assert got_id == 8453
    assert bool(reader._probed)
    assert eth.chain_id_calls == 3

    # 4. Subsequent read does not re-probe (cached on success)
    funcs = FakeContractFunctions(balances={"0x1111111111111111111111111111111111111111": 500})
    eth.contract_functions = funcs
    balance = await reader.read_hot_balance("base_usdc")
    assert balance == 500
    assert eth.chain_id_calls == 3, "Successful probe must be cached, no extra eth_chainId calls"


# -----------------------------------------------------------------------------
# 6. RECEIPT MAPPING MATRIX
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_receipt_mapping_matrix(fake_resolver: Any) -> None:
    """Verify receipt status mapping: None -> (False, 0), status 0 -> (False, 0),
    status 1 -> (True, confirmations).
    """
    tx_hash = "0x" + "b" * 64
    eth = FakeEth(block_number=100)
    w3 = FakeW3(eth)
    reader = BaseL2Reader(resolver=fake_resolver, w3=w3)

    # Case A: Receipt is None (pending or unknown)
    st_none = await reader.get_tx_status("base_usdc", tx_hash)
    assert st_none == TxStatus(confirmed=False, confirmations=0)

    # Case B: Receipt status == 0 (reverted execution: TERMINAL FAILURE)
    eth.receipts[tx_hash.lower()] = {"status": 0, "blockNumber": 95}
    st_reverted = await reader.get_tx_status("base_usdc", tx_hash)
    assert st_reverted == TxStatus(confirmed=False, confirmations=0)

    # Case C: Receipt status == 1, mined in same block (confirmations = 100 - 100 + 1 = 1)
    eth.receipts[tx_hash.lower()] = {"status": 1, "blockNumber": 100}
    st_mined_latest = await reader.get_tx_status("base_usdc", tx_hash)
    assert st_mined_latest == TxStatus(confirmed=True, confirmations=1)

    # Case D: Receipt status == 1, mined 10 blocks ago (confirmations = 100 - 90 + 1 = 11)
    eth.receipts[tx_hash.lower()] = {"status": 1, "blockNumber": 90}
    st_mined_past = await reader.get_tx_status("base_usdc", tx_hash)
    assert st_mined_past == TxStatus(confirmed=True, confirmations=11)


# -----------------------------------------------------------------------------
# 7. MINOR-UNITS IDENTITY LAW
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_minor_units_identity_law(
    fake_resolver: Any, fake_addresses: tuple[str, str]
) -> None:
    """Verify raw uint256 balanceOf is returned 1:1 without alteration."""
    hot_addr, cold_addr = fake_addresses
    funcs = FakeContractFunctions(
        balances={
            hot_addr.lower(): 123_456_789,
            cold_addr.lower(): 987_654_321,
        }
    )
    eth = FakeEth(contract_functions=funcs)
    w3 = FakeW3(eth)
    reader = BaseL2Reader(resolver=fake_resolver, w3=w3)

    hot_bal = await reader.read_hot_balance("base_usdc")
    cold_bal = await reader.read_cold_balance("base_usdc")

    assert hot_bal == 123_456_789
    assert cold_bal == 987_654_321


# -----------------------------------------------------------------------------
# 8. CONFIG VALIDATOR & .ENV.EXAMPLE SYNC
# -----------------------------------------------------------------------------


def test_base_usdc_address_validator(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Settings validates base_usdc_address regex ^0x[0-9a-fA-F]{40}$."""
    monkeypatch.setenv("FLX_PG_DSN", "postgresql://test:test@localhost:5432/test")
    monkeypatch.setenv("FLX_VAULT_MASTER_KEY", "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")
    monkeypatch.setenv("FLX_WEBHOOK_SIGNING_KEY", "a" * 32)
    monkeypatch.setenv("FLX_KEYCLOAK_JWKS_URL", "https://idp.local/jwks")
    monkeypatch.setenv("FLX_KEYCLOAK_ISSUER", "https://idp.local")
    monkeypatch.setenv("FLX_KEYCLOAK_AUDIENCE", "https://api.local")

    # Valid address passes
    settings = Settings(base_usdc_address="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
    assert settings.base_usdc_address == "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

    # Non-hex or invalid lengths fail
    with pytest.raises(ValidationError):
        Settings(base_usdc_address="0x123")  # too short

    with pytest.raises(ValidationError):
        Settings(base_usdc_address="1234567890123456789012345678901234567890")  # missing 0x

    with pytest.raises(ValidationError):
        Settings(base_usdc_address="0x" + "g" * 40)  # non-hex char


def test_env_example_contains_task_50_settings() -> None:
    """Verify all Task 50 Settings fields are declared in .env.example."""
    env_example_path = REPO_ROOT / ".env.example"
    content = env_example_path.read_text(encoding="utf-8")

    declared_vars = set(re.findall(r"^(?:#\s*)?(FLX_[A-Z0-9_]+)=", content, re.MULTILINE))

    required_vars = [
        "FLX_BASE_RPC_URL",
        "FLX_BASE_CHAIN_ID",
        "FLX_BASE_USDC_ADDRESS",
        "FLX_BASE_READER_TIMEOUT_S",
    ]
    for var in required_vars:
        assert var in declared_vars, f"Missing {var} in .env.example"


# -----------------------------------------------------------------------------
# 9. NO-KEYS META-TEST (TASK 44 EXTENSION TO BASE_L2.PY)
# -----------------------------------------------------------------------------


def test_no_keys_meta_test_base_l2() -> None:
    """Security invariant: base_l2.py must NEVER contain signing or private key tokens.

    Asserts absolute absence of:
    - "private_key"
    - "signing_key"
    - "mnemonic"
    - "Signer"
    - "Account.from_key"
    - "send_transaction"
    """
    base_l2_path = REPO_ROOT / "src" / "fluxpay" / "integrations" / "base_l2.py"
    assert base_l2_path.is_file(), f"base_l2.py not found at {base_l2_path}"

    forbidden_tokens = [
        "private_key",
        "signing_key",
        "mnemonic",
        "Signer",
        "Account.from_key",
        "send_transaction",
    ]

    content = base_l2_path.read_text(encoding="utf-8")
    for token in forbidden_tokens:
        assert token not in content, (
            f"SECURITY VIOLATION: Forbidden token '{token}' discovered in base_l2.py"
        )


# -----------------------------------------------------------------------------
# 10. ERROR REGISTRY UNTOUCHED
# -----------------------------------------------------------------------------


def test_error_registry_untouched() -> None:
    """Ensure Task 50 added no unapproved error classes to the core registry."""
    # The registry was frozen prior to Task 50 with exactly 12 domain errors.
    # BaseClient errors remain modular in shared.errors without polluting the core registry.
    assert "integration_error" not in ERROR_REGISTRY
    assert "base_l2_error" not in ERROR_REGISTRY


# -----------------------------------------------------------------------------
# 11. CONSTANTS INTEGRITY
# -----------------------------------------------------------------------------


def test_constants_selectors() -> None:
    """Validate ERC20 minimal selectors and ABI structure."""
    assert BALANCE_OF_SELECTOR == "0x70a08231"
    assert DECIMALS_SELECTOR == "0x313ce567"
    assert len(ERC20_MIN_ABI) == 2
    names = {fn["name"] for fn in ERC20_MIN_ABI}
    assert names == {"balanceOf", "decimals"}
