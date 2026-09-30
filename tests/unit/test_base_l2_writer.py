"""Unit tests for Base L2 On-Chain USDC Writer.

Comprehensive test suite verifying:
1. Protocol and security validations (checksum, zero address, self-transfer, amounts).
2. Pre-flight checks: Native gas (ETH) and ERC-20 token (USDC) balances.
3. EIP-1559 gas estimation with 20% safety margin.
4. Nonce management under per-hot-wallet asyncio.Lock and concurrent transfers.
5. Mempool nonce conflict detection and local water-mark re-syncing.
6. Execution revert handling (status=0) with revert reason extraction.
7. RPC transport retries, HTTP 429 rate limit backoff, and confirmation timeout.
8. Reorg detection (receipt dropping / block hash changing).
9. Key isolation and secret redaction invariants (LocalDev, AWS KMS, YubiHSM2).
10. Prometheus metrics emissions (FLX_HOT_WALLET_ETH_BALANCE, FLX_USDC_TRANSFERS_TOTAL, etc.).
"""

from __future__ import annotations

import asyncio
from decimal import Decimal
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from web3 import AsyncWeb3
from web3.exceptions import Web3RPCError
from web3.providers.async_base import AsyncBaseProvider
from web3.types import RPCResponse

from fluxpay.integrations.base_l2_writer import (
    BASE_MAINNET_CHAIN_ID,
    BASE_SEPOLIA_CHAIN_ID,
    BASE_USDC_CONTRACT,
    DEFAULT_MIN_GAS_THRESHOLD,
    FLX_HOT_WALLET_ETH_BALANCE,
    AwsKmsSigner,
    BaseL2Writer,
    BaseL2WriterError,
    InsufficientGasError,
    InsufficientUsdcError,
    InvalidAddressError,
    InvalidAmountError,
    LocalDevSigner,
    NonceConflictError,
    RpcRateLimitError,
    RpcTimeoutError,
    TransactionDroppedError,
    TransactionRevertedError,
    TransferReceipt,
    YubiHsmSigner,
)

pytestmark = pytest.mark.unit

TEST_PRIVATE_KEY: str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a0f367e15"
TEST_HOT_WALLET: str = "0xccB6b3d4E9479A83ccCcbaa2B641e328E70b274C"
TEST_RECIPIENT: str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
ZERO_ADDR: str = "0x0000000000000000000000000000000000000000"


# -----------------------------------------------------------------------------
# Scriptable Web3 Async Provider for In-Memory Unit Testing
# -----------------------------------------------------------------------------
class MockScriptableProvider(AsyncBaseProvider):
    """In-memory scriptable AsyncWeb3 provider for deterministic unit testing."""

    def __init__(
        self,
        *,
        chain_id: int = BASE_MAINNET_CHAIN_ID,
        block_number: int = 205,
        tx_block_number: int = 200,
        eth_balance_wei: int = (1 * 10**18),  # 1.0 ETH
        usdc_balance_minor: int = 1_000_000_000,  # 1,000 USDC
        nonce: int = 5,
        estimated_gas: int = 50_000,
        base_fee_wei: int = 1_000_000_000,  # 1 gwei
        priority_fee_wei: int = 1_000_000,  # 0.001 gwei
        receipt_status: int = 1,
        tx_hash: str = "0x" + "a" * 64,
        block_hash: str = "0x" + "b" * 64,
        gas_used: int = 42_000,
        send_raw_tx_error: Exception | None = None,
        receipts: dict[str, dict[str, Any] | None] | None = None,
        rate_limit_failures: int = 0,
        timeout_failures: int = 0,
    ) -> None:
        super().__init__()
        self.chain_id = chain_id
        self.block_number = block_number
        self.tx_block_number = tx_block_number
        self.eth_balance_wei = eth_balance_wei
        self.usdc_balance_minor = usdc_balance_minor
        self.nonce = nonce
        self.estimated_gas = estimated_gas
        self.base_fee_wei = base_fee_wei
        self.priority_fee_wei = priority_fee_wei
        self.receipt_status = receipt_status
        self.tx_hash = tx_hash
        self.block_hash = block_hash
        self.gas_used = gas_used
        self.send_raw_tx_error = send_raw_tx_error
        self.receipts = receipts if receipts is not None else {}
        self.rate_limit_failures = rate_limit_failures
        self.timeout_failures = timeout_failures
        self.recorded_requests: list[tuple[str, Any]] = []

    async def make_request(self, method: str, params: Any) -> RPCResponse:
        """Dispatch simulated JSON-RPC responses."""
        self.recorded_requests.append((method, params))

        if self.timeout_failures > 0:
            self.timeout_failures -= 1
            raise TimeoutError("Simulated RPC transport timeout")

        if self.rate_limit_failures > 0:
            self.rate_limit_failures -= 1
            raise Web3RPCError("HTTP 429 Too Many Requests: Rate limit exceeded")

        if method == "eth_chainId":
            return cast(
                RPCResponse,
                {"jsonrpc": "2.0", "id": 1, "result": hex(self.chain_id)},
            )

        if method == "eth_blockNumber":
            return cast(
                RPCResponse,
                {"jsonrpc": "2.0", "id": 1, "result": hex(self.block_number)},
            )

        if method == "eth_getBalance":
            return cast(
                RPCResponse,
                {"jsonrpc": "2.0", "id": 1, "result": hex(self.eth_balance_wei)},
            )

        if method == "eth_getTransactionCount":
            return cast(
                RPCResponse,
                {"jsonrpc": "2.0", "id": 1, "result": hex(self.nonce)},
            )

        if method == "eth_getBlockByNumber":
            return cast(
                RPCResponse,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "number": hex(self.block_number),
                        "baseFeePerGas": hex(self.base_fee_wei),
                        "hash": self.block_hash,
                    },
                },
            )

        if method == "eth_maxPriorityFeePerGas":
            return cast(
                RPCResponse,
                {"jsonrpc": "2.0", "id": 1, "result": hex(self.priority_fee_wei)},
            )

        if method == "eth_gasPrice":
            return cast(
                RPCResponse,
                {"jsonrpc": "2.0", "id": 1, "result": hex(self.base_fee_wei)},
            )

        if method == "eth_estimateGas":
            return cast(
                RPCResponse,
                {"jsonrpc": "2.0", "id": 1, "result": hex(self.estimated_gas)},
            )

        if method == "eth_sendRawTransaction":
            if self.send_raw_tx_error is not None:
                raise self.send_raw_tx_error
            return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": self.tx_hash})

        if method == "eth_getTransactionReceipt":
            target_hash = params[0] if params else self.tx_hash
            if target_hash in self.receipts:
                return cast(
                    RPCResponse,
                    {"jsonrpc": "2.0", "id": 1, "result": self.receipts[target_hash]},
                )
            return cast(
                RPCResponse,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "transactionHash": self.tx_hash,
                        "blockNumber": hex(self.tx_block_number),
                        "blockHash": self.block_hash,
                        "status": hex(self.receipt_status),
                        "gasUsed": hex(self.gas_used),
                        "effectiveGasPrice": hex(self.base_fee_wei + self.priority_fee_wei),
                    },
                },
            )

        if method == "eth_getTransactionByHash":
            return cast(
                RPCResponse,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "hash": self.tx_hash,
                        "blockNumber": hex(self.block_number),
                    },
                },
            )

        if method == "eth_call":
            call_obj = params[0] if params else {}
            data = call_obj.get("data", "")
            # decimals() selector
            if data.startswith("0x313ce567"):
                return cast(
                    RPCResponse,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": "0x" + "0" * 63 + "6",
                    },
                )
            # balanceOf(address) selector: 0x70a08231
            if data.startswith("0x70a08231"):
                hex_bal = hex(self.usdc_balance_minor)[2:].rjust(64, "0")
                return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": "0x" + hex_bal})

            # Return empty or simulate revert
            if self.receipt_status == 0:
                raise Web3RPCError("execution reverted: ERC20: transfer amount exceeds allowance")
            return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": "0x"})

        return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": None})


# -----------------------------------------------------------------------------
# Fixtures & Test Helpers
# -----------------------------------------------------------------------------
def make_test_writer(
    provider: MockScriptableProvider | None = None,
    signer: LocalDevSigner | None = None,
    min_gas_threshold: Decimal = DEFAULT_MIN_GAS_THRESHOLD,
    max_transfer_amount: Decimal = Decimal("100000"),
    default_confirmations: int = 1,
) -> tuple[BaseL2Writer, MockScriptableProvider, list[float]]:
    """Helper factory constructing BaseL2Writer with injected zero-sleep clock."""
    prov = provider if provider is not None else MockScriptableProvider()
    w3 = AsyncWeb3(prov)
    sig = signer if signer is not None else LocalDevSigner(TEST_PRIVATE_KEY)

    clock = [1000.0]
    sleeps: list[float] = []

    def mock_now() -> float:
        clock[0] += 0.05
        return clock[0]

    async def mock_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    writer = BaseL2Writer(
        signer=sig,
        w3=w3,
        chain_id=BASE_MAINNET_CHAIN_ID,
        usdc_address=BASE_USDC_CONTRACT,
        min_gas_threshold=min_gas_threshold,
        max_transfer_amount=max_transfer_amount,
        default_confirmations=default_confirmations,
        poll_interval_s=0.01,
        max_attempts=3,
        backoff_base_s=0.01,
        backoff_cap_s=0.05,
        sleep=mock_sleep,
        now=mock_now,
    )
    return writer, prov, sleeps


# -----------------------------------------------------------------------------
# Test Cases
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_successful_transfer_lifecycle() -> None:
    """Validate full end-to-end USDC transfer lifecycle and receipt generation."""
    writer, prov, _ = make_test_writer(default_confirmations=2)
    prov.block_number = 205  # 205 - 200 + 1 = 6 confirmations (> 2)

    receipt = await writer.transfer_usdc(
        to=TEST_RECIPIENT,
        amount=Decimal("150.50"),
        confirmations=2,
    )

    assert isinstance(receipt, TransferReceipt)
    assert receipt.tx_hash == prov.tx_hash
    assert receipt.to_address == TEST_RECIPIENT
    assert receipt.from_address == TEST_HOT_WALLET
    assert receipt.amount_usdc == Decimal("150.50")
    assert receipt.amount_minor == 150_500_000
    assert receipt.confirmations >= 2
    assert receipt.gas_used == 42_000
    assert receipt.duration_ms > 0

    # Verify metric emission
    val = FLX_HOT_WALLET_ETH_BALANCE._value.get()
    assert val == 1.0  # 1.0 ETH


@pytest.mark.asyncio
async def test_insufficient_gas_preflight_exhaustion() -> None:
    """Pre-flight check must raise InsufficientGasError if ETH balance < threshold."""
    prov = MockScriptableProvider(eth_balance_wei=int(0.001 * 10**18))  # 0.001 ETH < 0.005 ETH
    writer, _, _ = make_test_writer(provider=prov, min_gas_threshold=Decimal("0.005"))

    with pytest.raises(InsufficientGasError) as exc_info:
        await writer.transfer_usdc(to=TEST_RECIPIENT, amount=Decimal("10.00"))

    err = exc_info.value
    assert err.details["code"] == "INSUFFICIENT_GAS"
    assert "Top up gas wallet" in err.message


@pytest.mark.asyncio
async def test_insufficient_usdc_preflight_check() -> None:
    """Pre-flight check must raise InsufficientUsdcError if USDC balance < payout amount."""
    prov = MockScriptableProvider(usdc_balance_minor=50_000_000)  # 50 USDC
    writer, _, _ = make_test_writer(provider=prov)

    with pytest.raises(InsufficientUsdcError) as exc_info:
        await writer.transfer_usdc(to=TEST_RECIPIENT, amount=Decimal("100.00"))  # requires 100 USDC

    err = exc_info.value
    assert err.details["code"] == "INSUFFICIENT_USDC"
    assert err.details["required_minor"] == "100000000"


@pytest.mark.asyncio
async def test_tx_reverted_on_chain_with_reason() -> None:
    """Receipt status=0 must raise TransactionRevertedError with extracted revert reason."""
    prov = MockScriptableProvider(receipt_status=0)
    writer, _, _ = make_test_writer(provider=prov)

    with pytest.raises(TransactionRevertedError) as exc_info:
        await writer.transfer_usdc(to=TEST_RECIPIENT, amount=Decimal("10.00"))

    err = exc_info.value
    assert err.details["code"] == "TX_REVERTED"
    assert "reverted" in err.message.lower()


@pytest.mark.asyncio
async def test_nonce_conflict_resyncs_and_raises() -> None:
    """Nonce too low error during broadcast must raise NonceConflictError."""
    prov = MockScriptableProvider(
        send_raw_tx_error=Web3RPCError("nonce too low: address 0x2c... nonce 5 already used")
    )
    writer, _, _ = make_test_writer(provider=prov)

    with pytest.raises(NonceConflictError) as exc_info:
        await writer.transfer_usdc(to=TEST_RECIPIENT, amount=Decimal("10.00"))

    err = exc_info.value
    assert err.details["code"] == "NONCE_CONFLICT"
    assert err.details["wallet"] == TEST_HOT_WALLET


@pytest.mark.asyncio
async def test_concurrent_transfers_without_nonce_collision() -> None:
    """Concurrent transfers must allocate sequential nonces under the per-wallet lock."""
    prov = MockScriptableProvider(nonce=10)
    writer, _, _ = make_test_writer(provider=prov)

    # Launch two transfers concurrently
    task1 = asyncio.create_task(writer.transfer_usdc(to=TEST_RECIPIENT, amount=Decimal("1.00")))
    task2 = asyncio.create_task(writer.transfer_usdc(to=TEST_RECIPIENT, amount=Decimal("2.00")))

    receipt1, receipt2 = await asyncio.gather(task1, task2)
    assert receipt1.tx_hash is not None
    assert receipt2.tx_hash is not None
    # Next tracked nonce should advance monotonically to 12
    assert writer._next_nonces[TEST_HOT_WALLET] == 12


@pytest.mark.asyncio
async def test_rpc_rate_limit_backoff_and_exhaustion() -> None:
    """Upstream 429 rate limit must backoff with jitter and raise RpcRateLimitError if exhausted."""
    prov = MockScriptableProvider(rate_limit_failures=5)
    writer, _, sleeps = make_test_writer(provider=prov)

    with pytest.raises(RpcRateLimitError) as exc_info:
        await writer.transfer_usdc(to=TEST_RECIPIENT, amount=Decimal("10.00"))

    err = exc_info.value
    assert err.details["code"] == "RPC_RATE_LIMIT"
    assert len(sleeps) >= 2


@pytest.mark.asyncio
async def test_rpc_timeout_on_confirmation() -> None:
    """Exceeding timeout while waiting for receipt confirmations must raise RpcTimeoutError."""
    prov = MockScriptableProvider(block_number=200)
    writer, _, _ = make_test_writer(provider=prov)

    # 1 confirmation seen (200 - 200 + 1 = 1), but requires 10 confirmations
    with pytest.raises(RpcTimeoutError) as exc_info:
        await writer.transfer_usdc(
            to=TEST_RECIPIENT,
            amount=Decimal("10.00"),
            confirmations=10,
            timeout_s=0.02,
        )

    err = exc_info.value
    assert err.details["code"] == "RPC_TIMEOUT"


@pytest.mark.asyncio
async def test_reorg_detection_vanished_receipt() -> None:
    """Receipt vanishing after initially being seen mined must raise TransactionDroppedError."""
    tx_hash = "0x" + "c" * 64
    first_receipt = {
        "transactionHash": tx_hash,
        "blockNumber": hex(100),
        "blockHash": "0x" + "d" * 64,
        "status": hex(1),
        "gasUsed": hex(21000),
        "effectiveGasPrice": hex(1000000000),
    }
    # Initially returns first_receipt, then None (reorg drop)
    receipts_flow: dict[str, Any] = {tx_hash: first_receipt}
    prov = MockScriptableProvider(tx_hash=tx_hash, receipts=receipts_flow, block_number=100)
    writer, _, _ = make_test_writer(provider=prov)

    # We will simulate reorg by altering receipts_flow dynamically during wait
    original_get_receipt = prov.make_request
    receipt_calls = [0]

    async def flaky_make_request(method: str, params: Any) -> Any:
        if method == "eth_getTransactionReceipt":
            receipt_calls[0] += 1
            if receipt_calls[0] > 1:
                return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": None})
        return await original_get_receipt(method, params)

    prov.make_request = flaky_make_request  # type: ignore[method-assign]

    with pytest.raises(TransactionDroppedError) as exc_info:
        await writer.transfer_usdc(
            to=TEST_RECIPIENT,
            amount=Decimal("5.00"),
            confirmations=5,  # block 100 with current 100 has 1 confirmation, needs 5
            timeout_s=50.0,
        )

    assert exc_info.value.details["code"] == "TX_DROPPED"


# -----------------------------------------------------------------------------
# Input Validation & Security Rejections
# -----------------------------------------------------------------------------
def test_checksum_failure_rejection() -> None:
    """Non-checksummed address must be rejected with InvalidAddressError."""
    writer, _, _ = make_test_writer()
    lowercase_addr = TEST_RECIPIENT.lower()

    with pytest.raises(InvalidAddressError) as exc_info:
        writer.validate_destination_address(lowercase_addr)

    assert exc_info.value.details["code"] == "INVALID_ADDRESS"


def test_zero_address_rejection() -> None:
    """Transfer to zero address must be strictly prohibited."""
    writer, _, _ = make_test_writer()

    with pytest.raises(InvalidAddressError) as exc_info:
        writer.validate_destination_address(ZERO_ADDR)

    assert exc_info.value.details["code"] == "INVALID_ADDRESS"


def test_self_transfer_rejection() -> None:
    """Self-transfer to hot wallet address must be rejected."""
    writer, _, _ = make_test_writer()

    with pytest.raises(InvalidAddressError) as exc_info:
        writer.validate_destination_address(TEST_HOT_WALLET)

    assert exc_info.value.details["code"] == "INVALID_ADDRESS"


def test_invalid_address_format_rejection() -> None:
    """Malformed or non-hex string must be rejected."""
    writer, _, _ = make_test_writer()

    with pytest.raises(InvalidAddressError):
        writer.validate_destination_address("not_an_address")


def test_amount_validations() -> None:
    """Validate positive, ceiling, decimal, and float type constraints."""
    writer, _, _ = make_test_writer(max_transfer_amount=Decimal("10000"))

    # Float must be rejected with TypeError
    with pytest.raises(TypeError):
        writer.validate_amount(100.5)  # type: ignore[arg-type]

    # Zero or negative rejected
    with pytest.raises(InvalidAmountError):
        writer.validate_amount(Decimal("0"))
    with pytest.raises(InvalidAmountError):
        writer.validate_amount(Decimal("-10.00"))

    # Above max ceiling rejected
    with pytest.raises(InvalidAmountError):
        writer.validate_amount(Decimal("10001.00"))

    # Precision beyond 6 decimals rejected
    with pytest.raises(InvalidAmountError):
        writer.validate_amount(Decimal("10.1234567"))

    # Exactly 6 decimals converted correctly
    minor = writer.validate_amount(Decimal("10.123456"))
    assert minor == 10_123_456


# -----------------------------------------------------------------------------
# Signer Tests: LocalDev, AWS KMS, YubiHSM2
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_local_dev_signer_signing_and_key_isolation() -> None:
    """Verify LocalDevSigner signs txs and excludes key material from string repr."""
    signer = LocalDevSigner(TEST_PRIVATE_KEY)
    assert signer.address == TEST_HOT_WALLET

    # Secret isolation verification
    repr_str = repr(signer)
    str_val = str(signer)
    assert TEST_PRIVATE_KEY not in repr_str
    assert TEST_PRIVATE_KEY not in str_val
    assert "0x4c0883" not in repr_str

    tx_dict: dict[str, int | str | bytes] = {
        "chainId": BASE_MAINNET_CHAIN_ID,
        "from": TEST_HOT_WALLET,
        "to": TEST_RECIPIENT,
        "value": 0,
        "nonce": 1,
        "gas": 21000,
        "maxFeePerGas": 1000000000,
        "maxPriorityFeePerGas": 1000000,
        "data": b"",
        "type": 2,
    }

    signed_bytes = await signer.sign_transaction(tx_dict)
    assert isinstance(signed_bytes, bytes)
    assert len(signed_bytes) > 0
    assert signed_bytes[0] == 2  # EIP-1559 Type-2 envelope prefix

    signer.close()
    assert all(b == 0 for b in signer._key_bytes)


@pytest.mark.asyncio
async def test_aws_kms_signer_with_sign_fn() -> None:
    """Verify AwsKmsSigner computes low-s signature and recovers v correctly."""
    from eth_account import Account

    acct = Account.from_key(TEST_PRIVATE_KEY)

    async def mock_kms_sign(digest: bytes) -> bytes:
        from eth_account._utils.signing import sign_message_hash

        # Produce raw 64-byte r, s
        res = sign_message_hash(acct._key_obj, digest)
        r = int(res[1])
        s = int(res[2])
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    kms_signer = AwsKmsSigner(
        key_id="alias/fluxpay-hot-wallet",
        address=acct.address,
        sign_fn=mock_kms_sign,
    )
    assert kms_signer.address == acct.address
    assert "alias/fluxpay-hot-wallet" in repr(kms_signer)

    tx_dict: dict[str, int | str | bytes] = {
        "chainId": BASE_MAINNET_CHAIN_ID,
        "from": acct.address,
        "to": TEST_RECIPIENT,
        "value": 0,
        "nonce": 2,
        "gas": 25000,
        "maxFeePerGas": 1500000000,
        "maxPriorityFeePerGas": 2000000,
        "data": b"",
        "type": 2,
    }

    signed_bytes = await kms_signer.sign_transaction(tx_dict)
    assert isinstance(signed_bytes, bytes)
    assert signed_bytes[0] == 2


@pytest.mark.asyncio
async def test_yubi_hsm_signer_with_sign_fn() -> None:
    """Verify YubiHsmSigner processes transaction signing via sign_fn."""
    from eth_account import Account

    acct = Account.from_key(TEST_PRIVATE_KEY)

    async def mock_hsm_sign(digest: bytes) -> bytes:
        from eth_account._utils.signing import sign_message_hash

        res = sign_message_hash(acct._key_obj, digest)
        r = int(res[1])
        s = int(res[2])
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    hsm_signer = YubiHsmSigner(
        key_id=1,
        address=acct.address,
        sign_fn=mock_hsm_sign,
    )
    assert hsm_signer.address == acct.address
    assert "YubiHsmSigner" in str(hsm_signer)

    tx_dict: dict[str, int | str | bytes] = {
        "chainId": BASE_MAINNET_CHAIN_ID,
        "from": acct.address,
        "to": TEST_RECIPIENT,
        "value": 0,
        "nonce": 3,
        "gas": 21000,
        "maxFeePerGas": 1000000000,
        "maxPriorityFeePerGas": 1000000,
        "data": b"",
        "type": 2,
    }

    signed_bytes = await hsm_signer.sign_transaction(tx_dict)
    assert isinstance(signed_bytes, bytes)
    assert signed_bytes[0] == 2


@pytest.mark.asyncio
async def test_chain_id_probe_mismatch_raises() -> None:
    """Remote chain ID mismatch must raise BaseL2WriterError with CHAIN_ID_MISMATCH."""
    prov = MockScriptableProvider(chain_id=BASE_SEPOLIA_CHAIN_ID)  # 84532 != 8453
    writer, _, _ = make_test_writer(provider=prov)

    with pytest.raises(BaseL2WriterError) as exc_info:
        await writer.probe()

    assert exc_info.value.details["code"] == "CHAIN_ID_MISMATCH"


# -----------------------------------------------------------------------------
# Additional Branch Coverage & Exhaustive Invariant Tests
# -----------------------------------------------------------------------------
def test_metric_get_or_create_helpers() -> None:
    """Verify _get_or_create idempotency and exception branches."""
    from prometheus_client import CollectorRegistry

    from fluxpay.integrations.base_l2_writer import (
        _get_or_create_counter,
        _get_or_create_gauge,
        _get_or_create_histogram,
    )

    reg = CollectorRegistry()
    # 1. Counter
    c1 = _get_or_create_counter("test_cnt", "desc", ("label1",), registry=reg)
    c2 = _get_or_create_counter("test_cnt", "desc", ("label1",), registry=reg)
    assert c1 is c2

    # 2. Gauge
    g1 = _get_or_create_gauge("test_gauge", "desc", (), registry=reg)
    g2 = _get_or_create_gauge("test_gauge", "desc", (), registry=reg)
    assert g1 is g2

    # 3. Histogram
    h1 = _get_or_create_histogram("test_hist", "desc", (), (0.1, 0.5), registry=reg)
    h2 = _get_or_create_histogram("test_hist", "desc", (), (0.1, 0.5), registry=reg)
    assert h1 is h2

    # Collision with mismatched type raises ValueError
    with pytest.raises(ValueError):
        _get_or_create_gauge("test_cnt", "desc", (), registry=reg)
    with pytest.raises(ValueError):
        _get_or_create_counter("test_gauge", "desc", (), registry=reg)
    with pytest.raises(ValueError):
        _get_or_create_histogram("test_gauge", "desc", (), (0.1,), registry=reg)


def test_base_l2_writer_error_details_branches() -> None:
    """Verify BaseL2WriterError handles empty and populated details dicts."""
    err_no_details = BaseL2WriterError("test error", code="ERR_1")
    assert err_no_details.details == {"code": "ERR_1"}

    err_with_details = BaseL2WriterError("test error 2", code="ERR_2", details={"foo": "bar"})
    assert err_with_details.details == {"code": "ERR_2", "foo": "bar"}


def test_local_dev_signer_bytes_and_unprefixed_hex() -> None:
    """Verify LocalDevSigner accepts bytes and hex strings without 0x prefix."""
    raw_bytes = bytes.fromhex(TEST_PRIVATE_KEY[2:])
    signer_from_bytes = LocalDevSigner(raw_bytes)
    assert signer_from_bytes.address == TEST_HOT_WALLET

    unprefixed_hex = TEST_PRIVATE_KEY[2:]
    signer_from_unprefixed = LocalDevSigner(unprefixed_hex)
    assert signer_from_unprefixed.address == TEST_HOT_WALLET


@pytest.mark.asyncio
async def test_aws_kms_signer_client_and_error_branches() -> None:
    """Verify AwsKmsSigner with KMS client, DER signature, high-s normalization, and errors."""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from eth_account import Account

    from fluxpay.integrations.base_l2_writer import SECP256K1_N

    acct = Account.from_key(TEST_PRIVATE_KEY)

    # 1. Unconfigured signer raises BaseL2WriterError
    unconfigured = AwsKmsSigner(key_id="test-key", address=acct.address)
    with pytest.raises(BaseL2WriterError) as exc_info:
        await unconfigured.sign_transaction(
            {
                "chainId": 8453,
                "to": TEST_RECIPIENT,
                "value": 0,
                "nonce": 0,
                "gas": 21000,
                "maxFeePerGas": 1000,
                "maxPriorityFeePerGas": 100,
                "data": b"",
                "type": 2,
            }
        )
    assert exc_info.value.details["code"] == "KMS_UNCONFIGURED"

    # 2. KMS client with DER signature and high-s normalization
    class MockKmsClient:
        def sign(self, **kwargs: Any) -> dict[str, Any]:
            digest = kwargs["Message"]
            from eth_account._utils.signing import sign_message_hash

            res = sign_message_hash(acct._key_obj, digest)
            r = int(res[1])
            s = int(res[2])
            # Intentionally flip s to high-s (> N // 2) to test low-s normalization branch
            high_s = SECP256K1_N - s
            der_sig = encode_dss_signature(r, high_s)
            return {"Signature": der_sig}

    kms_client_signer = AwsKmsSigner(
        key_id="alias/test",
        address=acct.address,
        kms_client=MockKmsClient(),
    )
    assert "alias/test" in repr(kms_client_signer)
    assert acct.address in str(kms_client_signer)
    tx_dict: dict[str, int | str | bytes] = {
        "chainId": 8453,
        "from": acct.address,
        "to": TEST_RECIPIENT,
        "value": 0,
        "nonce": 1,
        "gas": 21000,
        "maxFeePerGas": 1000000000,
        "maxPriorityFeePerGas": 1000000,
        "data": b"",
        "type": 2,
    }
    signed_bytes = await kms_client_signer.sign_transaction(tx_dict)
    assert len(signed_bytes) > 0

    # 3. Test ValueError in Account._recover_hash (branch coverage for recovery error)
    def failing_recover(*args: Any, **kwargs: Any) -> str:
        raise ValueError("Invalid curve point")

    with patch.object(Account, "_recover_hash", side_effect=failing_recover):
        with pytest.raises(BaseL2WriterError) as exc_v:
            await kms_client_signer.sign_transaction(tx_dict)
        assert exc_v.value.details["code"] == "KMS_SIGNATURE_INVALID"

    # 4. Invalid signature (address mismatch triggers KMS_SIGNATURE_INVALID)
    other_acct = Account.create()
    invalid_addr_signer = AwsKmsSigner(
        key_id="alias/test",
        address=other_acct.address,  # address won't match signature from acct
        kms_client=MockKmsClient(),
    )
    with pytest.raises(BaseL2WriterError) as exc_info2:
        await invalid_addr_signer.sign_transaction(tx_dict)
    assert exc_info2.value.details["code"] == "KMS_SIGNATURE_INVALID"


@pytest.mark.asyncio
async def test_yubi_hsm_signer_session_and_error_branches() -> None:
    """Verify YubiHsmSigner with session, DER signature, high-s normalization, and errors."""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from eth_account import Account

    from fluxpay.integrations.base_l2_writer import SECP256K1_N

    acct = Account.from_key(TEST_PRIVATE_KEY)

    # 1. Unconfigured raises BaseL2WriterError
    unconfigured = YubiHsmSigner(key_id=1, address=acct.address)
    with pytest.raises(BaseL2WriterError) as exc_info:
        await unconfigured.sign_transaction(
            {
                "chainId": 8453,
                "to": TEST_RECIPIENT,
                "value": 0,
                "nonce": 0,
                "gas": 21000,
                "maxFeePerGas": 1000,
                "maxPriorityFeePerGas": 100,
                "data": b"",
                "type": 2,
            }
        )
    assert exc_info.value.details["code"] == "HSM_UNCONFIGURED"

    # 2. Session with DER signature and high-s
    class MockHsmSession:
        def sign_ecdsa_pkcs1v1_5(self, *, key_id: int, data: bytes) -> bytes:
            from eth_account._utils.signing import sign_message_hash

            res = sign_message_hash(acct._key_obj, data)
            r = int(res[1])
            s = int(res[2])
            high_s = SECP256K1_N - s
            return encode_dss_signature(r, high_s)

    session_signer = YubiHsmSigner(
        key_id=42,
        address=acct.address,
        session=MockHsmSession(),
    )
    assert repr(session_signer).startswith("<YubiHsmSigner")
    assert acct.address in str(session_signer)
    tx_dict: dict[str, int | str | bytes] = {
        "chainId": 8453,
        "from": acct.address,
        "to": TEST_RECIPIENT,
        "value": 0,
        "nonce": 1,
        "gas": 21000,
        "maxFeePerGas": 1000000000,
        "maxPriorityFeePerGas": 1000000,
        "data": b"",
        "type": 2,
    }
    signed_bytes = await session_signer.sign_transaction(tx_dict)
    assert len(signed_bytes) > 0

    # 3. Test ValueError in Account._recover_hash
    def failing_recover(*args: Any, **kwargs: Any) -> str:
        raise ValueError("Invalid curve point")

    with patch.object(Account, "_recover_hash", side_effect=failing_recover):
        with pytest.raises(BaseL2WriterError) as exc_hsm_v:
            await session_signer.sign_transaction(tx_dict)
        assert exc_hsm_v.value.details["code"] == "HSM_SIGNATURE_INVALID"

    # 4. Invalid signature triggers HSM_SIGNATURE_INVALID
    other_acct = Account.create()
    invalid_hsm = YubiHsmSigner(
        key_id=42,
        address=other_acct.address,
        session=MockHsmSession(),
    )
    with pytest.raises(BaseL2WriterError) as exc_info2:
        await invalid_hsm.sign_transaction(tx_dict)
    assert exc_info2.value.details["code"] == "HSM_SIGNATURE_INVALID"


@pytest.mark.asyncio
async def test_gas_parameters_estimation_fallbacks() -> None:
    """Verify gas parameter estimation handles missing base fee and missing priority fee."""

    # 1. Exception branch for priority fee (lines 1039-1040)
    class ExceptionProvider(MockScriptableProvider):
        async def make_request(self, method: str, params: Any) -> RPCResponse:
            if method == "eth_getBlockByNumber":
                return cast(
                    RPCResponse,
                    {"jsonrpc": "2.0", "id": 1, "result": {"number": hex(self.block_number)}},
                )
            if method == "eth_maxPriorityFeePerGas":
                raise RuntimeError("Node does not support eth_maxPriorityFeePerGas")
            return await super().make_request(method, params)

    writer_exc, _, _ = make_test_writer(provider=ExceptionProvider())
    gas_limit, max_fee, priority_fee = await writer_exc.estimate_gas_parameters(
        to=TEST_RECIPIENT,
        amount_minor=1000000,
        call_data=b"\xa9\x05\x9c\xbb",
    )
    assert gas_limit == int(50000 * 1.20)
    assert priority_fee == 1_000_000
    assert max_fee > 0

    # 2. Zero / negative priority fee fallback (line 1043)
    class ZeroFeeProvider(MockScriptableProvider):
        async def make_request(self, method: str, params: Any) -> RPCResponse:
            if method == "eth_maxPriorityFeePerGas":
                return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": "0x0"})
            return await super().make_request(method, params)

    writer_zero, _, _ = make_test_writer(provider=ZeroFeeProvider())
    _, _, priority_fee_zero = await writer_zero.estimate_gas_parameters(
        to=TEST_RECIPIENT,
        amount_minor=1000000,
        call_data=b"\xa9\x05\x9c\xbb",
    )
    assert priority_fee_zero == 1_000_000


@pytest.mark.asyncio
async def test_broadcast_formats_and_generic_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify allocate_and_broadcast handles bytes, unprefixed hex, and generic failures."""
    # 1. tx_hash returned as bytes
    prov_bytes = MockScriptableProvider()
    prov_bytes.tx_hash = b"\xde\xad" * 16  # type: ignore[assignment]
    writer1, _, _ = make_test_writer(provider=prov_bytes)
    h1, _n1 = await writer1.allocate_and_broadcast(
        call_data=b"",
        gas_limit=21000,
        max_fee_per_gas=1000,
        max_priority_fee_per_gas=100,
    )
    assert h1.startswith("0x")

    # 2. tx_hash returned as str with 0x prefix
    writer_s1, _, _ = make_test_writer()
    monkeypatch.setattr(
        writer_s1._w3.eth,
        "send_raw_transaction",
        AsyncMock(return_value="0x" + "11" * 32),
    )
    h_s1, _ = await writer_s1.allocate_and_broadcast(
        call_data=b"",
        gas_limit=21000,
        max_fee_per_gas=1000,
        max_priority_fee_per_gas=100,
    )
    assert h_s1 == "0x" + "11" * 32

    # 3. tx_hash returned as str without 0x prefix
    writer_s2, _, _ = make_test_writer()
    monkeypatch.setattr(
        writer_s2._w3.eth,
        "send_raw_transaction",
        AsyncMock(return_value="22" * 32),
    )
    h_s2, _ = await writer_s2.allocate_and_broadcast(
        call_data=b"",
        gas_limit=21000,
        max_fee_per_gas=1000,
        max_priority_fee_per_gas=100,
    )
    assert h_s2 == "0x" + "22" * 32

    # 4. tx_hash returned as custom bytearray/iterable
    writer_s3, _, _ = make_test_writer()
    monkeypatch.setattr(
        writer_s3._w3.eth,
        "send_raw_transaction",
        AsyncMock(return_value=bytearray(b"\x33" * 32)),
    )
    h_s3, _ = await writer_s3.allocate_and_broadcast(
        call_data=b"",
        gas_limit=21000,
        max_fee_per_gas=1000,
        max_priority_fee_per_gas=100,
    )
    assert h_s3 == "0x" + "33" * 32

    # 5. Rate limit 429 error during allocate_and_broadcast
    writer_429, _, _ = make_test_writer()
    monkeypatch.setattr(
        writer_429._w3.eth,
        "send_raw_transaction",
        AsyncMock(side_effect=RuntimeError("Rate limit exceeded 429")),
    )
    with pytest.raises(RpcRateLimitError):
        await writer_429.allocate_and_broadcast(
            call_data=b"",
            gas_limit=21000,
            max_fee_per_gas=1000,
            max_priority_fee_per_gas=100,
        )

    # 6. Generic unhandled error raises BaseL2WriterError with BROADCAST_FAILED
    prov_fail = MockScriptableProvider(send_raw_tx_error=RuntimeError("Mempool full error"))
    writer4, _, _ = make_test_writer(provider=prov_fail)
    with pytest.raises(BaseL2WriterError) as exc_info:
        await writer4.allocate_and_broadcast(
            call_data=b"",
            gas_limit=21000,
            max_fee_per_gas=1000,
            max_priority_fee_per_gas=100,
        )
    assert exc_info.value.details["code"] == "BROADCAST_FAILED"


@pytest.mark.asyncio
async def test_mempool_dropped_tx_and_shallow_reorg() -> None:
    """Verify detection of transaction dropped from mempool and shallow reorg."""
    # 1. Receipt is None, and get_transaction raises TransactionNotFound -> TransactionDroppedError
    tx_hash = "0x" + "e" * 64

    class DroppedProvider(MockScriptableProvider):
        async def make_request(self, method: str, params: Any) -> RPCResponse:
            if method == "eth_getTransactionReceipt":
                return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": None})
            if method == "eth_getTransactionByHash":
                return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": None})
            return await super().make_request(method, params)

    writer_drop, _, _ = make_test_writer(provider=DroppedProvider(tx_hash=tx_hash))
    with pytest.raises(TransactionDroppedError) as exc_info:
        await writer_drop.wait_for_confirmation(
            tx_hash=tx_hash,
            to=TEST_RECIPIENT,
            amount=Decimal("1.00"),
            amount_minor=1000000,
            call_data=b"",
            confirmations_required=1,
            timeout_s=5.0,
            start_time=1000.0,
        )
    assert exc_info.value.details["code"] == "TX_DROPPED"

    # 2. Receipt blockHash change (shallow reorg) and blockHash as bytes
    poll_count = [0]

    class ReorgProvider(MockScriptableProvider):
        async def make_request(self, method: str, params: Any) -> RPCResponse:
            if method == "eth_getTransactionReceipt":
                poll_count[0] += 1
                b_hash = b"\x01" * 32 if poll_count[0] == 1 else b"\x02" * 32
                return cast(
                    RPCResponse,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "transactionHash": self.tx_hash,
                            "blockNumber": hex(200),
                            "blockHash": b_hash,
                            "status": hex(1),
                            "gasUsed": hex(21000),
                            "effectiveGasPrice": hex(1000000000),
                        },
                    },
                )
            if method == "eth_blockNumber":
                # Return block 200 on poll 1 (1 conf), then block 202 on poll 2 (3 confs)
                b_num = 200 if poll_count[0] == 1 else 202
                return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": hex(b_num)})
            return await super().make_request(method, params)

    writer_reorg, _, _ = make_test_writer(provider=ReorgProvider(tx_hash=tx_hash))
    receipt = await writer_reorg.wait_for_confirmation(
        tx_hash=tx_hash,
        to=TEST_RECIPIENT,
        amount=Decimal("1.00"),
        amount_minor=1000000,
        call_data=b"",
        confirmations_required=2,
        timeout_s=50.0,
        start_time=1000.0,
    )
    assert receipt.confirmations >= 2

    # 3. Pending in mempool on poll 1, mined on poll 2 (1 conf), stable on poll 3 (2 confs)
    # Covers lines 1245-1246 (pending in mempool loop continuation)
    # and branch 1258->1268 (mined_block_hash == current_block_hash stable confirmation)
    poll_step = [0]
    stable_block_hash = "0x" + "aa" * 32

    class PendingThenStableProvider(MockScriptableProvider):
        async def make_request(self, method: str, params: Any) -> RPCResponse:
            if method == "eth_getTransactionReceipt":
                poll_step[0] += 1
                if poll_step[0] == 1:
                    # Pending: receipt is None
                    return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": None})
                # Mined in poll 2 and poll 3 with same stable block hash
                return cast(
                    RPCResponse,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "transactionHash": self.tx_hash,
                            "blockNumber": hex(200),
                            "blockHash": stable_block_hash,
                            "status": hex(1),
                            "gasUsed": hex(21000),
                            "effectiveGasPrice": hex(1000000000),
                        },
                    },
                )
            if method == "eth_getTransactionByHash":
                # In mempool on poll 1
                return cast(
                    RPCResponse,
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {"hash": self.tx_hash, "blockNumber": None},
                    },
                )
            if method == "eth_blockNumber":
                # Poll 2: 1 conf (block 200); Poll 3: 2 confs (block 201)
                b_num = 200 if poll_step[0] <= 2 else 201
                return cast(RPCResponse, {"jsonrpc": "2.0", "id": 1, "result": hex(b_num)})
            return await super().make_request(method, params)

    writer_pending, _, _ = make_test_writer(provider=PendingThenStableProvider(tx_hash=tx_hash))
    receipt_stable = await writer_pending.wait_for_confirmation(
        tx_hash=tx_hash,
        to=TEST_RECIPIENT,
        amount=Decimal("1.00"),
        amount_minor=1000000,
        call_data=b"",
        confirmations_required=2,
        timeout_s=50.0,
        start_time=1000.0,
    )
    assert receipt_stable.confirmations >= 2


@pytest.mark.asyncio
async def test_transfer_usdc_already_probed_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """When writer is already probed, transfer_usdc must skip probe call."""
    writer, _prov, _ = make_test_writer()
    probe_called = False

    async def mock_probe() -> int:
        nonlocal probe_called
        probe_called = True
        return 8453

    monkeypatch.setattr(writer, "probe", mock_probe)
    writer._probed = True
    await writer.transfer_usdc(to=TEST_RECIPIENT, amount=Decimal("1.00"), confirmations=1)
    assert not probe_called


@pytest.mark.asyncio
async def test_transfer_usdc_bytes_call_data(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify transfer_usdc handles raw bytes returned by ABI encoder."""
    writer, _, _ = make_test_writer()
    monkeypatch.setattr(
        writer._contract,
        "encode_abi",
        lambda *_: b"\xa9\x05\x9c\xbb" + b"\x00" * 64,
    )
    receipt = await writer.transfer_usdc(to=TEST_RECIPIENT, amount=Decimal("1.00"), confirmations=1)
    assert receipt.tx_hash.startswith("0x")


@pytest.mark.asyncio
async def test_rpc_ladder_transport_error_exhaustion() -> None:
    """Transport errors retried up to max_attempts and raised as RpcTimeoutError."""
    import httpx

    class FailingTransportProvider(MockScriptableProvider):
        async def make_request(self, method: str, params: Any) -> RPCResponse:
            raise httpx.TransportError("Simulated socket drop")

    writer, _, _ = make_test_writer(provider=FailingTransportProvider())
    with pytest.raises(RpcTimeoutError) as exc_info:
        await writer.probe()
    assert exc_info.value.details["error"] == "TransportError"
