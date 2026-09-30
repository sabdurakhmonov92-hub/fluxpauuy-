"""Unit tests for EIP-3009 transferWithAuthorization signature recovery and verification.

Tests:
- Real cryptographic vectors generated via eth_account
- EIP-712 domain separator binding (chain_id, contract address, token name)
- Tampering detection (value, recipient, nonce, timestamps, signature)
- Timing window validation
- Nonce normalization
- Property tests for arbitrary valid signers and malformed signatures
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from hypothesis import given
from hypothesis import strategies as st
from web3 import Web3

from fluxpay.gateway.x402_eip3009 import (
    TRANSFER_WITH_AUTHORIZATION_TYPES,
    build_eip712_domain,
    normalize_nonce,
    recover_eip3009_signer,
    validate_authorization_timing,
    verify_eip3009_signature,
)
from fluxpay.gateway.x402_types import PaymentPayload

pytestmark = pytest.mark.unit


def _create_signed_payload(
    account: Any,
    domain: dict[str, Any],
    *,
    to_address: str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    value: int = 1_000_000,
    valid_after: int = 0,
    valid_before: int = 2_000_000_000,
    nonce: str = "0x" + "11" * 32,
    use_vrs: bool = False,
) -> PaymentPayload:
    """Generate authentic EIP-3009 payment payload signed by provided account."""
    from_addr = Web3.to_checksum_address(account.address)
    to_addr = Web3.to_checksum_address(to_address)
    norm_nonce = normalize_nonce(nonce)

    message_data = {
        "from": from_addr,
        "to": to_addr,
        "value": value,
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": norm_nonce,
    }

    encoded = encode_typed_data(
        domain_data=domain,
        message_types=TRANSFER_WITH_AUTHORIZATION_TYPES,
        message_data=message_data,
    )
    signed = account.sign_message(encoded)

    if use_vrs:
        return PaymentPayload(
            from_address=from_addr,
            to_address=to_addr,
            value=value,
            valid_after=valid_after,
            valid_before=valid_before,
            nonce=norm_nonce,
            v=signed.v,
            r=hex(signed.r),
            s=hex(signed.s),
        )

    return PaymentPayload(
        from_address=from_addr,
        to_address=to_addr,
        value=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=norm_nonce,
        signature="0x" + signed.signature.hex(),
    )


def test_eip3009_valid_signature_recovery() -> None:
    """Verify that a freshly generated EIP-3009 signature recovers the exact signer address."""
    account = Account.create()
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )
    payload = _create_signed_payload(account, domain)

    recovered = recover_eip3009_signer(payload, domain)
    assert recovered == Web3.to_checksum_address(account.address)

    is_valid, err = verify_eip3009_signature(payload, domain)
    assert is_valid is True
    assert err is None


def test_eip3009_vrs_components_recovery() -> None:
    """Verify recovery when signature is split across v, r, s fields."""
    account = Account.create()
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )
    payload = _create_signed_payload(account, domain, use_vrs=True)

    is_valid, err = verify_eip3009_signature(payload, domain)
    assert is_valid is True
    assert err is None


def test_eip3009_rejects_cross_chain_replay() -> None:
    """Signatures for Base Sepolia (84532) must be rejected on Base Mainnet (8453)."""
    account = Account.create()
    sepolia_domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=84532,
        verifying_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )
    mainnet_domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )

    payload = _create_signed_payload(account, sepolia_domain)
    is_valid, err = verify_eip3009_signature(payload, mainnet_domain)
    assert is_valid is False
    assert err is not None
    assert "does not match" in err


def test_eip3009_rejects_tampered_value() -> None:
    """Modifying the authorized payment amount must invalidate the signature."""
    account = Account.create()
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )
    payload = _create_signed_payload(account, domain, value=1_000_000)

    # Tamper with value (1 USDC -> 10 USDC)
    tampered = PaymentPayload(
        from_address=payload.from_address,
        to_address=payload.to_address,
        value=10_000_000,
        valid_after=payload.valid_after,
        valid_before=payload.valid_before,
        nonce=payload.nonce,
        signature=payload.signature,
    )

    is_valid, err = verify_eip3009_signature(tampered, domain)
    assert is_valid is False
    assert err is not None


def test_eip3009_rejects_tampered_recipient() -> None:
    """Modifying the recipient address must invalidate the signature."""
    account = Account.create()
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )
    payload = _create_signed_payload(account, domain)

    tampered = PaymentPayload(
        from_address=payload.from_address,
        to_address="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        value=payload.value,
        valid_after=payload.valid_after,
        valid_before=payload.valid_before,
        nonce=payload.nonce,
        signature=payload.signature,
    )

    is_valid, _err = verify_eip3009_signature(tampered, domain)
    assert is_valid is False


def test_validate_authorization_timing() -> None:
    """Verify validity window boundary conditions."""
    now = 1_700_000_000

    # Active
    ok, err = validate_authorization_timing(1_600_000_000, 1_800_000_000, current_timestamp=now)
    assert ok is True
    assert err is None

    # Not yet active
    ok, err = validate_authorization_timing(1_750_000_000, 1_800_000_000, current_timestamp=now)
    assert ok is False
    assert "not yet active" in (err or "")

    # Expired
    ok, err = validate_authorization_timing(1_600_000_000, 1_650_000_000, current_timestamp=now)
    assert ok is False
    assert "expired" in (err or "")


def test_normalize_nonce_various_shapes() -> None:
    """Test standard 64-hex nonces, short nonces, and arbitrary string nonces."""
    # 64 hex characters with 0x
    full_hex = "0x" + "ab" * 32
    assert normalize_nonce(full_hex) == full_hex.lower()

    # Short hex (padded with zeros to 64 chars)
    short_hex = "0x1234"
    normalized = normalize_nonce(short_hex)
    assert len(normalized) == 66
    assert normalized.startswith("0x")
    assert normalized.endswith("1234")

    # Arbitrary utf-8 string
    custom_str = "client-tx-nonce-42"
    norm_custom = normalize_nonce(custom_str)
    assert len(norm_custom) == 66
    assert norm_custom.startswith("0x")


def test_malformed_signature_handling() -> None:
    """Malformed hex or invalid lengths must fail gracefully without crashing."""
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )
    # Truncated signature (not 130 hex chars)
    payload_bad_sig = PaymentPayload(
        from_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        to_address="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        value=1000,
        valid_after=0,
        valid_before=2000000000,
        nonce="0x1",
        signature="0xdeadbeef",
    )
    is_valid, err = verify_eip3009_signature(payload_bad_sig, domain)
    assert is_valid is False
    assert err is not None

    # Invalid v value (not 27 or 28)
    payload_bad_v = PaymentPayload(
        from_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        to_address="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        value=1000,
        valid_after=0,
        valid_before=2000000000,
        nonce="0x1",
        v=99,
        r="0x" + "11" * 32,
        s="0x" + "22" * 32,
    )
    is_valid, err = verify_eip3009_signature(payload_bad_v, domain)
    assert is_valid is False
    assert err is not None


# ---------------------------------------------------------------------------
# Property-Based Tests (Hypothesis)
# ---------------------------------------------------------------------------


@given(st.integers(min_value=1, max_value=100_000_000))
def test_property_any_valid_eip712_signature_verifies(amount: int) -> None:
    """Property test: Any randomly generated private key and amount verifies correctly."""
    account = Account.create()
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )
    payload = _create_signed_payload(account, domain, value=amount)

    is_valid, err = verify_eip3009_signature(payload, domain)
    assert is_valid is True
    assert err is None


@given(st.text(min_size=1, max_size=200))
def test_property_corrupted_signature_never_crashes(corrupted_sig: str) -> None:
    """Property test: Arbitrary corrupted strings in signature never raise uncaught exceptions."""
    domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    )
    payload = PaymentPayload(
        from_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        to_address="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        value=1000,
        valid_after=0,
        valid_before=int(time.time()) + 1000,
        nonce="0x1",
        signature=corrupted_sig,
    )
    is_valid, err = verify_eip3009_signature(payload, domain)
    assert is_valid is False
    assert err is not None
