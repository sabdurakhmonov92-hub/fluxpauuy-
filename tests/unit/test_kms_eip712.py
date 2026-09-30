"""Unit tests for EIP-712 and EIP-191 cryptographic hashing and EIP-3009 gasless payouts."""

from __future__ import annotations

import time

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from fluxpay.gateway.x402_eip3009 import (
    build_eip712_domain,
    recover_eip3009_signer,
    verify_eip3009_signature,
)
from fluxpay.gateway.x402_types import PaymentPayload
from fluxpay.shared.kms_eip712 import (
    BASE_USDC_CONTRACT,
    build_eip3009_transfer_payload,
    build_usdc_domain,
    compute_domain_separator,
    hash_eip191_message,
    hash_eip712_message,
)
from fluxpay.shared.kms_local import LocalDevSigner

pytestmark = pytest.mark.unit


def test_eip712_domain_separator_matches_usdc_on_base() -> None:
    """Assert domain separator matches canonical USDC contract binding on Base L2."""
    domain = build_usdc_domain(
        chain_id=8453,
        verifying_contract=BASE_USDC_CONTRACT,
        name="USD Coin",
        version="2",
    )
    separator = compute_domain_separator(domain)
    assert len(separator) == 32

    # Cross-verify against gateway implementation
    gw_domain = build_eip712_domain(
        name="USD Coin",
        version="2",
        chain_id=8453,
        verifying_contract=BASE_USDC_CONTRACT,
    )
    gw_signable = encode_typed_data(
        domain_data=gw_domain,
        message_types={"Empty": []},
        message_data={},
    )
    gw_separator = gw_signable.header
    assert separator == gw_separator


def test_eip712_domain_separator_base_sepolia() -> None:
    """Verify domain separator binding for Base Sepolia testnet."""
    sepolia_usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    mainnet_sep = compute_domain_separator(build_usdc_domain(chain_id=8453))
    sepolia_sep = compute_domain_separator(
        build_usdc_domain(chain_id=84532, verifying_contract=sepolia_usdc)
    )
    # Different chain_id and contract MUST result in distinct domain separators
    assert mainnet_sep != sepolia_sep


@pytest.mark.asyncio
async def test_eip3009_authorization_signing_and_verification() -> None:
    """Sign EIP-3009 payload using LocalDevSigner and verify with gateway recovery logic."""
    raw_key = "0x" + "a1" * 32
    signer = LocalDevSigner(private_key=raw_key)
    sender_addr = await signer.get_address()
    recipient_addr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

    payload_dict = build_eip3009_transfer_payload(
        from_address=sender_addr,
        to_address=recipient_addr,
        value=5_000_000,  # 5 USDC
        valid_after=0,
        valid_before=int(time.time()) + 3600,
        nonce="0x" + "22" * 32,
        chain_id=8453,
        verifying_contract=BASE_USDC_CONTRACT,
    )

    sig_bytes = await signer.sign_typed_data(payload_dict)
    assert len(sig_bytes) == 65

    # Verify with eth-account recovery
    digest = hash_eip712_message(payload_dict)
    recovered = Account._recover_hash(
        digest,
        vrs=(
            sig_bytes[64],
            int.from_bytes(sig_bytes[:32], "big"),
            int.from_bytes(sig_bytes[32:64], "big"),
        ),
    )
    assert recovered.lower() == sender_addr.lower()

    # Verify with x402 gateway verifier
    payload_obj = PaymentPayload(
        from_address=sender_addr,
        to_address=recipient_addr,
        value=5_000_000,
        valid_after=0,
        valid_before=int(time.time()) + 3600,
        nonce="0x" + "22" * 32,
        signature="0x" + sig_bytes.hex(),
    )
    recovered_gw = recover_eip3009_signer(
        payload_obj,
        domain=payload_dict["domain"],
    )
    assert recovered_gw.lower() == sender_addr.lower()
    assert verify_eip3009_signature(payload_obj, domain=payload_dict["domain"])


@pytest.mark.asyncio
async def test_eip191_message_signing_and_recovery() -> None:
    """Sign arbitrary text and bytes payload with EIP-191 and verify recovery."""
    raw_key = "0x" + "b2" * 32
    signer = LocalDevSigner(private_key=raw_key)
    signer_addr = await signer.get_address()

    # Test with bytes
    msg_bytes = b"FluxPay Autonomous Agent Escrow Authorization"
    sig_bytes = await signer.sign_message(msg_bytes)
    assert len(sig_bytes) == 65

    from eth_account.messages import encode_defunct

    signable = encode_defunct(primitive=msg_bytes)
    recovered_addr = Account.recover_message(signable, signature=sig_bytes)
    assert recovered_addr.lower() == signer_addr.lower()

    # Test hash_eip191_message with str
    hash_str = hash_eip191_message("FluxPay String Message")
    assert len(hash_str) == 32


def test_eip712_nonce_variants_and_sub_dictionaries() -> None:
    """Test build_eip3009_transfer_payload nonce formats and hash_eip712_message sub-dicts."""
    from fluxpay.shared.kms_eip712 import (
        TRANSFER_WITH_AUTHORIZATION_TYPES,
        build_eip3009_transfer_payload,
        build_usdc_domain,
    )

    # 1. Nonce as bytes
    p1 = build_eip3009_transfer_payload(
        from_address="0x" + "11" * 20,
        to_address="0x" + "22" * 20,
        value=1000,
        valid_after=0,
        valid_before=1000,
        nonce=b"\xab" * 32,
    )
    assert p1["message"]["nonce"] == "0x" + ("ab" * 32)

    # 2. Nonce as un-prefixed hex string
    p2 = build_eip3009_transfer_payload(
        from_address="0x" + "11" * 20,
        to_address="0x" + "22" * 20,
        value=1000,
        valid_after=0,
        valid_before=1000,
        nonce="cd" * 32,
    )
    assert p2["message"]["nonce"] == "0x" + ("cd" * 32)

    # 3. hash_eip712_message without primaryType
    domain = build_usdc_domain(chain_id=8453)
    types = {
        "TransferWithAuthorization": TRANSFER_WITH_AUTHORIZATION_TYPES["TransferWithAuthorization"],
    }
    digest = hash_eip712_message({"domain": domain, "types": types, "message": p1["message"]})
    assert len(digest) == 32
