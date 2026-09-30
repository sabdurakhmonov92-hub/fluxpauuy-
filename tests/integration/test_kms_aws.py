"""Integration tests for live AWS KMS Secp256k1 signing on Base Sepolia (Chain ID 84532).

Opt-in test suite requiring live AWS credentials and an asymmetric SECP256K1 KMS key.
Run via:
    pytest -m "aws" tests/integration/test_kms_aws.py
"""

from __future__ import annotations

import os

import pytest
from eth_account import Account
from web3 import Web3

from fluxpay.shared.kms_aws import AWSKMSSigner
from fluxpay.shared.kms_eip712 import build_eip3009_transfer_payload

pytestmark = [pytest.mark.aws, pytest.mark.integration]

BASE_SEPOLIA_CHAIN_ID = 84532
BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


@pytest.fixture
def aws_kms_signer() -> AWSKMSSigner:
    """Fixture providing AWSKMSSigner configured against AWS environment variables."""
    key_id = os.environ.get("FLUXPAY_KMS_AWS_KEY_ID")
    expected_address = os.environ.get("FLUXPAY_KMS_AWS_EXPECTED_ADDRESS")
    region = os.environ.get("FLUXPAY_KMS_AWS_REGION", "us-east-1")

    if not key_id or not expected_address:
        pytest.skip(
            "Live AWS KMS integration test skipped: FLUXPAY_KMS_AWS_KEY_ID and "
            "FLUXPAY_KMS_AWS_EXPECTED_ADDRESS environment variables are not set."
        )

    try:
        import boto3

        boto3.client("kms", region_name=region)
    except Exception as exc:
        pytest.skip(f"boto3 KMS client initialization failed: {exc}")

    return AWSKMSSigner(
        key_id=key_id,
        expected_address=expected_address,
        region=region,
    )


@pytest.mark.asyncio
async def test_live_aws_kms_public_key_and_address_verification(
    aws_kms_signer: AWSKMSSigner,
) -> None:
    """Verify live AWS KMS public key retrieval and address calculation."""
    verified_address = await aws_kms_signer.verify_remote_public_key()
    assert Web3.is_checksum_address(verified_address)
    assert verified_address.lower() == aws_kms_signer.address.lower()


@pytest.mark.asyncio
async def test_live_aws_kms_sign_base_sepolia_transaction(
    aws_kms_signer: AWSKMSSigner,
) -> None:
    """Sign live EIP-1559 transaction on Base Sepolia and verify on-chain signature validity."""
    signer_address = await aws_kms_signer.get_address()

    tx = {
        "chainId": BASE_SEPOLIA_CHAIN_ID,
        "nonce": 0,
        "maxPriorityFeePerGas": 1_000_000,
        "maxFeePerGas": 2_000_000,
        "gas": 21000,
        "to": signer_address,
        "value": 0,
        "data": b"",
        "type": 2,
    }

    signed_bytes = await aws_kms_signer.sign_transaction(tx)
    assert len(signed_bytes) > 0

    # Recover signer from signed transaction bytes
    recovered_address = Account.recover_transaction(signed_bytes)
    assert recovered_address.lower() == signer_address.lower()


@pytest.mark.asyncio
async def test_live_aws_kms_sign_eip712_base_sepolia(
    aws_kms_signer: AWSKMSSigner,
) -> None:
    """Sign live EIP-712 EIP-3009 authorization for Base Sepolia testnet USDC."""
    signer_address = await aws_kms_signer.get_address()
    recipient_address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

    payload_dict = build_eip3009_transfer_payload(
        from_address=signer_address,
        to_address=recipient_address,
        value=1_000_000,
        valid_after=0,
        valid_before=2_000_000_000,
        nonce="0x" + "aa" * 32,
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        verifying_contract=BASE_SEPOLIA_USDC,
    )

    sig_bytes = await aws_kms_signer.sign_typed_data(payload_dict)
    assert len(sig_bytes) == 65
