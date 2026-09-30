"""EIP-712 and EIP-191 cryptographic message hashing and serialization helpers.

Supports EIP-3009 (transferWithAuthorization) gasless USDC payment authorizations
on Base L2 (chain_id=8453) and Base Sepolia (84532).
"""

from __future__ import annotations

from typing import Any, Final

from eth_account.messages import (
    _hash_eip191_message,
    encode_defunct,
    encode_typed_data,
)
from web3 import Web3

__all__ = [
    "BASE_USDC_CONTRACT",
    "EIP712_DOMAIN_TYPE",
    "TRANSFER_WITH_AUTHORIZATION_TYPES",
    "build_eip3009_transfer_payload",
    "build_usdc_domain",
    "compute_domain_separator",
    "hash_eip191_message",
    "hash_eip712_message",
]

BASE_USDC_CONTRACT: Final[str] = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

EIP712_DOMAIN_TYPE: Final[list[dict[str, str]]] = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]

TRANSFER_WITH_AUTHORIZATION_TYPES: Final[dict[str, list[dict[str, str]]]] = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ],
}


def build_usdc_domain(
    *,
    chain_id: int = 8453,
    verifying_contract: str = BASE_USDC_CONTRACT,
    name: str = "USD Coin",
    version: str = "2",
) -> dict[str, Any]:
    """Construct canonical EIP-712 domain data for USDC on Base.

    Args:
        chain_id: EVM network chain ID (8453 for Base Mainnet, 84532 for Base Sepolia).
        verifying_contract: Checksummed address of the USDC contract.
        name: Token contract EIP-712 name.
        version: EIP-712 domain version string.

    Returns:
        EIP-712 domain dictionary.
    """
    return {
        "name": name,
        "version": version,
        "chainId": chain_id,
        "verifyingContract": Web3.to_checksum_address(verifying_contract),
    }


def compute_domain_separator(domain_data: dict[str, Any]) -> bytes:
    """Compute 32-byte EIP-712 domain separator hash.

    Args:
        domain_data: Dictionary containing name, version, chainId, verifyingContract.

    Returns:
        32-byte Keccak-256 hash representing the domain separator.
    """
    signable = encode_typed_data(
        domain_data=domain_data,
        message_types={"Empty": []},
        message_data={},
    )
    return signable.header


def hash_eip712_message(typed_data: dict[str, Any]) -> bytes:
    """Compute the 32-byte EIP-712 signing digest for structured data.

    Accepts either a full JSON-schema typed data object (with keys 'types', 'primaryType',
    'domain', 'message') or separate sub-dictionaries.

    Args:
        typed_data: EIP-712 typed data structure.

    Returns:
        32-byte Keccak-256 hash conforming to keccak256("\x19\x01" || domainSep || structHash).
    """
    if "primaryType" in typed_data and "domain" in typed_data and "message" in typed_data:
        signable = encode_typed_data(full_message=typed_data)
    else:
        signable = encode_typed_data(
            domain_data=typed_data.get("domain", {}),
            message_types=typed_data.get("types", {}),
            message_data=typed_data.get("message", {}),
        )
    return _hash_eip191_message(signable)


def hash_eip191_message(message: bytes | str) -> bytes:
    """Compute canonical EIP-191 personal_sign 32-byte digest.

    Args:
        message: Raw byte sequence or string to sign.

    Returns:
        32-byte Keccak-256 hash.
    """
    if isinstance(message, str):
        signable = encode_defunct(text=message)
    else:
        signable = encode_defunct(primitive=message)
    return _hash_eip191_message(signable)


def build_eip3009_transfer_payload(
    *,
    from_address: str,
    to_address: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: bytes | str,
    chain_id: int = 8453,
    verifying_contract: str = BASE_USDC_CONTRACT,
) -> dict[str, Any]:
    """Construct full EIP-712 typed data payload for EIP-3009 transferWithAuthorization.

    Args:
        from_address: Payer/authorizer address.
        to_address: Recipient address.
        value: Transfer amount in minor units (e.g. 10_000_000 for 10 USDC).
        valid_after: Unix timestamp before which authorization is invalid.
        valid_before: Unix timestamp after which authorization expires.
        nonce: 32-byte unique authorization nonce (hex string or raw bytes).
        chain_id: Target network chain ID.
        verifying_contract: Target USDC contract address.

    Returns:
        Full EIP-712 dictionary suitable for `sign_typed_data`.
    """
    domain = build_usdc_domain(chain_id=chain_id, verifying_contract=verifying_contract)

    if isinstance(nonce, bytes):
        nonce_hex = "0x" + nonce.hex()
    elif isinstance(nonce, str) and not nonce.startswith("0x"):
        nonce_hex = "0x" + nonce
    else:
        nonce_hex = nonce

    types = {
        "EIP712Domain": EIP712_DOMAIN_TYPE,
        "TransferWithAuthorization": TRANSFER_WITH_AUTHORIZATION_TYPES["TransferWithAuthorization"],
    }

    message = {
        "from": Web3.to_checksum_address(from_address),
        "to": Web3.to_checksum_address(to_address),
        "value": value,
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": nonce_hex,
    }

    return {
        "types": types,
        "primaryType": "TransferWithAuthorization",
        "domain": domain,
        "message": message,
    }
