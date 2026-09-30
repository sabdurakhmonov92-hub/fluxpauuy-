"""EIP-3009 transferWithAuthorization signature recovery and verification for Base L2 USDC.

Compliant with:
- EIP-3009: Transfer With Authorization (gasless payments)
- EIP-712: Typed structured data hashing and signing
- RFC 7231 / x402 payment specification
"""

from __future__ import annotations

import hmac
import time
from typing import Any, Final

from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

from fluxpay.gateway.x402_types import PaymentPayload

__all__ = [
    "TRANSFER_WITH_AUTHORIZATION_TYPES",
    "build_eip712_domain",
    "normalize_nonce",
    "recover_eip3009_signer",
    "validate_authorization_timing",
    "verify_eip3009_signature",
]

TRANSFER_WITH_AUTHORIZATION_TYPES: Final[dict[str, list[dict[str, str]]]] = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


def build_eip712_domain(
    *,
    name: str,
    version: str,
    chain_id: int,
    verifying_contract: str,
) -> dict[str, Any]:
    """Construct canonical EIP-712 domain separator dictionary for USDC on Base.

    Args:
        name: Token name in contract DOMAIN_SEPARATOR (e.g. "USD Coin" or "USDC").
        version: Token version (e.g. "2").
        chain_id: EVM chain ID (e.g. 8453 for Base Mainnet, 84532 for Base Sepolia).
        verifying_contract: Token contract address on chain.

    Returns:
        EIP-712 domain dictionary.
    """
    return {
        "name": name,
        "version": version,
        "chainId": chain_id,
        "verifyingContract": Web3.to_checksum_address(verifying_contract),
    }


def normalize_nonce(nonce: str) -> str:
    """Normalize nonce to a canonical 32-byte hexadecimal string with 0x prefix.

    Args:
        nonce: Raw nonce string (hex or alphanumeric).

    Returns:
        0x-prefixed 64-character lowercase hex string.
    """
    cleaned = nonce.strip()
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    # If standard 64 hex chars, preserve exactly
    if len(cleaned) == 64:
        try:
            int(cleaned, 16)
            return "0x" + cleaned.lower()
        except ValueError:
            pass

    # If shorter hex string, left-pad to 32 bytes (64 hex characters)
    if len(cleaned) < 64:
        try:
            int(cleaned, 16)
            return "0x" + cleaned.zfill(64).lower()
        except ValueError:
            pass

    # Fallback for arbitrary string identifiers: UTF-8 encoded left-padded or truncated
    raw_bytes = nonce.encode()
    if len(raw_bytes) <= 32:
        return "0x" + raw_bytes.rjust(32, b"\x00").hex()
    return "0x" + Web3.keccak(text=nonce).hex()


def _extract_signature(payload: PaymentPayload) -> dict[str, Any]:
    """Extract and validate signature components (v, r, s or raw signature bytes).

    Returns:
        Kwargs dictionary suitable for Account.recover_message.
    """
    if payload.signature is not None:
        sig_str = payload.signature.strip()
        if sig_str.startswith(("0x", "0X")):
            sig_str = sig_str[2:]
        if len(sig_str) != 130:
            raise ValueError(
                f"Invalid signature hex length: expected 130 chars, got {len(sig_str)}"
            )
        return {"signature": bytes.fromhex(sig_str)}

    if payload.v is not None and payload.r is not None and payload.s is not None:
        v = payload.v
        # Normalize 0/1 v values to 27/28 standard EVM recovery identifiers
        if v in (0, 1):
            v += 27
        elif v not in (27, 28):
            raise ValueError(f"Invalid recovery identifier v: {v}")

        r_val = payload.r.strip()
        s_val = payload.s.strip()
        r_int = int(r_val, 16) if r_val.startswith(("0x", "0X")) else int(r_val)
        s_int = int(s_val, 16) if s_val.startswith(("0x", "0X")) else int(s_val)
        return {"vrs": (v, r_int, s_int)}

    raise ValueError("Missing signature components: provide 'signature' or ('v', 'r', 's')")


def recover_eip3009_signer(
    payload: PaymentPayload,
    domain: dict[str, Any],
) -> str:
    """Recover the EVM signer address from an EIP-3009 authorization payload.

    Args:
        payload: Decoded payment authorization payload.
        domain: Target EIP-712 domain configuration.

    Returns:
        EIP-55 checksummed signer address.

    Raises:
        ValueError: If payload fields or signature are malformed.
    """
    from_addr = Web3.to_checksum_address(payload.from_address)
    to_addr = Web3.to_checksum_address(payload.to_address)
    norm_nonce = normalize_nonce(payload.nonce)

    message_data: dict[str, Any] = {
        "from": from_addr,
        "to": to_addr,
        "value": payload.value_int,
        "validAfter": payload.valid_after,
        "validBefore": payload.valid_before,
        "nonce": norm_nonce,
    }

    encoded_msg = encode_typed_data(
        domain_data=domain,
        message_types=TRANSFER_WITH_AUTHORIZATION_TYPES,
        message_data=message_data,
    )

    sig_kwargs = _extract_signature(payload)
    recovered = Account.recover_message(encoded_msg, **sig_kwargs)
    return Web3.to_checksum_address(recovered)


def verify_eip3009_signature(
    payload: PaymentPayload,
    domain: dict[str, Any],
) -> tuple[bool, str | None]:
    """Verify that an EIP-3009 authorization was signed by payload.from_address.

    Employs constant-time string comparison (hmac.compare_digest) to prevent timing attacks.

    Args:
        payload: Payment payload containing authorization and signature.
        domain: EIP-712 domain separator dictionary.

    Returns:
        (is_valid, failure_reason)
    """
    try:
        expected_address = Web3.to_checksum_address(payload.from_address)
        recovered_address = recover_eip3009_signer(payload, domain)
    except Exception as err:
        return False, f"Signature recovery failed: {err}"

    # Constant-time comparison on normalized lowercase addresses
    if hmac.compare_digest(recovered_address.lower(), expected_address.lower()):
        return True, None

    return (
        False,
        f"Signer {recovered_address} does not match authorization 'from' {expected_address}",
    )


def validate_authorization_timing(
    valid_after: int,
    valid_before: int,
    current_timestamp: int | None = None,
) -> tuple[bool, str | None]:
    """Verify that current Unix timestamp falls within [validAfter, validBefore].

    Args:
        valid_after: Minimum valid epoch seconds.
        valid_before: Expiration epoch seconds.
        current_timestamp: Optional override for time injection during testing.

    Returns:
        (is_valid, failure_reason)
    """
    now = int(time.time()) if current_timestamp is None else current_timestamp
    if now < valid_after:
        return False, f"Authorization not yet active: validAfter={valid_after}, now={now}"
    if now > valid_before:
        return False, f"Authorization expired: validBefore={valid_before}, now={now}"
    return True, None
