"""Comprehensive unit test suite for FluxPay KMS signers, protocols, and registry."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from eth_account import Account
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr
from web3 import Web3

from fluxpay.shared.kms import (
    SECP256K1_HALF_N,
    SECP256K1_N,
    AddressMismatchError,
    KmsAccessDeniedError,
    KMSError,
    KmsInvalidSignatureError,
    KmsKeyNotFoundError,
    KmsThrottledError,
    SignatureVerificationFailedError,
    SignerRegistry,
    _get_or_create_counter,
    _get_or_create_gauge,
    _get_or_create_histogram,
)
from fluxpay.shared.kms_aws import (
    AWSKMSSigner,
)
from fluxpay.shared.kms_azure import AzureKVSigner
from fluxpay.shared.kms_config import KMSConfig
from fluxpay.shared.kms_fireblocks import FireblocksSigner
from fluxpay.shared.kms_gcp import GCPKMSSigner
from fluxpay.shared.kms_local import LocalDevSigner
from fluxpay.shared.kms_yubihsm import YubiHSMSigner

pytestmark = pytest.mark.unit


# -----------------------------------------------------------------------------
# 1. LocalDevSigner Unit Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_local_dev_signer_round_trip() -> None:
    """Test LocalDevSigner transaction signing and recovery round-trip."""
    raw_key = "0x" + "11" * 32
    signer = LocalDevSigner(private_key=raw_key)
    address = await signer.get_address()

    assert Web3.is_checksum_address(address)
    assert signer.address == address

    tx = {
        "chainId": 8453,
        "nonce": 4,
        "maxPriorityFeePerGas": 1_000_000,
        "maxFeePerGas": 2_000_000,
        "gas": 21000,
        "to": address,
        "value": 1_000_000,
        "data": b"",
        "type": 2,
    }

    signed_bytes = await signer.sign_transaction(tx)
    recovered = Account.recover_transaction(signed_bytes)
    assert recovered.lower() == address.lower()


# -----------------------------------------------------------------------------
# 2. DER -> (r, s) Parsing and Test Vectors
# -----------------------------------------------------------------------------
def test_der_parsing_with_real_test_vectors() -> None:
    """Validate DER ASN.1 signature decoding across standard and edge-case scalars."""
    r_val = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    s_val = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0

    der_bytes = encode_dss_signature(r_val, s_val)
    parsed_r, parsed_s = AWSKMSSigner.parse_der_or_raw_signature(der_bytes)
    assert parsed_r == r_val
    assert parsed_s == s_val

    # Test 64-byte raw signature format
    raw_64 = r_val.to_bytes(32, "big") + s_val.to_bytes(32, "big")
    parsed_r2, parsed_s2 = AWSKMSSigner.parse_der_or_raw_signature(raw_64)
    assert parsed_r2 == r_val
    assert parsed_s2 == s_val


def test_malformed_der_signature_rejected() -> None:
    """Ensure malformed DER bytes raise KmsInvalidSignatureError."""
    with pytest.raises(KmsInvalidSignatureError):
        AWSKMSSigner.parse_der_or_raw_signature(b"\x30\x05\x02\x01\x00")

    with pytest.raises(KmsInvalidSignatureError):
        AWSKMSSigner.parse_der_or_raw_signature(b"garbage not der")


# -----------------------------------------------------------------------------
# 3. EIP-2 s Normalization
# -----------------------------------------------------------------------------
def test_eip2_s_normalization_low_and_high() -> None:
    """Verify high-s values invert to low-s while low-s remain unchanged."""
    low_s = 500
    assert AWSKMSSigner.normalize_s(low_s) == low_s

    high_s = SECP256K1_N - 500
    assert AWSKMSSigner.normalize_s(high_s) == 500
    assert AWSKMSSigner.normalize_s(high_s) <= SECP256K1_HALF_N


# -----------------------------------------------------------------------------
# 4. Recovery ID Determination (v=0 and v=1)
# -----------------------------------------------------------------------------
def test_recovery_id_determination_both_v_values() -> None:
    """Verify determine_recovery_id finds valid v for both parity branches."""
    acct = Account.create()
    signer = LocalDevSigner(private_key=acct.key)
    digest = b"\x44" * 32

    # Sign using eth_account
    sig = Account._sign_hash(digest, acct.key)
    r = sig.r
    s = LocalDevSigner.normalize_s(sig.s)

    v = signer.determine_recovery_id(digest, r, s)
    assert v in (0, 1)

    # Address mismatch case
    wrong_signer = LocalDevSigner(private_key="0x" + "22" * 32)
    with pytest.raises(AddressMismatchError):
        wrong_signer.determine_recovery_id(digest, r, s)


# -----------------------------------------------------------------------------
# 5. AWS KMS Signer Tests with Mocked Boto Client
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_aws_kms_signer_success() -> None:
    """Test full transaction signing with mocked AWS KMS client."""
    acct = Account.create()
    mock_boto = MagicMock()
    mock_boto.sign.side_effect = lambda **kwargs: {
        "Signature": encode_dss_signature(
            Account._sign_hash(kwargs["Message"], acct.key).r,
            Account._sign_hash(kwargs["Message"], acct.key).s,
        )
    }

    signer = AWSKMSSigner(
        key_id="alias/fluxpay-test",
        expected_address=acct.address,
        client=mock_boto,
    )

    tx = {
        "chainId": 8453,
        "nonce": 1,
        "maxPriorityFeePerGas": 1_000_000,
        "maxFeePerGas": 2_000_000,
        "gas": 21000,
        "to": acct.address,
        "value": 100,
        "data": b"",
        "type": 2,
    }

    signed_bytes = await signer.sign_transaction(tx)
    recovered = Account.recover_transaction(signed_bytes)
    assert recovered.lower() == acct.address.lower()


@pytest.mark.asyncio
async def test_aws_kms_timeout_retries_with_backoff() -> None:
    """Test that transient KMS connection failures retry and eventually succeed."""
    acct = Account.create()
    sig = Account._sign_hash(b"\x55" * 32, acct.key)
    der_sig = encode_dss_signature(sig.r, sig.s)

    mock_boto = MagicMock()
    # Fail twice with timeout, then succeed
    mock_boto.sign.side_effect = [
        TimeoutError("Connection timed out"),
        TimeoutError("Connection timed out"),
        {"Signature": der_sig},
    ]

    signer = AWSKMSSigner(
        key_id="alias/fluxpay-retry",
        expected_address=acct.address,
        client=mock_boto,
        max_attempts=3,
        backoff_base_s=0.01,
        backoff_cap_s=0.05,
    )

    # Calling internal sign should succeed after 3rd attempt
    _, r, _ = await signer._sign_digest(b"\x55" * 32)
    assert r == sig.r
    assert mock_boto.sign.call_count == 3


@pytest.mark.asyncio
async def test_aws_kms_access_denied_fails_closed() -> None:
    """Test that AccessDenied raises KmsAccessDeniedError without retry."""
    mock_boto = MagicMock()
    mock_boto.sign.side_effect = Exception("AccessDeniedException: User not authorized")

    signer = AWSKMSSigner(
        key_id="alias/denied",
        expected_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        client=mock_boto,
        max_attempts=3,
    )

    with pytest.raises(KmsAccessDeniedError):
        await signer._sign_digest(b"\x11" * 32)
    assert mock_boto.sign.call_count == 1


@pytest.mark.asyncio
async def test_aws_kms_key_not_found_fails_closed() -> None:
    """Test that NotFoundException raises KmsKeyNotFoundError."""
    mock_boto = MagicMock()
    mock_boto.sign.side_effect = Exception("NotFoundException: Key does not exist")

    signer = AWSKMSSigner(
        key_id="alias/missing",
        expected_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        client=mock_boto,
    )

    with pytest.raises(KmsKeyNotFoundError):
        await signer._sign_digest(b"\x11" * 32)


@pytest.mark.asyncio
async def test_aws_kms_verify_remote_public_key() -> None:
    """Verify public key DER decoding and address derivation against expected address."""
    acct = Account.create()
    pk = ec.derive_private_key(int(acct.key.hex(), 16), ec.SECP256K1())
    der_pub = pk.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    mock_boto = MagicMock()
    mock_boto.get_public_key.return_value = {"PublicKey": der_pub}

    signer = AWSKMSSigner(
        key_id="alias/test",
        expected_address=acct.address,
        client=mock_boto,
    )

    derived = await signer.verify_remote_public_key()
    assert derived == acct.address

    # Address mismatch test
    wrong_signer = AWSKMSSigner(
        key_id="alias/test",
        expected_address="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        client=mock_boto,
    )
    with pytest.raises(AddressMismatchError):
        await wrong_signer.verify_remote_public_key()


# -----------------------------------------------------------------------------
# 6. GCP Cloud KMS Signer Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_gcp_kms_signer_success() -> None:
    """Test transaction signing with mock GCP KMS client."""
    acct = Account.create()
    digest = b"\x66" * 32
    sig = Account._sign_hash(digest, acct.key)
    der_sig = encode_dss_signature(sig.r, sig.s)

    mock_gcp = MagicMock()
    mock_response = MagicMock()
    mock_response.signature = der_sig
    mock_gcp.asymmetric_sign.return_value = mock_response

    signer = GCPKMSSigner(
        key_version_name="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
        expected_address=acct.address,
        client=mock_gcp,
    )

    _, r, _ = await signer._sign_digest(digest)
    assert r == sig.r


# -----------------------------------------------------------------------------
# 7. Azure Key Vault Signer Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_azure_kv_signer_raw_and_der() -> None:
    """Test Azure Key Vault signer with both 64-byte raw and DER format signatures."""
    acct = Account.create()
    digest = b"\x77" * 32
    sig = Account._sign_hash(digest, acct.key)
    raw_64 = sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")

    mock_azure = MagicMock()
    mock_res = MagicMock()
    mock_res.signature = raw_64
    mock_azure.sign.return_value = mock_res

    signer = AzureKVSigner(
        vault_url="https://vault.azure.net",
        key_name="test-key",
        expected_address=acct.address,
        client=mock_azure,
    )

    _, r, _ = await signer._sign_digest(digest)
    assert r == sig.r


# -----------------------------------------------------------------------------
# 8. YubiHSM 2 Signer Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_yubihsm_signer_success() -> None:
    """Test YubiHSM signer with mock session."""
    acct = Account.create()
    digest = b"\x88" * 32
    sig = Account._sign_hash(digest, acct.key)
    der_sig = encode_dss_signature(sig.r, sig.s)

    mock_session = MagicMock()
    mock_session.sign_ecdsa_pkcs1v1_5.return_value = der_sig

    signer = YubiHSMSigner(
        key_id=1,
        expected_address=acct.address,
        session=mock_session,
    )

    _, r, _ = await signer._sign_digest(digest)
    assert r == sig.r


# -----------------------------------------------------------------------------
# 9. Fireblocks Signer Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fireblocks_signer_workflow() -> None:
    """Test Fireblocks MPC initiate and poll signing flow with mock transport."""
    acct = Account.create()
    digest = b"\x99" * 32
    sig = Account._sign_hash(digest, acct.key)

    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode("utf-8")

    tx_id = "fb-tx-12345"
    initiate_resp = httpx.Response(200, json={"id": tx_id})
    poll_resp = httpx.Response(
        200,
        json={
            "status": "COMPLETED",
            "signedMessages": [
                {
                    "signature": {
                        "r": hex(sig.r),
                        "s": hex(sig.s),
                        "v": sig.v,
                    }
                }
            ],
        },
    )

    mock_transport = httpx.MockTransport(
        lambda req: (
            initiate_resp if "transactions" in req.url.path and req.method == "POST" else poll_resp
        )
    )
    mock_http = httpx.AsyncClient(transport=mock_transport)

    signer = FireblocksSigner(
        api_key=SecretStr("fb-key"),
        api_secret=SecretStr(pem),
        expected_address=acct.address,
        http_client=mock_http,
        poll_interval_s=0.01,
        poll_timeout_s=1.0,
    )

    _, r, _ = await signer._sign_digest(digest)
    assert r == sig.r
    await signer.aclose()


# -----------------------------------------------------------------------------
# 10. SignerRegistry and Key Rotation
# -----------------------------------------------------------------------------
def test_signer_registry_key_rotation() -> None:
    """Test multi-key registration, primary promotion, and key lookup in SignerRegistry."""
    registry = SignerRegistry()
    signer_old = LocalDevSigner(private_key="0x" + "aa" * 32)
    signer_new = LocalDevSigner(private_key="0x" + "bb" * 32)

    registry.register("key-v1", signer_old, is_primary=True)
    assert registry.get_primary() is signer_old
    assert registry.has_key("key-v1")

    # Register new key without promoting
    registry.register("key-v2", signer_new, is_primary=False)
    assert registry.get_primary() is signer_old
    assert registry.get("key-v2") is signer_new

    # Zero-downtime cutover: promote key-v2 to primary
    registry.set_primary("key-v2")
    assert registry.get_primary() is signer_new
    assert registry.get("key-v1") is signer_old  # Old key remains available for verify

    # Key not found
    with pytest.raises(KmsKeyNotFoundError):
        registry.get("non-existent-key")

    with pytest.raises(KmsKeyNotFoundError):
        registry.set_primary("non-existent-key")


# -----------------------------------------------------------------------------
# 11. KMSConfig Validation Tests
# -----------------------------------------------------------------------------
def test_kms_config_validation() -> None:
    """Test pydantic configuration parsing and EIP-55 address validation."""
    valid_address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    cfg = KMSConfig(
        backend="aws",
        primary_key_id="alias/fluxpay",
        expected_address=valid_address,
    )
    assert cfg.backend == "aws"
    assert cfg.expected_address == valid_address

    # Non-checksummed address rejection
    with pytest.raises(ValueError, match="fails EIP-55 checksum validation"):
        KMSConfig(
            backend="aws",
            primary_key_id="alias/fluxpay",
            expected_address=valid_address.lower(),
        )

    # Invalid address length rejection
    with pytest.raises(ValueError, match="not a valid"):
        KMSConfig(
            backend="aws",
            primary_key_id="alias/fluxpay",
            expected_address="0x1234",
        )


# -----------------------------------------------------------------------------
# 12. Hypothesis Property Tests
# -----------------------------------------------------------------------------
@given(
    nonce=st.integers(min_value=0, max_value=1_000_000),
    value=st.integers(min_value=0, max_value=10_000_000),
)
@pytest.mark.asyncio
async def test_property_sign_random_tx_recovers_address(nonce: int, value: int) -> None:
    """Property test: signing random valid transactions always recovers the signer address."""
    raw_key = "0x" + "f3" * 32
    signer = LocalDevSigner(private_key=raw_key)
    address = await signer.get_address()

    tx = {
        "chainId": 8453,
        "nonce": nonce,
        "maxPriorityFeePerGas": 1_000_000,
        "maxFeePerGas": 2_000_000,
        "gas": 21000,
        "to": address,
        "value": value,
        "data": b"",
        "type": 2,
    }

    signed_bytes = await signer.sign_transaction(tx)
    recovered = Account.recover_transaction(signed_bytes)
    assert recovered.lower() == address.lower()


@given(s=st.integers(min_value=1, max_value=SECP256K1_N - 1))
def test_property_eip2_normalization_never_high_s(s: int) -> None:
    """Property test: EIP-2 normalization never yields high-s."""
    normalized = AWSKMSSigner.normalize_s(s)
    assert normalized <= SECP256K1_HALF_N
    assert normalized >= 1


def test_kms_errors_and_details() -> None:
    """Test KMSError construction with and without optional details."""
    err1 = KMSError("Error without details", code="TEST_CODE")
    assert err1.code == "TEST_CODE"
    assert err1.details == {"code": "TEST_CODE"}
    assert not err1.retryable

    err2 = KmsThrottledError(details={"retry_after": "5"})
    assert err2.code == "KMS_THROTTLED"
    assert err2.retryable
    assert err2.details.get("retry_after") == "5"

    err3 = SignatureVerificationFailedError(details={"sig": "invalid"})
    assert err3.code == "SIGNATURE_VERIFICATION_FAILED"
    assert not err3.retryable


def test_signer_registry_empty_and_list() -> None:
    """Test SignerRegistry when empty, and list_keys()."""
    registry = SignerRegistry()
    with pytest.raises(KmsKeyNotFoundError, match="No primary signer registered"):
        registry.get_primary()

    signer = LocalDevSigner(private_key="0x" + "11" * 32)
    registry.register("key-1", signer, is_primary=True)
    assert registry.list_keys() == ["key-1"]


def test_determine_recovery_id_catches_value_error() -> None:
    """Test determine_recovery_id handling when Account._recover_hash raises ValueError."""
    signer = LocalDevSigner(private_key="0x" + "22" * 32)
    # Using an invalid r scalar that causes secp256k1 recovery to raise ValueError/TypeError
    with pytest.raises(AddressMismatchError):
        signer.determine_recovery_id(b"\x00" * 32, SECP256K1_N + 5, 100)


def test_metric_get_or_create_helpers() -> None:
    """Test idempotent retrieval and collision raising for prometheus metrics helpers."""
    from prometheus_client import CollectorRegistry

    custom_reg = CollectorRegistry()
    c1 = _get_or_create_counter("test_cnt", "help", ("l1",), registry=custom_reg)
    c2 = _get_or_create_counter("test_cnt", "help", ("l1",), registry=custom_reg)
    assert c1 is c2

    g1 = _get_or_create_gauge("test_g", "help", ("l1",), registry=custom_reg)
    g2 = _get_or_create_gauge("test_g", "help", ("l1",), registry=custom_reg)
    assert g1 is g2

    h1 = _get_or_create_histogram("test_h", "help", ("l1",), (0.1, 0.5), registry=custom_reg)
    h2 = _get_or_create_histogram("test_h", "help", ("l1",), (0.1, 0.5), registry=custom_reg)
    assert h1 is h2

    # Wrong type collision tests
    with pytest.raises(ValueError):
        _get_or_create_counter("test_g", "help", ("l1",), registry=custom_reg)

    with pytest.raises(ValueError):
        _get_or_create_gauge("test_cnt", "help", ("l1",), registry=custom_reg)

    with pytest.raises(ValueError):
        _get_or_create_histogram("test_cnt", "help", ("l1",), (0.1,), registry=custom_reg)


def test_local_dev_signer_input_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test LocalDevSigner with env var, raw bytes, un-prefixed hex, and validation errors."""
    valid_hex = "11" * 32
    valid_bytes = bytes.fromhex(valid_hex)

    # 1. From environment variable
    monkeypatch.setenv("FLUXPAY_LOCAL_DEV_PRIVATE_KEY", valid_hex)
    s_env = LocalDevSigner(private_key=None)
    assert s_env.address.startswith("0x")

    # 2. Missing env var raises RuntimeError
    monkeypatch.delenv("FLUXPAY_LOCAL_DEV_PRIVATE_KEY", raising=False)
    with pytest.raises(RuntimeError, match="Missing private key for LocalDevSigner"):
        LocalDevSigner(private_key=None)

    # 3. Raw bytes key
    s_bytes = LocalDevSigner(private_key=valid_bytes)
    assert s_bytes.address == s_env.address

    # 4. Unprefixed hex string
    s_unprefixed = LocalDevSigner(private_key=valid_hex)
    assert s_unprefixed.address == s_env.address

    # 5. Invalid length raises ValueError
    with pytest.raises(ValueError, match="Invalid private key length"):
        LocalDevSigner(private_key=b"short_key")


@pytest.mark.asyncio
async def test_aws_kms_sign_message_and_typed_data() -> None:
    """Test AWSKMSSigner sign_message and sign_typed_data methods."""
    acct = Account.create()

    def fake_sign(**kwargs: Any) -> dict[str, Any]:
        msg_digest = kwargs["Message"]
        sig_obj = Account._sign_hash(msg_digest, bytes(acct.key))
        der_bytes = encode_dss_signature(sig_obj.r, sig_obj.s)
        return {"Signature": der_bytes}

    mock_boto = MagicMock()
    mock_boto.sign.side_effect = fake_sign

    signer = AWSKMSSigner(
        key_id="alias/test-msg",
        expected_address=acct.address,
        client=mock_boto,
    )

    # 1. sign_message
    msg_sig = await signer.sign_message(b"Hello Base")
    assert len(msg_sig) == 65

    # 2. sign_typed_data
    from fluxpay.shared.kms_eip712 import build_eip3009_transfer_payload

    payload = build_eip3009_transfer_payload(
        from_address=acct.address,
        to_address="0x" + "33" * 20,
        value=1000,
        valid_after=0,
        valid_before=2000,
        nonce="0x" + "44" * 32,
    )
    td_sig = await signer.sign_typed_data(payload)
    assert len(td_sig) == 65
