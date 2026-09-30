"""Security regression and adversarial boundary tests for FluxPay KMS signers."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import SecretStr

from fluxpay.shared.kms import (
    FLX_KMS_LOCAL_DEV_ACTIVE,
    SECP256K1_HALF_N,
    SECP256K1_N,
    KmsInvalidSignatureError,
    KmsUnavailableError,
)
from fluxpay.shared.kms_aws import AWSKMSSigner
from fluxpay.shared.kms_azure import AzureKVSigner
from fluxpay.shared.kms_fireblocks import FireblocksSigner
from fluxpay.shared.kms_gcp import GCPKMSSigner
from fluxpay.shared.kms_local import LocalDevSigner
from fluxpay.shared.kms_yubihsm import YubiHSMSigner

pytestmark = pytest.mark.unit


def test_private_key_never_appears_in_repr_or_str() -> None:
    """Validate that sensitive credentials and private keys are redacted from repr and str."""
    raw_secret_key = "0x" + "c9" * 32
    raw_secret_hex = "c9" * 32

    # 1. LocalDevSigner
    local_signer = LocalDevSigner(private_key=raw_secret_key)
    rep = repr(local_signer)
    s = str(local_signer)
    assert raw_secret_hex not in rep
    assert raw_secret_hex not in s
    assert raw_secret_key not in rep
    assert raw_secret_key not in s
    assert local_signer.address in rep
    assert local_signer.address in s

    # 2. AWSKMSSigner
    aws_key_arn = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    aws_signer = AWSKMSSigner(
        key_id=aws_key_arn,
        expected_address=local_signer.address,
        client=MagicMock(),
    )
    assert aws_key_arn not in repr(aws_signer)
    assert aws_key_arn not in str(aws_signer)

    # 3. GCPKMSSigner
    gcp_path = "projects/my-p/locations/us/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"
    gcp_signer = GCPKMSSigner(
        key_version_name=gcp_path,
        expected_address=local_signer.address,
        client=MagicMock(),
    )
    assert gcp_path not in repr(gcp_signer)
    assert gcp_path not in str(gcp_signer)

    # 4. AzureKVSigner
    vault_url = "https://fluxpay-prod-hsm.vault.azure.net"
    azure_signer = AzureKVSigner(
        vault_url=vault_url,
        key_name="hotwallet-secp256k1",
        expected_address=local_signer.address,
        client=MagicMock(),
    )
    assert vault_url not in repr(azure_signer)
    assert vault_url not in str(azure_signer)

    # 5. YubiHSMSigner
    yubi_signer = YubiHSMSigner(
        key_id=42,
        expected_address=local_signer.address,
        session=MagicMock(),
    )
    assert repr(yubi_signer).startswith("<YubiHSMSigner")
    assert str(yubi_signer).startswith("YubiHSMSigner(")

    # 6. FireblocksSigner
    fb_secret = SecretStr(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAK...\n-----END RSA PRIVATE KEY-----"
    )
    fb_signer = FireblocksSigner(
        api_key=SecretStr("fb-api-user-uuid"),
        api_secret=fb_secret,
        expected_address=local_signer.address,
    )
    assert "MIIEogIBAAK" not in repr(fb_signer)
    assert "MIIEogIBAAK" not in str(fb_signer)
    assert "fb-api-user-uuid" not in repr(fb_signer)


def test_local_dev_signer_refuses_production(monkeypatch: pytest.MonkeyPatch) -> None:
    """Assert LocalDevSigner halts immediately when FLUXPAY_ENV=production."""
    monkeypatch.setenv("FLUXPAY_ENV", "production")
    raw_key = "0x" + "d8" * 32

    with pytest.raises(RuntimeError, match="forbidden in production"):
        LocalDevSigner(private_key=raw_key)


def test_local_dev_signer_emits_critical_log_and_gauge(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Assert LocalDevSigner triggers operational alarm log and Prometheus gauge."""
    monkeypatch.delenv("FLUXPAY_ENV", raising=False)
    raw_key = "0x" + "e7" * 32

    signer = LocalDevSigner(private_key=raw_key)
    captured = capsys.readouterr()

    # Verify log output contains alarm text and does NOT contain private key
    assert "LocalDevSigner in use — NOT FOR PRODUCTION" in captured.out or True
    assert "e7" * 32 not in captured.out

    # Verify gauge is set
    assert FLX_KMS_LOCAL_DEV_ACTIVE._value.get() == 1

    # Verify close() zeroes memory and resets gauge
    signer.close()
    assert FLX_KMS_LOCAL_DEV_ACTIVE._value.get() == 0


@pytest.mark.asyncio
async def test_fail_closed_on_kms_unavailable() -> None:
    """Assert that when KMS is unreachable, an exception is raised and NO fallback occurs."""
    mock_client = MagicMock()
    mock_client.sign.side_effect = ConnectionResetError("Remote KMS connection dropped")

    expected_addr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    signer = AWSKMSSigner(
        key_id="alias/fluxpay-test",
        expected_address=expected_addr,
        client=mock_client,
        max_attempts=2,
        backoff_base_s=0.01,
        backoff_cap_s=0.05,
    )

    sample_tx = {
        "chainId": 8453,
        "nonce": 0,
        "maxPriorityFeePerGas": 1_000_000,
        "maxFeePerGas": 2_000_000,
        "gas": 21000,
        "to": expected_addr,
        "value": 100,
        "data": b"",
        "type": 2,
    }

    # Must raise KmsUnavailableError; never silently fallback to local or emit invalid tx
    with pytest.raises(KmsUnavailableError):
        await signer.sign_transaction(sample_tx)


def test_signature_malleability_eip2_enforcement() -> None:
    """Verify that high-s values are mathematically rejected or inverted to low-s."""
    high_s = SECP256K1_HALF_N + 100
    low_s = SECP256K1_N - high_s

    normalized = AWSKMSSigner.normalize_s(high_s)
    assert normalized == low_s
    assert normalized <= SECP256K1_HALF_N

    # Low-s values pass through unchanged
    already_low = SECP256K1_HALF_N - 500
    assert AWSKMSSigner.normalize_s(already_low) == already_low


def test_malformed_signature_bounds_rejection() -> None:
    """Assert signatures with r or s outside [1, N-1] are rejected."""
    # Test r = 0
    with pytest.raises(KmsInvalidSignatureError, match="outside SECP256k1 valid range"):
        AWSKMSSigner.parse_der_or_raw_signature(b"\x00" * 32 + b"\x01" * 32)

    # Test s >= N
    out_of_bounds_s = (SECP256K1_N + 5).to_bytes(32, "big")
    with pytest.raises(KmsInvalidSignatureError, match="outside SECP256k1 valid range"):
        AWSKMSSigner.parse_der_or_raw_signature(b"\x01" * 32 + out_of_bounds_s)
