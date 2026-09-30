"""AWS Key Management Service (AWS KMS) Secp256k1 Asymmetric Signer.

Provides hardware-backed, FIPS 140-3 Level 3 HSM transaction signing for Base L2.
Uses asymmetric keys with spec ECC_SECG_P256K1 and algorithm ECDSA_SHA_256.

All calls to boto3 are executed non-blockingly via asyncio.to_thread with exponential
backoff and jitter. Raw private keys NEVER leave the AWS KMS Nitro enclave.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable
from typing import Any, Final, cast

from cryptography.hazmat.primitives import serialization
from web3 import Web3

from fluxpay.shared.kms import (
    FLX_KMS_BACKEND_UP,
    FLX_KMS_ERRORS_TOTAL,
    FLX_KMS_SIGN_DURATION_SECONDS,
    FLX_KMS_SIGN_TOTAL,
    AddressMismatchError,
    BaseSigner,
    KmsAccessDeniedError,
    KmsInvalidSignatureError,
    KmsKeyNotFoundError,
    KmsThrottledError,
    KmsUnavailableError,
    hash_key_id,
)
from fluxpay.shared.kms_eip712 import hash_eip191_message, hash_eip712_message
from fluxpay.shared.logging import get_logger

__all__ = ["AWSKMSSigner", "derive_ethereum_address_from_kms_pubkey"]

_logger = get_logger("fluxpay.shared.kms.aws")


def derive_ethereum_address_from_kms_pubkey(der_bytes: bytes) -> str:
    """Derive an EIP-55 checksummed Ethereum address from AWS KMS SubjectPublicKeyInfo DER bytes.

    Args:
        der_bytes: X.509 SubjectPublicKeyInfo DER-encoded public key returned by KMS GetPublicKey.

    Returns:
        EIP-55 checksummed EVM address.
    """
    pub = serialization.load_der_public_key(der_bytes)
    raw_pub = pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    # SECP256k1 uncompressed point is 65 bytes: 0x04 || X (32 bytes) || Y (32 bytes)
    # Ethereum address is last 20 bytes of keccak256(X || Y)
    addr_bytes = Web3.keccak(raw_pub[1:])[12:]
    return Web3.to_checksum_address("0x" + addr_bytes.hex())


class AWSKMSSigner(BaseSigner):
    """Hardware-enforced AWS KMS asymmetric signer using secp256k1 elliptic curve.

    Security Properties:
    - Zero in-memory private key presence.
    - Constant-time verification of recovered address before emitting signature.
    - Automated EIP-2 low-s canonicalization.
    - Non-blocking thread-pool execution for boto3 synchronous SDK calls.
    - Sink-level redaction: key_id is never logged in plaintext.
    """

    backend: Final[str] = "aws"

    def __init__(
        self,
        *,
        key_id: str,
        expected_address: str,
        client: Any | None = None,
        region: str | None = None,
        max_attempts: int = 3,
        backoff_base_s: float = 0.1,
        backoff_cap_s: float = 2.0,
    ) -> None:
        """Initialize AWSKMSSigner with KMS key ARN/ID and expected hot-wallet address.

        Args:
            key_id: AWS KMS KeyId, Key ARN, or Alias (e.g. 'alias/fluxpay-hotwallet').
            expected_address: EIP-55 checksummed address representing this key.
            client: Injected boto3 KMS client (for testing or custom sessions).
            region: AWS region name (e.g. 'us-east-1').
            max_attempts: Maximum retry count for transient network/throttling errors.
            backoff_base_s: Initial backoff delay for retries.
            backoff_cap_s: Maximum backoff ceiling.

        Raises:
            AddressMismatchError: If derived public key does not match expected_address.
        """
        checksummed_expected = Web3.to_checksum_address(expected_address)
        super().__init__(address=checksummed_expected)

        self._key_id: Final[str] = key_id
        self._key_fingerprint: Final[str] = hash_key_id(key_id)
        self._region: Final[str | None] = region
        self._max_attempts: Final[int] = max_attempts
        self._backoff_base_s: Final[float] = backoff_base_s
        self._backoff_cap_s: Final[float] = backoff_cap_s

        if client is not None:
            self._client = client
        else:
            try:
                import boto3  # type: ignore[import-untyped,import-not-found,unused-ignore]

                self._client = boto3.client("kms", region_name=region)
            except ImportError:
                # boto3 may be injected or imported lazily
                self._client = None

        FLX_KMS_BACKEND_UP.labels(backend=self.backend).set(1)
        _logger.info(
            "kms_signer_initialized",
            backend=self.backend,
            address=self._address,
            key_fingerprint=self._key_fingerprint,
        )

    async def verify_remote_public_key(self) -> str:
        """Fetch remote public key from KMS, derive EVM address, and assert match.

        Returns:
            Checksummed verified address.

        Raises:
            AddressMismatchError: If remote key derives to a different address.
            KmsUnavailableError: If KMS endpoint is unreachable.
        """
        if self._client is None:
            raise KmsUnavailableError("boto3 KMS client is not initialized")

        pubkey_response: dict[str, Any] = await self._call_kms_with_retry(
            lambda: cast(dict[str, Any], self._client.get_public_key(KeyId=self._key_id))
        )
        der_bytes = pubkey_response.get("PublicKey", b"")
        derived = derive_ethereum_address_from_kms_pubkey(der_bytes)

        if derived.lower() != self._address.lower():
            FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type="ADDRESS_MISMATCH").inc()
            raise AddressMismatchError(
                message="KMS public key derives to an unexpected EVM address",
                details={
                    "expected": self._address,
                    "derived": derived,
                    "key_fingerprint": self._key_fingerprint,
                },
            )

        _logger.info("kms_address_verified", backend=self.backend, address=derived)
        return derived

    async def _call_kms_with_retry[T](self, fn: Callable[[], T]) -> T:
        """Execute a KMS call in a worker thread with exponential backoff and jitter."""
        last_exc: Exception | None = None

        for attempt in range(1, self._max_attempts + 1):
            try:
                if asyncio.iscoroutinefunction(fn):
                    return cast(T, await fn())
                # Run synchronous boto3 call in thread pool to prevent blocking asyncio loop
                return cast(T, await asyncio.to_thread(fn))
            except Exception as exc:
                last_exc = exc
                err_code = self._classify_boto_error(exc)

                if err_code == "KMS_ACCESS_DENIED":
                    FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type=err_code).inc()
                    raise KmsAccessDeniedError(
                        message=f"AWS KMS Access Denied for key: {self._key_fingerprint}",
                        details={"error": str(exc), "key_fingerprint": self._key_fingerprint},
                    ) from exc

                if err_code == "KMS_KEY_NOT_FOUND":
                    FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type=err_code).inc()
                    raise KmsKeyNotFoundError(
                        message=f"AWS KMS key not found: {self._key_fingerprint}",
                        details={"error": str(exc), "key_fingerprint": self._key_fingerprint},
                    ) from exc

                # Transient errors: Throttling and Endpoint unavailability
                if err_code in ("KMS_THROTTLED", "KMS_UNAVAILABLE"):
                    FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type=err_code).inc()
                    if attempt < self._max_attempts:
                        # Full jitter backoff formula:
                        # min(cap, base * 2^(attempt-1)) * uniform(0.5, 1.5)
                        backoff = min(
                            self._backoff_cap_s,
                            self._backoff_base_s * (2 ** (attempt - 1)),
                        ) * random.uniform(0.5, 1.5)  # noqa: S311
                        await asyncio.sleep(backoff)
                        continue

                    if err_code == "KMS_THROTTLED":
                        raise KmsThrottledError(
                            message=f"AWS KMS rate limit exceeded after {attempt} attempts",
                            details={"key_fingerprint": self._key_fingerprint},
                        ) from exc
                    raise KmsUnavailableError(
                        message=f"AWS KMS endpoint unavailable after {attempt} attempts",
                        details={"key_fingerprint": self._key_fingerprint},
                    ) from exc

                # Unclassified failure: fail closed
                FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type="UNCLASSIFIED").inc()
                raise KmsUnavailableError(
                    message=f"Unexpected AWS KMS error: {exc}",
                    details={"key_fingerprint": self._key_fingerprint},
                ) from exc

        raise KmsUnavailableError(
            message=f"AWS KMS operation failed after {self._max_attempts} attempts",
            details={"key_fingerprint": self._key_fingerprint},
        ) from last_exc

    @staticmethod
    def _classify_boto_error(exc: Exception) -> str:
        """Classify AWS botocore client exception into canonical error taxonomy."""
        exc_str = str(exc)
        exc_type = type(exc).__name__

        if "AccessDenied" in exc_str or "AccessDeniedException" in exc_type:
            return "KMS_ACCESS_DENIED"
        if (
            "NotFoundException" in exc_type
            or "NotFoundException" in exc_str
            or "ResourceNotFoundException" in exc_str
            or "not found" in exc_str.lower()
            or "not exist" in exc_str.lower()
        ):
            return "KMS_KEY_NOT_FOUND"
        if (
            "ThrottlingException" in exc_type
            or "ProvisionedThroughputExceeded" in exc_str
            or "Rate exceeded" in exc_str
        ):
            return "KMS_THROTTLED"
        if (
            "EndpointConnectionError" in exc_type
            or "ConnectTimeoutError" in exc_type
            or "ReadTimeoutError" in exc_type
            or "TimeoutError" in exc_type
            or "Timeout" in exc_type
            or "timed out" in exc_str.lower()
            or "timeout" in exc_str.lower()
            or "KMSInternalException" in exc_type
            or "ServiceUnavailable" in exc_str
        ):
            return "KMS_UNAVAILABLE"

        return "UNCLASSIFIED"

    async def _sign_digest(self, digest: bytes) -> tuple[int, int, int]:
        """Sign a 32-byte digest via AWS KMS, parse DER, normalize s, and determine recovery id."""
        if self._client is None:
            raise KmsUnavailableError("boto3 KMS client is not configured")

        def _raw_sign() -> dict[str, Any]:
            return self._client.sign(  # type: ignore[no-any-return]
                KeyId=self._key_id,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm="ECDSA_SHA_256",
            )

        response: dict[str, Any] = await self._call_kms_with_retry(_raw_sign)
        der_signature = response.get("Signature", b"")

        if not der_signature:
            raise KmsInvalidSignatureError("AWS KMS returned an empty signature payload")

        r, raw_s = self.parse_der_or_raw_signature(der_signature)
        s = self.normalize_s(raw_s)
        v = self.determine_recovery_id(digest, r, s)
        return v, r, s

    async def sign_transaction(self, tx: dict[str, Any]) -> bytes:
        """Sign an EIP-1559 transaction dict via AWS KMS and assemble raw signed bytes."""
        start_time = time.monotonic()
        _logger.info("kms_sign_started", backend=self.backend)

        try:
            clean_tx, tx_hash = self.hash_eip1559_transaction(tx)
            v, r, s = await self._sign_digest(tx_hash)
            signed_bytes = self.assemble_eip1559_signed_transaction(clean_tx, v, r, s)

            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="ok").inc()
            FLX_KMS_SIGN_DURATION_SECONDS.labels(backend=self.backend).observe(duration)
            _logger.info(
                "kms_sign_completed",
                backend=self.backend,
                duration_ms=int(duration * 1000),
            )
            return signed_bytes
        except Exception as exc:
            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="error").inc()
            _logger.error(
                "kms_sign_failed",
                backend=self.backend,
                error_type=type(exc).__name__,
                duration_ms=int(duration * 1000),
            )
            raise

    async def sign_message(self, message: bytes) -> bytes:
        """Sign an arbitrary byte payload according to EIP-191 personal_sign."""
        start_time = time.monotonic()
        _logger.info("kms_sign_started", backend=self.backend)

        try:
            digest = hash_eip191_message(message)
            v, r, s = await self._sign_digest(digest)
            canonical_sig = self.assemble_65byte_signature(r, s, v)

            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="ok").inc()
            FLX_KMS_SIGN_DURATION_SECONDS.labels(backend=self.backend).observe(duration)
            _logger.info(
                "kms_sign_completed",
                backend=self.backend,
                duration_ms=int(duration * 1000),
            )
            return canonical_sig
        except Exception as exc:
            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="error").inc()
            _logger.error(
                "kms_sign_failed",
                backend=self.backend,
                error_type=type(exc).__name__,
                duration_ms=int(duration * 1000),
            )
            raise

    async def sign_typed_data(self, typed_data: dict[str, Any]) -> bytes:
        """Sign structured EIP-712 typed data via AWS KMS."""
        start_time = time.monotonic()
        _logger.info("kms_sign_started", backend=self.backend)

        try:
            digest = hash_eip712_message(typed_data)
            v, r, s = await self._sign_digest(digest)
            canonical_sig = self.assemble_65byte_signature(r, s, v)

            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="ok").inc()
            FLX_KMS_SIGN_DURATION_SECONDS.labels(backend=self.backend).observe(duration)
            _logger.info(
                "kms_sign_completed",
                backend=self.backend,
                duration_ms=int(duration * 1000),
            )
            return canonical_sig
        except Exception as exc:
            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="error").inc()
            _logger.error(
                "kms_sign_failed",
                backend=self.backend,
                error_type=type(exc).__name__,
                duration_ms=int(duration * 1000),
            )
            raise
