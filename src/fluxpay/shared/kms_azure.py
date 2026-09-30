"""Azure Key Vault Managed HSM Secp256k1 Signer.

Provides hardware-isolated ECDSA signing via Azure Key Vault Managed HSM.
Uses key type EC-HSM, curve SECP256K1, and signing algorithm ES256K.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable
from typing import Any, Final, cast

from web3 import Web3

from fluxpay.shared.kms import (
    FLX_KMS_BACKEND_UP,
    FLX_KMS_ERRORS_TOTAL,
    FLX_KMS_SIGN_DURATION_SECONDS,
    FLX_KMS_SIGN_TOTAL,
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

__all__ = ["AzureKVSigner"]

_logger = get_logger("fluxpay.shared.kms.azure")


class AzureKVSigner(BaseSigner):
    """Azure Key Vault Managed HSM signer using secp256k1 EC keys and ES256K algorithm."""

    backend: Final[str] = "azure"

    def __init__(
        self,
        *,
        vault_url: str,
        key_name: str,
        expected_address: str,
        key_version: str | None = None,
        client: Any | None = None,
        max_attempts: int = 3,
        backoff_base_s: float = 0.1,
        backoff_cap_s: float = 2.0,
    ) -> None:
        """Initialize AzureKVSigner.

        Args:
            vault_url: Azure Key Vault URL (e.g. 'https://myvault.managedhsm.azure.net').
            key_name: Name of the EC-HSM key in Key Vault.
            expected_address: EIP-55 checksummed address corresponding to this key.
            key_version: Specific key version string (optional).
            client: Injected CryptographyClient instance (optional).
            max_attempts: Maximum retry count for transient errors.
            backoff_base_s: Initial backoff delay for retries.
            backoff_cap_s: Maximum backoff delay cap.
        """
        checksummed_expected = Web3.to_checksum_address(expected_address)
        super().__init__(address=checksummed_expected)

        self._vault_url: Final[str] = vault_url
        self._key_name: Final[str] = key_name
        self._key_version: Final[str | None] = key_version
        self._key_fingerprint: Final[str] = hash_key_id(f"{vault_url}/{key_name}")
        self._max_attempts: Final[int] = max_attempts
        self._backoff_base_s: Final[float] = backoff_base_s
        self._backoff_cap_s: Final[float] = backoff_cap_s

        if client is not None:
            self._client = client
        else:
            try:
                from azure.identity import (  # type: ignore[import-untyped,import-not-found,unused-ignore]
                    DefaultAzureCredential,
                )
                from azure.keyvault.keys import (  # type: ignore[import-untyped,import-not-found,unused-ignore]
                    KeyClient,
                )
                from azure.keyvault.keys.crypto import (  # type: ignore[import-untyped,import-not-found,unused-ignore]
                    CryptographyClient,
                )

                credential = DefaultAzureCredential()
                key_client = KeyClient(vault_url=vault_url, credential=credential)
                key = key_client.get_key(key_name, version=key_version)
                self._client = CryptographyClient(key, credential=credential)
            except ImportError:
                self._client = None

        FLX_KMS_BACKEND_UP.labels(backend=self.backend).set(1)
        _logger.info(
            "kms_signer_initialized",
            backend=self.backend,
            address=self._address,
            key_fingerprint=self._key_fingerprint,
        )

    async def _call_azure_with_retry[T](self, fn: Callable[[], T]) -> T:
        """Execute Azure Key Vault call in worker thread with exponential backoff and jitter."""
        last_exc: Exception | None = None

        for attempt in range(1, self._max_attempts + 1):
            try:
                if asyncio.iscoroutinefunction(fn):
                    return cast(T, await fn())
                return cast(T, await asyncio.to_thread(fn))
            except Exception as exc:
                last_exc = exc
                err_code = self._classify_azure_error(exc)

                if err_code == "KMS_ACCESS_DENIED":
                    FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type=err_code).inc()
                    raise KmsAccessDeniedError(
                        message=f"Azure Key Vault access denied: {self._key_fingerprint}",
                        details={"error": str(exc), "key_fingerprint": self._key_fingerprint},
                    ) from exc

                if err_code == "KMS_KEY_NOT_FOUND":
                    FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type=err_code).inc()
                    raise KmsKeyNotFoundError(
                        message=f"Azure Key Vault key not found: {self._key_fingerprint}",
                        details={"error": str(exc), "key_fingerprint": self._key_fingerprint},
                    ) from exc

                if err_code in ("KMS_THROTTLED", "KMS_UNAVAILABLE"):
                    FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type=err_code).inc()
                    if attempt < self._max_attempts:
                        backoff = min(
                            self._backoff_cap_s,
                            self._backoff_base_s * (2 ** (attempt - 1)),
                        ) * random.uniform(0.5, 1.5)  # noqa: S311
                        await asyncio.sleep(backoff)
                        continue

                    if err_code == "KMS_THROTTLED":
                        raise KmsThrottledError(
                            message=f"Azure Key Vault throttled after {attempt} attempts",
                            details={"key_fingerprint": self._key_fingerprint},
                        ) from exc
                    raise KmsUnavailableError(
                        message=f"Azure Key Vault unavailable after {attempt} attempts",
                        details={"key_fingerprint": self._key_fingerprint},
                    ) from exc

                FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type="UNCLASSIFIED").inc()
                raise KmsUnavailableError(
                    message=f"Unexpected Azure Key Vault error: {exc}",
                    details={"key_fingerprint": self._key_fingerprint},
                ) from exc

        raise KmsUnavailableError(
            message=f"Azure Key Vault operation failed after {self._max_attempts} attempts",
            details={"key_fingerprint": self._key_fingerprint},
        ) from last_exc

    @staticmethod
    def _classify_azure_error(exc: Exception) -> str:
        """Classify Azure SDK exceptions."""
        exc_str = str(exc)
        exc_type = type(exc).__name__

        if "ClientAuthenticationError" in exc_type or "Forbidden" in exc_str:
            return "KMS_ACCESS_DENIED"
        if "ResourceNotFoundError" in exc_type or "not found" in exc_str.lower():
            return "KMS_KEY_NOT_FOUND"
        if "429" in exc_str or "Rate limit" in exc_str or "TooManyRequests" in exc_type:
            return "KMS_THROTTLED"
        if "ServiceRequestError" in exc_type or "503" in exc_str or "RetryError" in exc_type:
            return "KMS_UNAVAILABLE"
        return "UNCLASSIFIED"

    async def _sign_digest(self, digest: bytes) -> tuple[int, int, int]:
        """Sign a 32-byte digest via Azure Key Vault CryptographyClient."""
        if self._client is None:
            raise KmsUnavailableError("Azure Key Vault CryptographyClient is not initialized")

        def _raw_sign() -> bytes:
            try:
                from azure.keyvault.keys.crypto import SignatureAlgorithm

                algo = SignatureAlgorithm.es256k
            except ImportError:
                algo = "ES256K"

            result = self._client.sign(algo, digest)
            if hasattr(result, "signature"):
                return result.signature  # type: ignore[no-any-return]
            if isinstance(result, dict):
                return result.get("signature", b"")  # type: ignore[no-any-return]
            return bytes(result)

        sig_bytes: bytes = await self._call_azure_with_retry(_raw_sign)
        if not sig_bytes:
            raise KmsInvalidSignatureError("Azure Key Vault returned an empty signature payload")

        r, raw_s = self.parse_der_or_raw_signature(sig_bytes)
        s = self.normalize_s(raw_s)
        v = self.determine_recovery_id(digest, r, s)
        return v, r, s

    async def sign_transaction(self, tx: dict[str, Any]) -> bytes:
        """Sign an EIP-1559 transaction dict via Azure Key Vault."""
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
                "kms_sign_completed", backend=self.backend, duration_ms=int(duration * 1000)
            )
            return signed_bytes
        except Exception as exc:
            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="error").inc()
            _logger.error("kms_sign_failed", backend=self.backend, error_type=type(exc).__name__)
            raise

    async def sign_message(self, message: bytes) -> bytes:
        """Sign an arbitrary byte payload according to EIP-191."""
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
                "kms_sign_completed", backend=self.backend, duration_ms=int(duration * 1000)
            )
            return canonical_sig
        except Exception as exc:
            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="error").inc()
            _logger.error("kms_sign_failed", backend=self.backend, error_type=type(exc).__name__)
            raise

    async def sign_typed_data(self, typed_data: dict[str, Any]) -> bytes:
        """Sign structured EIP-712 typed data via Azure Key Vault."""
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
                "kms_sign_completed", backend=self.backend, duration_ms=int(duration * 1000)
            )
            return canonical_sig
        except Exception as exc:
            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="error").inc()
            _logger.error("kms_sign_failed", backend=self.backend, error_type=type(exc).__name__)
            raise
