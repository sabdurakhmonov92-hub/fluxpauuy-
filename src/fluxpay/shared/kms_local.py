"""Local in-memory signer for local development and non-production testing ONLY.

SECURITY WARNING:
This backend loads raw ECDSA private keys directly into process memory. It is strictly
forbidden in production environments. Attempting to initialize this signer when
FLUXPAY_ENV=production raises a fatal RuntimeError and aborts process boot.
"""

from __future__ import annotations

import os
import time
from typing import Any, Final

from eth_account import Account

from fluxpay.shared.kms import (
    FLX_KMS_ERRORS_TOTAL,
    FLX_KMS_LOCAL_DEV_ACTIVE,
    FLX_KMS_SIGN_DURATION_SECONDS,
    FLX_KMS_SIGN_TOTAL,
    BaseSigner,
)
from fluxpay.shared.kms_eip712 import hash_eip191_message, hash_eip712_message
from fluxpay.shared.logging import get_logger

__all__ = ["LocalDevSigner"]

_logger = get_logger("fluxpay.shared.kms.local")


class LocalDevSigner(BaseSigner):
    """Development-only signer managing an unencrypted private key in memory.

    Features:
    - Fails immediately if `FLUXPAY_ENV=production`.
    - Emits a CRITICAL log event on instantiation.
    - Sets Prometheus gauge `FLX_KMS_LOCAL_DEV_ACTIVE = 1`.
    - Sanitizes `__repr__` and `__str__` to prevent private key leakage.
    - Provides `close()` to wipe private key bytes from memory.
    """

    backend: Final[str] = "local"

    def __init__(self, private_key: str | bytes | None = None) -> None:
        """Initialize LocalDevSigner with explicit key or from environment.

        Args:
            private_key: Hex string or 32-byte private key. If None, reads from
                         FLUXPAY_LOCAL_DEV_PRIVATE_KEY.

        Raises:
            RuntimeError: If FLUXPAY_ENV is set to 'production', or if no key is provided.
        """
        env_mode = os.environ.get("FLUXPAY_ENV", "").strip().lower()
        if env_mode == "production":
            raise RuntimeError(
                "CRITICAL SECURITY VIOLATION: LocalDevSigner is forbidden in production! "
                "Use AWSKMSSigner, GCPKMSSigner, AzureKVSigner, YubiHSMSigner, or FireblocksSigner."
            )

        if private_key is None:
            raw_key = os.environ.get("FLUXPAY_LOCAL_DEV_PRIVATE_KEY")
            if not raw_key:
                raise RuntimeError(
                    "Missing private key for LocalDevSigner. Pass explicitly or "
                    "set FLUXPAY_LOCAL_DEV_PRIVATE_KEY."
                )
            private_key = raw_key

        if isinstance(private_key, str):
            clean = private_key.strip()
            if clean.startswith("0x"):
                clean = clean[2:]
            self._key_bytes: bytearray = bytearray(bytes.fromhex(clean))
        else:
            self._key_bytes = bytearray(private_key)

        if len(self._key_bytes) != 32:
            raise ValueError(
                f"Invalid private key length: expected 32 bytes, got {len(self._key_bytes)}"
            )

        account = Account.from_key(bytes(self._key_bytes))
        super().__init__(address=account.address)

        # Telemetry: emit critical log and set dead-man / alert gauge
        _logger.critical(
            "LocalDevSigner in use — NOT FOR PRODUCTION",
            address=self._address,
            backend=self.backend,
        )
        FLX_KMS_LOCAL_DEV_ACTIVE.set(1)

    async def sign_transaction(self, tx: dict[str, Any]) -> bytes:
        """Sign an EIP-1559 transaction dict and return raw serialized bytes."""
        start_time = time.monotonic()
        _logger.info("kms_sign_started", backend=self.backend)
        try:
            signed = Account.sign_transaction(tx, bytes(self._key_bytes))
            raw_bytes = bytes(signed.raw_transaction)

            # Local verification sanity check
            recovered = Account.recover_transaction(raw_bytes)
            if recovered.lower() != self._address.lower():
                raise RuntimeError("Recovered address does not match expected address")

            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="ok").inc()
            FLX_KMS_SIGN_DURATION_SECONDS.labels(backend=self.backend).observe(duration)
            _logger.info(
                "kms_sign_completed", backend=self.backend, duration_ms=int(duration * 1000)
            )
            return raw_bytes
        except Exception as exc:
            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="error").inc()
            FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type="SIGN_FAILED").inc()
            _logger.error("kms_sign_failed", backend=self.backend, error=str(exc))
            raise

    async def sign_message(self, message: bytes) -> bytes:
        """Sign arbitrary byte payload according to EIP-191 personal_sign."""
        start_time = time.monotonic()
        _logger.info("kms_sign_started", backend=self.backend)
        try:
            digest = hash_eip191_message(message)
            sig = Account._sign_hash(digest, bytes(self._key_bytes))
            v = sig.v
            r = sig.r
            s = self.normalize_s(sig.s)
            canonical_sig = self.assemble_65byte_signature(r, s, v)

            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="ok").inc()
            FLX_KMS_SIGN_DURATION_SECONDS.labels(backend=self.backend).observe(duration)
            _logger.info(
                "kms_sign_completed", backend=self.backend, duration_ms=int(duration * 1000)
            )
            return canonical_sig
        except Exception as exc:
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="error").inc()
            FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type="SIGN_FAILED").inc()
            _logger.error("kms_sign_failed", backend=self.backend, error=str(exc))
            raise

    async def sign_typed_data(self, typed_data: dict[str, Any]) -> bytes:
        """Sign structured EIP-712 typed data."""
        start_time = time.monotonic()
        _logger.info("kms_sign_started", backend=self.backend)
        try:
            digest = hash_eip712_message(typed_data)
            sig = Account._sign_hash(digest, bytes(self._key_bytes))
            v = sig.v
            r = sig.r
            s = self.normalize_s(sig.s)
            canonical_sig = self.assemble_65byte_signature(r, s, v)

            duration = time.monotonic() - start_time
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="ok").inc()
            FLX_KMS_SIGN_DURATION_SECONDS.labels(backend=self.backend).observe(duration)
            _logger.info(
                "kms_sign_completed", backend=self.backend, duration_ms=int(duration * 1000)
            )
            return canonical_sig
        except Exception as exc:
            FLX_KMS_SIGN_TOTAL.labels(backend=self.backend, outcome="error").inc()
            FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type="SIGN_FAILED").inc()
            _logger.error("kms_sign_failed", backend=self.backend, error=str(exc))
            raise

    def close(self) -> None:
        """Wipe private key material from memory."""
        for i in range(len(self._key_bytes)):
            self._key_bytes[i] = 0
        FLX_KMS_LOCAL_DEV_ACTIVE.set(0)

    def __del__(self) -> None:
        """Defense-in-depth zeroing upon garbage collection."""
        try:
            self.close()
        except Exception as exc:
            _logger.debug("LocalDevSigner finalizer error", error=str(exc))
