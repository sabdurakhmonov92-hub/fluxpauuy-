"""YubiHSM 2 Hardware Security Module Signer via PKCS#11.

Provides on-premise hardware-isolated transaction signing for Base L2 via YubiHSM 2.
Interfaces with the YubiHSM PKCS#11 dynamic module or direct session interface.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Final, Protocol, cast

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
    KmsUnavailableError,
    hash_key_id,
)
from fluxpay.shared.kms_eip712 import hash_eip191_message, hash_eip712_message
from fluxpay.shared.logging import get_logger

__all__ = ["PKCS11SessionProtocol", "YubiHSMSigner"]

_logger = get_logger("fluxpay.shared.kms.yubihsm")


class PKCS11SessionProtocol(Protocol):
    """Protocol for YubiHSM PKCS#11 or native session."""

    def sign_ecdsa_pkcs1v1_5(self, *, key_id: int, data: bytes) -> bytes:
        """Sign raw digest using ECDSA secp256k1 key."""
        ...


class YubiHSMSigner(BaseSigner):
    """Hardware Security Module signer using YubiHSM 2 via PKCS#11 session."""

    backend: Final[str] = "yubihsm"

    def __init__(
        self,
        *,
        key_id: int,
        expected_address: str,
        session: PKCS11SessionProtocol | Any | None = None,
        connector_url: str | None = None,
    ) -> None:
        """Initialize YubiHSMSigner.

        Args:
            key_id: YubiHSM integer Object ID containing the secp256k1 private key.
            expected_address: EIP-55 checksummed EVM address matching this key.
            session: Active PKCS#11 session or session mock.
            connector_url: URL or path to yubihsm-connector (optional).
        """
        checksummed_expected = Web3.to_checksum_address(expected_address)
        super().__init__(address=checksummed_expected)

        self._key_id: Final[int] = key_id
        self._key_fingerprint: Final[str] = hash_key_id(str(key_id))
        self._session: Final[Any | None] = session
        self._connector_url: Final[str | None] = connector_url

        FLX_KMS_BACKEND_UP.labels(backend=self.backend).set(1)
        _logger.info(
            "kms_signer_initialized",
            backend=self.backend,
            address=self._address,
            key_fingerprint=self._key_fingerprint,
        )

    async def _sign_digest(self, digest: bytes) -> tuple[int, int, int]:
        """Sign digest on YubiHSM 2 hardware module."""
        session = self._session
        if session is None:
            raise KmsUnavailableError(
                message="YubiHSM session is not configured",
                details={"key_fingerprint": self._key_fingerprint},
            )

        def _raw_sign() -> bytes:
            try:
                if hasattr(session, "sign_ecdsa_pkcs1v1_5"):
                    return cast(
                        bytes,
                        session.sign_ecdsa_pkcs1v1_5(
                            key_id=self._key_id,
                            data=digest,
                        ),
                    )
                if hasattr(session, "sign"):
                    return cast(bytes, session.sign(self._key_id, digest))
                raise KmsUnavailableError("Session lacks sign method")
            except Exception as exc:
                exc_str = str(exc).lower()
                if "not found" in exc_str or "object" in exc_str:
                    raise KmsKeyNotFoundError(
                        message=f"YubiHSM key {self._key_id} not found",
                        details={"key_fingerprint": self._key_fingerprint},
                    ) from exc
                if "auth" in exc_str or "permission" in exc_str or "pin" in exc_str:
                    raise KmsAccessDeniedError(
                        message="YubiHSM session unauthorized",
                        details={"key_fingerprint": self._key_fingerprint},
                    ) from exc
                raise KmsUnavailableError(
                    message=f"YubiHSM signing failed: {exc}",
                    details={"key_fingerprint": self._key_fingerprint},
                ) from exc

        # Execute C-extension / PKCS#11 calls in thread pool to prevent blocking asyncio
        sig_bytes = await asyncio.to_thread(_raw_sign)
        if not sig_bytes:
            raise KmsInvalidSignatureError("YubiHSM returned empty signature")

        r, raw_s = self.parse_der_or_raw_signature(sig_bytes)
        s = self.normalize_s(raw_s)
        v = self.determine_recovery_id(digest, r, s)
        return v, r, s

    async def sign_transaction(self, tx: dict[str, Any]) -> bytes:
        """Sign an EIP-1559 transaction dict via YubiHSM 2."""
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
            FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type=type(exc).__name__).inc()
            _logger.error("kms_sign_failed", backend=self.backend, error_type=type(exc).__name__)
            raise

    async def sign_message(self, message: bytes) -> bytes:
        """Sign arbitrary byte payload according to EIP-191."""
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
            FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type=type(exc).__name__).inc()
            _logger.error("kms_sign_failed", backend=self.backend, error_type=type(exc).__name__)
            raise

    async def sign_typed_data(self, typed_data: dict[str, Any]) -> bytes:
        """Sign structured EIP-712 typed data via YubiHSM 2."""
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
            FLX_KMS_ERRORS_TOTAL.labels(backend=self.backend, type=type(exc).__name__).inc()
            _logger.error("kms_sign_failed", backend=self.backend, error_type=type(exc).__name__)
            raise
