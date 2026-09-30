"""Fireblocks Multi-Party Computation (MPC) Raw Transaction Signer.

Provides enterprise custody signing via Fireblocks MPC API (REST v1).
Delegates threshold signature creation to distributed MPC key shares without exposing
the private key in a single location.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from typing import Any, Final
from uuid import uuid4

import httpx
import jwt
from pydantic import SecretStr
from web3 import Web3

from fluxpay.shared.kms import (
    FLX_KMS_BACKEND_UP,
    FLX_KMS_ERRORS_TOTAL,
    FLX_KMS_SIGN_DURATION_SECONDS,
    FLX_KMS_SIGN_TOTAL,
    KmsAccessDeniedError,
    KmsInvalidSignatureError,
    KmsThrottledError,
    KmsUnavailableError,
    MPCSigner,
    hash_key_id,
)
from fluxpay.shared.kms_eip712 import hash_eip191_message, hash_eip712_message
from fluxpay.shared.logging import get_logger

__all__ = ["FireblocksSigner"]

_logger = get_logger("fluxpay.shared.kms.fireblocks")


class FireblocksSigner(MPCSigner):
    """Enterprise MPC signer delegating transaction signing to Fireblocks threshold enclaves."""

    backend: Final[str] = "fireblocks"

    def __init__(
        self,
        *,
        api_key: str | SecretStr,
        api_secret: str | SecretStr,
        expected_address: str,
        base_url: str = "https://api.fireblocks.io",
        http_client: httpx.AsyncClient | None = None,
        poll_interval_s: float = 0.5,
        poll_timeout_s: float = 30.0,
    ) -> None:
        """Initialize FireblocksSigner.

        Args:
            api_key: Fireblocks API user UUID.
            api_secret: RSA private key PEM for API JWT signing.
            expected_address: EIP-55 checksummed EVM address of the vault account.
            base_url: Fireblocks API base endpoint.
            http_client: Injected httpx.AsyncClient (optional).
            poll_interval_s: Delay between status polling attempts.
            poll_timeout_s: Maximum timeout for MPC quorum completion.
        """
        checksummed_expected = Web3.to_checksum_address(expected_address)
        super().__init__(address=checksummed_expected)

        self._api_key_str = (
            api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
        )
        self._api_secret_str = (
            api_secret.get_secret_value() if isinstance(api_secret, SecretStr) else api_secret
        )
        self._base_url = base_url.rstrip("/")
        self._key_fingerprint: Final[str] = hash_key_id(self._api_key_str)
        self._http = http_client if http_client is not None else httpx.AsyncClient(timeout=10.0)
        self._owns_http = http_client is None
        self._poll_interval_s = poll_interval_s
        self._poll_timeout_s = poll_timeout_s

        FLX_KMS_BACKEND_UP.labels(backend=self.backend).set(1)
        _logger.info(
            "kms_signer_initialized",
            backend=self.backend,
            address=self._address,
            key_fingerprint=self._key_fingerprint,
        )

    def _generate_jwt_token(self, path: str, body_str: str) -> str:
        """Generate Fireblocks RS256 authenticated JWT token."""
        body_hash = hashlib.sha256(body_str.encode("utf-8")).hexdigest()
        now_ts = int(time.time())
        claims = {
            "uri": path,
            "nonce": uuid4().hex,
            "iat": now_ts,
            "exp": now_ts + 55,
            "sub": self._api_key_str,
            "bodyHash": body_hash,
        }
        return jwt.encode(claims, self._api_secret_str, algorithm="RS256")

    async def initiate_signing(self, message_hash: bytes) -> str:
        """Initiate asynchronous MPC raw signing request on Fireblocks.

        Args:
            message_hash: 32-byte hash to sign.

        Returns:
            Fireblocks transaction ID string.
        """
        path = "/v1/transactions"
        body = {
            "operation": "RAW",
            "assetId": "BASE",
            "extraParameters": {
                "rawMessageData": {
                    "messages": [
                        {
                            "content": message_hash.hex(),
                        }
                    ]
                }
            },
        }
        import orjson

        body_bytes = orjson.dumps(body)
        body_str = body_bytes.decode("utf-8")
        token = self._generate_jwt_token(path, body_str)
        headers = {
            "X-API-Key": self._api_key_str,
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        try:
            resp = await self._http.post(
                f"{self._base_url}{path}",
                content=body_bytes,
                headers=headers,
            )
        except Exception as exc:
            raise KmsUnavailableError(f"Fireblocks API transport error: {exc}") from exc

        if resp.status_code == 401 or resp.status_code == 403:
            raise KmsAccessDeniedError(f"Fireblocks authentication failed: {resp.text}")
        if resp.status_code == 429:
            raise KmsThrottledError(f"Fireblocks rate limit exceeded: {resp.text}")
        if resp.status_code != 200:
            raise KmsUnavailableError(f"Fireblocks API rejected signing request: {resp.text}")

        res_data = resp.json()
        tx_id = res_data.get("id")
        if not tx_id:
            raise KmsInvalidSignatureError("Fireblocks response missing transaction ID")
        return str(tx_id)

    async def poll_signature(
        self,
        operation_id: str,
        *,
        timeout_s: float = 30.0,
    ) -> tuple[int, int, int]:
        """Poll Fireblocks transaction status until threshold signing completes."""
        start_time = time.monotonic()
        path = f"/v1/transactions/{operation_id}"

        while time.monotonic() - start_time < timeout_s:
            token = self._generate_jwt_token(path, "")
            headers = {
                "X-API-Key": self._api_key_str,
                "Authorization": f"Bearer {token}",
            }
            try:
                resp = await self._http.get(f"{self._base_url}{path}", headers=headers)
            except Exception as exc:
                raise KmsUnavailableError(f"Fireblocks polling error: {exc}") from exc

            if resp.status_code != 200:
                raise KmsUnavailableError(
                    f"Fireblocks polling failed with status {resp.status_code}"
                )

            data = resp.json()
            status = data.get("status")

            if status == "COMPLETED":
                signed_messages = data.get("signedMessages", [])
                if not signed_messages:
                    raise KmsInvalidSignatureError("Fireblocks COMPLETED with empty signedMessages")
                sig_info = signed_messages[0].get("signature", {})
                r_hex = sig_info.get("r", "")
                s_hex = sig_info.get("s", "")
                v_val = sig_info.get("v", 0)

                r = int(r_hex, 16) if isinstance(r_hex, str) else int(r_hex)
                raw_s = int(s_hex, 16) if isinstance(s_hex, str) else int(s_hex)
                s = self.normalize_s(raw_s)
                return int(v_val), r, s

            if status in ("FAILED", "BLOCKED", "REJECTED", "CANCELLED"):
                sub_status = data.get("subStatus", "UNKNOWN")
                raise KmsInvalidSignatureError(
                    f"Fireblocks MPC transaction {status} (subStatus: {sub_status})"
                )

            await asyncio.sleep(self._poll_interval_s)

        raise KmsUnavailableError(f"Fireblocks signing timed out after {timeout_s}s")

    async def _sign_digest(self, digest: bytes) -> tuple[int, int, int]:
        """Orchestrate initiate + poll MPC workflow and verify address."""
        op_id = await self.initiate_signing(digest)
        _, r, s = await self.poll_signature(op_id, timeout_s=self._poll_timeout_s)

        # Confirm or recover valid v against expected address
        valid_v = self.determine_recovery_id(digest, r, s)
        return valid_v, r, s

    async def sign_transaction(self, tx: dict[str, Any]) -> bytes:
        """Sign an EIP-1559 transaction dict via Fireblocks MPC."""
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
        """Sign an arbitrary byte payload according to EIP-191 via Fireblocks MPC."""
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
        """Sign structured EIP-712 typed data via Fireblocks MPC."""
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

    async def aclose(self) -> None:
        """Close underlying HTTP client if owned."""
        if self._owns_http:
            await self._http.aclose()
