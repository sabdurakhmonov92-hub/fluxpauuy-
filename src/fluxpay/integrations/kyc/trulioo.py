"""Trulioo KYC provider integration adapter (Block J, Task 55).

==============================================================================
TRULIOO GLOBALGATEWAY INTEGRATION & ARCHITECTURAL PRIORITIZATION
==============================================================================
Sumsub is FluxPay's PRIMARY automated KYC provider; Trulioo is SECONDARY.

WHY SUMSUB WAS PRIORITIZED OVER TRULIOO:
1. Hosted-flow privacy: Sumsub's WebSDK and hosted flows allow direct browser-to-provider
   document uploads. Our server never touches passports, selfies, or biometrics.
   Trulioo's GlobalGateway API, by contrast, frequently requires the merchant application
   or merchant server to ingest and forward identity fields (SSN, national ID numbers),
   substantially increasing our PCI-DSS and PII compliance scope.
2. Webhook maturity: Sumsub provides cryptographic HMAC-SHA256 webhook signatures
   out-of-the-box (`X-Payload-Digest`), enabling asynchronous review pipelines.
   Trulioo GlobalGateway webhooks require custom webhook secret provisioning and
   vary by contracted gateway edition.

PHASE 1 SCOPE (THE STUB-WITH-FLOW-DOC DISCIPLINE):
In Phase 1, TruliooProvider is protocol-complete and configuration-probed:
- `healthcheck()` tests the sandbox connection test endpoint.
- `start_verification()` submits a sandbox TestEntity verification call.
- `fetch_status()` maps Trulioo RecordStatus to normalized KycState.
- `verify_webhook()` is an honest stub (returns None and logs WARNING).
Full GlobalGateway multi-jurisdiction watchlist matching is scheduled for Phase 2.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable, Coroutine, Mapping
from typing import Any, Final, Literal

import httpx

from fluxpay.integrations.base import BaseClient
from fluxpay.integrations.kyc.protocol import KycState, VerificationStart

__all__ = [
    "TRULIOO_STATUS_MAP",
    "TruliooProvider",
]

# Frozen mapping table: Trulioo RecordResult/RecordStatus -> normalized KycState.status.
# Unknown statuses default safely to 'pending' with raw carried.
TRULIOO_STATUS_MAP: Final[dict[str, Literal["pending", "cleared", "declined"]]] = {
    "match": "cleared",
    "nomatch": "declined",
    "pending": "pending",
    "completed": "cleared",
    "fail": "declined",
}


class TruliooProvider(BaseClient):
    """Trulioo GlobalGateway KYC provider adapter conforming to KycProvider protocol."""

    IDEMPOTENCY_HEADER: str | None = None  # type: ignore[assignment]

    def __init__(
        self,
        *,
        api_key: str,
        api_base: str = "https://gateway.trulioo.com",
        http: httpx.AsyncClient,
        max_attempts: int = 3,
        backoff_base_s: float = 0.5,
        backoff_cap_s: float = 8.0,
        sleep: Callable[[float], Coroutine[Any, Any, Any]] = asyncio.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(
            provider_name="trulioo",
            http=http,
            max_attempts=max_attempts,
            backoff_base_s=backoff_base_s,
            backoff_cap_s=backoff_cap_s,
            sleep=sleep,
            now=now,
        )
        self._api_key = api_key
        self.api_base = api_base.rstrip("/")

    def _auth_headers(self) -> dict[str, str]:
        """Trulioo authentication headers (bearer API key + x-trulioo-api-key)."""
        return {
            "Authorization": f"Bearer {self._api_key}",
            "x-trulioo-api-key": self._api_key,
        }

    async def start_verification(self, *, subject_ref: str) -> VerificationStart:
        """Initiate verification using sandbox TestEntity schema (Phase 1 shape).

        GlobalGateway flow document:
        Full production verification submits DataFields containing PersonInfo,
        Location, Communication, and NationalIds to /verifications/v1/verify.
        The sandbox TestEntity call validates connectivity and returns a TransactionID.
        """
        path = "/verifications/v1/verify"
        payload = {
            "AcceptTruliooTermsAndConditions": True,
            "ConfigurationName": "Identity Verification",
            "CountryCode": "US",
            "DataFields": {
                "PersonInfo": {
                    "FirstGivenName": "Test",
                    "FirstSurName": "Entity",
                }
            },
            "CustomerReferenceID": subject_ref,
        }
        headers = self._auth_headers()
        headers["Content-Type"] = "application/json"

        resp = await self.request(
            op="start_verification",
            method="POST",
            url_path=f"{self.api_base}{path}",
            json=payload,
            headers=headers,
        )
        data = resp.json()
        tx_id = (
            data.get("TransactionID")
            or data.get("RecordID")
            or data.get("transactionId")
            or subject_ref
        )
        return VerificationStart(ref=str(tx_id), redirect_url=None)

    async def fetch_status(self, ref: str) -> KycState:
        """Fetch verification status by transaction ref."""
        path = f"/verifications/v1/transaction/{ref}"
        headers = self._auth_headers()

        resp = await self.request(
            op="fetch_status",
            method="GET",
            url_path=f"{self.api_base}{path}",
            headers=headers,
        )
        raw = resp.json()

        # Extract record status
        record_status = ""
        record = raw.get("Record")
        if isinstance(record, dict):
            record_status = str(record.get("RecordStatus", "")).lower()
        if not record_status and "RecordStatus" in raw:
            record_status = str(raw.get("RecordStatus", "")).lower()
        if not record_status and "Status" in raw:
            record_status = str(raw.get("Status", "")).lower()

        mapped_status = TRULIOO_STATUS_MAP.get(record_status, "pending")
        return KycState(status=mapped_status, raw=raw)

    def verify_webhook(
        self, *, payload: bytes, headers: Mapping[str, str]
    ) -> dict[str, Any] | None:
        """Honest Phase 1 stub for Trulioo webhooks."""
        self._logger.warning("trulioo webhooks not configured Phase 1")
        return None

    async def healthcheck(self) -> bool:
        """Cheapest authenticated ping (connection test endpoint)."""
        try:
            path = "/connection/v1/sayhello/test-connection"
            headers = self._auth_headers()
            resp = await self.request(
                op="healthcheck",
                method="GET",
                url_path=f"{self.api_base}{path}",
                headers=headers,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def extract_provider_error(self, response: httpx.Response) -> str:
        """Extract machine error code from Trulioo response, dropping PII."""
        with contextlib.suppress(Exception):
            data = response.json()
            if isinstance(data, dict):
                code = data.get("Code")
                if code is not None:
                    return str(code)
                errors = data.get("Errors")
                if isinstance(errors, list) and len(errors) > 0 and isinstance(errors[0], dict):
                    err_code = errors[0].get("Code")
                    if err_code is not None:
                        return str(err_code)
        return f"http_{response.status_code}"
