"""Sumsub KYC provider integration adapter (Block J, Task 55).

==============================================================================
SUMSUB AUTHENTICATION & SIGNATURE SCHEME
==============================================================================
Every HTTP request to Sumsub API must carry three authentication headers:
1. `X-App-Token`: The application token generated in Sumsub Dashboard.
2. `X-App-Access-Ts`: The current Unix epoch timestamp in seconds.
3. `X-App-Access-Sig`: Lowercase hexadecimal HMAC-SHA256 signature calculated over:
   `str(ts) + httpMethod.upper() + path_with_query + (body if body else "")`
   using the App Secret Key.

STOP-THE-LINE:
Formula drift = regenerate Known Answer Test (KAT) = breaking-change alarm.
The formula string lives in ONE module constant (FORMULA_DOC).
Formula confirmed against official Sumsub API documentation:
  timestamp (seconds) + uppercase HTTP method + request URI (including query parameters)
  + request body (omitted/empty if no body is transmitted).

==============================================================================
DOCUMENT-CUSTODY PRIVACY ARCHITECTURE
==============================================================================
Sumsub hosted flow (`POST /resources/accessTokens?levelName=...`) allows the merchant's
client application to embed the Sumsub WebSDK or navigate directly to a Sumsub-hosted
flow. The merchant uploads documents (passports, national IDs, utility bills, selfies)
directly to Sumsub's secure, SOC2 / ISO 27001-certified infrastructure.

FluxPay servers NEVER custody, process, or store identity documents.
We hold decisions, provider references, and immutable audit logs.
Document-custody stays with the compliance provider — a vital privacy architecture win.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import time
from collections.abc import Callable, Coroutine, Mapping
from typing import Any, Final, Literal

import httpx
import orjson

from fluxpay.integrations.base import BaseClient
from fluxpay.integrations.kyc.protocol import KycState, VerificationStart

__all__ = [
    "FORMULA_DOC",
    "SUMSUB_STATUS_MAP",
    "SumsubProvider",
]

# STOP-THE-LINE: formula drift = regenerate KAT = breaking-change alarm.
# The formula string lives in ONE module constant.
FORMULA_DOC: Final[str] = "ts + method.upper() + path_with_query + (body if body else '')"

# Frozen mapping table: (reviewStatus, reviewAnswer) -> normalized KycState.status.
# Any unknown combination falls back to 'pending' with raw payload retained for human review.
# The provider-recommends law in miniature: automation never invents a verdict.
KycStatus = Literal["pending", "cleared", "declined"]
SUMSUB_STATUS_MAP: Final[dict[tuple[str, str | None], KycStatus]] = {
    ("completed", "GREEN"): "cleared",
    ("completed", "RED"): "declined",
    ("completed", "YELLOW"): "pending",
    ("pending", None): "pending",
    ("pending", "GREEN"): "pending",
    ("pending", "RED"): "declined",
    ("init", None): "pending",
    ("prechecked", None): "pending",
    ("queued", None): "pending",
    ("onHold", None): "pending",
}


class SumsubProvider(BaseClient):
    """Sumsub KYC provider adapter conforming to KycProvider protocol."""

    # Sumsub does not support a generic HTTP Idempotency-Key header.
    IDEMPOTENCY_HEADER: str | None = None  # type: ignore[assignment]

    def __init__(
        self,
        *,
        api_key: str,
        secret_key: str,
        api_base: str = "https://api.sumsub.com",
        level_name: str = "basic-kyc-level",
        http: httpx.AsyncClient,
        max_attempts: int = 3,
        backoff_base_s: float = 0.5,
        backoff_cap_s: float = 8.0,
        sleep: Callable[[float], Coroutine[Any, Any, Any]] = asyncio.sleep,
        now: Callable[[], float] = time.monotonic,
        ts_fn: Callable[[], int] | None = None,
    ) -> None:
        super().__init__(
            provider_name="sumsub",
            http=http,
            max_attempts=max_attempts,
            backoff_base_s=backoff_base_s,
            backoff_cap_s=backoff_cap_s,
            sleep=sleep,
            now=now,
        )
        self._api_key = api_key
        self._secret_key = secret_key
        self.api_base = api_base.rstrip("/")
        self.level_name = level_name
        self._ts_fn: Callable[[], int] = ts_fn if ts_fn is not None else (lambda: int(time.time()))

    def _auth_headers(self, method: str, path: str, body: bytes = b"") -> dict[str, str]:
        """Compute Sumsub cryptographic authentication headers.

        Signs: str(ts) + method.upper() + path + body_str
        using HMAC-SHA256 with self._secret_key.
        """
        ts = self._ts_fn()
        body_str = body.decode("utf-8", errors="replace") if body else ""
        string_to_sign = f"{ts}{method.upper()}{path}{body_str}"
        sig = (
            hmac.new(
                self._secret_key.encode("utf-8"),
                string_to_sign.encode("utf-8"),
                hashlib.sha256,
            )
            .hexdigest()
            .lower()
        )

        return {
            "X-App-Token": self._api_key,
            "X-App-Access-Sig": sig,
            "X-App-Access-Ts": str(ts),
        }

    async def start_verification(self, *, subject_ref: str) -> VerificationStart:
        """Start Sumsub verification flow.

        1. Creates or registers applicant with externalUserId = subject_ref.
        2. Generates hosted flow access token.

        Returns:
            VerificationStart with applicant ID as ref, and optional hosted URL.
        """
        # Step 1: Create applicant
        applicant_path = f"/resources/applicants?levelName={self.level_name}"
        applicant_payload = {"externalUserId": subject_ref}
        applicant_body = orjson.dumps(applicant_payload)
        applicant_headers = self._auth_headers("POST", applicant_path, applicant_body)
        applicant_headers["Content-Type"] = "application/json"

        resp = await self.request(
            op="create_applicant",
            method="POST",
            url_path=f"{self.api_base}{applicant_path}",
            json=applicant_payload,
            headers=applicant_headers,
        )
        applicant_data = resp.json()
        applicant_id = str(applicant_data.get("id", ""))

        # Step 2: Generate access token for hosted WebSDK flow
        token_path = f"/resources/accessTokens?userId={subject_ref}&levelName={self.level_name}"
        token_headers = self._auth_headers("POST", token_path, b"")
        token_resp = await self.request(
            op="create_access_token",
            method="POST",
            url_path=f"{self.api_base}{token_path}",
            headers=token_headers,
        )
        token_data = token_resp.json()
        redirect_url = token_data.get("url")

        return VerificationStart(ref=applicant_id, redirect_url=redirect_url)

    async def fetch_status(self, ref: str) -> KycState:
        """Fetch verification review status for applicant ref.

        Maps provider review status and review answer into normalized KycState.
        """
        path = f"/resources/applicants/{ref}/status"
        headers = self._auth_headers("GET", path, b"")

        resp = await self.request(
            op="fetch_status",
            method="GET",
            url_path=f"{self.api_base}{path}",
            headers=headers,
        )
        raw = resp.json()

        review_status = str(raw.get("reviewStatus", "")).lower()
        review_result = raw.get("reviewResult")
        review_answer: str | None = None
        if isinstance(review_result, dict):
            raw_answer = review_result.get("reviewAnswer")
            if isinstance(raw_answer, str):
                review_answer = raw_answer.upper()
        if review_answer is None and "reviewAnswer" in raw:
            raw_answer = raw.get("reviewAnswer")
            if isinstance(raw_answer, str):
                review_answer = raw_answer.upper()

        mapped_status = SUMSUB_STATUS_MAP.get((review_status, review_answer), "pending")
        return KycState(status=mapped_status, raw=raw)

    def verify_webhook(
        self, *, payload: bytes, headers: Mapping[str, str]
    ) -> dict[str, Any] | None:
        """Verify incoming Sumsub webhook signature (X-Payload-Digest).

        Returns:
            Parsed payload dict if signature is valid; None if unverified or malformed.
        """
        if not self._secret_key:
            self._logger.warning("sumsub_webhook_secret_not_configured")
            return None

        # Case-insensitive header lookup
        digest_header: str | None = None
        for k, v in headers.items():
            if k.lower() == "x-payload-digest":
                digest_header = v
                break

        if not digest_header:
            self._logger.warning("sumsub_webhook_missing_digest_header")
            return None

        expected_digest = (
            hmac.new(
                self._secret_key.encode("utf-8"),
                payload,
                hashlib.sha256,
            )
            .hexdigest()
            .lower()
        )

        if not hmac.compare_digest(expected_digest, digest_header.strip().lower()):
            self._logger.warning("sumsub_webhook_signature_mismatch")
            return None

        try:
            parsed = orjson.loads(payload)
        except Exception as exc:
            self._logger.warning(
                "sumsub_webhook_valid_signature_malformed_json",
                error=str(exc),
            )
            return None

        if not isinstance(parsed, dict):
            return None

        return parsed

    async def healthcheck(self) -> bool:
        """Cheapest authenticated ping against Sumsub API."""
        try:
            path = "/resources/status/api"
            headers = self._auth_headers("GET", path, b"")
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
        """Extract machine error code from Sumsub response, dropping PII."""
        with contextlib.suppress(Exception):
            data = response.json()
            if isinstance(data, dict):
                code = data.get("errorCode") or data.get("code")
                if code is not None:
                    return str(code)
        return f"http_{response.status_code}"
