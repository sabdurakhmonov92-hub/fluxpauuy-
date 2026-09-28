"""Wise external rail integration client and cross-border fiat utilities (Task 53).

==============================================================================
THE ANTI-CONVERSION ESSAY IN WISE DIALECT (THE MINOR-UNITS IDENTITY LAW)
==============================================================================
Restating the fundamental law established in Task 52 (Stripe): the single most
frequent source of discrepancy and reconciliation failure in cross-border payment
integrations is unnecessary floating-point conversion between human major units
and machine minor units.

Wise's API amounts (e.g. quote `amount`, transfer funding) accept exact integer minor
currency units (cents for USD/EUR, pence for GBP). FluxPay's internal ledger,
risk engine, and payment pipelines represent all fiat balances and amounts in
exact integer minor units:
  - USD: 2 decimal places -> 1 cent  = 1 minor unit. $10.50 = 1050 minor units.
  - EUR: 2 decimal places -> 1 cent  = 1 minor unit. €10.50 = 1050 minor units.
  - GBP: 2 decimal places -> 1 pence = 1 minor unit. £10.50 = 1050 minor units.

For all supported currencies in `CURRENCY_EXPONENTS`, the relationship between
FluxPay minor units and Wise API amount units is a 1:1 IDENTITY.
Multiplying or dividing by 100.0 introduces IEEE 754 floating-point inaccuracies,
rounding drift, and subtle off-by-one reconciliation errors across multi-currency
clearing boundaries.

Therefore, this adapter passes integer minor units directly through to Wise without
arithmetic conversion. The `CURRENCY_EXPONENTS` dictionary serves strictly as an
allowlist and decimal precision reference for validation and display. Unknown currencies
are rejected immediately with `ValueError`.

==============================================================================
DESIGN LAWS & INVARIANTS:
==============================================================================
1. THE CUSTOMER_TRANSACTION_ID IDEMPOTENCY REALITY:
   Wise does not honor a universal HTTP `Idempotency-Key` header across its API
   endpoints (`IDEMPOTENCY_HEADER = None`). Instead, Wise implements client-side
   deduplication at the entity payload layer via the `customerTransactionId` field
   on transfer creation. If a client submits a transfer with an already-used
   `customerTransactionId`, Wise idempotently returns the EXISTING transfer record
   rather than creating a duplicate disbursement. The adapter strictly enforces that
   `reference` is non-empty before dispatching HTTP calls.

2. TWO-PHASE QUOTE-THEN-TRANSFER SAFETY:
   In Wise's architecture, creating a quote (`POST /v3/quotes`) is an inert operation
   that locks an FX rate for a guaranteed window without moving funds. Outbound
   transfers (`POST /v1/transfers`) reference the immutable `quote_id`. The quote ID
   functions as a natural idempotency anchor: retry attempts reference the existing
   quote, while Task 11's database-level idempotency ensures FluxPay never creates
   conflicting payout intents.

3. WEBHOOK SIGNATURE ASYMMETRY (STRIPE VS WISE):
   Stripe transmits a timestamp and lowercase hex signature (`t=...,v1=...`),
   allowing header-level replay window enforcement.
   Wise transmits an `X-Signature-SHA256` header containing a BASE64-encoded
   HMAC-SHA256 digest of the raw payload. Wise does NOT provide a timestamp in the
   signature header; replay protection primarily relies on event ID deduplication
   at our endpoint layer (Task 38's UNIQUE constraint). The verifier validates the
   cryptographic signature offline and checks an optional event timestamp inside
   the payload if present. Hex-encoded signatures are rejected strictly.

4. VERIFY-RETURNS-NONE & NONE-BUT-LOGGED SIGNAL:
   `verify_webhook()` returns `None` on invalid signatures, missing secrets, or
   malformed JSON to allow webhook ingestion handlers to respond 400 Bad Request
   without exception stack overhead. If a payload possesses a VALID cryptographic
   signature but fails JSON decoding, a high-priority WARNING is logged:
   "wise webhook: valid signature, invalid json" as a critical anomaly signal.

5. PROVIDER ERROR HOOK (ABSENCE LAW & PRIVACY):
   `extract_provider_error()` parses Wise error dialects (`{"code": "...", ...}`
   or `{"errors": [{"code": ...}]}`) and returns only the machine error code into
   exception details. The human-readable `message` is deliberately DROPPED to
   prevent customer PII or beneficiary account details from leaking into logs.

6. HEALTHCHECK BOOL LAW:
   `healthcheck()` issues `GET /v1/profiles` as the cheapest authenticated read.
   It catches all exceptions and returns a boolean `True` (200) or `False` (401/error).
   Monitors poll health as a signal; typed exceptions belong to operational requests.

7. DICT-TYPED RECIPIENT HONESTY:
   Recipient account structures vary drastically by jurisdiction (US Routing/Account,
   Eurozone IBAN/BIC, UK Sort Code/Account No). The adapter acts as a secure,
   authenticated transport layer (`create_recipient_account`), returning raw provider
   dicts. Strict schema validation belongs in core product workflows (Phase 2).

8. SANDBOX-DEFAULT CONFIGURATION GUARD:
   The adapter defaults to `https://api.sandbox.transferwise.tech`. Defaulting to
   production base URLs risks test API keys interacting with live banking rails.
   Production base URLs must be configured explicitly in environment variables.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import time
from collections.abc import Callable, Coroutine
from datetime import datetime
from typing import Any, Final

import httpx
import orjson

from fluxpay.integrations.base import BaseClient
from fluxpay.shared.errors import IntegrationError
from fluxpay.shared.logging import get_logger

__all__ = [
    "CURRENCY_EXPONENTS",
    "EXPONENTS",
    "WiseClient",
    "minor_to_major_str",
]

# Supported fiat currency exponents (ISO 4217 decimal places)
# 2 = 2 decimal places (e.g. cents, pence)
CURRENCY_EXPONENTS: Final[dict[str, int]] = {
    "usd": 2,
    "eur": 2,
    "gbp": 2,
}

# Alias for compatibility with Task 52 naming conventions
EXPONENTS: Final[dict[str, int]] = CURRENCY_EXPONENTS


def minor_to_major_str(amount_minor: int, currency: str) -> str:
    """Validate currency and return integer minor units as a string.

    NOTE: Wise's API accepts integer smallest units (cents for USD/EUR, pence for GBP),
    which are 1:1 identical to FluxPay's minor units. This helper validates currency
    support against CURRENCY_EXPONENTS and formats amount_minor without floating-point math.

    Args:
        amount_minor: Amount in smallest currency units (e.g. 1050 cents = $10.50).
        currency: 3-letter ISO currency code.

    Returns:
        String representation of amount_minor.

    Raises:
        ValueError: If currency is not in CURRENCY_EXPONENTS.
    """
    curr = currency.lower()
    if curr not in CURRENCY_EXPONENTS:
        supported = sorted(CURRENCY_EXPONENTS.keys())
        raise ValueError(f"Unsupported currency: '{currency}'. Supported: {supported}")
    return str(amount_minor)


class WiseClient(BaseClient):
    """Wise external rail integration adapter (Block J, Part 4 / Task 53).

    Inherits BaseClient's retry ladder, exponential backoff, circuit telemetry,
    and 401/403 IntegrationAuthError mapping.
    """

    # Override: Wise does NOT support an HTTP Idempotency-Key header.
    # Idempotency is enforced at the entity level via customerTransactionId.
    IDEMPOTENCY_HEADER: str | None = None  # type: ignore[assignment]

    def __init__(
        self,
        *,
        api_key: str,
        api_base: str = "https://api.sandbox.transferwise.tech",
        webhook_secret: str | None = None,
        webhook_tolerance_s: int = 300,
        http: httpx.AsyncClient,
        max_attempts: int = 3,
        backoff_base_s: float = 0.5,
        backoff_cap_s: float = 8.0,
        sleep: Callable[[float], Coroutine[Any, Any, Any]] = asyncio.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the Wise integration client.

        Args:
            api_key: Wise API key (account-level read/write bearer token).
            api_base: Wise API base URL (default: sandbox environment).
            webhook_secret: Optional Wise webhook signing secret for signature verification.
            webhook_tolerance_s: Optional payload event timestamp tolerance in seconds
                (default: 300s).
            http: Injected async HTTP client. Composition root owns lifecycle.
            max_attempts: Maximum retry attempts for transient 5xx/transport errors.
            backoff_base_s: Initial retry backoff in seconds.
            backoff_cap_s: Maximum retry backoff cap in seconds.
            sleep: Injected async sleep coroutine for zero-sleep testing.
            now: Injected monotonic clock for deterministic latency measurement.
        """
        super().__init__(
            provider_name="wise",
            http=http,
            max_attempts=max_attempts,
            backoff_base_s=backoff_base_s,
            backoff_cap_s=backoff_cap_s,
            sleep=sleep,
            now=now,
        )
        self._api_key = api_key
        self.api_base = api_base.rstrip("/")
        self.webhook_secret = webhook_secret
        self.webhook_tolerance_s = webhook_tolerance_s
        self._wise_logger = get_logger("fluxpay.integrations.wise").bind(provider="wise")

    def _auth_headers(self) -> dict[str, str]:
        """Construct Bearer authorization header for Wise API calls.

        WHY CALL-TIME AUTH HEADERS:
        BaseClient is shared across operations, while authentication is per-instance.
        Injecting auth headers per-call preserves clean instance encapsulation and
        avoids mutating global transport defaults.
        """
        return {"Authorization": f"Bearer {self._api_key}"}

    def extract_provider_error(self, response: httpx.Response) -> str:
        """Extract machine-readable error code from Wise error response.

        HOOK OVERRIDE:
        Wise error bodies commonly appear in these shapes:
            1) {"code": "INVALID_TOKEN", "message": "..."}
            2) {"error": "invalid_grant", "error_description": "..."}
            3) {"errors": [{"code": "AMOUNT_TOO_HIGH", "message": "..."}]}

        WHY MESSAGE DROPPED (ABSENCE LAW & FORENSIC PRIVACY):
        Wise error messages frequently contain beneficiary bank details, routing numbers,
        or account holder names which constitute sensitive financial data. We extract
        ONLY the machine-readable error code into exception details.
        The human 'message' string is deliberately DROPPED and never included in
        exception details or logs, preserving audit privacy.
        """
        try:
            data = response.json()
            if isinstance(data, dict):
                # Standard code field
                code = data.get("code")
                if isinstance(code, str) and code:
                    return code
                # OAuth/generic error field
                err = data.get("error")
                if isinstance(err, str) and err:
                    return err
                # Validation error list
                err_list = data.get("errors")
                if isinstance(err_list, list) and err_list:
                    first = err_list[0]
                    if isinstance(first, dict):
                        first_code = first.get("code")
                        if isinstance(first_code, str) and first_code:
                            return first_code
        except Exception:
            return f"http_{response.status_code}"
        return f"http_{response.status_code}"

    async def request(
        self,
        op: str,
        method: str,
        url_path: str,
        *,
        json: Any | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> httpx.Response:
        """Execute HTTP request with Wise-specific header semantics.

        Wise does not support an HTTP Idempotency-Key header; passing one to BaseClient
        when IDEMPOTENCY_HEADER is None would cause a None key in headers.
        We pass idempotency_key=None to BaseClient; idempotency is handled via payload fields.
        """
        return await super().request(
            op=op,
            method=method,
            url_path=url_path,
            json=json,
            params=params,
            headers=headers,
            idempotency_key=None,
        )

    async def healthcheck(self) -> bool:
        """Cheapest authenticated ping for Wise (/v1/profiles).

        WHY BOOL LAW (NO RAISE):
        Health probes are invoked periodically by background monitors (Task 69).
        Monitors need a clean binary operational signal (True/False).
        Typed exceptions (IntegrationError, IntegrationAuthError) are reserved for
        actual operational requests where callers must handle specific failure modes.
        Health probes catch all exceptions and return False cleanly.

        Returns:
            True if Wise responds with HTTP 200, False otherwise.
        """
        try:
            resp = await self.request(
                op="healthcheck",
                method="GET",
                url_path=f"{self.api_base}/v1/profiles",
                headers=self._auth_headers(),
            )
            return resp.status_code == 200
        except Exception:
            return False

    async def get_profile(self) -> dict[str, Any]:
        """Fetch user profiles and return the primary personal profile.

        The sandbox-proven authentication probe. Returns the raw provider-shaped
        profile dictionary for Phase 2 product orchestration.

        Returns:
            Dictionary representing the primary profile.

        Raises:
            IntegrationAuthError: On 401/403 credentials defects.
            IntegrationError: On network failures, empty profiles list, or parse error.
        """
        resp = await self.request(
            op="get_profile",
            method="GET",
            url_path=f"{self.api_base}/v1/profiles",
            headers=self._auth_headers(),
        )

        try:
            data = resp.json()
        except Exception as exc:
            raise IntegrationError(
                details={
                    "provider": self.provider_name,
                    "op": "get_profile",
                    "phase": "parse",
                    "error": "invalid_json",
                }
            ) from exc

        if isinstance(data, list):
            if not data:
                raise IntegrationError(
                    details={
                        "provider": self.provider_name,
                        "op": "get_profile",
                        "phase": "parse",
                        "error": "empty_profiles",
                    }
                )
            personal = next(
                (p for p in data if isinstance(p, dict) and p.get("type") == "personal"),
                data[0],
            )
            if not isinstance(personal, dict):
                raise IntegrationError(
                    details={
                        "provider": self.provider_name,
                        "op": "get_profile",
                        "phase": "parse",
                        "error": "invalid_profile_shape",
                    }
                )
            return personal
        elif isinstance(data, dict):
            return data
        else:
            raise IntegrationError(
                details={
                    "provider": self.provider_name,
                    "op": "get_profile",
                    "phase": "parse",
                    "error": "invalid_profile_shape",
                }
            )

    async def create_quote(
        self,
        *,
        source_currency: str,
        target_currency: str,
        amount_minor: int,
    ) -> dict[str, Any]:
        """Create an inert FX quote with a guaranteed rate window.

        Args:
            source_currency: Originating currency (usd, eur, gbp).
            target_currency: Destination payout currency (usd, eur, gbp).
            amount_minor: Amount in smallest currency units (cents, pence).

        Returns:
            Wise quote dictionary containing quote 'id'.

        Raises:
            ValueError: If amount_minor <= 0 or currencies not in CURRENCY_EXPONENTS.
            IntegrationAuthError: On 401/403 authentication failures.
            IntegrationError: On network errors, provider errors, or missing quote id in 2xx.
        """
        if amount_minor <= 0:
            raise ValueError(f"Amount must be strictly positive (got {amount_minor})")

        src = source_currency.lower()
        tgt = target_currency.lower()

        if src not in CURRENCY_EXPONENTS:
            supported = sorted(CURRENCY_EXPONENTS.keys())
            raise ValueError(
                f"Unsupported source currency: '{source_currency}'. Supported: {supported}"
            )

        if tgt not in CURRENCY_EXPONENTS:
            supported = sorted(CURRENCY_EXPONENTS.keys())
            raise ValueError(
                f"Unsupported target currency: '{target_currency}'. Supported: {supported}"
            )

        payload = {
            "source": src,
            "target": tgt,
            "amount": amount_minor,
        }

        resp = await self.request(
            op="create_quote",
            method="POST",
            url_path=f"{self.api_base}/v3/quotes",
            json=payload,
            headers=self._auth_headers(),
        )

        try:
            data = resp.json()
        except Exception as exc:
            raise IntegrationError(
                details={
                    "provider": self.provider_name,
                    "op": "create_quote",
                    "phase": "parse",
                    "error": "invalid_json",
                }
            ) from exc

        if not isinstance(data, dict) or "id" not in data or not data["id"]:
            raise IntegrationError(
                details={
                    "provider": self.provider_name,
                    "op": "create_quote",
                    "phase": "parse",
                    "error": "missing_id",
                }
            )

        return data

    async def create_recipient_account(self, *, account_json: dict[str, Any]) -> dict[str, Any]:
        """Register a destination beneficiary account.

        WHY DICT-TYPED RECIPIENT HONESTY:
        Recipient requirements are jurisdiction-specific (ACH routing, IBAN/BIC, Sort Code).
        This adapter is a secure, authenticated transport layer. Schema enforcement
        belongs at the product / validation tier in Phase 2.

        Args:
            account_json: Provider-specific recipient account payload dictionary.

        Returns:
            Wise recipient account response dictionary.

        Raises:
            IntegrationAuthError: On 401/403 authentication failures.
            IntegrationError: On network failures or unparseable responses.
        """
        resp = await self.request(
            op="create_recipient_account",
            method="POST",
            url_path=f"{self.api_base}/v1/accounts",
            json=account_json,
            headers=self._auth_headers(),
        )

        try:
            data = resp.json()
        except Exception as exc:
            raise IntegrationError(
                details={
                    "provider": self.provider_name,
                    "op": "create_recipient_account",
                    "phase": "parse",
                    "error": "invalid_json",
                }
            ) from exc

        if not isinstance(data, dict):
            raise IntegrationError(
                details={
                    "provider": self.provider_name,
                    "op": "create_recipient_account",
                    "phase": "parse",
                    "error": "invalid_response_shape",
                }
            )

        return data

    async def create_transfer(
        self,
        *,
        quote_id: str,
        recipient_account_id: int,
        reference: str,
    ) -> dict[str, Any]:
        """Initiate an outbound transfer referencing an existing quote and idempotency handle.

        RESEARCH NOTE & IDEMPOTENCY ENFORCEMENT:
        customerTransactionId IS Wise's client-side idempotency handle. Re-executing
        with the identical customerTransactionId returns the EXISTING transfer without
        duplicating payout execution. The reference argument is therefore mandatory
        and enforced before dispatching any HTTP traffic.

        Args:
            quote_id: UUID of the previously locked quote.
            recipient_account_id: Numeric ID of the verified recipient account.
            reference: Client idempotency key / transaction handle (customerTransactionId).

        Returns:
            Wise transfer response dictionary.

        Raises:
            ValueError: If reference is empty, quote_id is empty, or recipient_account_id <= 0.
            IntegrationAuthError: On 401/403 authentication failures.
            IntegrationError: On network errors or provider errors.
        """
        if not reference or not reference.strip():
            raise ValueError(
                "Transfer reference (customerTransactionId) must be non-empty for idempotency. "
                "Never generate reference dynamically per retry attempt."
            )

        if not quote_id or not quote_id.strip():
            raise ValueError("quote_id must be non-empty")

        if recipient_account_id <= 0:
            raise ValueError(f"recipient_account_id must be positive (got {recipient_account_id})")

        payload = {
            "targetAccount": recipient_account_id,
            "quote": quote_id,
            "customerTransactionId": reference,
        }

        resp = await self.request(
            op="create_transfer",
            method="POST",
            url_path=f"{self.api_base}/v1/transfers",
            json=payload,
            headers=self._auth_headers(),
        )

        try:
            data = resp.json()
        except Exception as exc:
            raise IntegrationError(
                details={
                    "provider": self.provider_name,
                    "op": "create_transfer",
                    "phase": "parse",
                    "error": "invalid_json",
                }
            ) from exc

        if not isinstance(data, dict):
            raise IntegrationError(
                details={
                    "provider": self.provider_name,
                    "op": "create_transfer",
                    "phase": "parse",
                    "error": "invalid_response_shape",
                }
            )

        return data

    def verify_webhook(
        self,
        *,
        payload: bytes,
        sig_header: str,
        webhook_secret: str | None = None,
        now: Callable[[], float] | float | int = time.time,
    ) -> dict[str, Any] | None:
        """Verify Wise webhook signature timing-safely and parse JSON payload.

        THE CRYPTOGRAPHIC CONTRACT:
        1. Extract header X-Signature-SHA256.
        2. Decode Base64 signature. If header is hex-encoded or invalid Base64, reject strictly.
        3. Compute expected HMAC: HMAC-SHA256(webhook_secret, raw_payload).digest().
        4. Compare timing-safely using `hmac.compare_digest`.
        5. Parse JSON payload with orjson.loads(payload).
           - If signature is VALID but JSON is MALFORMED, log WARNING:
             "wise webhook: valid signature, invalid json" and return None.
        6. If payload contains an event timestamp field ('timestamp', 'occurred_at', 'created_at'),
           verify abs(now - ts) <= tolerance_s. If outside tolerance, return None.

        WHY VERIFY-RETURNS-NONE-NOT-RAISE:
        Webhook ingestion endpoints sit in the high-volume public ingress path.
        Returning None allows the endpoint handler to immediately respond 400 Bad Request
        without expensive Python exception stack allocation and tracebacks.

        Args:
            payload: Raw request body bytes.
            sig_header: The 'X-Signature-SHA256' header string (Base64-encoded).
            webhook_secret: Optional override; defaults to self.webhook_secret.
            now: Injected current timestamp or clock callable (default: time.time).

        Returns:
            Parsed event dictionary on valid signature, or None on failure/expiration.
        """
        secret = webhook_secret if webhook_secret is not None else self.webhook_secret
        if not secret:
            return None

        if not sig_header or not isinstance(sig_header, str):
            return None

        sig_str = sig_header.strip()

        # Base64 strict validation: SHA-256 binary digest is exactly 32 bytes
        try:
            decoded_sig = base64.b64decode(sig_str, validate=True)
        except Exception:
            return None

        if len(decoded_sig) != 32:
            return None

        expected_digest = hmac.new(
            secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(decoded_sig, expected_digest):
            return None

        try:
            data = orjson.loads(payload)
        except Exception:
            self._wise_logger.warning("wise webhook: valid signature, invalid json")
            return None

        if not isinstance(data, dict):
            self._wise_logger.warning("wise webhook: valid signature, invalid json")
            return None

        # Optional payload timestamp tolerance validation
        ts_field = data.get("timestamp") or data.get("occurred_at") or data.get("created_at")
        if ts_field is not None:
            try:
                event_ts: float | None = None
                if isinstance(ts_field, int | float):
                    event_ts = float(ts_field)
                elif isinstance(ts_field, str):
                    try:
                        event_ts = float(ts_field)
                    except ValueError:
                        event_ts = datetime.fromisoformat(ts_field).timestamp()

                if event_ts is not None:
                    curr_time: float = float(now()) if callable(now) else float(now)
                    if abs(curr_time - event_ts) > self.webhook_tolerance_s:
                        return None
            except Exception:
                return None

        return data
