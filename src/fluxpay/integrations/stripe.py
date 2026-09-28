"""Stripe external rail integration client and fiat utilities (Block J, Part 3).

==============================================================================
THE ANTI-CONVERSION ESSAY (THE MINOR-UNITS IDENTITY LAW)
==============================================================================
A pervasive defect in payment integrations is unnecessary currency conversion.
Junior engineers often assume that because human invoices say "$10.50", an API
expects a floating-point "10.50" or that a conversion function `to_minor()` or
`to_major()` must divide or multiply by 100.0.

In truth, Stripe's API amounts (`unit_amount`, `amount`) are ALWAYS specified in
the currency's smallest subunit (cents for USD/EUR, integer yen for JPY).
FluxPay's internal ledger and gateway represent fiat amounts in exact integer
minor units:
  - USD: 2 decimal places -> 1 cent = 1 minor unit. $10.50 = 1050 minor units.
  - EUR: 2 decimal places -> 1 cent = 1 minor unit. €10.50 = 1050 minor units.
  - JPY: 0 decimal places -> 1 yen  = 1 minor unit. ¥1050  = 1050 minor units.

The relationship between FluxPay minor units and Stripe API amount units is an
EXACT 1:1 IDENTITY for all supported currencies. Performing multiplication or
division introduces floating-point truncation, rounding error, and subtle off-by-one
cent reconciliation discrepancies.

Therefore, this adapter performs NO unit conversion on amounts passed to Stripe.
The `EXPONENTS` dictionary serves strictly as a currency allowlist and decimal
precision reference for validation and display formatting.
Unknown currencies are rejected immediately with `ValueError` (the fiat equivalent
of Task 50's runtime decimals guard).

Note on USDC:
USDC is NOT a Stripe currency in our integration. The future merchant on-ramp
(Phase 2) accepts fiat via Stripe Payment Links and converts to USDC off-platform
or via internal treasury netting. The Stripe adapter mints links and verifies
incoming webhooks; it never modifies balances or converts crypto.

==============================================================================
DESIGN LAWS & INVARIANTS:
==============================================================================
1. TIMING-SAFE WEBHOOK VERIFICATION:
   Stripe webhook signatures use HMAC-SHA256 over `f"{timestamp}.{payload}"`.
   Signatures are verified using `hmac.compare_digest` to prevent timing attacks.
   Multiple `v1` signatures in the `Stripe-Signature` header are evaluated per the
   Stripe specification: if ANY signature matches, verification succeeds.
   Stripe signatures are strictly lowercase hex; uppercase signatures are rejected.

2. VERIFY-RETURNS-NONE LAW (HOT PATH RESILIENCE):
   Webhook receivers must respond 400 Bad Request to unverified or expired payloads
   without incurring Python exception allocation overhead in the hot path.
   `verify_webhook()` returns `None` on verification failure, expiration, or
   malformed JSON. The log sink captures forensic audit details.

3. NONE-BUT-LOGGED INVALID JSON SIGNAL:
   A payload with a VALID cryptographic signature but INVALID JSON is a severe
   anomaly — either upstream message corruption or an active signature collision/
   replay attempt. `verify_webhook()` logs a high-priority WARNING:
   "stripe webhook: valid signature, invalid json", documenting that returning None
   is never a silent drop.

4. CALL-TIME AUTHENTICATION HEADERS:
   `BaseClient` manages connection pooling and shared transport across instances.
   Authentication credentials (`_secret_key`) are per-instance. Auth headers are
   attached per-request via `_auth_headers()`, preserving thread-safety and
   preventing header pollution across tenants.

5. PROVIDER ERROR HOOK (ABSENCE LAW & PRIVACY):
   `extract_provider_error()` extracts only the machine-readable error `code`
   (e.g. 'card_declined'). The human-readable `message` is deliberately DROPPED
   and never logged or placed in exception details, preventing customer PII or
   card details from leaking into application logs or SIEM indexers.

6. HEALTHCHECK BOOL LAW:
   `healthcheck()` issues `GET /v1/balance` as the cheapest authenticated probe.
   It catches all exceptions and returns a boolean `True` (200) or `False` (401/error).
   Monitors poll health as a signal; typed exceptions belong to operational requests.

7. MINIMAL PHASE 1 SCOPE:
   This adapter contains only `create_payment_link`, `healthcheck`, and `verify_webhook`.
   No balance writes, no refunds, no payouts, no subscriptions.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import time
from collections.abc import Callable, Coroutine
from typing import Any, Final

import httpx
import orjson

from fluxpay.integrations.base import BaseClient
from fluxpay.shared.errors import IntegrationError
from fluxpay.shared.logging import get_logger

__all__ = [
    "EXPONENTS",
    "StripeClient",
    "minor_to_major_str",
]

# Supported fiat currency exponents (ISO 4217 decimal places)
# 2 = 2 decimal places (cents), 0 = 0 decimal places (e.g. JPY)
EXPONENTS: Final[dict[str, int]] = {
    "usd": 2,
    "eur": 2,
    "jpy": 0,
}


def minor_to_major_str(amount_minor: int, currency: str) -> str:
    """Validate currency and return integer minor units as a string.

    NOTE: Stripe's API accepts integer smallest units (cents for USD/EUR, yen for JPY),
    which are 1:1 identical to FluxPay's minor units. This helper validates currency
    support against EXPONENTS and formats amount_minor as a string without floating-point math.

    Args:
        amount_minor: Amount in smallest currency units (e.g. 1050 cents = $10.50).
        currency: 3-letter ISO currency code.

    Returns:
        String representation of amount_minor.

    Raises:
        ValueError: If currency is not in EXPONENTS.
    """
    curr = currency.lower()
    if curr not in EXPONENTS:
        supported = sorted(EXPONENTS.keys())
        raise ValueError(f"Unsupported currency: '{currency}'. Supported: {supported}")
    return str(amount_minor)


class StripeClient(BaseClient):
    """Stripe external rail integration adapter (Block J, Part 3).

    Inherits BaseClient's retry ladder, exponential backoff, circuit telemetry,
    and 401/403 IntegrationAuthError mapping.
    """

    IDEMPOTENCY_HEADER: str = "Idempotency-Key"

    def __init__(
        self,
        *,
        secret_key: str,
        webhook_secret: str | None = None,
        api_base: str = "https://api.stripe.com",
        webhook_tolerance_s: int = 300,
        http: httpx.AsyncClient,
        max_attempts: int = 3,
        backoff_base_s: float = 0.5,
        backoff_cap_s: float = 8.0,
        sleep: Callable[[float], Coroutine[Any, Any, Any]] = asyncio.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the Stripe integration client.

        Args:
            secret_key: Stripe secret API key (starts with sk_test_ in sandbox).
            webhook_secret: Optional Stripe webhook signing secret (whsec_...).
            api_base: Stripe API base URL (default: https://api.stripe.com).
            webhook_tolerance_s: Webhook timestamp tolerance in seconds (default: 300s).
            http: Injected async HTTP client. Composition root owns lifecycle.
            max_attempts: Maximum retry attempts for transient 5xx/transport errors.
            backoff_base_s: Initial retry backoff in seconds.
            backoff_cap_s: Maximum retry backoff cap in seconds.
            sleep: Injected async sleep coroutine for zero-sleep testing.
            now: Injected monotonic clock for deterministic latency measurement.
        """
        super().__init__(
            provider_name="stripe",
            http=http,
            max_attempts=max_attempts,
            backoff_base_s=backoff_base_s,
            backoff_cap_s=backoff_cap_s,
            sleep=sleep,
            now=now,
        )
        self._secret_key = secret_key
        self.webhook_secret = webhook_secret
        self.api_base = api_base.rstrip("/")
        self.webhook_tolerance_s = webhook_tolerance_s
        self._stripe_logger = get_logger("fluxpay.integrations.stripe").bind(provider="stripe")

    def _auth_headers(self) -> dict[str, str]:
        """Construct Bearer authorization header for Stripe API calls.

        WHY CALL-TIME AUTH HEADERS:
        BaseClient is shared across operations, while authentication is per-instance.
        Injecting auth headers per-call preserves clean instance encapsulation and
        avoids mutating global transport defaults.
        """
        return {"Authorization": f"Bearer {self._secret_key}"}

    def extract_provider_error(self, response: httpx.Response) -> str:
        """Extract machine-readable error code from Stripe error response.

        HOOK OVERRIDE:
        Stripe error responses follow the shape:
            {"error": {"code": "card_declined", "message": "...", "type": "..."}}

        WHY MESSAGE DROPPED (ABSENCE LAW & FORENSIC PRIVACY):
        Stripe error messages often echo input values, card brands, or customer details
        which could constitute PII or sensitive payment data. We extract ONLY the
        machine error code (e.g. 'card_declined') into error details.
        The human 'message' string is deliberately DROPPED and never included in
        exception details or logs, preserving audit privacy.
        """
        try:
            data = response.json()
            if isinstance(data, dict):
                error_obj = data.get("error")
                if isinstance(error_obj, dict):
                    code = error_obj.get("code")
                    if isinstance(code, str) and code:
                        return code
                    err_type = error_obj.get("type")
                    if isinstance(err_type, str) and err_type:
                        return err_type
        except Exception:
            return f"http_{response.status_code}"
        return f"http_{response.status_code}"

    async def healthcheck(self) -> bool:
        """Cheapest authenticated ping for Stripe (/v1/balance).

        WHY BOOL LAW (NO RAISE):
        Health probes are invoked periodically by background monitors (Task 69).
        Monitors need a clean binary operational signal (True/False).
        Typed exceptions (IntegrationError, IntegrationAuthError) are reserved for
        actual business requests where callers must handle specific error modes.
        Health probes catch all exceptions and return False cleanly.

        Returns:
            True if Stripe responds with HTTP 200, False otherwise.
        """
        try:
            resp = await self.request(
                op="healthcheck",
                method="GET",
                url_path=f"{self.api_base}/v1/balance",
                headers=self._auth_headers(),
            )
            return resp.status_code == 200
        except Exception:
            return False

    async def create_payment_link(
        self,
        *,
        amount_minor: int,
        currency: str,
        description: str,
        idempotency_key: str,
    ) -> str:
        """Create a Stripe Payment Link for customer checkout (future on-ramp primitive).

        Args:
            amount_minor: Payment amount in smallest currency units (cents, yen).
            currency: 3-letter ISO currency code (usd, eur, jpy).
            description: Product line-item description.
            idempotency_key: Client-supplied idempotency key for safe POST retries.

        Returns:
            The generated Stripe checkout URL string.

        Raises:
            ValueError: If amount_minor <= 0 or currency is not supported in EXPONENTS.
            IntegrationAuthError: On 401/403 authentication failures.
            IntegrationError: On network failures, provider errors, or missing/invalid url in 2xx.
        """
        if amount_minor <= 0:
            raise ValueError(f"Amount must be strictly positive (got {amount_minor})")

        curr = currency.lower()
        if curr not in EXPONENTS:
            supported = sorted(EXPONENTS.keys())
            raise ValueError(f"Unsupported currency: '{currency}'. Supported: {supported}")

        payload = {
            "line_items": [
                {
                    "price_data": {
                        "currency": curr,
                        "unit_amount": amount_minor,
                        "product_data": {
                            "name": description,
                        },
                    },
                    "quantity": 1,
                }
            ]
        }

        resp = await self.request(
            op="create_payment_link",
            method="POST",
            url_path=f"{self.api_base}/v1/payment_links",
            json=payload,
            headers=self._auth_headers(),
            idempotency_key=idempotency_key,
        )

        try:
            data = resp.json()
        except Exception as exc:
            raise IntegrationError(
                details={
                    "provider": self.provider_name,
                    "op": "create_payment_link",
                    "phase": "parse",
                    "error": "invalid_json",
                }
            ) from exc

        if (
            not isinstance(data, dict)
            or "url" not in data
            or not isinstance(data["url"], str)
            or not data["url"]
        ):
            raise IntegrationError(
                details={
                    "provider": self.provider_name,
                    "op": "create_payment_link",
                    "phase": "parse",
                    "error": "missing_url",
                }
            )

        return data["url"]

    def verify_webhook(
        self,
        *,
        payload: bytes,
        sig_header: str,
        webhook_secret: str | None = None,
        now: Callable[[], float] | float | int = time.time,
    ) -> dict[str, Any] | None:
        """Verify Stripe webhook signature timing-safely and parse JSON payload.

        THE CRYPTOGRAPHIC CONTRACT:
        1. Parse header: "t=<timestamp>,v1=<sig1>,v1=<sig2>".
        2. Validate timestamp against tolerance window: abs(now - t) <= tolerance_s.
        3. Form signed payload: b"<t>.<payload>".
        4. Compute expected HMAC: HMAC-SHA256(webhook_secret, signed_payload).hexdigest().
        5. Compare timing-safely with `hmac.compare_digest`.
           - ANY matching v1 signature validates the request (per Stripe spec).
           - Signatures are strictly lowercase hex (uppercase signatures are rejected).
        6. Decode payload via orjson.loads(payload).

        WHY VERIFY-RETURNS-NONE-NOT-RAISE:
        Webhook ingestion endpoints sit in the high-volume public ingress path.
        Returning None allows the endpoint handler to immediately respond 400 Bad Request
        without expensive Python exception stack allocation and tracebacks.

        WHY NONE-BUT-LOGGED FOR MALFORMED JSON:
        A valid cryptographic signature coupled with unparseable JSON payload is an
        ATTACK SIGNAL or upstream provider anomaly. It returns None (rejecting the event)
        while emitting a WARNING log: "stripe webhook: valid signature, invalid json"
        for SIEM forensics. None-but-logged != silent drop.

        Args:
            payload: Raw request body bytes.
            sig_header: The 'Stripe-Signature' header string.
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

        t_str: str | None = None
        v1_signatures: list[str] = []

        for item in sig_header.split(","):
            item = item.strip()
            if not item or "=" not in item:
                continue
            key, _, val = item.partition("=")
            key = key.strip()
            val = val.strip()
            if key == "t":
                t_str = val
            elif key == "v1":
                v1_signatures.append(val)

        if t_str is None or not v1_signatures:
            return None

        try:
            t = int(t_str)
        except (ValueError, TypeError):
            return None

        curr_time: float = float(now()) if callable(now) else float(now)
        if abs(curr_time - t) > self.webhook_tolerance_s:
            return None

        signed_payload = f"{t}.".encode() + payload
        expected_sig = hmac.new(
            secret.encode(),
            signed_payload,
            hashlib.sha256,
        ).hexdigest()

        matched = False
        for sig in v1_signatures:
            # Stripe sends strictly lowercase hex signatures; reject uppercase signatures
            if any(c.isupper() for c in sig):
                continue
            if hmac.compare_digest(sig, expected_sig):
                matched = True
                break

        if not matched:
            return None

        try:
            data = orjson.loads(payload)
        except Exception:
            self._stripe_logger.warning("stripe webhook: valid signature, invalid json")
            return None

        if not isinstance(data, dict):
            self._stripe_logger.warning("stripe webhook: valid signature, invalid json")
            return None

        return data
