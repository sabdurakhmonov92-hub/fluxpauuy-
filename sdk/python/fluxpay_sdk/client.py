"""=============================================================================
FluxPay Python SDK Client — The Developer-Facing Interface
=============================================================================
Vendoring Law:
    This client is thin and self-contained. It depends strictly on `httpx` and the
    Python standard library. It does NOT import any server-side modules from `fluxpay`.
    Models are defined as lightweight frozen dataclasses mirroring the server-side
    Task 24 wire contract without requiring Pydantic or server dependencies.

Retry Law (Task 4 Parity):
    - Retries transient errors (429 RateLimit, 502 Bad Gateway, 503 Service Unavailable,
      and transport/network timeouts) using exponential backoff with jitter capped at 8s.
    - NEVER retries permanent errors (400 InsufficientFunds, 401 Authentication,
      403 Forbidden, 404 NotFound, 409 IdempotencyConflict, 422 Validation/Policy).
    - Preserves the same `X-FLX-Idempotency-Key` across retries of write operations (`pay`),
      guaranteeing convergence through server-side idempotency tiers.
=============================================================================
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Literal
from uuid import UUID, uuid4

import httpx

from .signing import (
    HEADER_AUTH,
    HEADER_IDEMPOTENCY,
    HEADER_NONCE,
    HEADER_TIMESTAMP,
    sign,
    validate_idempotency_key,
)

__all__ = [
    "CURRENCY_PATTERN",
    "MERCHANT_ID_PATTERN",
    "Balance",
    "FluxPayApiError",
    "FluxPayClient",
    "FluxPayError",
    "FluxPayNetworkError",
    "PaymentDetail",
    "PaymentResult",
    "PaymentStatus",
]

PaymentStatus = Literal["settled", "held"]

# Task 24 mirrored wire regex constraints
MERCHANT_ID_PATTERN: Final[str] = r"^[a-z0-9_.-]{3,64}$"
_MERCHANT_REGEX: Final[re.Pattern[str]] = re.compile(MERCHANT_ID_PATTERN)

CURRENCY_PATTERN: Final[str] = r"^[A-Z0-9]{2,10}$"
_CURRENCY_REGEX: Final[re.Pattern[str]] = re.compile(CURRENCY_PATTERN)


# =============================================================================
# 1. TYPED EXCEPTIONS (Machine-Readable Error Dialect)
# =============================================================================


class FluxPayError(Exception):
    """Base exception for all errors raised by the FluxPay SDK."""


class FluxPayApiError(FluxPayError):
    """Exception raised when the FluxPay gateway returns an HTTP 4xx or 5xx error.

    Exposes typed, machine-readable properties conforming to Task 4's ErrorEnvelope:
    - code: Machine-readable category string (e.g. 'rate_limited', 'not_found').
    - message: Sanitized human-readable error description.
    - retryable: Boolean indicating whether client agents may safely retry.
    - status: HTTP status code returned by the gateway.
    """

    def __init__(
        self,
        *,
        code: str,
        message: str,
        retryable: bool,
        status: int,
    ) -> None:
        self.code = code
        self.message = message
        self.retryable = retryable
        self.status = status
        super().__init__(f"[{status}] {code}: {message} (retryable={retryable})")


class FluxPayNetworkError(FluxPayError):
    """Exception raised when network transport fails after exhausting retry budget.

    Retryable semantics: TRUE. Network blips, DNS issues, or connection timeouts
    are transient infrastructure conditions. Callers may retry at a later time.
    """

    def __init__(
        self,
        message: str,
        *,
        retryable: bool = True,
        cause: Exception | None = None,
    ) -> None:
        self.message = message
        self.retryable = retryable
        self.cause = cause
        super().__init__(message)


# =============================================================================
# 2. DATA MODELS (Frozen Mirrored Wire Shapes)
# =============================================================================


@dataclass(frozen=True)
class PaymentResult:
    """Result of POST /v1/payments (Task 24 PaymentResponse mirror).

    Attributes:
        id: Unique payment identifier (UUID corresponding 1:1 with ledger tx_id).
        status: Terminal execution status ('settled' or 'held').
    """

    id: UUID
    status: PaymentStatus


@dataclass(frozen=True)
class Balance:
    """Result of GET /v1/balance (Task 24 BalanceResponse mirror).

    Attributes:
        balance: Available ledger balance in integer minor units (non-negative).
        currency: Currency code (e.g. 'USDC').
    """

    balance: int
    currency: str


@dataclass(frozen=True)
class PaymentDetail:
    """Result of GET /v1/payments/{payment_id} (Task 24 PaymentDetail mirror).

    Attributes:
        id: Unique payment identifier (UUID).
        status: Payment execution status ('settled' or 'held').
        amount: Payment amount in integer minor units.
        currency: Currency code.
        created_at: Payment creation timestamp (UTC timezone-aware datetime).
    """

    id: UUID
    status: PaymentStatus
    amount: int
    currency: str
    created_at: datetime


# =============================================================================
# 3. CLIENT IMPLEMENTATION
# =============================================================================


class FluxPayClient:
    """Asynchronous client for the FluxPay Agent Payment Gateway.

    Hides request signing (FLXP1 HMAC-SHA256), replay protection (nonces/timestamps),
    idempotency key generation, and bounded exponential retries.
    """

    def __init__(
        self,
        *,
        agent_id: str,
        secret: str,
        base_url: str,
        timeout_s: float = 10.0,
        max_retries: int = 3,
        http: httpx.AsyncClient | None = None,
        sleep_fn: Callable[[float], Coroutine[Any, Any, None]] | None = None,
    ) -> None:
        """Initialize FluxPayClient.

        Args:
            agent_id: The UUID of the calling agent (provided at agent provisioning).
            secret: The agent's secret key as a string (from one-time creation display).
                    Converted to UTF-8 bytes internally; never logged or exposed.
            base_url: The base URL of the FluxPay gateway (e.g. 'https://api.fluxpay.dev').
            timeout_s: HTTP request timeout in seconds (default: 10.0).
            max_retries: Maximum number of retries on transient errors (default: 3).
            http: Optional external httpx.AsyncClient instance for connection reuse or testing.
            sleep_fn: Injected sleep function for testability (defaults to asyncio.sleep).
        """
        self._agent_id = str(agent_id).strip()
        self._secret_bytes = secret.encode("utf-8")
        self._base_url = base_url.rstrip("/")
        self._timeout_s = float(timeout_s)
        self._max_retries = int(max_retries)
        self._sleep = sleep_fn if sleep_fn is not None else asyncio.sleep

        if http is not None:
            self._http = http
            self._owns_http = False
        else:
            self._http = httpx.AsyncClient(
                timeout=self._timeout_s,
                base_url=self._base_url,
                http2=True,
            )
            self._owns_http = True

    async def __aenter__(self) -> FluxPayClient:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close underlying HTTP client session if owned by this instance."""
        if self._owns_http:
            await self._http.aclose()

    async def pay(
        self,
        *,
        to: str,
        amount: int,
        currency: str = "USDC",
        idempotency_key: str | None = None,
    ) -> PaymentResult:
        """Execute a payment transfer to a merchant (The 3-Line Face).

        Args:
            to: Target merchant external ID handle (must match [a-z0-9_.-]{3,64}).
            amount: Payment amount in integer minor units (e.g. 1050 = $10.50 USDC).
            currency: Currency symbol (e.g. 'USDC').
            idempotency_key: Optional client-specified idempotency key (16-128 chars).
                             If omitted, an opaque UUID-v4 hex string is generated.

        Returns:
            PaymentResult containing the payment UUID and terminal status.

        Raises:
            ValueError: If `to`, `amount`, `currency`, or `idempotency_key` are invalid.
            FluxPayApiError: If the gateway rejects the payment (e.g. insufficient funds, 404).
            FluxPayNetworkError: If transport fails after exhausting max retries.
        """
        # Client-side fast validation: fail fast, save an unnecessary network roundtrip
        if not isinstance(to, str) or not _MERCHANT_REGEX.fullmatch(to):
            raise ValueError(
                f"Invalid merchant id format: {to!r}. Must match {_MERCHANT_REGEX.pattern}"
            )
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise ValueError(f"Amount must be a positive integer in minor units, got {amount!r}")
        if not isinstance(currency, str) or not _CURRENCY_REGEX.fullmatch(currency):
            raise ValueError(
                f"Invalid currency format: {currency!r}. Must match {_CURRENCY_REGEX.pattern}"
            )

        idem = idempotency_key if idempotency_key is not None else uuid4().hex
        validate_idempotency_key(idem)

        # Body serialization: stdlib json with compact separators (",", ":")
        payload = {"to": to, "amount": amount, "currency": currency}
        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        response = await self._request_with_retry(
            method="POST",
            path="/v1/payments",
            body=body_bytes,
            idem=idem,
        )
        return self._parse_payment_response(response)

    async def get_payment(self, payment_id: str | UUID) -> PaymentDetail:
        """Retrieve details of an existing payment by its unique ID.

        Args:
            payment_id: The UUID of the payment.

        Returns:
            PaymentDetail containing status, amount, currency, and creation timestamp.

        Raises:
            FluxPayApiError: If payment is not found (404) or on gateway error.
            FluxPayNetworkError: If network transport fails.
        """
        pid = str(payment_id).strip()
        response = await self._request_with_retry(
            method="GET",
            path=f"/v1/payments/{pid}",
            body=b"",
        )
        return self._parse_payment_detail_response(response)

    async def balance(self, currency: str = "USDC") -> Balance:
        """Retrieve the available ledger balance for the authenticated agent.

        Args:
            currency: Currency code (default: 'USDC').

        Returns:
            Balance containing available integer minor units and currency code.

        Raises:
            FluxPayApiError: On gateway error.
            FluxPayNetworkError: If network transport fails.
        """
        # Note: Query strings are strictly forbidden in FLXP1 signed routes.
        # GET /v1/balance evaluates the agent's account.
        response = await self._request_with_retry(
            method="GET",
            path="/v1/balance",
            body=b"",
        )
        return self._parse_balance_response(response)

    # -------------------------------------------------------------------------
    # Core Request & Retry Engine
    # -------------------------------------------------------------------------

    async def _request_with_retry(
        self,
        method: str,
        path: str,
        body: bytes,
        idem: str | None = None,
    ) -> httpx.Response:
        """Send authenticated request with bounded exponential backoff on retryable errors.

        SAME-KEY RETRY LAW:
        When retrying `POST` operations, the SAME `idem` key is preserved across all attempts.
        Fresh timestamps and nonces are generated on every attempt to satisfy replay protection,
        while the idempotency key remains constant so the server converges via Task 22/11 tiers.
        """
        for attempt in range(self._max_retries + 1):
            ts_str = str(int(time.time() * 1000))
            nonce_val = uuid4().hex

            sig = sign(
                secret=self._secret_bytes,
                method=method,
                path=path,
                timestamp=ts_str,
                nonce=nonce_val,
                body=body,
            )

            headers: dict[str, str] = {
                HEADER_AUTH: f"FLXP1 {self._agent_id}:{sig}",
                HEADER_TIMESTAMP: ts_str,
                HEADER_NONCE: nonce_val,
            }
            if idem is not None:
                headers[HEADER_IDEMPOTENCY] = idem
            if body:
                headers["Content-Type"] = "application/json"

            try:
                resp = await self._http.request(
                    method=method,
                    url=path,
                    content=body,
                    headers=headers,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                if attempt < self._max_retries:
                    # Bounded exponential backoff with jitter: 0.5 * 2^attempt + jitter, cap 8s
                    jitter = random.SystemRandom().uniform(0.0, 0.1)
                    backoff = min(8.0, 0.5 * (2**attempt) + jitter)
                    await self._sleep(backoff)
                    continue
                raise FluxPayNetworkError(
                    f"Network request failed after {self._max_retries} retries: {exc}",
                    retryable=True,
                    cause=exc,
                ) from exc

            # Success responses (200, 201) return immediately
            if resp.is_success:
                return resp

            # Retryable HTTP status codes per Task 4:
            # 429 (RateLimitError), 502 (Bad Gateway), 503 (OCCConflict / GateUnavailable)
            if resp.status_code in (429, 502, 503):
                if attempt < self._max_retries:
                    jitter = random.SystemRandom().uniform(0.0, 0.1)
                    backoff = min(8.0, 0.5 * (2**attempt) + jitter)
                    await self._sleep(backoff)
                    continue
                # Exhausted retry budget on retryable status
                raise self._parse_error_envelope(resp)

            # Permanent non-retryable errors (400, 401, 403, 404, 409, 422, etc.)
            raise self._parse_error_envelope(resp)

        # Unreachable under normal conditions, but satisfies static type checking
        raise FluxPayNetworkError(  # pragma: no cover
            f"Request failed after {self._max_retries} retries",
            retryable=True,
        )

    # -------------------------------------------------------------------------
    # Response Parsing Helpers (Vendoring Law: No Pydantic Required)
    # -------------------------------------------------------------------------

    @staticmethod
    def _parse_error_envelope(resp: httpx.Response) -> FluxPayApiError:
        """Extract typed error from standard ErrorEnvelope or build fallback."""
        try:
            data = resp.json()
            if isinstance(data, dict) and "error" in data and isinstance(data["error"], dict):
                err = data["error"]
                code = str(err.get("code", "unknown_error"))
                message = str(err.get("message", resp.text))
                retryable = bool(err.get("retryable", False))
                return FluxPayApiError(
                    code=code,
                    message=message,
                    retryable=retryable,
                    status=resp.status_code,
                )
        except (ValueError, TypeError):
            # Response was not valid JSON or dictionary structure; fallback below
            pass

        return FluxPayApiError(
            code="http_error",
            message=resp.text or f"HTTP {resp.status_code}",
            retryable=resp.status_code in (429, 502, 503),
            status=resp.status_code,
        )

    @staticmethod
    def _parse_payment_response(resp: httpx.Response) -> PaymentResult:
        """Parse POST /v1/payments JSON response into PaymentResult."""
        data = resp.json()
        raw_id = data.get("id")
        raw_status = data.get("status")
        if not raw_id or raw_status not in ("settled", "held"):
            raise FluxPayApiError(
                code="invalid_response",
                message=f"Malformed payment response: {data!r}",
                retryable=False,
                status=resp.status_code,
            )
        return PaymentResult(id=UUID(str(raw_id)), status=raw_status)

    @staticmethod
    def _parse_balance_response(resp: httpx.Response) -> Balance:
        """Parse GET /v1/balance JSON response into Balance."""
        data = resp.json()
        if "balance" not in data or "currency" not in data:
            raise FluxPayApiError(
                code="invalid_response",
                message=f"Malformed balance response: {data!r}",
                retryable=False,
                status=resp.status_code,
            )
        return Balance(balance=int(data["balance"]), currency=str(data["currency"]))

    @staticmethod
    def _parse_payment_detail_response(resp: httpx.Response) -> PaymentDetail:
        """Parse GET /v1/payments/{id} JSON response into PaymentDetail."""
        data = resp.json()
        raw_id = data.get("id")
        raw_status = data.get("status")
        if (
            not raw_id
            or raw_status not in ("settled", "held")
            or "amount" not in data
            or "currency" not in data
            or "created_at" not in data
        ):
            raise FluxPayApiError(
                code="invalid_response",
                message=f"Malformed payment detail response: {data!r}",
                retryable=False,
                status=resp.status_code,
            )
        return PaymentDetail(
            id=UUID(str(raw_id)),
            status=raw_status,
            amount=int(data["amount"]),
            currency=str(data["currency"]),
            created_at=datetime.fromisoformat(str(data["created_at"])),
        )
