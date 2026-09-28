"""Integration Base Client: the unified external provider adapter contract.

This module establishes the single base client inherited by all external provider
adapters (readers, Stripe, Wise, KYC) in FluxPay Block J. It enforces:
- Injected HTTP client lifecycle (MockTransport-friendly, no module-level clients).
- Injected clock and sleep primitives for deterministic, zero-sleep unit testing.
- Reliable exponential backoff ladder with jitter and Retry-After header precedence.
- Semantic error classification (401/403 config auth defects vs 502 transient upstream).
- Strict secret-free and PII-free observability (absence law).
- Method law for idempotency keys (POST only).
- Stable operation-level correlation IDs across all retry attempts.
"""

from __future__ import annotations

import asyncio
import random
import time
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

import httpx

from fluxpay.shared.errors import IntegrationAuthError, IntegrationError
from fluxpay.shared.logging import get_logger


@dataclass(frozen=True, slots=True)
class ProviderCall:
    """The observation unit for external provider operations.

    Emitted via structlog for downstream ingestion by Task 69's metrics pipeline.
    BaseClient never stores state internally; observation records are strictly transient.
    """

    provider: str
    op: str
    status: int | None
    duration_ms: int
    ok: bool


class BaseClient:
    """Base class for all third-party API and external rail integrations.

    Implements the standard retry ladder, 429 Retry-After pacing, secret-free logging,
    and contract error mapping. Subclasses override `extract_provider_error()` to map
    provider-specific error bodies and implement `healthcheck()` for authenticated pings.
    """

    # Extension point for provider-specific idempotency header conventions
    # (e.g. Stripe uses 'Idempotency-Key', other providers may use custom headers).
    IDEMPOTENCY_HEADER: str = "Idempotency-Key"

    def __init__(
        self,
        *,
        provider_name: str,
        http: httpx.AsyncClient,
        max_attempts: int = 3,
        backoff_base_s: float = 0.5,
        backoff_cap_s: float = 8.0,
        sleep: Callable[[float], Coroutine[Any, Any, Any]] = asyncio.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialize the integration client with injected dependencies.

        Args:
            provider_name: Unique identifier for the provider (e.g. 'stripe', 'wise').
            http: Injected async HTTP client. Application composition root owns lifecycle;
                  unit tests inject httpx.MockTransport.
            max_attempts: Maximum total attempts for retryable failures (transient 5xx/transport).
            backoff_base_s: Initial backoff duration in seconds (base * 2^n).
            backoff_cap_s: Maximum ceiling for backoff sleep durations in seconds.
            sleep: Injected sleep coroutine for zero-sleep testing discipline.
            now: Injected monotonic clock for deterministic latency measurement.
        """
        self.provider_name = provider_name
        self._http = http
        self.max_attempts = max_attempts
        self.backoff_base_s = backoff_base_s
        self.backoff_cap_s = backoff_cap_s
        self._sleep = sleep
        self._now = now
        self._logger = get_logger("fluxpay.integrations").bind(provider=provider_name)

    def extract_provider_error(self, response: httpx.Response) -> str:
        """Extract a provider-specific machine error code from the response.

        HOOK: Default implementation returns 'http_{status_code}'.
        Subclasses override this hook to parse provider-specific JSON dialects
        (e.g. Stripe's {"error": {"code": ...}} or Wise's {"errors": [...]}).
        The provider dialect stays strictly isolated within the concrete adapter;
        BaseClient never parses provider-specific response schemas.
        """
        return f"http_{response.status_code}"

    async def healthcheck(self) -> bool:
        """Cheapest authenticated ping for this external provider.

        Must be implemented by concrete provider adapters (Tasks 50, 52, 55).
        """
        raise NotImplementedError(
            f"Provider '{self.provider_name}' does not implement healthcheck(). "
            "Concrete adapters must define their cheapest authenticated ping."
        )

    def _record_call(self, call: ProviderCall) -> None:
        # --- Task 69 append ---
        import importlib

        m = importlib.import_module("fluxpay.shared.metrics")
        m.FLX_PROVIDER_CALLS_TOTAL.labels(
            provider=call.provider, op=call.op, ok=str(call.ok).lower()
        ).inc()
        m.FLX_PROVIDER_DURATION_SECONDS.labels(provider=call.provider, op=call.op).observe(
            call.duration_ms / 1000.0
        )

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
        """Execute an HTTP operation against the external provider via the retry ladder.

        Args:
            op: Operation name (e.g. 'create_payment_intent', 'payout_quote').
            method: HTTP verb ('GET', 'POST', 'PUT', 'DELETE', etc.).
            url_path: Target URL path or full URL.
            json: JSON serializable payload (omitted from logs by absence law).
            params: Query string parameters.
            headers: Caller-supplied HTTP headers.
            idempotency_key: Optional idempotency key attached only to POST requests.

        Returns:
            httpx.Response on successful 2xx execution.

        Raises:
            IntegrationAuthError: On 401 or 403 responses (internal configuration defect).
            IntegrationError: On other 4xx responses (immediate), 5xx exhaustion,
                or transport drops.
        """
        op_start = self._now()

        # ----------------------------------------------------------------------
        # 1) Headers merge & Correlation ID
        # WHY PER OPERATION (stable across retries):
        # X-FLX-Provider-Request-Id is OUR correlation ID for provider support tickets.
        # Generated once per operation, NOT per attempt. If an operation undergoes 3 attempts,
        # all 3 requests carry the identical correlation ID so upstream support engineers
        # and internal operators can trace the complete retry chain across provider logs.
        # ----------------------------------------------------------------------
        correlation_id = uuid.uuid4().hex
        merged_headers: dict[str, str] = {
            "X-FLX-Provider-Request-Id": correlation_id,
        }
        if headers is not None:
            merged_headers.update(headers)

        # ----------------------------------------------------------------------
        # 2) Idempotency Header
        # WHY METHOD LAW: Idempotency keys are only meaningful for state-mutating requests (POST).
        # GET requests are inherently idempotent by HTTP specification (RFC 9110 §9.2.2).
        # Attaching idempotency keys to GET requests degrades caching, pollutes provider
        # idempotency tables, or triggers 400 Bad Request responses on strict providers.
        # ----------------------------------------------------------------------
        if idempotency_key is not None and method.upper() == "POST":
            merged_headers[self.IDEMPOTENCY_HEADER] = idempotency_key

        last_status: int | None = None

        # ----------------------------------------------------------------------
        # 3) Attempt Loop
        # ----------------------------------------------------------------------
        for attempt in range(1, self.max_attempts + 1):
            attempt_start = self._now()
            response: httpx.Response | None = None

            try:
                response = await self._http.request(
                    method=method,
                    url=url_path,
                    json=json,
                    params=params,
                    headers=merged_headers,
                )
                status_code: int | None = response.status_code
                last_status = status_code
            except (httpx.TransportError, httpx.TimeoutException):
                status_code = None
                last_status = None

            attempt_duration_ms = int((self._now() - attempt_start) * 1000)

            # Observability: structlog line per attempt
            # ABSENCE LAW: NEVER log request body, NEVER log response body, NEVER log auth headers.
            self._logger.info(
                "provider_call_attempt",
                provider=self.provider_name,
                op=op,
                attempt=attempt,
                status=status_code,
                duration_ms=attempt_duration_ms,
            )

            # ------------------------------------------------------------------
            # 3a) 2xx Success -> return response
            # ------------------------------------------------------------------
            if response is not None and 200 <= response.status_code < 300:
                total_duration_ms = int((self._now() - op_start) * 1000)
                call = ProviderCall(
                    provider=self.provider_name,
                    op=op,
                    status=response.status_code,
                    duration_ms=total_duration_ms,
                    ok=True,
                )
                self._record_call(call)
                self._logger.info(
                    "provider_call_completed",
                    provider=call.provider,
                    op=call.op,
                    attempt=attempt,
                    status=call.status,
                    duration_ms=call.duration_ms,
                    ok=call.ok,
                )
                return response

            # ------------------------------------------------------------------
            # 3b) 429 Too Many Requests -> respect Retry-After header, then continue
            # ------------------------------------------------------------------
            if response is not None and response.status_code == 429:
                if attempt >= self.max_attempts:
                    break

                # WHY RETRY-AFTER PRIORITY: The provider's own pacing request outranks our
                # internal backoff math. Ignoring Retry-After deepens the rate-limit hole,
                # risks extended IP/account bans, and violates upstream service level agreements.
                retry_after_hdr = response.headers.get("Retry-After")
                sleep_s: float | None = None
                if retry_after_hdr is not None:
                    try:
                        parsed_val = float(retry_after_hdr)
                        if parsed_val >= 0:
                            sleep_s = parsed_val
                    except (ValueError, TypeError):
                        sleep_s = None

                if sleep_s is not None:
                    # Respect Retry-After exactly, capped at backoff_cap_s
                    if sleep_s > self.backoff_cap_s:
                        sleep_duration: float = self.backoff_cap_s
                    else:
                        sleep_duration = int(sleep_s) if sleep_s.is_integer() else sleep_s
                else:
                    # 429 without header -> normal ladder backoff (base * 2^n + jitter, capped)
                    n = attempt - 1
                    nominal = self.backoff_base_s * (2**n)
                    jitter = nominal * random.uniform(0.0, 0.25)  # noqa: S311 (retry jitter)
                    sleep_duration = min(self.backoff_cap_s, nominal + jitter)

                await self._sleep(sleep_duration)
                continue

            # ------------------------------------------------------------------
            # 3c) Other 4xx Client Errors -> Immediate raise (no retry)
            # ------------------------------------------------------------------
            if response is not None and 400 <= response.status_code < 500:
                total_duration_ms = int((self._now() - op_start) * 1000)
                call = ProviderCall(
                    provider=self.provider_name,
                    op=op,
                    status=response.status_code,
                    duration_ms=total_duration_ms,
                    ok=False,
                )
                self._record_call(call)
                self._logger.info(
                    "provider_call_completed",
                    provider=call.provider,
                    op=call.op,
                    attempt=attempt,
                    status=call.status,
                    duration_ms=call.duration_ms,
                    ok=call.ok,
                )

                provider_err = self.extract_provider_error(response)
                details = {
                    "provider": self.provider_name,
                    "op": op,
                    "status": str(response.status_code),
                    "provider_error": provider_err,
                }

                # WHY 401/403 -> IntegrationAuthError:
                # Invalid, expired, or revoked API keys represent OUR internal configuration
                # defect, not a transient external outage. Retrying with defective credentials
                # is pure noise. A non-retryable 500 signals internal misconfiguration for SEV
                # triage while keeping upstream provider identity strictly private from callers.
                if response.status_code in (401, 403):
                    raise IntegrationAuthError(details=details)

                # WHY OTHER 4xx -> IntegrationError IMMEDIATELY:
                # 400 Bad Request, 404 Not Found, 422 Unprocessable Entity indicate request shape
                # defects. Retrying client errors is futile and exhausts upstream rate limits.
                # ABSENCE LAW: Response body is strictly excluded from details to prevent
                # leaking card numbers, names, or other provider PII into application logs.
                raise IntegrationError(details=details)

            # ------------------------------------------------------------------
            # 3d) 5xx / TransportError / Timeout -> Ladder backoff with jitter
            # ------------------------------------------------------------------
            if attempt < self.max_attempts:
                n = attempt - 1
                nominal = self.backoff_base_s * (2**n)
                jitter = nominal * random.uniform(0.0, 0.25)  # noqa: S311 (retry jitter)
                sleep_duration = min(self.backoff_cap_s, nominal + jitter)
                await self._sleep(sleep_duration)
                continue

        # ----------------------------------------------------------------------
        # 4) Ladder Exhausted -> IntegrationError
        # ----------------------------------------------------------------------
        total_duration_ms = int((self._now() - op_start) * 1000)
        call = ProviderCall(
            provider=self.provider_name,
            op=op,
            status=last_status,
            duration_ms=total_duration_ms,
            ok=False,
        )
        self._record_call(call)
        self._logger.info(
            "provider_call_completed",
            provider=call.provider,
            op=call.op,
            attempt=self.max_attempts,
            status=call.status,
            duration_ms=call.duration_ms,
            ok=call.ok,
        )

        exhausted_details = {
            "provider": self.provider_name,
            "op": op,
            "attempts": str(self.max_attempts),
        }
        if last_status is not None:
            exhausted_details["status"] = str(last_status)

        raise IntegrationError(details=exhausted_details)
