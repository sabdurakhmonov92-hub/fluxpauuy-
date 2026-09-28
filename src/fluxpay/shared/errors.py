"""Typed error hierarchy and frozen failure contract for FluxPay.

In a payment platform consumed by autonomous AI agents, error responses are a critical
half of the public API contract. Error codes are immutable identifiers; the `retryable`
flag explicitly controls agent loop behavior to prevent runaway retries or premature
abandonment of transient failures.

Design Invariants:
- Zero internal dependencies (leaf module): safe for import by middleware, models, and workers.
- Diagnostic details (account IDs, SQL fragments, stack context) are kept strictly in
  `details` and NEVER serialized to external clients.
- `to_payload()` emits the frozen wire format expected by HTTP clients and openapi.yaml.
"""

import inspect
import sys
from typing import Final

__all__ = [
    "ERROR_REGISTRY",
    "AuthenticationError",
    "FluxPayError",
    "ForbiddenError",
    "IdempotencyConflict",
    "InsufficientFunds",
    "IntegrationAuthError",
    "IntegrationError",
    "InternalError",
    "LedgerNotFoundError",
    "NotFoundError",
    "OCCConflict",
    "PayoutNotOpenError",
    "RateLimitError",
    "ReplayError",
    "UnbalancedTransaction",
    "ValidationError",
    "as_fluxpay_error",
]


class FluxPayError(Exception):
    """Base error for all domain and platform failures in FluxPay.

    Every failure returned to API clients inherits from this class. It guarantees
    a stable machine-readable code, an HTTP status code, an explicit retryable flag,
    and a sanitized human-readable client message.

    Internal diagnostics (account IDs, balance amounts, SQL contexts) must ONLY
    be passed via `details` and are strictly excluded from client serialization.
    """

    code: str = "fluxpay_error"
    status: int = 500
    retryable: bool = False
    client_message: str = "An unexpected platform error occurred."

    def __init__(
        self,
        *,
        details: dict[str, str] | None = None,
        message: str | None = None,
    ) -> None:
        self.message: str = message if message is not None else self.client_message
        self.details: dict[str, str] = details.copy() if details is not None else {}
        super().__init__(self.message)

    def __str__(self) -> str:
        """Return only the client-safe message to prevent accidental log leaks."""
        return self.message

    def to_payload(self) -> dict[str, dict[str, str | bool]]:
        """Produce the frozen external API error payload.

        Details are strictly omitted from this payload; they exist exclusively for
        internal logging and audit trails.
        """
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "retryable": self.retryable,
            }
        }


# --- Gateway / Auth (Blueprint §3) ---


class AuthenticationError(FluxPayError):
    """Client authentication credentials were missing, expired, or invalid."""

    code: str = "authentication_failed"
    status: int = 401
    retryable: bool = False
    client_message: str = "Authentication credentials were missing or invalid."


class ReplayError(FluxPayError):
    """Request timestamp expired or nonce was already processed within replay window."""

    code: str = "replay_detected"
    status: int = 401
    retryable: bool = False
    client_message: str = "Request timestamp or nonce has already been processed or expired."


class RateLimitError(FluxPayError):
    """Agent exceeded request rate limit for the sliding window.

    Retryable semantics: TRUE. Rate limits are transient; the same request is expected
    to succeed after the backoff window elapses.
    """

    code: str = "rate_limited"
    status: int = 429
    retryable: bool = True
    client_message: str = "Too many requests. Please retry after backoff."


class IdempotencyConflict(FluxPayError):  # noqa: N818
    """Idempotency key was reused with a different request payload or hash.

    Retryable semantics: FALSE. Reusing a key with conflicting payload is a programming
    bug or protocol misuse; retrying without changing the key will never succeed.
    """

    code: str = "idempotency_conflict"
    status: int = 409
    retryable: bool = False
    client_message: str = "Idempotency key was reused with a different request payload."


# --- Money Path (Blueprint §5) ---


class InsufficientFunds(FluxPayError):  # noqa: N818
    """Source account lacks sufficient available balance to complete the transfer."""

    code: str = "insufficient_funds"
    status: int = 400
    retryable: bool = False
    client_message: str = "Account does not have sufficient available balance."


class UnbalancedTransaction(FluxPayError):  # noqa: N818
    """Ledger transaction entries do not sum to zero (double-entry invariant violation).

    This represents a critical system defect. If raised, the transaction is rejected,
    the platform halts affected operations, and SEV1 alerts trigger immediately.
    Client message remains strictly generic to avoid exposing internal ledger state.
    """

    code: str = "internal_ledger_error"
    status: int = 500
    retryable: bool = False
    client_message: str = "An internal ledger error occurred."


class LedgerNotFoundError(FluxPayError):
    """Referenced ledger account or asset balance was not found."""

    code: str = "account_not_found"
    status: int = 404
    retryable: bool = False
    client_message: str = "The requested ledger account was not found."


# --- Concurrency ---


class OCCConflict(FluxPayError):  # noqa: N818
    """Optimistic concurrency control conflict during account balance mutation.

    Retryable semantics: TRUE. OCC conflicts occur under concurrent updates. In the
    ledger layer, bounded retries with jitter are attempted. If this error escapes
    to the client, bounded retries were exhausted and the client should retry after backoff.
    """

    code: str = "conflict_retry_required"
    status: int = 503
    retryable: bool = True
    client_message: str = "Concurrent update conflict. Request may succeed on retry."


# --- Boundary ---


class ValidationError(FluxPayError):
    """Incoming request payload failed schema validation or business constraints."""

    code: str = "validation_failed"
    status: int = 422
    retryable: bool = False
    client_message: str = "Request payload failed validation."


class NotFoundError(FluxPayError):
    """Requested API resource was not found."""

    code: str = "not_found"
    status: int = 404
    retryable: bool = False
    client_message: str = "The requested resource was not found."


class InternalError(FluxPayError):
    """Unhandled server error. Safe generic fallback for unhandled exceptions."""

    code: str = "internal_error"
    status: int = 500
    retryable: bool = False
    client_message: str = "An internal server error occurred."


def as_fluxpay_error(exc: Exception) -> FluxPayError:
    """Convert any arbitrary exception into a client-safe FluxPayError.

    - Existing FluxPayError instances pass through untouched.
    - Any other exception is converted into an InternalError with details containing
      only the exception type name.
    - Crucial security invariant: raw exception strings (`str(exc)`) are NEVER included
      because they leak SQL queries, file system paths, and memory contents.
    """
    if isinstance(exc, FluxPayError):
        return exc
    return InternalError(details={"type": type(exc).__name__})


# Auto-derived registry mapping error codes to their respective FluxPayError classes.
# Built dynamically by scanning module classes to prevent manual registry rot.
ERROR_REGISTRY: Final[dict[str, type[FluxPayError]]] = {
    cls.code: cls
    for _, cls in inspect.getmembers(
        sys.modules[__name__],
        lambda m: inspect.isclass(m) and issubclass(m, FluxPayError),
    )
}


# --- Task 7 append ---


class VaultError(FluxPayError):
    """Cryptographic vault operation failure.

    Decryption failure indicates corrupted data, wrong key, or tampering —
    an OPERATIONAL ALARM, never a client-facing detail.
    """

    code: str = "vault_error"
    status: int = 500
    retryable: bool = False
    client_message: str = "internal security module failure"


# --- Task 8 append ---


class TransactionError(FluxPayError):
    """Transaction boundary failure or invariant violation."""

    code = "transaction_error"
    status = 500
    retryable = False
    client_message = "internal transaction failure"


# --- Task 9 append ---


class EventPublishError(FluxPayError):
    """Event publication or deserialization failure on the event bus.

    WHY retryable=True: bus failures are transient infra conditions
    (Redis restart, network blip) — internal callers may retry with
    backoff.
    """

    code: str = "event_publish_failed"
    status: int = 500
    retryable: bool = True
    client_message: str = "event delivery temporarily unavailable"


# --- Task 11 append ---


class IdempotencyStateError(FluxPayError):
    """Internal idempotency state-machine violation or lost reservation race.

    Indicates an unhandled state transition, concurrent takeover race condition,
    or internal middleware bug. This is an operational alarm (SEV2), never a client-side
    error or retryable condition.
    """

    code: str = "idempotency_state_error"
    status: int = 500
    retryable: bool = False
    client_message: str = "internal idempotency failure"


# --- Task 20 append ---


class GateUnavailable(FluxPayError):  # noqa: N818
    """Valkey/Redis rate-limiting or anti-replay gate is unreachable or timed out.

    Retryable semantics: TRUE. Infrastructure blips or transient connectivity issues
    with Valkey are temporary; caller should retry with backoff.
    """

    code: str = "gate_unavailable"
    status: int = 503
    retryable: bool = True
    client_message: str = "service temporarily unavailable, retry"


# --- Task 29 append ---


class ForbiddenError(FluxPayError):
    """Client role or privileges are insufficient for the requested administrative action."""

    code: str = "forbidden"
    status: int = 403
    retryable: bool = False
    client_message: str = "insufficient permissions"


ERROR_REGISTRY[ForbiddenError.code] = ForbiddenError


# --- Task 28 append ---


class PaymentPolicyError(FluxPayError):
    """Payment rejected by risk policy (e.g. transient velocity ceiling).

    Retryable semantics: FALSE. Policy rejections are not transient network glitches;
    agent clients must stop retrying immediately.
    """

    code: str = "payment_policy_rejected"
    status: int = 422
    retryable: bool = False
    client_message: str = "payment rejected by risk policy"


ERROR_REGISTRY[PaymentPolicyError.code] = PaymentPolicyError


# --- Task 45 append ---


class PayoutNotOpenError(FluxPayError):
    """Cold payout record is not in an open state for the requested operation."""

    code: str = "payout_not_open"
    status: int = 409
    retryable: bool = False
    client_message: str = "cold payout is not in open status"


ERROR_REGISTRY[PayoutNotOpenError.code] = PayoutNotOpenError


# --- Task 49 append ---


class IntegrationError(FluxPayError):
    """External provider temporarily unavailable.

    WHY 502 (not 500): the platform is healthy; the UPSTREAM failed —
    the status tells the agent "retry later" truthfully (retryable True matches).
    WHY not 503 (GateUnavailable's code): 503 is OUR infra's "come back" (Task 20's
    fail-closed gate); 502 is "we relayed your request and the provider died" —
    distinct operational meaning, distinct code, no collision.
    """

    code: str = "integration_error"
    status: int = 502
    retryable: bool = True
    client_message: str = "external provider temporarily unavailable"


class IntegrationAuthError(FluxPayError):
    """Internal provider configuration error.

    WHY non-retryable 500: bad/expired API key = OUR misconfiguration —
    retries are noise, SEV ticket is the cure; client never learns which
    provider (details stay internal).
    """

    code: str = "integration_auth_error"
    status: int = 500
    retryable: bool = False
    client_message: str = "internal provider configuration error"
