"""API contract schemas: Pydantic v2 wire models for machine-to-machine payment agents.

Contract Laws:
1. Strict Validation: Coercion failures are client bugs. Booleans are not money,
   numeric strings are not integers. All monetary fields use StrictInt to reject
   ambiguous inputs with HTTP 422 Unprocessable Entity rather than silent coercion.
2. Extra Forbid: Unknown fields are forbidden (extra="forbid"). A misspelled parameter
   like 'ammount' fails immediately at the gateway rather than disappearing silently.
3. Immutability: All request and response models are frozen (frozen=True). Once validated,
   payload values cannot be mutated across handlers or pipeline stages.
4. Leaf Independence: This module imports NOTHING from fluxpay, fastapi, or starlette.
   External SDKs, background workers, and automated client agents can consume these
   models directly without server-side dependencies.
"""

from datetime import UTC, datetime
from typing import Final, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictInt, field_serializer

# ==============================================================================
# a) SHARED CONSTRAINTS (Module Constants — Single Source of Truth)
# ==============================================================================

# Task 12 law L1 mirror: Currency codes must be 2 to 10 uppercase alphanumeric
# characters (e.g. 'USDC', 'USD', 'EUR'). Lowercase or special characters are rejected.
CURRENCY_PATTERN: Final[str] = r"^[A-Z0-9]{2,10}$"

# FREEZE: Merchant external_id grammar (Task 26 lookup key).
# WHY lowercase-only: Human-typed merchant handles are case-ambiguous; autonomous agents
# are deterministic machines. Enforcing a single canonical lowercase grammar (3-64 chars,
# lowercase alphanumeric plus '.', '_', '-') eliminates casing normalization bugs.
MERCHANT_ID_PATTERN: Final[str] = r"^[a-z0-9_.-]{3,64}$"

# Mirrors Task 19 (_IDEMPOTENCY_KEY_REGEX in fluxpay.gateway.canonical).
# Documented mirror: Idempotency keys live exclusively in the `X-FLX-Idempotency-Key`
# HTTP header (Task 19/21/22) and are enforced by gateway middleware. Request payload
# schemas do not re-check it, keeping the body protocol decoupled from transport headers.
IDEMPOTENCY_KEY_PATTERN: Final[str] = r"^[A-Za-z0-9-]{16,128}$"


# ==============================================================================
# b) REQUEST MODELS
# ==============================================================================


class PaymentRequest(BaseModel):
    """Wire model for POST /v1/payments request body.

    Transport Note:
    The idempotency key is intentionally omitted from this payload because it is conveyed
    via the `X-FLX-Idempotency-Key` HTTP header (Task 19/21/22). This allows reverse proxies
    and gateway middleware to inspect and enforce deduplication before reading the request body.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "example": {
                "to": "merchant_demo",
                "amount": 1050,
                "currency": "USDC",
            }
        },
    )

    to: str = Field(
        ...,
        pattern=MERCHANT_ID_PATTERN,
        description="Target merchant identifier (canonical lowercase handle).",
        json_schema_extra={"example": "merchant_demo"},
    )
    # WHY StrictInt: bool is not money (True becoming 1 is a catastrophic money bug),
    # "100" is not money — coercion failures are client bugs surfaced as 422 validation_failed,
    # NOT silent corrections.
    # Minor units: 1050 = $10.50 USDC (2 decimals) or minor units: 6 decimals for USDC (10_500_000).
    amount: StrictInt = Field(
        ...,
        gt=0,
        description=(
            "Payment amount in integer minor units (e.g. 1050 = $10.50 USDC; "
            "minor units: 6 decimals for USDC)."
        ),
        json_schema_extra={"example": 1050},
    )
    currency: str = Field(
        ...,
        pattern=CURRENCY_PATTERN,
        description="Currency symbol (2-10 uppercase alphanumeric characters, e.g. 'USDC').",
        json_schema_extra={"example": "USDC"},
    )


# ==============================================================================
# c) RESPONSE MODELS
# ==============================================================================


class PaymentResponse(BaseModel):
    """Wire model for POST /v1/payments (HTTP 201 Created).

    Identity Guarantee (Task 31):
    In Phase 1, `id` is identical to the ledger transaction ID (tx_id) — there is exactly
    one internal ledger transaction per external payment.

    Status Guarantee:
    Only terminal success states ('settled' | 'held') are valid for 201 Created.
    WHY no 'failed': Failures are ERROR responses (HTTP 4xx/5xx) serialized using the standard
    ErrorEnvelope. Returning a 201 with status='failed' would force autonomous agent clients to
    inspect payload contents rather than relying on HTTP status semantics.

    Status Evolution Rule:
    'pending' is reserved for future asynchronous settlement rails (Phase 2).
    Adding enum members is backward-compatible for tolerant agent parsers; today's contract
    strictly freezes status to 'settled' | 'held'.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "example": {
                "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "status": "settled",
            }
        },
    )

    id: UUID = Field(
        ...,
        description="Unique payment identifier (corresponds 1:1 with ledger tx_id in Phase 1).",
        json_schema_extra={"example": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
    )
    status: Literal["settled", "held"] = Field(
        ...,
        description="Terminal execution status for synchronous rails ('settled' or 'held').",
        json_schema_extra={"example": "settled"},
    )


class BalanceResponse(BaseModel):
    """Wire model for GET /v1/balance (HTTP 200 OK)."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "example": {
                "balance": 1050,
                "currency": "USDC",
            }
        },
    )

    balance: StrictInt = Field(
        ...,
        ge=0,
        description="Available ledger balance in minor units (non-negative integer).",
        json_schema_extra={"example": 1050},
    )
    currency: str = Field(
        ...,
        pattern=CURRENCY_PATTERN,
        description="Currency code for the balance account.",
        json_schema_extra={"example": "USDC"},
    )


class PaymentDetail(BaseModel):
    """Wire model for GET /v1/payments/{id} (HTTP 200 OK)."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "example": {
                "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "status": "settled",
                "amount": 1050,
                "currency": "USDC",
                "created_at": "2026-09-25T12:00:00+00:00",
            }
        },
    )

    id: UUID = Field(
        ...,
        description="Unique payment identifier (ledger tx_id).",
        json_schema_extra={"example": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
    )
    status: Literal["settled", "held"] = Field(
        ...,
        description="Payment status ('settled' or 'held').",
        json_schema_extra={"example": "settled"},
    )
    amount: StrictInt = Field(
        ...,
        gt=0,
        description="Payment amount in integer minor units (minor units: 6 decimals for USDC).",
        json_schema_extra={"example": 1050},
    )
    currency: str = Field(
        ...,
        pattern=CURRENCY_PATTERN,
        description="Currency code.",
        json_schema_extra={"example": "USDC"},
    )
    # tz-aware UTC serialized ISO-8601 — naive datetime REJECTED (tz-aware only —
    # ledger discipline mirrors Task 12).
    created_at: AwareDatetime = Field(
        ...,
        description="Creation timestamp in UTC ISO-8601 format with explicit '+00:00' offset.",
        json_schema_extra={"example": "2026-09-25T12:00:00+00:00"},
    )

    @field_serializer("created_at", when_used="json")
    def _serialize_created_at(self, dt: datetime) -> str:
        """Serialize datetime in UTC ISO-8601 format with explicit '+00:00' timezone offset.

        WHY: Pydantic v2 by default serializes UTC datetime with trailing 'Z'. In financial
        protocols consumed by machine agents across heterogeneous language runtimes,
        freezing the '+00:00' wire format guarantees deterministic lexical stability.
        """
        return dt.astimezone(UTC).isoformat()


# ==============================================================================
# d) ERROR ENVELOPE (Task 4 Structural Mirror)
# ==============================================================================


class ErrorBody(BaseModel):
    """Sanitized machine-readable error payload returned to API consumers."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "example": {
                "code": "validation_failed",
                "message": "Request payload failed validation.",
                "retryable": False,
            }
        },
    )

    code: str = Field(
        ...,
        description="Machine-readable error category identifier.",
        json_schema_extra={"example": "validation_failed"},
    )
    message: str = Field(
        ...,
        description="Sanitized client-safe description of the failure.",
        json_schema_extra={"example": "Request payload failed validation."},
    )
    retryable: bool = Field(
        ...,
        description="Indicates whether client agents may safely retry the request.",
        json_schema_extra={"example": False},
    )


class ErrorEnvelope(BaseModel):
    """Universal top-level error envelope for HTTP 4xx and 5xx responses.

    STRUCTURAL mirror of Task 4 to_payload() wire shape:
    {"error": {"code": str, "message": str, "retryable": bool}}.
    Roundtrip tests prove byte-level semantic equality across all classes
    in fluxpay.shared.errors.ERROR_REGISTRY.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "example": {
                "error": {
                    "code": "validation_failed",
                    "message": "Request payload failed validation.",
                    "retryable": False,
                }
            }
        },
    )

    error: ErrorBody = Field(
        ...,
        description="Standardized error details.",
    )
