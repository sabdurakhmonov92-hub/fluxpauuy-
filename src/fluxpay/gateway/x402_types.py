"""Domain types and protocols for x402 payment authorization (RFC 7231 / x402).

This module defines Pydantic payload models, typed domain schemas, and frozen protocols
for EIP-3009 transfer authorizations, facilitator outcomes, agent resolution, and ledger
posting.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "AgentRecord",
    "AgentRegistry",
    "LedgerClient",
    "PaymentPayload",
    "PaymentRequired",
    "PaymentRequiredExtra",
    "PaymentResponse",
    "ReconciliationQueue",
    "SettleResult",
    "VerifyResult",
]


class PaymentRequiredExtra(BaseModel):
    """Metadata describing the payment asset and version parameters."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore", frozen=True)

    name: str = "USDC"
    version: str = "2"
    decimals: int = 6


class PaymentRequired(BaseModel):
    """x402 challenge schema returned in PAYMENT-REQUIRED response header and body.

    Spec: https://x402.org/spec
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore", frozen=True)

    scheme: str = "exact"
    network: str = "base"
    asset: str
    amount: str
    pay_to: str = Field(alias="payTo")
    max_timeout_seconds: int = Field(default=300, alias="maxTimeoutSeconds")
    extra: PaymentRequiredExtra = Field(default_factory=PaymentRequiredExtra)
    error: str = "payment_required"


class PaymentPayload(BaseModel):
    """Decoded EIP-3009 transferWithAuthorization payload received in X-PAYMENT.

    Supports both flat authorization representations and nested authorization wrappers
    standardized across x402 implementations.
    """

    model_config = ConfigDict(populate_by_name=True, extra="ignore", frozen=True)

    from_address: str = Field(alias="from")
    to_address: str = Field(alias="to")
    value: str | int
    valid_after: int = Field(alias="validAfter")
    valid_before: int = Field(alias="validBefore")
    nonce: str
    v: int | None = None
    r: str | None = None
    s: str | None = None
    signature: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _unwrap_nested_payload(cls, data: Any) -> Any:
        """Unwrap nested 'authorization' structures if passed by x402 client."""
        if not isinstance(data, dict):
            return data
        copied = dict(data)
        auth = copied.get("authorization")
        if isinstance(auth, dict):
            # Promote authorization fields to top-level if missing
            for key, val in auth.items():
                copied.setdefault(key, val)
        return copied

    @property
    def value_int(self) -> int:
        """Convert string or integer value to exact integer minor units."""
        return int(self.value)


class PaymentResponse(BaseModel):
    """Receipt returned in X-PAYMENT-RESPONSE upon successful on-chain settlement."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore", frozen=True)

    success: bool = True
    tx_hash: str = Field(alias="txHash")
    network: str = "base"
    amount: str
    asset: str
    pay_to: str = Field(alias="payTo")
    from_address: str = Field(alias="from")
    nonce: str
    settled_at: int = Field(alias="settledAt")
    block_number: int | None = Field(default=None, alias="blockNumber")


class VerifyResult(BaseModel):
    """Result of signature and balance verification emitted by a facilitator."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore", frozen=True)

    valid: bool
    error: str | None = None
    reason: str | None = None
    agent_address: str | None = None
    balance: int | None = None
    required_amount: int | None = None


class SettleResult(BaseModel):
    """Result of on-chain execution emitted by a facilitator."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore", frozen=True)

    success: bool
    tx_hash: str | None = None
    block_number: int | None = None
    error: str | None = None
    reason: str | None = None
    fee_paid: int | None = None


@dataclass(frozen=True, slots=True)
class AgentRecord:
    """Agent identity and account mapping in the FluxPay ecosystem."""

    agent_id: str
    address: str
    account_id: UUID
    active: bool = True


@runtime_checkable
class AgentRegistry(Protocol):
    """Abstract interface for resolving agent identity and ledger accounts."""

    async def resolve_agent(self, address: str) -> AgentRecord | None:
        """Resolve agent record from on-chain EVM address."""
        ...

    async def get_or_create_agent(self, address: str) -> AgentRecord:
        """Retrieve existing agent or provision an account record."""
        ...


@runtime_checkable
class LedgerClient(Protocol):
    """Abstract double-entry ledger interface for recording payment settlements."""

    async def record_payment(
        self,
        *,
        agent_id: str,
        merchant_id: str,
        amount_minor: int,
        currency: str,
        idempotency_key: str,
        agent_account_id: UUID | None = None,
        merchant_account_id: UUID | None = None,
    ) -> Any:
        """Atomically record double-entry debit and credit legs for settled payment."""
        ...


@runtime_checkable
class ReconciliationQueue(Protocol):
    """Dead-letter or reconciliation queue for post-settlement ledger write failures."""

    async def enqueue(self, job_data: dict[str, Any]) -> None:
        """Enqueue an urgent reconciliation task for off-band retry."""
        ...
