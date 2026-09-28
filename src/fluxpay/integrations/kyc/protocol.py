"""KYC provider integration protocol and data contracts (Block J, Task 55).

==============================================================================
THE IDENTITY OF TRUTH ESSAY (PROVIDER RECOMMENDS, PLATFORM DECIDES)
==============================================================================
A webhook says "applicant cleared" — but FROM WHOM, signed HOW, mapped to WHICH
internal merchant, and WHO decided the final approval?

Provider recommendation and platform decision are DIFFERENT authorities.
A SumSub review event carries Sumsub's recommendation ("GREEN" / "RED").
A Trulioo verification response carries Trulioo's record match status.
These are external inputs to a platform decision, NEVER the decision itself.

Design Law: The provider RECOMMENDS; the platform DECIDES.
Task 29's admin decide endpoint (/admin/kyc/{id}/decide) remains the ONLY
approval authority in the system. Providers never auto-write kyc_requests.status.
Automated signals inform human review, but never usurp administrative authority.

==============================================================================
DOCUMENT-CUSTODY PRIVACY ARCHITECTURE
==============================================================================
In hosted-flow verification (e.g. Sumsub WebSDK), the merchant's browser or device
communicates directly with the KYC provider via temporary access tokens.
Our servers never receive, store, or custody passports, driver licenses, or selfie
biometrics. Document custody stays with the licensed, certified compliance provider.
FluxPay holds decisions, provider references, and audit logs — not identity documents.
This eliminates high-liability biometric/PII data stores from our core database.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "KycProvider",
    "KycState",
    "VerificationStart",
]


@dataclass(frozen=True, slots=True)
class VerificationStart:
    """Result of initiating a KYC verification flow with a provider.

    Attributes:
        ref: Provider reference identifier (e.g. Sumsub applicantId, Trulioo transactionId,
             or internal kyc_request_id for manual mode).
             Written one-way to kyc_requests.provider_ref.
        redirect_url: Hosted-flow URL (for browser-based hosted flows like Sumsub)
                      or None (for manual review or direct SDK token flows).
    """

    ref: str
    redirect_url: str | None = None


@dataclass(frozen=True, slots=True)
class KycState:
    """Normalized provider verification status.

    Attributes:
        status: Normalized status: 'pending', 'cleared', or 'declined'.
        raw: Provider-shaped response payload for admin operator context (display-only).
    """

    status: Literal["pending", "cleared", "declined"]
    raw: dict[str, Any]


@runtime_checkable
class KycProvider(Protocol):
    """Protocol contract for all KYC identity verification adapters.

    Every provider (Sumsub, Trulioo, Manual) conforms to this single protocol,
    allowing the orchestrator and admin plane to remain provider-blind.
    """

    async def start_verification(self, *, subject_ref: str) -> VerificationStart:
        """Start a verification session for a subject.

        Args:
            subject_ref: FluxPay's internal kyc_request row ID (UUID string).
                         Used as externalUserId / client reference by providers.
                         The mapping direction (our-id -> their-ref) is one-way
                         written to kyc_requests.provider_ref at start time.

        Returns:
            VerificationStart containing provider reference and optional redirect URL.
        """
        ...

    async def fetch_status(self, ref: str) -> KycState:
        """Fetch current verification status from provider.

        Args:
            ref: Provider reference identifier previously returned by start_verification.

        Returns:
            KycState with normalized status ('pending'|'cleared'|'declined') and raw payload.
        """
        ...

    def verify_webhook(
        self, *, payload: bytes, headers: Mapping[str, str]
    ) -> dict[str, Any] | None:
        """Verify cryptographic webhook signature and return parsed payload.

        Args:
            payload: Raw unparsed HTTP request body bytes.
            headers: Incoming HTTP headers mapping.

        Returns:
            Parsed payload dict if signature is valid; None if unverified or malformed.
            Enforces verify-returns-none law (log forensics, no exception overhead on hot path).
        """
        ...

    async def healthcheck(self) -> bool:
        """Cheapest authenticated ping.

        Returns:
            True if provider connection is healthy and credentials valid, False otherwise.
            Never raises exceptions.
        """
        ...
